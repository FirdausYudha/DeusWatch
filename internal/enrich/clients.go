package enrich

// Real CTI/GeoIP clients (replacing MockProvider in production):
//   - AbuseIPDB  : IP reputation (abuseConfidenceScore + countryCode)  — needs API key
//   - OTX        : AlienVault OTX pulse count                          — needs API key
//   - ip-api.com : free GeoIP (countryCode + city), no key             — opt-in
//
// CompositeProvider merges the configured sub-clients into a single Indicator.
// Private/loopback IPs are skipped (no external calls). A single source's failure is
// logged and ignored as long as at least one source succeeds; if all fail → error
// (the worker marks enrichment 'failed', the event is still stored).

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"deuswatch/internal/blocklist"
)

const defaultHTTPTimeout = 8 * time.Second

func newHTTPClient() *http.Client { return &http.Client{Timeout: defaultHTTPTimeout} }

// isPrivateIP reports whether ip is private/loopback/link-local/invalid — skipped.
func isPrivateIP(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return true
	}
	return p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast() || p.IsUnspecified()
}

// getJSON does a GET with optional headers and decodes the JSON body into dst.
func getJSON(ctx context.Context, hc *http.Client, rawURL string, headers map[string]string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

// ── AbuseIPDB ─────────────────────────────────────────────

const defaultAbuseBase = "https://api.abuseipdb.com"

type AbuseIPDBClient struct {
	key  string
	base string
	hc   *http.Client
}

func NewAbuseIPDBClient(key string) *AbuseIPDBClient {
	return &AbuseIPDBClient{key: key, base: defaultAbuseBase, hc: newHTTPClient()}
}

// Check returns the abuse score (0..100) & country code for ip.
func (c *AbuseIPDBClient) Check(ctx context.Context, ip string) (score int, country string, err error) {
	u := c.base + "/api/v2/check?" + url.Values{
		"ipAddress":    {ip},
		"maxAgeInDays": {"90"},
	}.Encode()
	var out struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
		} `json:"data"`
	}
	if err := getJSON(ctx, c.hc, u, map[string]string{"Key": c.key}, &out); err != nil {
		return 0, "", fmt.Errorf("abuseipdb: %w", err)
	}
	return out.Data.AbuseConfidenceScore, out.Data.CountryCode, nil
}

// ── AlienVault OTX ────────────────────────────────────────

const defaultOTXBase = "https://otx.alienvault.com"

type OTXClient struct {
	key  string
	base string
	hc   *http.Client
}

func NewOTXClient(key string) *OTXClient {
	return &OTXClient{key: key, base: defaultOTXBase, hc: newHTTPClient()}
}

// Pulses returns the OTX pulse count for ip.
func (c *OTXClient) Pulses(ctx context.Context, ip string) (int, error) {
	u := c.base + "/api/v1/indicators/IPv4/" + url.PathEscape(ip) + "/general"
	var out struct {
		PulseInfo struct {
			Count int `json:"count"`
		} `json:"pulse_info"`
	}
	if err := getJSON(ctx, c.hc, u, map[string]string{"X-OTX-API-KEY": c.key}, &out); err != nil {
		return 0, fmt.Errorf("otx: %w", err)
	}
	return out.PulseInfo.Count, nil
}

// ── GeoIP (ip-api.com, free, no key) ──────────────────────

const defaultGeoBase = "http://ip-api.com"

type GeoClient struct {
	base string
	hc   *http.Client
}

func NewGeoClient() *GeoClient { return &GeoClient{base: defaultGeoBase, hc: newHTTPClient()} }

// Geo returns the country code & city for ip.
func (c *GeoClient) Geo(ctx context.Context, ip string) (country, city string, err error) {
	u := c.base + "/json/" + url.PathEscape(ip) + "?fields=status,message,countryCode,city"
	var out struct {
		Status      string `json:"status"`
		Message     string `json:"message"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
	}
	if err := getJSON(ctx, c.hc, u, nil, &out); err != nil {
		return "", "", fmt.Errorf("geoip: %w", err)
	}
	if out.Status != "success" {
		return "", "", fmt.Errorf("geoip: %s", out.Message)
	}
	return out.CountryCode, out.City, nil
}

// ── Composite ─────────────────────────────────────────────

// CompositeProvider runs the configured sub-clients and merges their results.
// Nil fields are skipped.
type CompositeProvider struct {
	Abuse     *AbuseIPDBClient
	OTX       *OTXClient
	Geo       *GeoClient
	Blocklist *blocklist.Set // community blocklist (optional)
}

// Lookup satisfies Provider.
func (p *CompositeProvider) Lookup(ctx context.Context, ip string) (Indicator, error) {
	if isPrivateIP(ip) {
		return Indicator{FeedName: "internal"}, nil // never query private IPs against external services
	}
	var (
		ind   Indicator
		feeds []string
		ok    bool
		errs  []string
	)
	// The community blocklist is a strong malicious signal (offline, no API).
	if p.Blocklist != nil && p.Blocklist.Contains(ip) {
		ind.AbuseConfidence = 100
		feeds, ok = append(feeds, "blocklist"), true
	}
	if p.Abuse != nil {
		if score, country, err := p.Abuse.Check(ctx, ip); err != nil {
			log.Printf("enrich: %v", err)
			errs = append(errs, err.Error())
		} else {
			if score > ind.AbuseConfidence { // do not lower the blocklist floor
				ind.AbuseConfidence = score
			}
			ind.CountryISO = country
			feeds, ok = append(feeds, "abuseipdb"), true
		}
	}
	if p.OTX != nil {
		if count, err := p.OTX.Pulses(ctx, ip); err != nil {
			log.Printf("enrich: %v", err)
			errs = append(errs, err.Error())
		} else {
			ind.OTXPulseCount = count
			feeds, ok = append(feeds, "otx"), true
		}
	}
	if p.Geo != nil && (ind.CountryISO == "" || ind.City == "") {
		if country, city, err := p.Geo.Geo(ctx, ip); err != nil {
			log.Printf("enrich: %v", err)
			errs = append(errs, err.Error())
		} else {
			if ind.CountryISO == "" {
				ind.CountryISO = country
			}
			ind.City = city
			feeds, ok = append(feeds, "ip-api"), true
		}
	}
	if !ok && len(errs) > 0 {
		return Indicator{}, fmt.Errorf("enrich: all sources failed: %s", strings.Join(errs, "; "))
	}
	ind.FeedName = strings.Join(feeds, ",")
	return ind, nil
}

// ProviderFromEnv builds a provider from the environment:
//
//	ABUSEIPDB_API_KEY  -> enable the AbuseIPDB client
//	OTX_API_KEY        -> enable the OTX client
//	GEOIP_ENABLED=1    -> enable GeoIP (ip-api.com, free)
//
// If nothing is configured, it falls back to the demo MockProvider (dev) + false flag.
func ProviderFromEnv() (Provider, bool) {
	abuseKey := os.Getenv("ABUSEIPDB_API_KEY")
	otxKey := os.Getenv("OTX_API_KEY")
	geoOn, _ := strconv.ParseBool(os.Getenv("GEOIP_ENABLED"))
	blURLs := splitCSV(os.Getenv("BLOCKLIST_URLS"))

	if abuseKey == "" && otxKey == "" && !geoOn && len(blURLs) == 0 {
		return NewDemoProvider(), false
	}
	cp := &CompositeProvider{}
	if abuseKey != "" {
		cp.Abuse = NewAbuseIPDBClient(abuseKey)
	}
	if otxKey != "" {
		cp.OTX = NewOTXClient(otxKey)
	}
	if geoOn {
		cp.Geo = NewGeoClient()
	}
	if len(blURLs) > 0 {
		if set, err := blocklist.Load(context.Background(), nil, blURLs); err != nil {
			log.Printf("enrich: failed to load blocklist: %v", err)
		} else {
			cp.Blocklist = set
			log.Printf("enrich: community blocklist loaded (%d entries)", set.Len())
			go blocklist.Refresh(context.Background(), nil, blURLs, blocklistRefresh(), set)
		}
	}
	return cp, true
}

// splitCSV splits a comma-separated string into non-empty, trimmed tokens.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// blocklistRefresh reads the blocklist refresh interval (BLOCKLIST_REFRESH), default 6h.
func blocklistRefresh() time.Duration {
	if v := os.Getenv("BLOCKLIST_REFRESH"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 6 * time.Hour
}
