package enrich

// Klien CTI/GeoIP nyata (menggantikan MockProvider untuk produksi):
//   - AbuseIPDB  : reputasi IP (abuseConfidenceScore + countryCode)  — butuh API key
//   - OTX        : jumlah pulse AlienVault OTX                        — butuh API key
//   - ip-api.com : GeoIP gratis (countryCode + city), tanpa key      — opt-in
//
// CompositeProvider menggabungkan sub-klien yang dikonfigurasi menjadi satu Indicator.
// IP privat/loopback dilewati (tak ada panggilan eksternal). Kegagalan satu sumber
// di-log dan diabaikan selama minimal satu sumber berhasil; bila semua gagal → error
// (worker menandai enrichment 'failed', event tetap tersimpan).

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

// isPrivateIP melaporkan apakah ip privat/loopback/link-local/tak valid — dilewati.
func isPrivateIP(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return true
	}
	return p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast() || p.IsUnspecified()
}

// getJSON melakukan GET dengan header opsional dan men-decode body JSON ke dst.
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

// Check mengembalikan skor abuse (0..100) & kode negara untuk ip.
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

// Pulses mengembalikan jumlah pulse OTX untuk ip.
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

// ── GeoIP (ip-api.com, gratis tanpa key) ──────────────────

const defaultGeoBase = "http://ip-api.com"

type GeoClient struct {
	base string
	hc   *http.Client
}

func NewGeoClient() *GeoClient { return &GeoClient{base: defaultGeoBase, hc: newHTTPClient()} }

// Geo mengembalikan kode negara & kota untuk ip.
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

// CompositeProvider menjalankan sub-klien yang dikonfigurasi dan menggabungkan
// hasilnya. Field nil dilewati.
type CompositeProvider struct {
	Abuse     *AbuseIPDBClient
	OTX       *OTXClient
	Geo       *GeoClient
	Blocklist *blocklist.Set // daftar blokir komunitas (opsional)
}

// Lookup memenuhi Provider.
func (p *CompositeProvider) Lookup(ctx context.Context, ip string) (Indicator, error) {
	if isPrivateIP(ip) {
		return Indicator{FeedName: "internal"}, nil // jangan kueri IP privat ke layanan luar
	}
	var (
		ind   Indicator
		feeds []string
		ok    bool
		errs  []string
	)
	// Daftar blokir komunitas = sinyal malicious kuat (offline, tanpa API).
	if p.Blocklist != nil && p.Blocklist.Contains(ip) {
		ind.AbuseConfidence = 100
		feeds, ok = append(feeds, "blocklist"), true
	}
	if p.Abuse != nil {
		if score, country, err := p.Abuse.Check(ctx, ip); err != nil {
			log.Printf("enrich: %v", err)
			errs = append(errs, err.Error())
		} else {
			if score > ind.AbuseConfidence { // jangan turunkan floor dari blocklist
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
		return Indicator{}, fmt.Errorf("enrich: semua sumber gagal: %s", strings.Join(errs, "; "))
	}
	ind.FeedName = strings.Join(feeds, ",")
	return ind, nil
}

// ProviderFromEnv membangun provider dari environment:
//
//	ABUSEIPDB_API_KEY  -> aktifkan klien AbuseIPDB
//	OTX_API_KEY        -> aktifkan klien OTX
//	GEOIP_ENABLED=1    -> aktifkan GeoIP (ip-api.com, gratis)
//
// Bila tak satu pun dikonfigurasi, kembali ke MockProvider demo (dev) + flag false.
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
			log.Printf("enrich: blocklist gagal dimuat: %v", err)
		} else {
			cp.Blocklist = set
			log.Printf("enrich: blocklist komunitas dimuat (%d entri)", set.Len())
			go blocklist.Refresh(context.Background(), nil, blURLs, blocklistRefresh(), set)
		}
	}
	return cp, true
}

// splitCSV memecah string dipisah koma menjadi token non-kosong yang sudah di-trim.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// blocklistRefresh membaca interval refresh blocklist (BLOCKLIST_REFRESH), default 6 jam.
func blocklistRefresh() time.Duration {
	if v := os.Getenv("BLOCKLIST_REFRESH"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 6 * time.Hour
}
