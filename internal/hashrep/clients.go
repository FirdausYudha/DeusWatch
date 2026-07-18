package hashrep

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultHTTPTimeout = 10 * time.Second

func newHTTPClient() *http.Client { return &http.Client{Timeout: defaultHTTPTimeout} }

// ── CIRCL hashlookup (free, no API key, no rate limit) ────
// https://hashlookup.circl.lu — aggregates NSRL (known-good) plus known-bad sets.
// A 200 means the hash is KNOWN; a "KnownMalicious" marker makes it known-bad, otherwise
// it is treated as known-good. 404 means the hash is unknown to CIRCL.

const defaultCIRCLBase = "https://hashlookup.circl.lu"

type CIRCLClient struct {
	base string
	hc   *http.Client
}

func NewCIRCLClient() *CIRCLClient { return &CIRCLClient{base: defaultCIRCLBase, hc: newHTTPClient()} }

func (c *CIRCLClient) Lookup(ctx context.Context, sha256 string) (Verdict, string, error) {
	u := c.base + "/lookup/sha256/" + url.PathEscape(strings.ToUpper(sha256))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("circl: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return VerdictUnknown, "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("circl: HTTP %d", resp.StatusCode)
	}
	// Decode loosely: CIRCL returns a flat object whose fields vary by source.
	var out map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", fmt.Errorf("circl: decode: %w", err)
	}
	if raw, ok := out["KnownMalicious"]; ok && len(raw) > 0 && string(raw) != "null" && string(raw) != `""` {
		detail := strings.Trim(string(raw), `"`)
		return VerdictKnownBad, "CIRCL known-malicious: " + detail, nil
	}
	detail := "known to CIRCL/NSRL"
	if raw, ok := out["FileName"]; ok {
		if fn := strings.Trim(string(raw), `"`); fn != "" {
			detail = "known file: " + fn
		}
	}
	return VerdictKnownGood, detail, nil
}

// ── VirusTotal (file lookup; free tier ≈4/min, 500/day) ──
// GET /api/v3/files/{sha256} with the x-apikey header. last_analysis_stats.malicious > 0
// → known-bad; 0 → known-good; 404 → unknown.

const defaultVTBase = "https://www.virustotal.com"

type VirusTotalClient struct {
	key  string
	base string
	hc   *http.Client
}

func NewVirusTotalClient(key string) *VirusTotalClient {
	return &VirusTotalClient{key: key, base: defaultVTBase, hc: newHTTPClient()}
}

func (c *VirusTotalClient) Lookup(ctx context.Context, sha256 string) (Verdict, string, error) {
	u := c.base + "/api/v3/files/" + url.PathEscape(sha256)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-apikey", c.key)
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("virustotal: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return VerdictUnknown, "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("virustotal: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", fmt.Errorf("virustotal: decode: %w", err)
	}
	s := out.Data.Attributes.LastAnalysisStats
	total := s.Malicious + s.Suspicious + s.Harmless + s.Undetected
	if s.Malicious > 0 {
		return VerdictKnownBad, fmt.Sprintf("%d/%d engines flagged", s.Malicious, total), nil
	}
	return VerdictKnownGood, fmt.Sprintf("0/%d detections", total), nil
}

// ── MalwareBazaar (abuse.ch; a database of KNOWN malware samples) ──
// https://bazaar.abuse.ch — a hit means the exact file is a catalogued malware sample, so it is
// always known-bad; a miss is "unknown" (MB never asserts known-good). The API needs a free
// Auth-Key (abuse.ch account); without one it is left disabled.
const defaultMBBase = "https://mb-api.abuse.ch"

type MalwareBazaarClient struct {
	key  string
	base string
	hc   *http.Client
}

func NewMalwareBazaarClient(key string) *MalwareBazaarClient {
	return &MalwareBazaarClient{key: key, base: defaultMBBase, hc: newHTTPClient()}
}

func (c *MalwareBazaarClient) Lookup(ctx context.Context, sha256 string) (Verdict, string, error) {
	form := url.Values{"query": {"get_info"}, "hash": {sha256}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/api/v1/", strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.key != "" {
		req.Header.Set("Auth-Key", c.key)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("malwarebazaar: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("malwarebazaar: HTTP %d", resp.StatusCode)
	}
	var out struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			Signature string `json:"signature"`
			FileType  string `json:"file_type"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", fmt.Errorf("malwarebazaar: decode: %w", err)
	}
	switch out.QueryStatus {
	case "ok":
		detail := "known malware sample"
		if len(out.Data) > 0 {
			if sig := out.Data[0].Signature; sig != "" {
				detail = "MalwareBazaar: " + sig
			} else if ft := out.Data[0].FileType; ft != "" {
				detail = "MalwareBazaar sample (" + ft + ")"
			}
		}
		return VerdictKnownBad, detail, nil
	case "hash_not_found", "no_results":
		return VerdictUnknown, "", nil
	default:
		return "", "", fmt.Errorf("malwarebazaar: %s", out.QueryStatus)
	}
}
