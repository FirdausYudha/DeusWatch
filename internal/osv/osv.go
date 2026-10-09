// Package osv is the OSV.dev vulnerability source: an API-based alternative to the local Trivy DB.
//
// Why it exists: Trivy needs a ~700MB bbolt database on disk, which has to be downloaded, kept
// fresh, and held open by exactly one process (a second holder deadlocks every scan). On a modest
// remote host that is a lot of moving parts. OSV needs none of it: the worker POSTs a batch of
// package URLs over HTTPS and gets vulnerabilities back.
//
// Flow (two steps, because the API is shaped that way):
//  1. /v1/querybatch takes many purls at once but returns only vulnerability IDs.
//  2. /v1/vulns/{id} returns the full record: the upstream CVE, the severity, and the fixed version
//     per distro release. These records are stable, so the caller caches them and only fetches IDs
//     it has never seen.
//
// Coverage note: OSV carries Ubuntu, Debian, Alpine, Rocky Linux and AlmaLinux. It does NOT carry
// Red Hat Enterprise Linux or SUSE, so those hosts need the Trivy source instead.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"
)

// DefaultBaseURL is the public OSV.dev API.
const DefaultBaseURL = "https://api.osv.dev"

// batchSize caps how many purls go in one querybatch request. OSV accepts large batches; we keep
// them bounded so one request stays small enough to retry cheaply.
const batchSize = 500

// Client talks to the OSV API.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// New returns a Client with sane timeouts.
func New(baseURL string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// Package is one installed package to look up.
type Package struct {
	Name    string
	Version string
	Arch    string
}

// Vuln is the distilled record we store and show.
type Vuln struct {
	ID       string            // OSV id, e.g. UBUNTU-CVE-2024-11053
	CVE      string            // upstream CVE id, e.g. CVE-2024-11053 (falls back to ID)
	Severity string            // critical|high|medium|low|negligible|unknown
	CVSS     float64           // highest CVSS v3 base score across the record (0 = none published)
	Fixed    map[string]string // "<ecosystem>|<package>" -> fixed version (| so it survives JSONB)
}

// ── package URLs / ecosystems ───────────────────────────────────────────────────

// PURL builds the package URL OSV matches on. The `distro` qualifier is what scopes the lookup to
// the host's release: pkg:deb/ubuntu/curl@8.5.0-2ubuntu10.1?distro=noble is the form verified
// against the live API. Returns "" for a distro OSV does not carry.
func PURL(osID, pkgManager, name, version, codename string) string {
	osID = strings.ToLower(osID)
	distro := codename
	if distro == "" {
		distro = osID
	}
	switch osID {
	case "ubuntu", "debian":
		return fmt.Sprintf("pkg:deb/%s/%s@%s?distro=%s", osID, esc(name), esc(version), esc(distro))
	case "rocky", "almalinux", "alma", "alpine":
		family := osID
		if family == "alma" {
			family = "almalinux"
		}
		if pkgManager == "rpm" || family == "alpine" {
			scheme := "rpm"
			if family == "alpine" {
				scheme = "apk"
			}
			return fmt.Sprintf("pkg:%s/%s/%s@%s?distro=%s", scheme, family, esc(name), esc(version), esc(distro))
		}
	}
	return "" // OSV has no data for this distro (e.g. RHEL, SUSE) - use the Trivy source there
}

// esc percent-encodes the characters that would otherwise break a purl (deb epochs contain ':',
// versions contain '+').
func esc(s string) string {
	r := strings.NewReplacer(":", "%3A", "+", "%2B", " ", "%20", "?", "%3F", "#", "%23", "@", "%40")
	return r.Replace(s)
}

// EcosystemPrefix is the OSV ecosystem family for this distro, used to pick the affected entry that
// belongs to THIS host (OSV lists every release in one record).
func EcosystemPrefix(osID string) string {
	switch strings.ToLower(osID) {
	case "ubuntu":
		return "Ubuntu:"
	case "debian":
		return "Debian:"
	case "rocky":
		return "Rocky Linux:"
	case "almalinux", "alma":
		return "AlmaLinux:"
	case "alpine":
		return "Alpine:"
	default:
		return ""
	}
}

// Supported reports whether OSV carries vulnerability data for this distro.
func Supported(osID string) bool { return EcosystemPrefix(osID) != "" }

// ── querybatch ──────────────────────────────────────────────────────────────────

type batchQuery struct {
	Package struct {
		PURL string `json:"purl"`
	} `json:"package"`
	PageToken string `json:"page_token,omitempty"`
}

type batchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

// QueryPackages returns, for each input package, the OSV vulnerability IDs affecting it. The result
// slice matches the input order (the API guarantees this). Advisory-level records (USN-*, DSA-*,
// RLSA-*) are dropped: they aggregate the per-CVE records that are also returned, so keeping both
// would double-count every finding.
func (c *Client) QueryPackages(ctx context.Context, purls []string) ([][]string, error) {
	out := make([][]string, len(purls))
	for start := 0; start < len(purls); start += batchSize {
		end := start + batchSize
		if end > len(purls) {
			end = len(purls)
		}
		chunk := purls[start:end]
		queries := make([]batchQuery, len(chunk))
		for i, p := range chunk {
			queries[i].Package.PURL = p
		}
		// Pagination: a package with very many vulns comes back with a next_page_token; keep asking
		// for just those queries until every one is exhausted, otherwise findings are silently lost.
		idx := make([]int, len(chunk)) // position in `out` for each pending query
		for i := range chunk {
			idx[i] = start + i
		}
		for round := 0; len(queries) > 0 && round < 20; round++ {
			resp, err := c.postBatch(ctx, queries)
			if err != nil {
				return nil, err
			}
			if len(resp.Results) != len(queries) {
				return nil, fmt.Errorf("osv: querybatch returned %d results for %d queries", len(resp.Results), len(queries))
			}
			var nextQ []batchQuery
			var nextIdx []int
			for i, r := range resp.Results {
				for _, v := range r.Vulns {
					if isAdvisoryID(v.ID) {
						continue
					}
					out[idx[i]] = append(out[idx[i]], v.ID)
				}
				if r.NextPageToken != "" {
					q := queries[i]
					q.PageToken = r.NextPageToken
					nextQ = append(nextQ, q)
					nextIdx = append(nextIdx, idx[i])
				}
			}
			queries, idx = nextQ, nextIdx
		}
	}
	return out, nil
}

func (c *Client) postBatch(ctx context.Context, queries []batchQuery) (*batchResponse, error) {
	body, err := json.Marshal(map[string]any{"queries": queries})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: querybatch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: querybatch: HTTP %d", resp.StatusCode)
	}
	var out batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("osv: decode querybatch: %w", err)
	}
	return &out, nil
}

// isAdvisoryID reports whether an OSV id is a vendor advisory that bundles several CVEs (USN-7162-1,
// DSA-5555-1, RLSA-2024:1234). We keep only the per-CVE records so each finding appears once.
func isAdvisoryID(id string) bool {
	for _, p := range []string{"USN-", "DSA-", "DLA-", "RLSA-", "ALSA-", "ALAS-", "RHSA-"} {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

// ── vulnerability detail ────────────────────────────────────────────────────────

type vulnRecord struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Upstream []string `json:"upstream"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// FetchVuln returns one vulnerability record, distilled to what we store.
func (c *Client) FetchVuln(ctx context.Context, id string) (Vuln, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return Vuln{}, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Vuln{}, fmt.Errorf("osv: fetch %s: %w", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Vuln{}, fmt.Errorf("osv: fetch %s: HTTP %d", id, resp.StatusCode)
	}
	var rec vulnRecord
	if err := json.NewDecoder(resp.Body).Decode(&rec); err != nil {
		return Vuln{}, fmt.Errorf("osv: decode %s: %w", id, err)
	}
	return distill(rec), nil
}

// distill converts an OSV record into the fields we persist.
func distill(rec vulnRecord) Vuln {
	v := Vuln{ID: rec.ID, CVE: cveOf(rec), Fixed: map[string]string{}}

	// Severity: prefer the distro's own rating (e.g. {"type":"Ubuntu","score":"medium"}), which is
	// what the vendor actually tells operators to act on. Fall back to deriving it from the CVSS
	// base score when only CVSS vectors are published.
	for _, s := range rec.Severity {
		if strings.HasPrefix(strings.ToUpper(s.Type), "CVSS") {
			if score := cvssBaseScore(s.Score); score > v.CVSS {
				v.CVSS = score
			}
			continue
		}
		if v.Severity == "" {
			v.Severity = normalizeSeverity(s.Score)
		}
	}
	if v.Severity == "" || v.Severity == "unknown" {
		if sev := severityFromScore(v.CVSS); sev != "unknown" {
			v.Severity = sev
		}
	}
	if v.Severity == "" {
		v.Severity = "unknown"
	}

	for _, a := range rec.Affected {
		fixed := ""
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					fixed = e.Fixed
				}
			}
		}
		if a.Package.Name == "" {
			continue
		}
		v.Fixed[a.Package.Ecosystem+"|"+a.Package.Name] = fixed
	}
	return v
}

// cveOf picks the upstream CVE id for a distro record (UBUNTU-CVE-2024-11053 -> CVE-2024-11053),
// preferring the explicit upstream/aliases fields and falling back to trimming the vendor prefix.
func cveOf(rec vulnRecord) string {
	for _, list := range [][]string{rec.Upstream, rec.Aliases} {
		for _, a := range list {
			if strings.HasPrefix(a, "CVE-") {
				return a
			}
		}
	}
	if i := strings.Index(rec.ID, "CVE-"); i >= 0 {
		return rec.ID[i:]
	}
	return rec.ID
}

// FixedFor returns the fixed version for a package on a given distro release. OSV lists one affected
// entry per release (Ubuntu:24.04:LTS, Ubuntu:Pro:14.04:LTS, ...), so we must pick the one matching
// this host: entries for OTHER releases carry versions that would be nonsense to show, and the
// ":Pro:" ESM entries only apply with a paid subscription.
func (v Vuln) FixedFor(ecosystemPrefix, osVersion, pkg string) string {
	best := ""
	for key, fixed := range v.Fixed {
		eco, name, ok := strings.Cut(key, "|")
		if !ok || name != pkg {
			continue
		}
		if !strings.HasPrefix(eco, ecosystemPrefix) || !strings.Contains(eco, osVersion) {
			continue
		}
		if strings.Contains(eco, ":Pro:") {
			if best == "" {
				best = fixed // only as a last resort
			}
			continue
		}
		return fixed
	}
	return best
}

// ── severity helpers ────────────────────────────────────────────────────────────

func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	case "negligible", "unimportant":
		return "negligible"
	default:
		return "unknown"
	}
}

// severityFromScore maps a CVSS base score onto the same scale the UI uses.
func severityFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
	}
}

// cvssBaseScore computes the CVSS v3.x base score from a vector string. OSV publishes the vector
// ("CVSS:3.1/AV:N/AC:L/...") rather than the number, and the UI wants the number, so we implement
// the published formula. An unparseable vector yields 0.
func cvssBaseScore(vector string) float64 {
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		k, val, ok := strings.Cut(part, ":")
		if ok {
			m[k] = val
		}
	}
	if !strings.HasPrefix(vector, "CVSS:3") {
		return 0
	}
	scopeChanged := m["S"] == "C"
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	if scopeChanged {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}[m["PR"]]
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, i, a := cia[m["C"]], cia[m["I"]], cia[m["A"]]
	if av == 0 || ac == 0 || ui == 0 || pr == 0 {
		return 0 // incomplete vector
	}

	iss := 1 - ((1 - c) * (1 - i) * (1 - a))
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}
	exploitability := 8.22 * av * ac * pr * ui
	base := impact + exploitability
	if scopeChanged {
		base = 1.08 * base
	}
	if base > 10 {
		base = 10
	}
	return roundUp1(base)
}

// roundUp1 is the CVSS "Roundup": the smallest number to one decimal place that is >= the input.
// The integer-arithmetic form avoids the float artefacts the spec warns about.
func roundUp1(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}
