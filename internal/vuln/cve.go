package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

// defaultCVEClient has a generous per-request timeout because the Ubuntu CVE endpoint occasionally
// responds slowly during a full-fleet cold start. Kept as a package var so tests can replace it.
var defaultCVEClient = &http.Client{Timeout: 30 * time.Second}

// Ubuntu per-CVE priority enrichment. Ubuntu's USN notices.json feed doesn't carry per-CVE severity
// (see feed.go comment on ParseUSN), so USN advisories previously landed with severity="unknown".
// This file fetches the missing datum from ubuntu.com/security/CVE-YYYY-NNNN.json (which does have
// a `priority` field) and hands it back to the caller. A CVE cache (internal/store/cve_cache.go +
// migration 000058) makes each CVE a one-time fetch across the fleet's lifetime.

// ubuntuCVEURL is a package var (not a const) so tests can point it at an httptest server. The
// format specifier consumes the CVE identifier (e.g. "CVE-2024-0001").
var ubuntuCVEURL = "https://ubuntu.com/security/%s.json"

// Test hooks — used by cve_test.go to redirect fetches at a test server without exporting the
// mutable var into the public API. Package-private on purpose.
func ubuntuCVEURLTemplate() string      { return ubuntuCVEURL }
func setUbuntuCVEURLTemplate(t string) { ubuntuCVEURL = t }

// PriorityCache is the subset of *store.Store this file needs; kept as an interface so the vuln
// package doesn't grow a hard dep on internal/store (which pulls in pgxpool).
type PriorityCache interface {
	GetCVEPriority(ctx context.Context, cve string) (string, bool, error)
	PutCVEPriority(ctx context.Context, cve, priority string, ttl time.Duration) error
}

// FetchUbuntuCVEPriority returns the "priority" field for a single CVE from Ubuntu's public CVE
// JSON endpoint. Empty string is a valid answer — some CVEs have no assigned priority yet, and we
// preserve that instead of guessing. A missing CVE (404) returns "" with no error, so an unknown
// identifier costs one request but doesn't fail the whole enrichment pass.
func FetchUbuntuCVEPriority(ctx context.Context, client *http.Client, cve string) (string, error) {
	url := fmt.Sprintf(ubuntuCVEURL, cve)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "DeusWatch-VA")
	if client == nil {
		client = defaultCVEClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("vuln: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vuln: fetch %s: HTTP %d", url, resp.StatusCode)
	}
	var body struct {
		Priority string `json:"priority"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("vuln: decode %s: %w", url, err)
	}
	return strings.TrimSpace(body.Priority), nil
}

// EnrichUSNSeverity fills in Advisory.Severity for the USN-sourced entries whose severity is empty.
// It reads through the cache first; on a miss it calls FetchUbuntuCVEPriority and writes the result
// (including "") back to the cache with the given TTL. Fetching is bounded to `concurrency` in-flight
// requests so a cold-start with hundreds of CVEs doesn't hammer ubuntu.com.
//
// Non-USN advisories and USN advisories that already carry a severity are left untouched.
func EnrichUSNSeverity(ctx context.Context, client *http.Client, cache PriorityCache,
	advs []Advisory, concurrency int, ttl time.Duration) error {

	if cache == nil {
		return nil
	}
	if concurrency <= 0 {
		concurrency = 4
	}
	// Deduplicate CVEs — a single CVE is emitted once per (release, package), so a 500-line USN
	// batch can easily be 30 distinct CVEs, and we only want one network round trip per CVE.
	need := make(map[string]struct{})
	for _, a := range advs {
		if a.Source != "usn" || strings.TrimSpace(a.Severity) != "" {
			continue
		}
		need[a.CVE] = struct{}{}
	}
	if len(need) == 0 {
		return nil
	}

	// Cache lookup pass — resolves everything that's already known and shrinks `need` to real work.
	priorities := make(map[string]string, len(need))
	var priMu sync.Mutex
	for cve := range need {
		p, hit, err := cache.GetCVEPriority(ctx, cve)
		if err != nil {
			return err
		}
		if hit {
			priorities[cve] = p
			delete(need, cve)
		}
	}

	// Network pass — bounded fan-out over the remaining CVEs.
	if len(need) > 0 {
		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(concurrency)
		for cve := range need {
			cve := cve
			g.Go(func() error {
				p, err := FetchUbuntuCVEPriority(gctx, client, cve)
				if err != nil {
					// A single CVE failure shouldn't abort the whole enrichment — the advisory
					// simply stays without severity, which is what happens today anyway. Log via
					// caller? Return nil to preserve overall progress; the miss is naturally
					// re-tried next feed cycle since we don't cache errors.
					return nil
				}
				priMu.Lock()
				priorities[cve] = p
				priMu.Unlock()
				// Cache the answer — including the legitimate empty string, so we don't re-fetch
				// on every refresh for CVEs Ubuntu simply hasn't rated.
				return cache.PutCVEPriority(gctx, cve, p, ttl)
			})
		}
		if err := g.Wait(); err != nil {
			return err
		}
	}

	// Apply pass — mutate the slice in place. Advisory.Severity is later fed through
	// normalizeSeverity in match.go, which already knows the Ubuntu vocabulary.
	for i := range advs {
		if advs[i].Source != "usn" || strings.TrimSpace(advs[i].Severity) != "" {
			continue
		}
		if p, ok := priorities[advs[i].CVE]; ok && p != "" {
			advs[i].Severity = p
		}
	}
	return nil
}
