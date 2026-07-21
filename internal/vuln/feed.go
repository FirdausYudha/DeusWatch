package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Feed ingestion: fetch vendor security data and turn it into Advisory rows. Parsing is separated
// from fetching so the parsers are pure and unit-tested against the documented schemas; the
// fetchers are thin HTTP wrappers. Everything is scoped to a set of release codenames — there is no
// point caching advisories for a distro release no agent runs.

const (
	usnAPIURL     = "https://ubuntu.com/security/notices.json"
	debianDataURL = "https://security-tracker.debian.org/tracker/data/json"
)

// ── Ubuntu USN ────────────────────────────────────────────────────────────────

type usnPage struct {
	Notices []struct {
		ID              string   `json:"id"`
		CVEs            []string `json:"cves_ids"`
		ReleasePackages map[string][]struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			IsSource bool   `json:"is_source"`
		} `json:"release_packages"`
	} `json:"notices"`
	Total int `json:"total_results"`
}

// ParseUSN turns one page of the Ubuntu notices.json API into advisories, keeping only the given
// releases. It returns the advisories and the total notice count (for pagination). A USN lists the
// CVEs it fixes and the source packages (with their fixed version) per release; we emit one
// advisory per (release, source package, CVE). Ubuntu's notices API carries no per-CVE severity, so
// severity is left unknown here.
func ParseUSN(data []byte, keep map[string]bool) ([]Advisory, int, error) {
	var page usnPage
	if err := json.Unmarshal(data, &page); err != nil {
		return nil, 0, fmt.Errorf("vuln: parse USN: %w", err)
	}
	var out []Advisory
	for _, n := range page.Notices {
		for rel, pkgs := range n.ReleasePackages {
			if len(keep) > 0 && !keep[rel] {
				continue
			}
			for _, p := range pkgs {
				if !p.IsSource || p.Name == "" || p.Version == "" {
					continue
				}
				for _, cve := range n.CVEs {
					if !strings.HasPrefix(cve, "CVE-") {
						continue
					}
					out = append(out, Advisory{
						Source: "usn", CVE: cve, Package: p.Name, Release: rel,
						FixedVersion: p.Version, Title: n.ID,
					})
				}
			}
		}
	}
	return out, page.Total, nil
}

// FetchUSN paginates the Ubuntu notices API and returns advisories for the given releases. It walks
// pages of `limit` until every notice is seen.
func FetchUSN(ctx context.Context, client *http.Client, keep map[string]bool) ([]Advisory, error) {
	const limit = 500
	var all []Advisory
	for offset := 0; ; offset += limit {
		url := fmt.Sprintf("%s?limit=%d&offset=%d", usnAPIURL, limit, offset)
		body, err := httpGet(ctx, client, url)
		if err != nil {
			return nil, err
		}
		advs, total, err := ParseUSN(body, keep)
		if err != nil {
			return nil, err
		}
		all = append(all, advs...)
		if offset+limit >= total || total == 0 {
			break
		}
	}
	return all, nil
}

// ── Debian security tracker ─────────────────────────────────────────────────

// debianTracker mirrors https://security-tracker.debian.org/tracker/data/json :
// source-package -> CVE -> { releases: codename -> { status, fixed_version, urgency } }.
type debianTracker map[string]map[string]struct {
	Releases map[string]struct {
		Status       string `json:"status"`
		FixedVersion string `json:"fixed_version"`
		Urgency      string `json:"urgency"`
	} `json:"releases"`
}

// ParseDebian turns the Debian security-tracker JSON into advisories for the given releases.
// Semantics of a per-release entry:
//   - status "resolved" with a real fixed_version → fixed in that version (emit it as the fix).
//   - status "open"                               → vulnerable, no fix yet (empty fixed version).
//   - fixed_version "0" (never affected) / status "undetermined" → not a finding, skipped.
func ParseDebian(data []byte, keep map[string]bool) ([]Advisory, error) {
	var tr debianTracker
	if err := json.Unmarshal(data, &tr); err != nil {
		return nil, fmt.Errorf("vuln: parse Debian: %w", err)
	}
	var out []Advisory
	for pkg, cves := range tr {
		for cve, entry := range cves {
			if !strings.HasPrefix(cve, "CVE-") {
				continue // skip TEMP-* and other non-CVE identifiers
			}
			for rel, r := range entry.Releases {
				if len(keep) > 0 && !keep[rel] {
					continue
				}
				sev := strings.Trim(r.Urgency, "* ")
				switch r.Status {
				case "resolved":
					if r.FixedVersion == "" || r.FixedVersion == "0" {
						continue // "0" = the release was never affected
					}
					out = append(out, Advisory{Source: "debian", CVE: cve, Package: pkg,
						Release: rel, FixedVersion: r.FixedVersion, Severity: sev})
				case "open":
					out = append(out, Advisory{Source: "debian", CVE: cve, Package: pkg,
						Release: rel, FixedVersion: "", Severity: sev})
				default:
					// "undetermined" and anything else: not actionable.
				}
			}
		}
	}
	return out, nil
}

// FetchDebian downloads and parses the Debian security-tracker JSON for the given releases.
func FetchDebian(ctx context.Context, client *http.Client, keep map[string]bool) ([]Advisory, error) {
	body, err := httpGet(ctx, client, debianDataURL)
	if err != nil {
		return nil, err
	}
	return ParseDebian(body, keep)
}

// ── shared ──────────────────────────────────────────────────────────────────

// FeedForDistro reports which feed source ("usn"/"debian") serves a given os-release ID, or "" if
// unsupported. Used to decide what to fetch for the fleet's distros.
func FeedForDistro(osID string) string {
	switch strings.ToLower(osID) {
	case "ubuntu":
		return "usn"
	case "debian":
		return "debian"
	default:
		return ""
	}
}

func httpGet(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "DeusWatch-VA")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vuln: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vuln: fetch %s: HTTP %d", url, resp.StatusCode)
	}
	// Advisory feeds are large; cap at 128 MiB to bound memory but not truncate a real feed.
	return io.ReadAll(io.LimitReader(resp.Body, 128<<20))
}
