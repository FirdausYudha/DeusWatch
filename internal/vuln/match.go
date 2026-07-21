package vuln

import "strings"

// Advisory is one (CVE, source-package, release) vulnerability record from a vendor feed.
type Advisory struct {
	Source       string // feed: "usn" (Ubuntu) | "debian"
	CVE          string
	Package      string // SOURCE package the advisory concerns
	Release      string // distro codename the advisory is scoped to: jammy | bookworm
	FixedVersion string // version that fixes it; "" = no fix published yet (vulnerable regardless)
	Severity     string // critical | high | medium | low | negligible | unknown
	Title        string
}

// InstalledPackage is the subset of an inventory package the matcher needs. Kept local so this
// package stays dependency-free and trivially testable.
type InstalledPackage struct {
	Name    string
	Version string
	Source  string // source package ("" = same as Name)
}

// Finding is a vulnerable package on a host: an installed package that an advisory says is not yet
// at (or past) its fixed version.
type Finding struct {
	Package          string `json:"package"` // the source package to upgrade
	InstalledVersion string `json:"installed_version"`
	FixedVersion     string `json:"fixed_version"` // "" = no fix available yet
	CVE              string `json:"cve"`
	Severity         string `json:"severity"`
	Source           string `json:"source"`
}

// sourceOf returns the package's source name, falling back to the binary name.
func sourceOf(p InstalledPackage) string {
	if p.Source != "" {
		return p.Source
	}
	return p.Name
}

// IsVulnerable reports whether an installed version is affected by an advisory: an advisory with no
// published fix is always a hit (the package is vulnerable at any version until one ships), and one
// with a fix is a hit only while the installed version is STRICTLY OLDER than the fix.
func IsVulnerable(installed string, a Advisory) bool {
	if a.FixedVersion == "" {
		return true
	}
	return CompareVersions(installed, a.FixedVersion) < 0
}

// Match produces the findings for a host's installed packages against advisories that have ALREADY
// been scoped to the host's release and keyed by source-package name. Keeping the release filter in
// the caller (a DB query) keeps this function pure and cheap.
//
// Findings are de-duplicated on (source package, CVE): several binaries built from one source
// (libssl3, libssl-dev … from "openssl") share a source version, so a CVE in that source is one
// finding to act on, not one per binary.
func Match(pkgs []InstalledPackage, advisoriesBySource map[string][]Advisory) []Finding {
	var out []Finding
	seen := make(map[string]bool)
	for _, p := range pkgs {
		src := sourceOf(p)
		for _, a := range advisoriesBySource[src] {
			if !IsVulnerable(p.Version, a) {
				continue
			}
			key := src + "\x00" + a.CVE
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Finding{
				Package:          src,
				InstalledVersion: p.Version,
				FixedVersion:     a.FixedVersion,
				CVE:              a.CVE,
				Severity:         normalizeSeverity(a.Severity),
				Source:           a.Source,
			})
		}
	}
	return out
}

// SeverityRank orders severities for sorting/prioritisation (higher = worse). Unknown sorts lowest.
func SeverityRank(sev string) int {
	switch normalizeSeverity(sev) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "negligible":
		return 1
	default:
		return 0
	}
}

// normalizeSeverity maps the varied vendor severity vocabularies to one scale. Ubuntu uses
// negligible/low/medium/high/critical; Debian uses urgency words (unimportant/low/medium/high) and
// "not yet assigned". Anything unrecognised becomes "unknown".
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "negligible", "unimportant":
		return "negligible"
	default:
		return "unknown"
	}
}
