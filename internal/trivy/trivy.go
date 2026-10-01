// Package trivy is the server-side Trivy integration: it turns an agent's collected inventory into
// something Trivy can scan and parses Trivy's JSON back into findings with a real severity.
//
// Why server-side: the agent stays light (it only enumerates packages, which it already does for the
// existing OVAL matcher). The manager owns Trivy + its vulnerability DB. We call the trivy binary in
// client/server mode (`--server`), so the heavy DB lives once in the trivy service and the worker
// only needs the small trivy client binary.
//
// Why we synthesize a rootfs for dpkg rather than hand-build a CycloneDX SBOM: Trivy's dpkg analyzer
// is battle-tested and its input (a Debian control-file `status` + `os-release`) is simple text we
// can reproduce exactly, so DEB scanning is robust. RPM has no plain-text package DB, so those go
// through a CycloneDX SBOM with pkg:rpm PURLs instead.
package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Config is how the worker runs Trivy. Bin is the trivy binary; CacheDir is the trivy cache
// directory that holds the vulnerability DB. Trivy is run STANDALONE (not client/server): `trivy
// sbom`/`fs` ignore --server and would otherwise download the ~700MB DB per scan and OOM the worker.
// Instead the separate `trivy` service downloads/refreshes the DB into a shared cache volume, and the
// worker scans against it with --skip-db-update (the bolt DB is mmap'd, so RAM stays low). From env
// TRIVY_BIN, TRIVY_CACHE_DIR.
type Config struct {
	Bin      string
	CacheDir string
}

func (c Config) cacheDir() string {
	if c.CacheDir != "" {
		return c.CacheDir
	}
	return "/trivy-cache"
}

func (c Config) bin() string {
	if c.Bin != "" {
		return c.Bin
	}
	return "trivy"
}

// Package is one installed package (mirrors agent.Package / vuln.InstalledPackage).
type Package struct {
	Name    string
	Version string
	Arch    string
	Source  string // source package; "" = same as Name
}

// OS identifies the host distro for Trivy's OVAL selection.
type OS struct {
	ID         string // os-release ID: ubuntu | debian | rhel | rocky | almalinux | centos | fedora | amzn
	Version    string // os-release VERSION_ID: 24.04 | 12 | 9
	Codename   string // VERSION_CODENAME: noble | bookworm (optional, deb only)
	PkgManager string // dpkg | rpm
}

// Finding is one vulnerability Trivy reported. Shape matches internal/vuln.Finding so the store can
// persist it through the same path, but this package stays dependency-free.
type Finding struct {
	Package          string
	InstalledVersion string
	FixedVersion     string
	CVE              string
	Severity         string  // lowercased: critical|high|medium|low|negligible|unknown
	CVSS             float64 // highest CVSS base score across sources (0 = none reported)
	Source           string  // always "trivy" here
}

// Manifest is one language dependency file to scan for SCA (path gives Trivy the right filename).
type Manifest struct {
	Path    string
	Content string
}

// SCAFinding is one vulnerable language package Trivy reported in a manifest.
type SCAFinding struct {
	Target           string // the manifest the package came from
	PkgType          string // ecosystem: npm | gomod | pip | gem | ...
	Package          string
	InstalledVersion string
	FixedVersion     string
	VulnID           string // CVE-... or GHSA-...
	Severity         string
	CVSS             float64
}

// ── Trivy JSON output (the subset we read) ──────────────────────────────────────
type trivyReport struct {
	Results []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			CVSS             map[string]struct {
				V3Score float64 `json:"V3Score"`
				V2Score float64 `json:"V2Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// bestCVSS returns the highest CVSS base score across all reporting sources (nvd, redhat, ghsa, …),
// preferring v3 and falling back to v2. 0 means no score was reported.
func bestCVSS(m map[string]struct {
	V3Score float64 `json:"V3Score"`
	V2Score float64 `json:"V2Score"`
}) float64 {
	best := 0.0
	for _, s := range m {
		score := s.V3Score
		if score == 0 {
			score = s.V2Score
		}
		if score > best {
			best = score
		}
	}
	return best
}

// EnsureDB makes sure the vulnerability DB in CacheDir exists and is fresh, downloading it if not.
//
// The worker OWNS this cache: nothing else may hold the DB open. Trivy's DB is a bbolt file and a
// long-running `trivy server` keeps an exclusive lock on it, so a concurrent standalone scan of the
// same file blocks on that lock until our timeout kills it ("signal: killed", empty stderr). That is
// why there is no trivy server any more and the worker downloads its own DB here.
//
// Trivy skips the download when the cached DB is still fresh, so calling this before a scan cycle is
// cheap. A failure is returned (and logged by the caller) but is not fatal: scans fall back to
// whatever DB is already cached, so a network blip degrades to "last known" rather than going blank.
func (c Config) EnsureDB(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Minute) // cold start pulls a few hundred MB
	defer cancel()
	cmd := exec.CommandContext(cctx, c.bin(),
		"image", "--download-db-only", "--cache-dir", c.cacheDir())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("trivy: download db: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// ScanOS scans a host's OS packages and returns findings with severity. It feeds Trivy a CycloneDX
// SBOM (not a synthesized rootfs): in client/server mode Trivy parses the OS straight out of the SBOM
// and sends it to the server, whereas a scanned fake rootfs left the server seeing family="none" and
// detecting nothing. One code path covers both dpkg and rpm. No packages / unsupported manager →
// nil, nil.
func (c Config) ScanOS(ctx context.Context, host OS, pkgs []Package) ([]Finding, error) {
	if len(pkgs) == 0 || host.pkgType() == "" {
		return nil, nil
	}
	dir, err := os.MkdirTemp("", "dw-trivy-*")
	if err != nil {
		return nil, fmt.Errorf("trivy: temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	sbom := filepath.Join(dir, "sbom.cdx.json")
	if err := os.WriteFile(sbom, buildOSBOM(host, pkgs), 0o600); err != nil {
		return nil, fmt.Errorf("trivy: write sbom: %w", err)
	}
	return c.run(ctx, "sbom", sbom)
}

// ScanManifests runs Software Composition Analysis: it reconstructs the reported dependency files
// under a temp directory (preserving their host path so siblings like go.mod + go.sum stay together
// and same-named lockfiles in different apps don't collide) and runs `trivy fs` over it, returning
// language-package vulnerabilities. No manifests → nil, nil.
func (c Config) ScanManifests(ctx context.Context, manifests []Manifest) ([]SCAFinding, error) {
	if len(manifests) == 0 {
		return nil, nil
	}
	dir, err := os.MkdirTemp("", "dw-trivy-sca-*")
	if err != nil {
		return nil, fmt.Errorf("trivy: temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	wrote := 0
	for _, m := range manifests {
		rel := sanitizeRel(m.Path)
		if rel == "" {
			continue
		}
		dst := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			continue
		}
		if err := os.WriteFile(dst, []byte(m.Content), 0o600); err != nil {
			continue
		}
		wrote++
	}
	if wrote == 0 {
		return nil, nil
	}
	return c.runSCA(ctx, dir)
}

// sanitizeRel turns a host path (possibly absolute, Windows drive, or with ..) into a safe relative
// path under the temp scan root.
func sanitizeRel(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if i := strings.Index(p, ":"); i >= 0 && i <= 2 { // strip a Windows drive letter (C:)
		p = p[i+1:]
	}
	p = strings.TrimLeft(p, "/")
	p = strings.ReplaceAll(p, "../", "") // defuse traversal
	return strings.TrimSpace(p)
}

// runSCA scans a reconstructed manifest tree (standalone, against the shared DB cache) and parses
// language-package findings.
func (c Config) runSCA(ctx context.Context, dir string) ([]SCAFinding, error) {
	args := []string{
		"fs", "--quiet", "--format", "json", "--scanners", "vuln",
		"--pkg-types", "library",
		"--skip-db-update", "--skip-java-db-update",
		"--cache-dir", c.cacheDir(),
		dir,
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, c.bin(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy: run sca: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var rep trivyReport
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		return nil, fmt.Errorf("trivy: parse sca json: %w", err)
	}
	var out []SCAFinding
	seen := map[string]bool{}
	for _, r := range rep.Results {
		if r.Class != "lang-pkgs" {
			continue
		}
		for _, v := range r.Vulnerabilities {
			if v.VulnerabilityID == "" || v.PkgName == "" {
				continue
			}
			key := v.VulnerabilityID + "\x00" + v.PkgName + "\x00" + v.InstalledVersion
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, SCAFinding{
				Target: r.Target, PkgType: r.Type, Package: v.PkgName,
				InstalledVersion: v.InstalledVersion, FixedVersion: v.FixedVersion,
				VulnID: v.VulnerabilityID, Severity: normalizeSeverity(v.Severity),
				CVSS: bestCVSS(v.CVSS),
			})
		}
	}
	return out, nil
}

// run scans an sbom file (standalone, against the shared DB cache) and parses OS-package findings.
func (c Config) run(ctx context.Context, mode, target string) ([]Finding, error) {
	args := []string{
		mode,
		"--quiet",
		"--format", "json",
		"--scanners", "vuln",
		"--skip-db-update",      // the trivy service owns DB downloads; the worker must never download
		"--skip-java-db-update", // avoid the worker pulling the java DB (jar SCA is best-effort)
		"--cache-dir", c.cacheDir(),
		target,
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, c.bin(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy: run %s: %w: %s", mode, err, strings.TrimSpace(stderr.String()))
	}
	return parseReport(stdout.Bytes())
}

// parseReport turns trivy --format json into findings, de-duplicating on (CVE, package).
func parseReport(data []byte) ([]Finding, error) {
	var rep trivyReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("trivy: parse json: %w", err)
	}
	var out []Finding
	seen := map[string]bool{}
	for _, r := range rep.Results {
		for _, v := range r.Vulnerabilities {
			if v.VulnerabilityID == "" || v.PkgName == "" {
				continue
			}
			key := v.VulnerabilityID + "\x00" + v.PkgName
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Finding{
				Package:          v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				CVE:              v.VulnerabilityID,
				Severity:         normalizeSeverity(v.Severity),
				CVSS:             bestCVSS(v.CVSS),
				Source:           "trivy",
			})
		}
	}
	return out, nil
}

// ── CycloneDX SBOM (OS packages, deb + rpm) ─────────────────────────────────────

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type cdxComponent struct {
	Type       string        `json:"type"`
	BOMRef     string        `json:"bom-ref"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	PURL       string        `json:"purl,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}
type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}
type cdxBOM struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Version     int    `json:"version"`
	Metadata    struct {
		Component cdxComponent `json:"component"`
	} `json:"metadata"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies,omitempty"`
}

// pkgType maps an OS to Trivy's package type / OVAL family ("ubuntu", "debian", "redhat", "amazon",
// …). Empty means Trivy has no OVAL for this distro, so there is nothing to scan.
func (o OS) pkgType() string {
	switch strings.ToLower(o.ID) {
	case "ubuntu":
		return "ubuntu"
	case "debian":
		return "debian"
	case "rhel", "redhat", "centos", "rocky", "almalinux", "alma", "oracle", "ol":
		return "redhat"
	case "amzn", "amazon":
		return "amazon"
	case "fedora":
		return "fedora"
	case "alpine":
		return "alpine"
	case "opensuse", "opensuse-leap", "opensuse-tumbleweed":
		return "opensuse"
	case "sles", "suse":
		return "suse linux enterprise server"
	default:
		return ""
	}
}

// purlType is the PURL scheme for the package manager: deb or rpm.
func (o OS) purlType() string {
	if o.PkgManager == "rpm" {
		return "rpm"
	}
	return "deb"
}

// buildOSBOM emits a CycloneDX BOM shaped like Trivy's own output so Trivy re-detects the OS and its
// packages from the SBOM (client/server mode parses it locally and ships the result to the server).
// The operating-system component fixes the distro + OVAL family; each package carries its PURL and
// the trivy PkgType property; and the dependency graph (root → os → packages) binds them together,
// which is how Trivy associates OS packages with the detected OS. Covers both deb and rpm.
func buildOSBOM(host OS, pkgs []Package) []byte {
	pt := host.pkgType()
	purlType := host.purlType()
	distro := strings.ToLower(host.ID) + "-" + host.Version // e.g. ubuntu-24.04, rhel-9

	var bom cdxBOM
	bom.BOMFormat = "CycloneDX"
	bom.SpecVersion = "1.5"
	bom.Version = 1
	bom.Metadata.Component = cdxComponent{Type: "application", BOMRef: "root", Name: "deuswatch-inventory", Version: "0"}

	osRef := "os:" + distro
	osComp := cdxComponent{
		Type: "operating-system", BOMRef: osRef, Name: pt, Version: host.Version,
		Properties: []cdxProperty{{Name: "aquasecurity:trivy:PkgType", Value: pt}},
	}
	bom.Components = append(bom.Components, osComp)

	pkgRefs := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		if p.Name == "" || p.Version == "" {
			continue
		}
		purl := fmt.Sprintf("pkg:%s/%s/%s@%s?arch=%s&distro=%s", purlType, pt, p.Name, p.Version, p.Arch, distro)
		props := []cdxProperty{
			{Name: "aquasecurity:trivy:PkgType", Value: pt},
			{Name: "aquasecurity:trivy:PkgID", Value: p.Name + "@" + p.Version},
		}
		if p.Source != "" && p.Source != p.Name {
			props = append(props, cdxProperty{Name: "aquasecurity:trivy:SrcName", Value: p.Source})
			props = append(props, cdxProperty{Name: "aquasecurity:trivy:SrcVersion", Value: p.Version})
		}
		bom.Components = append(bom.Components, cdxComponent{
			Type: "library", BOMRef: purl, Name: p.Name, Version: p.Version, PURL: purl, Properties: props,
		})
		pkgRefs = append(pkgRefs, purl)
	}
	bom.Dependencies = []cdxDependency{
		{Ref: "root", DependsOn: []string{osRef}},
		{Ref: osRef, DependsOn: pkgRefs},
	}
	b, _ := json.Marshal(bom)
	return b
}

// normalizeSeverity lowercases Trivy's UPPERCASE severities to our scale.
func normalizeSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	case "NEGLIGIBLE":
		return "negligible"
	default:
		return "unknown"
	}
}

