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

// Config is how the worker reaches Trivy. Bin is the trivy client binary; Server is the trivy
// server URL (client/server mode). Both come from env (TRIVY_BIN, TRIVY_SERVER).
type Config struct {
	Bin    string
	Server string
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
	Severity         string // lowercased: critical|high|medium|low|negligible|unknown
	Source           string // always "trivy" here
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
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// ScanOS scans a host's OS packages and returns findings with severity. It picks the right input for
// the package manager (dpkg → synthesized rootfs, rpm → CycloneDX SBOM), runs trivy, and parses the
// result. A host with no packages or an unsupported manager returns nil, nil (nothing to do).
func (c Config) ScanOS(ctx context.Context, host OS, pkgs []Package) ([]Finding, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}
	dir, err := os.MkdirTemp("", "dw-trivy-*")
	if err != nil {
		return nil, fmt.Errorf("trivy: temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	switch host.PkgManager {
	case "dpkg":
		if err := writeDpkgRootfs(dir, host, pkgs); err != nil {
			return nil, err
		}
		return c.run(ctx, "rootfs", dir)
	case "rpm":
		sbom := filepath.Join(dir, "sbom.cdx.json")
		if err := os.WriteFile(sbom, buildRPMSBOM(host, pkgs), 0o600); err != nil {
			return nil, fmt.Errorf("trivy: write sbom: %w", err)
		}
		return c.run(ctx, "sbom", sbom)
	default:
		return nil, nil // unsupported package manager
	}
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

// runSCA scans a reconstructed manifest tree and parses language-package findings.
func (c Config) runSCA(ctx context.Context, dir string) ([]SCAFinding, error) {
	bin := c.Bin
	if bin == "" {
		bin = "trivy"
	}
	args := []string{
		"fs", "--quiet", "--format", "json", "--scanners", "vuln",
		"--pkg-types", "library",
		"--cache-dir", filepath.Join(os.TempDir(), "trivy-cache"),
	}
	if c.Server != "" {
		args = append(args, "--server", c.Server)
	}
	args = append(args, dir)

	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
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
			})
		}
	}
	return out, nil
}

// run invokes the trivy client against a target (a rootfs dir or an sbom file) and parses findings.
func (c Config) run(ctx context.Context, mode, target string) ([]Finding, error) {
	bin := c.Bin
	if bin == "" {
		bin = "trivy"
	}
	args := []string{
		mode,
		"--quiet",
		"--format", "json",
		"--scanners", "vuln",
		"--cache-dir", filepath.Join(os.TempDir(), "trivy-cache"),
		"--pkg-types", "os",
	}
	if c.Server != "" {
		args = append(args, "--server", c.Server)
	}
	if mode == "sbom" {
		// SBOM scans carry their own package types (os + library); don't restrict.
		args = removeArg(args, "--pkg-types", "os")
	}
	args = append(args, target)

	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
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
				Source:           "trivy",
			})
		}
	}
	return out, nil
}

// writeDpkgRootfs synthesizes the two files Trivy's rootfs scanner reads for a Debian/Ubuntu host:
// /etc/os-release (distro identity) and /var/lib/dpkg/status (installed packages). This is exactly
// the format a real host presents, so Trivy applies the correct Ubuntu/Debian OVAL with severity.
func writeDpkgRootfs(dir string, host OS, pkgs []Package) error {
	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, "var", "lib", "dpkg"), 0o755); err != nil {
		return err
	}
	var osrel strings.Builder
	fmt.Fprintf(&osrel, "ID=%s\n", host.ID)
	fmt.Fprintf(&osrel, "VERSION_ID=%q\n", host.Version)
	if host.Codename != "" {
		fmt.Fprintf(&osrel, "VERSION_CODENAME=%s\n", host.Codename)
	}
	fmt.Fprintf(&osrel, "PRETTY_NAME=%q\n", host.ID+" "+host.Version)
	if err := os.WriteFile(filepath.Join(dir, "etc", "os-release"), []byte(osrel.String()), 0o644); err != nil {
		return err
	}

	var st strings.Builder
	for _, p := range pkgs {
		if p.Name == "" || p.Version == "" {
			continue
		}
		fmt.Fprintf(&st, "Package: %s\n", p.Name)
		fmt.Fprintf(&st, "Status: install ok installed\n")
		if p.Arch != "" {
			fmt.Fprintf(&st, "Architecture: %s\n", p.Arch)
		}
		if p.Source != "" && p.Source != p.Name {
			fmt.Fprintf(&st, "Source: %s\n", p.Source)
		}
		fmt.Fprintf(&st, "Version: %s\n\n", p.Version)
	}
	return os.WriteFile(filepath.Join(dir, "var", "lib", "dpkg", "status"), []byte(st.String()), 0o644)
}

// ── CycloneDX SBOM for RPM hosts ────────────────────────────────────────────────

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type cdxComponent struct {
	Type       string        `json:"type"`
	BOMRef     string        `json:"bom-ref"`
	Name       string        `json:"name"`
	Version    string        `json:"version"`
	PURL       string        `json:"purl,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}
type cdxBOM struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Version     int    `json:"version"`
	Metadata    struct {
		Component cdxComponent `json:"component"`
	} `json:"metadata"`
	Components []cdxComponent `json:"components"`
}

// buildRPMSBOM emits a CycloneDX BOM Trivy reads as an RPM-based host: an operating-system metadata
// component fixes the distro (so Trivy picks the RedHat/Amazon/etc OVAL), and each package carries a
// pkg:rpm PURL plus the trivy PkgType property, mirroring Trivy's own SBOM output.
func buildRPMSBOM(host OS, pkgs []Package) []byte {
	pkgType := rpmPkgType(host.ID)
	distro := host.ID + "-" + host.Version // e.g. rhel-9, rocky-9, amzn-2023
	var bom cdxBOM
	bom.BOMFormat = "CycloneDX"
	bom.SpecVersion = "1.5"
	bom.Version = 1
	bom.Metadata.Component = cdxComponent{
		Type: "operating-system", BOMRef: "os", Name: pkgType, Version: host.Version,
		Properties: []cdxProperty{{Name: "aquasecurity:trivy:PkgType", Value: pkgType}},
	}
	for _, p := range pkgs {
		if p.Name == "" || p.Version == "" {
			continue
		}
		purl := fmt.Sprintf("pkg:rpm/%s/%s@%s?arch=%s&distro=%s", pkgType, p.Name, p.Version, p.Arch, distro)
		props := []cdxProperty{{Name: "aquasecurity:trivy:PkgType", Value: pkgType}}
		if p.Source != "" && p.Source != p.Name {
			props = append(props, cdxProperty{Name: "aquasecurity:trivy:SrcName", Value: p.Source})
			props = append(props, cdxProperty{Name: "aquasecurity:trivy:SrcVersion", Value: p.Version})
		}
		bom.Components = append(bom.Components, cdxComponent{
			Type: "library", BOMRef: purl, Name: p.Name, Version: p.Version, PURL: purl, Properties: props,
		})
	}
	b, _ := json.Marshal(bom)
	return b
}

// rpmPkgType maps an os-release ID to Trivy's RPM package type / OVAL family.
func rpmPkgType(osID string) string {
	switch strings.ToLower(osID) {
	case "rhel", "redhat", "centos", "rocky", "almalinux", "alma", "oracle", "ol":
		return "redhat"
	case "amzn", "amazon":
		return "amazon"
	case "fedora":
		return "fedora"
	case "opensuse", "suse", "sles":
		return "suse linux enterprise server"
	default:
		return strings.ToLower(osID)
	}
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

// removeArg drops a `flag value` pair from an args slice (used to strip --pkg-types for sbom scans).
func removeArg(args []string, flag, value string) []string {
	out := args[:0:0]
	for i := 0; i < len(args); i++ {
		if args[i] == flag && i+1 < len(args) && args[i+1] == value {
			i++ // skip value too
			continue
		}
		out = append(out, args[i])
	}
	return out
}
