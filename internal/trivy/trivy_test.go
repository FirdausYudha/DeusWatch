package trivy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseReport(t *testing.T) {
	sample := `{
	  "Results": [
	    {"Class":"os-pkgs","Type":"ubuntu","Vulnerabilities":[
	      {"VulnerabilityID":"CVE-2024-1","PkgName":"bash","InstalledVersion":"5.1","FixedVersion":"5.2","Severity":"HIGH"},
	      {"VulnerabilityID":"CVE-2024-1","PkgName":"bash","InstalledVersion":"5.1","FixedVersion":"5.2","Severity":"HIGH"},
	      {"VulnerabilityID":"CVE-2024-2","PkgName":"openssl","InstalledVersion":"3.0","FixedVersion":"","Severity":"CRITICAL"},
	      {"VulnerabilityID":"","PkgName":"x","Severity":"LOW"}
	    ]}
	  ]
	}`
	f, err := parseReport([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	// Two unique findings (dup CVE-2024-1 collapsed, empty-id dropped).
	if len(f) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(f), f)
	}
	bySev := map[string]string{}
	for _, x := range f {
		bySev[x.CVE] = x.Severity
		if x.Source != "trivy" {
			t.Errorf("source = %q, want trivy", x.Source)
		}
	}
	if bySev["CVE-2024-1"] != "high" || bySev["CVE-2024-2"] != "critical" {
		t.Errorf("severities not lowercased/mapped: %+v", bySev)
	}
}

func TestWriteDpkgRootfs(t *testing.T) {
	dir := t.TempDir()
	host := OS{ID: "ubuntu", Version: "24.04", Codename: "noble", PkgManager: "dpkg"}
	pkgs := []Package{
		{Name: "bash", Version: "5.2-1", Arch: "amd64"},
		{Name: "libssl3", Version: "3.0.2", Arch: "amd64", Source: "openssl"},
		{Name: "", Version: "skip"}, // dropped
	}
	if err := writeDpkgRootfs(dir, host, pkgs); err != nil {
		t.Fatal(err)
	}
	osrel, err := os.ReadFile(filepath.Join(dir, "etc", "os-release"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(osrel), "ID=ubuntu") || !strings.Contains(string(osrel), "VERSION_CODENAME=noble") {
		t.Errorf("os-release missing distro fields:\n%s", osrel)
	}
	status, err := os.ReadFile(filepath.Join(dir, "var", "lib", "dpkg", "status"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(status)
	if !strings.Contains(s, "Package: bash") || !strings.Contains(s, "Version: 5.2-1") {
		t.Errorf("status missing bash block:\n%s", s)
	}
	if !strings.Contains(s, "Source: openssl") {
		t.Errorf("status missing source package for libssl3:\n%s", s)
	}
	if strings.Contains(s, "Package: \n") {
		t.Errorf("empty package should have been skipped:\n%s", s)
	}
}

func TestBuildRPMSBOM(t *testing.T) {
	host := OS{ID: "rhel", Version: "9", PkgManager: "rpm"}
	pkgs := []Package{{Name: "openssl", Version: "3.0.7-1.el9", Arch: "x86_64"}}
	raw := buildRPMSBOM(host, pkgs)
	var bom cdxBOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("invalid CycloneDX JSON: %v", err)
	}
	if bom.BOMFormat != "CycloneDX" || len(bom.Components) != 1 {
		t.Fatalf("unexpected bom: %+v", bom)
	}
	c := bom.Components[0]
	if !strings.HasPrefix(c.PURL, "pkg:rpm/redhat/openssl@3.0.7-1.el9") {
		t.Errorf("purl = %q, want pkg:rpm/redhat/openssl@...", c.PURL)
	}
	if !strings.Contains(c.PURL, "distro=rhel-9") {
		t.Errorf("purl missing distro qualifier: %q", c.PURL)
	}
	if bom.Metadata.Component.Type != "operating-system" || bom.Metadata.Component.Name != "redhat" {
		t.Errorf("os metadata wrong: %+v", bom.Metadata.Component)
	}
}
