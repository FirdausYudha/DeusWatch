package trivy

import (
	"encoding/json"
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

func TestBuildOSBOMDeb(t *testing.T) {
	host := OS{ID: "ubuntu", Version: "24.04", Codename: "noble", PkgManager: "dpkg"}
	pkgs := []Package{
		{Name: "bash", Version: "5.2-1", Arch: "amd64"},
		{Name: "libssl3", Version: "3.0.2", Arch: "amd64", Source: "openssl"},
		{Name: "", Version: "skip"}, // dropped
	}
	var bom cdxBOM
	if err := json.Unmarshal(buildOSBOM(host, pkgs), &bom); err != nil {
		t.Fatalf("invalid CycloneDX JSON: %v", err)
	}
	// 1 operating-system component + 2 package components (empty name dropped).
	if len(bom.Components) != 3 {
		t.Fatalf("want 3 components, got %d: %+v", len(bom.Components), bom.Components)
	}
	osc := bom.Components[0]
	if osc.Type != "operating-system" || osc.Name != "ubuntu" || osc.Version != "24.04" {
		t.Errorf("os component wrong: %+v", osc)
	}
	bash := bom.Components[1]
	if !strings.HasPrefix(bash.PURL, "pkg:deb/ubuntu/bash@5.2-1") || !strings.Contains(bash.PURL, "distro=ubuntu-24.04") {
		t.Errorf("bash purl wrong: %q", bash.PURL)
	}
	if !hasProp(bash.Properties, "aquasecurity:trivy:PkgType", "ubuntu") {
		t.Errorf("bash missing PkgType property: %+v", bash.Properties)
	}
	// Dependency graph: root -> os -> both packages, so Trivy binds packages to the detected OS.
	if len(bom.Dependencies) != 2 || len(bom.Dependencies[1].DependsOn) != 2 {
		t.Errorf("dependency graph wrong: %+v", bom.Dependencies)
	}
}

func TestBuildOSBOMRpm(t *testing.T) {
	host := OS{ID: "rhel", Version: "9", PkgManager: "rpm"}
	var bom cdxBOM
	if err := json.Unmarshal(buildOSBOM(host, []Package{{Name: "openssl", Version: "3.0.7-1.el9", Arch: "x86_64"}}), &bom); err != nil {
		t.Fatalf("invalid CycloneDX JSON: %v", err)
	}
	if bom.Components[0].Name != "redhat" {
		t.Errorf("os family = %q, want redhat", bom.Components[0].Name)
	}
	if !strings.HasPrefix(bom.Components[1].PURL, "pkg:rpm/redhat/openssl@3.0.7-1.el9") {
		t.Errorf("rpm purl wrong: %q", bom.Components[1].PURL)
	}
}

func hasProp(props []cdxProperty, name, value string) bool {
	for _, p := range props {
		if p.Name == name && p.Value == value {
			return true
		}
	}
	return false
}
