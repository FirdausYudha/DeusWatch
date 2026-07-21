package vuln

import "testing"

func TestMatch(t *testing.T) {
	pkgs := []InstalledPackage{
		{Name: "libssl3", Version: "3.0.2-0ubuntu1.15", Source: "openssl"},
		{Name: "libssl-dev", Version: "3.0.2-0ubuntu1.15", Source: "openssl"}, // same source
		{Name: "nginx-core", Version: "1.18.0-6ubuntu14.5", Source: "nginx"},  // already patched
		{Name: "bash", Version: "5.1-6ubuntu1", Source: ""},                   // source == name
	}
	adv := map[string][]Advisory{
		"openssl": {
			{Source: "usn", CVE: "CVE-2023-0286", Package: "openssl", FixedVersion: "3.0.2-0ubuntu1.16", Severity: "high"},
			{Source: "usn", CVE: "CVE-2022-4304", Package: "openssl", FixedVersion: "3.0.2-0ubuntu1.10", Severity: "medium"}, // already fixed in installed
		},
		"nginx": {
			{Source: "usn", CVE: "CVE-2021-23017", Package: "nginx", FixedVersion: "1.18.0-6ubuntu14.4", Severity: "critical"}, // installed is newer → not vuln
		},
		"bash": {
			{Source: "usn", CVE: "CVE-2019-0000", Package: "bash", FixedVersion: "", Severity: "low"}, // no fix yet → always vulnerable
		},
	}

	findings := Match(pkgs, adv)

	// Expected: openssl/CVE-2023-0286 (installed older than fix) ONCE despite two binaries;
	// bash/CVE-2019-0000 (no fix). NOT: the already-fixed openssl CVE, NOT the patched nginx.
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}
	byCVE := map[string]Finding{}
	for _, f := range findings {
		byCVE[f.CVE] = f
	}
	if f, ok := byCVE["CVE-2023-0286"]; !ok {
		t.Fatal("must flag the un-patched openssl CVE")
	} else if f.Package != "openssl" || f.FixedVersion != "3.0.2-0ubuntu1.16" || f.Severity != "high" {
		t.Fatalf("openssl finding wrong: %+v", f)
	}
	if _, ok := byCVE["CVE-2019-0000"]; !ok {
		t.Fatal("must flag an advisory with no published fix")
	}
	if _, ok := byCVE["CVE-2022-4304"]; ok {
		t.Fatal("must NOT flag a CVE already fixed in the installed version")
	}
	if _, ok := byCVE["CVE-2021-23017"]; ok {
		t.Fatal("must NOT flag a package newer than the fixed version")
	}

	// De-dup: only one finding for the two openssl binaries.
	n := 0
	for _, f := range findings {
		if f.Package == "openssl" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("two binaries from one source must yield ONE finding per CVE, got %d", n)
	}
}

func TestIsVulnerable(t *testing.T) {
	if !IsVulnerable("1.0-1", Advisory{FixedVersion: ""}) {
		t.Fatal("no published fix must always be vulnerable")
	}
	if !IsVulnerable("1.0-1", Advisory{FixedVersion: "1.0-2"}) {
		t.Fatal("older than fix must be vulnerable")
	}
	if IsVulnerable("1.0-2", Advisory{FixedVersion: "1.0-2"}) {
		t.Fatal("exactly the fixed version must NOT be vulnerable")
	}
	if IsVulnerable("1.0-3", Advisory{FixedVersion: "1.0-2"}) {
		t.Fatal("newer than fix must NOT be vulnerable")
	}
}

func TestSeverityRank(t *testing.T) {
	if SeverityRank("critical") <= SeverityRank("high") || SeverityRank("high") <= SeverityRank("medium") {
		t.Fatal("severity ranking is not monotonic")
	}
	if SeverityRank("not yet assigned") != 0 {
		t.Fatal("unknown severity must rank 0")
	}
}
