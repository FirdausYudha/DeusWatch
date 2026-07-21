package vuln

import "testing"

// TestParseUSN checks the Ubuntu notices.json shape (confirmed against the live API): one advisory
// per (release, SOURCE package, CVE), binaries and non-kept releases excluded.
func TestParseUSN(t *testing.T) {
	data := []byte(`{
	  "notices": [
	    {
	      "id": "USN-6000-1",
	      "cves_ids": ["CVE-2023-0286", "CVE-2023-0215"],
	      "release_packages": {
	        "jammy": [
	          {"name": "openssl", "version": "3.0.2-0ubuntu1.16", "is_source": true},
	          {"name": "libssl3", "version": "3.0.2-0ubuntu1.16", "is_source": false}
	        ],
	        "focal": [
	          {"name": "openssl", "version": "1.1.1f-1ubuntu2.19", "is_source": true}
	        ]
	      }
	    }
	  ],
	  "total_results": 1
	}`)
	advs, total, err := ParseUSN(data, map[string]bool{"jammy": true})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("total = %d, want 1", total)
	}
	// jammy only (focal filtered out), source package only (libssl3 binary excluded), 2 CVEs → 2.
	if len(advs) != 2 {
		t.Fatalf("expected 2 advisories, got %d: %+v", len(advs), advs)
	}
	for _, a := range advs {
		if a.Release != "jammy" || a.Package != "openssl" || a.FixedVersion != "3.0.2-0ubuntu1.16" || a.Source != "usn" {
			t.Fatalf("bad advisory: %+v", a)
		}
	}
}

// TestParseDebian checks the security-tracker shape: resolved→fixed version, open→no fix,
// fixed_version "0"→skipped (never affected), and release filtering.
func TestParseDebian(t *testing.T) {
	data := []byte(`{
	  "openssl": {
	    "CVE-2023-0286": {
	      "releases": {
	        "bookworm": {"status": "resolved", "fixed_version": "3.0.8-1", "urgency": "high"},
	        "bullseye": {"status": "resolved", "fixed_version": "1.1.1n-0+deb11u4", "urgency": "medium"}
	      }
	    },
	    "CVE-2024-9999": {
	      "releases": {
	        "bookworm": {"status": "open", "urgency": "not yet assigned"}
	      }
	    },
	    "CVE-2000-0000": {
	      "releases": {
	        "bookworm": {"status": "resolved", "fixed_version": "0", "urgency": "unimportant"}
	      }
	    }
	  },
	  "somepkg": {
	    "TEMP-0000000-ABCDEF": {
	      "releases": {"bookworm": {"status": "open", "urgency": "low"}}
	    }
	  }
	}`)
	advs, err := ParseDebian(data, map[string]bool{"bookworm": true})
	if err != nil {
		t.Fatal(err)
	}
	// bookworm only; the "0"/never-affected CVE and the TEMP- id are dropped → 2 advisories.
	if len(advs) != 2 {
		t.Fatalf("expected 2 advisories, got %d: %+v", len(advs), advs)
	}
	byCVE := map[string]Advisory{}
	for _, a := range advs {
		byCVE[a.CVE] = a
	}
	if f := byCVE["CVE-2023-0286"]; f.FixedVersion != "3.0.8-1" || f.Severity != "high" || f.Package != "openssl" {
		t.Fatalf("resolved advisory wrong: %+v", f)
	}
	if o, ok := byCVE["CVE-2024-9999"]; !ok || o.FixedVersion != "" {
		t.Fatalf("open advisory should have empty fixed version: %+v", o)
	}
	if _, ok := byCVE["CVE-2000-0000"]; ok {
		t.Fatal("a 'fixed_version: 0' (never affected) entry must be skipped")
	}
}

func TestFeedForDistro(t *testing.T) {
	if FeedForDistro("ubuntu") != "usn" || FeedForDistro("debian") != "debian" {
		t.Fatal("distro→feed mapping wrong")
	}
	if FeedForDistro("alpine") != "" {
		t.Fatal("unsupported distro must map to empty")
	}
}
