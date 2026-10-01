package osv

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestCVSSBaseScore(t *testing.T) {
	// Vectors with published base scores (first two are from the real CVE-2024-7264 record).
	cases := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L", 6.3},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", 6.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0},
		{"not-a-vector", 0},
	}
	for _, c := range cases {
		if got := cvssBaseScore(c.vector); math.Abs(got-c.want) > 0.001 {
			t.Errorf("cvssBaseScore(%q) = %v, want %v", c.vector, got, c.want)
		}
	}
}

func TestSeverityPrefersDistroRating(t *testing.T) {
	// Shape taken verbatim from the live UBUNTU-CVE-2024-7264 record: CVSS vectors plus the
	// distro's own rating. The distro rating must win, and CVSS must still be captured.
	raw := `{
	  "id":"UBUNTU-CVE-2024-7264",
	  "upstream":["CVE-2024-7264"],
	  "severity":[
	    {"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"},
	    {"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"},
	    {"type":"Ubuntu","score":"medium"}
	  ],
	  "affected":[
	    {"package":{"name":"curl","ecosystem":"Ubuntu:Pro:14.04:LTS"},
	     "ranges":[{"events":[{"introduced":"0"},{"fixed":"7.35.0-1ubuntu2.20+esm18"}]}]},
	    {"package":{"name":"curl","ecosystem":"Ubuntu:24.04:LTS"},
	     "ranges":[{"events":[{"introduced":"0"},{"fixed":"8.5.0-2ubuntu10.2"}]}]}
	  ]
	}`
	var rec vulnRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		t.Fatal(err)
	}
	v := distill(rec)

	if v.CVE != "CVE-2024-7264" {
		t.Errorf("CVE = %q, want CVE-2024-7264", v.CVE)
	}
	if v.Severity != "medium" {
		t.Errorf("Severity = %q, want medium (the distro rating)", v.Severity)
	}
	if math.Abs(v.CVSS-6.5) > 0.001 { // highest of the two vectors
		t.Errorf("CVSS = %v, want 6.5", v.CVSS)
	}
	// Must pick THIS release, not the Pro/ESM entry for a different one.
	if got := v.FixedFor("Ubuntu:", "24.04", "curl"); got != "8.5.0-2ubuntu10.2" {
		t.Errorf("FixedFor(24.04) = %q, want 8.5.0-2ubuntu10.2", got)
	}
}

func TestSeverityFallsBackToCVSS(t *testing.T) {
	var rec vulnRecord
	_ = json.Unmarshal([]byte(`{"id":"CVE-1","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`), &rec)
	v := distill(rec)
	if v.Severity != "critical" {
		t.Errorf("Severity = %q, want critical (derived from 9.8)", v.Severity)
	}
}

func TestPURL(t *testing.T) {
	got := PURL("ubuntu", "dpkg", "imagemagick", "8:6.9.12.98+dfsg1-5.2build2", "noble")
	if !strings.HasPrefix(got, "pkg:deb/ubuntu/imagemagick@") || !strings.Contains(got, "distro=noble") {
		t.Fatalf("purl = %q", got)
	}
	// Epoch ':' and '+' must be escaped or the purl is malformed.
	if strings.Contains(got, "8:6.9") || strings.Contains(got, "+dfsg1") {
		t.Errorf("purl not escaped: %q", got)
	}
	if PURL("rhel", "rpm", "openssl", "3.0.7", "") != "" {
		t.Error("RHEL must report unsupported (OSV has no Red Hat data)")
	}
	if !Supported("ubuntu") || Supported("rhel") {
		t.Error("Supported() wrong for ubuntu/rhel")
	}
}

func TestIsAdvisoryID(t *testing.T) {
	for _, id := range []string{"USN-7162-1", "DSA-5555-1", "RLSA-2024:1234"} {
		if !isAdvisoryID(id) {
			t.Errorf("%s should be treated as an advisory aggregate", id)
		}
	}
	if isAdvisoryID("UBUNTU-CVE-2024-7264") {
		t.Error("per-CVE record must be kept")
	}
}
