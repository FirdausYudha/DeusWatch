package hashrep

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const goodHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // 64-hex

func TestIsSHA256(t *testing.T) {
	if !IsSHA256(goodHash) {
		t.Fatal("valid sha256 rejected")
	}
	for _, bad := range []string{"", "abc", strings.Repeat("z", 64), goodHash + "0"} {
		if IsSHA256(bad) {
			t.Fatalf("invalid hash accepted: %q", bad)
		}
	}
}

func TestVirusTotalClientVerdicts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/bad"):
			_, _ = w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":12,"undetected":58}}}}`))
		case strings.HasSuffix(r.URL.Path, "/good"):
			_, _ = w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":0,"harmless":70}}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := &VirusTotalClient{key: "k", base: srv.URL, hc: srv.Client()}

	if v, d, err := c.Lookup(context.Background(), "bad"); err != nil || v != VerdictKnownBad || d == "" {
		t.Fatalf("bad: v=%s d=%q err=%v", v, d, err)
	}
	if v, _, err := c.Lookup(context.Background(), "good"); err != nil || v != VerdictKnownGood {
		t.Fatalf("good: v=%s err=%v", v, err)
	}
	if v, _, err := c.Lookup(context.Background(), "missing"); err != nil || v != VerdictUnknown {
		t.Fatalf("missing: v=%s err=%v", v, err)
	}
}

func TestCIRCLClientVerdicts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/AAA"):
			_, _ = w.Write([]byte(`{"FileName":"kernel32.dll","hashlookup:trust":99}`))
		case strings.HasSuffix(r.URL.Path, "/BBB"):
			_, _ = w.Write([]byte(`{"KnownMalicious":"malshare"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := &CIRCLClient{base: srv.URL, hc: srv.Client()}

	if v, _, err := c.Lookup(context.Background(), "aaa"); err != nil || v != VerdictKnownGood {
		t.Fatalf("good: v=%s err=%v", v, err)
	}
	if v, _, err := c.Lookup(context.Background(), "bbb"); err != nil || v != VerdictKnownBad {
		t.Fatalf("bad: v=%s err=%v", v, err)
	}
	if v, _, err := c.Lookup(context.Background(), "ccc"); err != nil || v != VerdictUnknown {
		t.Fatalf("unknown: v=%s err=%v", v, err)
	}
}

func TestCompositeKnownBadOutranks(t *testing.T) {
	// VT says malicious, CIRCL says good → composite must be known_bad, and CIRCL skipped.
	vt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":5,"undetected":60}}}}`))
	}))
	defer vt.Close()
	circlHit := false
	circl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		circlHit = true
		_, _ = w.Write([]byte(`{"FileName":"x"}`))
	}))
	defer circl.Close()

	p := &CompositeProvider{
		VT:    &VirusTotalClient{key: "k", base: vt.URL, hc: vt.Client()},
		CIRCL: &CIRCLClient{base: circl.URL, hc: circl.Client()},
	}
	ind, err := p.LookupHash(context.Background(), goodHash)
	if err != nil || ind.Verdict != VerdictKnownBad {
		t.Fatalf("want known_bad: %+v err=%v", ind, err)
	}
	if circlHit {
		t.Fatal("CIRCL must be skipped once VT flags the hash bad")
	}
	if !strings.Contains(ind.Source, "virustotal") {
		t.Fatalf("source missing virustotal: %q", ind.Source)
	}
}

func TestBuildProviderDisabled(t *testing.T) {
	if _, ok := BuildProvider("", false); ok {
		t.Fatal("no config should disable the provider")
	}
	if p, ok := BuildProvider("", true); !ok || p == nil {
		t.Fatal("circlOn should enable the provider")
	}
}
