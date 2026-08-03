package vuln

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeCache is an in-memory PriorityCache — good enough for the unit test and independent of the
// real Postgres-backed one in internal/store.
type fakeCache struct {
	mu   sync.Mutex
	data map[string]string // cve -> priority ("" = "we already checked, Ubuntu had nothing")
}

func newFakeCache() *fakeCache { return &fakeCache{data: map[string]string{}} }

func (f *fakeCache) GetCVEPriority(_ context.Context, cve string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.data[cve]
	return p, ok, nil
}

func (f *fakeCache) PutCVEPriority(_ context.Context, cve, priority string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[cve] = priority
	return nil
}

// TestFetchUbuntuCVEPriority covers the three shapes the endpoint returns: normal 200 with a
// priority, 404 (unknown CVE — must be silent), and 5xx (must surface as an error so a transient
// network issue doesn't get cached as "no priority").
func TestFetchUbuntuCVEPriority(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/CVE-2024-0001.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"priority":"high"}`)
		case "/CVE-2024-0404.json":
			http.NotFound(w, r)
		case "/CVE-2024-0500.json":
			http.Error(w, "boom", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Swap the endpoint template to point at our test server (path shape must match: /<CVE>.json).
	orig := ubuntuCVEURLTemplate()
	setUbuntuCVEURLTemplate(srv.URL + "/%s.json")
	defer setUbuntuCVEURLTemplate(orig)

	ctx := context.Background()
	if p, err := FetchUbuntuCVEPriority(ctx, srv.Client(), "CVE-2024-0001"); err != nil || p != "high" {
		t.Fatalf("normal fetch: p=%q err=%v", p, err)
	}
	if p, err := FetchUbuntuCVEPriority(ctx, srv.Client(), "CVE-2024-0404"); err != nil || p != "" {
		t.Fatalf("404 must be silent (empty priority, no error): p=%q err=%v", p, err)
	}
	if _, err := FetchUbuntuCVEPriority(ctx, srv.Client(), "CVE-2024-0500"); err == nil {
		t.Fatal("5xx must surface as an error")
	}
}

// TestEnrichUSNSeverity is the end-to-end proof of the operator-facing fix: given a batch of
// advisories where every USN entry has empty severity (which is exactly what ParseUSN produces),
// EnrichUSNSeverity fills them in, does one network round trip per distinct CVE (not per
// advisory), leaves non-USN advisories alone, and caches results so a second pass makes zero
// network calls.
func TestEnrichUSNSeverity(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/CVE-2024-0001.json":
			fmt.Fprint(w, `{"priority":"critical"}`)
		case "/CVE-2024-0002.json":
			fmt.Fprint(w, `{"priority":"low"}`)
		case "/CVE-2024-0003.json":
			// Deliberately blank — the CVE is real but Ubuntu hasn't rated it.
			fmt.Fprint(w, `{"priority":""}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	orig := ubuntuCVEURLTemplate()
	setUbuntuCVEURLTemplate(srv.URL + "/%s.json")
	defer setUbuntuCVEURLTemplate(orig)

	advs := []Advisory{
		// Same CVE emitted twice (per (release,package)) — dedup must yield ONE network call.
		{Source: "usn", CVE: "CVE-2024-0001", Package: "openssl", Release: "jammy"},
		{Source: "usn", CVE: "CVE-2024-0001", Package: "openssl", Release: "focal"},
		{Source: "usn", CVE: "CVE-2024-0002", Package: "bash", Release: "jammy"},
		{Source: "usn", CVE: "CVE-2024-0003", Package: "curl", Release: "jammy"},
		// Non-USN advisory — must NOT be touched.
		{Source: "debian", CVE: "CVE-2024-9999", Package: "nginx", Release: "bookworm", Severity: "medium"},
		// USN advisory that already carries a severity (shouldn't in real life, but is a safe no-op).
		{Source: "usn", CVE: "CVE-2024-0007", Package: "ssh", Release: "jammy", Severity: "high"},
	}
	cache := newFakeCache()

	if err := EnrichUSNSeverity(context.Background(), srv.Client(), cache, advs, 2, time.Hour); err != nil {
		t.Fatalf("enrich: %v", err)
	}
	// One network call per DISTINCT USN CVE that started empty: 0001, 0002, 0003 = 3.
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("network calls: got %d, want 3 (one per distinct CVE)", got)
	}
	// Severities filled in per rule: 0001 -> critical, 0002 -> low, 0003 stays empty (Ubuntu blank).
	want := []string{"critical", "critical", "low", "", "medium", "high"}
	for i, w := range want {
		if advs[i].Severity != w {
			t.Errorf("advs[%d].Severity: got %q, want %q", i, advs[i].Severity, w)
		}
	}

	// Second pass — no new network calls; the cache serves everything (including the empty answer
	// for CVE-2024-0003, which is what protects Ubuntu from being hammered every refresh cycle).
	before := atomic.LoadInt32(&calls)
	// Clear the pre-filled severities so we can prove the cache re-fills them.
	for i := range advs {
		if advs[i].Source == "usn" && advs[i].CVE != "CVE-2024-0007" {
			advs[i].Severity = ""
		}
	}
	if err := EnrichUSNSeverity(context.Background(), srv.Client(), cache, advs, 2, time.Hour); err != nil {
		t.Fatalf("enrich #2: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != before {
		t.Errorf("second pass hit network %d extra times, want 0 (all cached)", got-before)
	}
	if advs[0].Severity != "critical" || advs[2].Severity != "low" {
		t.Errorf("cached priorities not re-applied: %q / %q", advs[0].Severity, advs[2].Severity)
	}
}

// TestEnrichUSNSeverityFetchFailureIsSoft: a per-CVE fetch error MUST NOT abort the whole batch.
// The unhappy CVE keeps empty severity, everything else gets enriched. Otherwise a single 503
// during a nightly feed refresh would leave the fleet with 100% "unknown" severities until the
// next cycle.
func TestEnrichUSNSeverityFetchFailureIsSoft(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/CVE-2024-0002.json" {
			http.Error(w, "sad", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"priority":"medium"}`)
	}))
	defer srv.Close()
	orig := ubuntuCVEURLTemplate()
	setUbuntuCVEURLTemplate(srv.URL + "/%s.json")
	defer setUbuntuCVEURLTemplate(orig)

	advs := []Advisory{
		{Source: "usn", CVE: "CVE-2024-0001", Package: "a", Release: "jammy"},
		{Source: "usn", CVE: "CVE-2024-0002", Package: "b", Release: "jammy"}, // 503
		{Source: "usn", CVE: "CVE-2024-0003", Package: "c", Release: "jammy"},
	}
	if err := EnrichUSNSeverity(context.Background(), srv.Client(), newFakeCache(), advs, 2, time.Hour); err != nil {
		t.Fatalf("enrich should swallow per-CVE errors: %v", err)
	}
	if advs[0].Severity != "medium" || advs[2].Severity != "medium" {
		t.Errorf("other CVEs must still be enriched, got %q / %q", advs[0].Severity, advs[2].Severity)
	}
	if advs[1].Severity != "" {
		t.Errorf("failed CVE must remain empty, got %q", advs[1].Severity)
	}
}
