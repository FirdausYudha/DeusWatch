package respond

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

// fakeRouter mimics the RouterOS REST address-list endpoints in-memory.
type fakeRouter struct {
	mu      sync.Mutex
	entries []mtEntry
	nextID  int
}

func (f *fakeRouter) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/ip/firewall/address-list", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case http.MethodGet: // list
			_ = json.NewEncoder(w).Encode(f.entries)
		case http.MethodPut: // add
			var p map[string]string
			_ = json.NewDecoder(r.Body).Decode(&p)
			f.nextID++
			f.entries = append(f.entries, mtEntry{
				ID: "*" + itoa(f.nextID), Address: p["address"], Comment: p["comment"],
			})
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/rest/ip/firewall/address-list/remove", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var p map[string]string
		_ = json.NewDecoder(r.Body).Decode(&p)
		kept := f.entries[:0]
		for _, e := range f.entries {
			if e.ID != p[".id"] {
				kept = append(kept, e)
			}
		}
		f.entries = kept
	})
	return mux
}

func (f *fakeRouter) addrs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var a []string
	for _, e := range f.entries {
		a = append(a, e.Address+"|"+e.Comment)
	}
	sort.Strings(a)
	return a
}

func itoa(n int) string { return strings.TrimSpace(jsonNumber(n)) }
func jsonNumber(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestMikrotikSyncReconciles(t *testing.T) {
	f := &fakeRouter{}
	// Pre-seed: one manual entry (must survive) + one stale DeusWatch entry (must be removed).
	f.entries = []mtEntry{
		{ID: "*1", Address: "10.0.0.1", Comment: "manual-admin"},
		{ID: "*2", Address: "1.1.1.1", Comment: "deuswatch"}, // stale - not in desired
	}
	f.nextID = 2
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	m := NewMikrotikResponder(srv.URL, "u", "p", "deuswatch_ban", false)
	// Desired: block two IPs; 1.1.1.1 should be dropped, 10.0.0.1 (manual) untouched.
	if err := m.Sync(context.Background(), []string{"2.2.2.2", "3.3.3.3"}); err != nil {
		t.Fatalf("sync: %v", err)
	}
	got := f.addrs()
	want := []string{"10.0.0.1|manual-admin", "2.2.2.2|deuswatch", "3.3.3.3|deuswatch"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("after sync got %v, want %v", got, want)
	}

	// Idempotent: syncing the same desired set again changes nothing.
	if err := m.Sync(context.Background(), []string{"2.2.2.2", "3.3.3.3"}); err != nil {
		t.Fatalf("sync 2: %v", err)
	}
	if got2 := f.addrs(); strings.Join(got2, ",") != strings.Join(want, ",") {
		t.Fatalf("second sync must be idempotent, got %v", got2)
	}

	// Unban everything: managed entries removed, manual stays.
	if err := m.Sync(context.Background(), nil); err != nil {
		t.Fatalf("sync empty: %v", err)
	}
	if got3 := f.addrs(); strings.Join(got3, ",") != "10.0.0.1|manual-admin" {
		t.Fatalf("empty sync should leave only the manual entry, got %v", got3)
	}
}

func TestMultiResponderFansOut(t *testing.T) {
	f1, f2 := &fakeRouter{}, &fakeRouter{}
	s1 := httptest.NewServer(f1.handler())
	s2 := httptest.NewServer(f2.handler())
	defer s1.Close()
	defer s2.Close()

	multi := NewMultiResponder([]Responder{
		NewMikrotikResponder(s1.URL, "u", "p", "l", false),
		NewMikrotikResponder(s2.URL, "u", "p", "l", false),
	})
	if err := multi.Sync(context.Background(), []string{"9.9.9.9"}); err != nil {
		t.Fatalf("multi sync: %v", err)
	}
	if len(f1.addrs()) != 1 || len(f2.addrs()) != 1 {
		t.Fatalf("both routers must receive the block: f1=%v f2=%v", f1.addrs(), f2.addrs())
	}
}
