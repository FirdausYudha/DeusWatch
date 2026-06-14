package blocklist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseLines(t *testing.T) {
	data := []byte("# header comment\n; semicolon comment\n\n45.155.205.99\n185.220.0.0/16 # tor exit\n1.2.3.4,malware\n")
	got := ParseLines(data)
	want := []string{"45.155.205.99", "185.220.0.0/16", "1.2.3.4"}
	if len(got) != len(want) {
		t.Fatalf("token count %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("token[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

func TestSetContains(t *testing.T) {
	s := NewSet()
	s.Replace([]string{"45.155.205.99", "185.220.0.0/16", "bogus", "10.0.0.0/8"})
	if s.Len() != 3 { // bogus is skipped
		t.Fatalf("Len=%d, want 3", s.Len())
	}
	cases := map[string]bool{
		"45.155.205.99": true,  // exact IP
		"185.220.5.7":   true,  // within CIDR
		"10.255.1.1":    true,  // within /8
		"8.8.8.8":       false, // not a member
		"185.221.0.1":   false, // outside the CIDR
	}
	for ip, want := range cases {
		if got := s.Contains(ip); got != want {
			t.Errorf("Contains(%q)=%v, want %v", ip, got, want)
		}
	}
}

func TestReplaceSwaps(t *testing.T) {
	s := NewSet()
	s.Replace([]string{"1.1.1.1"})
	if !s.Contains("1.1.1.1") {
		t.Fatal("initial entry lost")
	}
	s.Replace([]string{"2.2.2.2"})
	if s.Contains("1.1.1.1") || !s.Contains("2.2.2.2") {
		t.Fatal("Replace should swap, not append")
	}
}

func TestLoadHTTP(t *testing.T) {
	feed1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("# feed1\n45.155.205.99\n185.220.0.0/16\n"))
	}))
	defer feed1.Close()
	feed2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("203.0.113.10\n"))
	}))
	defer feed2.Close()

	set, err := Load(context.Background(), feed1.Client(), []string{feed1.URL, feed2.URL})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, ip := range []string{"45.155.205.99", "185.220.1.1", "203.0.113.10"} {
		if !set.Contains(ip) {
			t.Errorf("%s should be in the merged blocklist", ip)
		}
	}
}

func TestLoadPartialFailureStillLoads(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("9.9.9.9\n"))
	}))
	defer good.Close()

	// one valid URL + one unreachable -> still loads the valid one.
	set, err := Load(context.Background(), good.Client(), []string{good.URL, "http://127.0.0.1:0/x"})
	if err != nil {
		t.Fatalf("a partial failure must not fail Load: %v", err)
	}
	if !set.Contains("9.9.9.9") {
		t.Fatal("the valid entry should still be loaded")
	}
}

func TestLoadAllFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := Load(context.Background(), srv.Client(), []string{srv.URL}); err == nil {
		t.Fatal("all sources failing must return an error")
	}
}
