package main

import (
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestRoutesRegister guards against the class of bug that crash-looped the api in v2.15.0: a route
// pattern that conflicts with another under Go's ServeMux rules panics at REGISTRATION, which
// `go build` never exercises (it compiles the strings but never registers them). This test reads the
// actual route patterns out of main.go and registers every one into a fresh ServeMux, so any
// conflicting or malformed pattern fails here instead of at container startup.
func TestRoutesRegister(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	// Match `mux.Handle("PATTERN"` and `mux.HandleFunc("PATTERN"`, capturing the pattern literal.
	re := regexp.MustCompile(`mux\.Handle(?:Func)?\(\s*"([^"]+)"`)

	mux := http.NewServeMux()
	h := func(w http.ResponseWriter, r *http.Request) {}
	seen := map[string]bool{}
	count := 0
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue // skip commented-out route lines (e.g. the WIP process-threats block)
		}
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		pat := m[1]
		if seen[pat] {
			continue // a pattern registered in two conditional branches is not a real conflict
		}
		seen[pat] = true
		// ServeMux.Handle panics on a conflicting/invalid pattern; that panic IS the test failure.
		mux.HandleFunc(pat, h)
		count++
	}
	if count == 0 {
		t.Fatal("no route patterns found in main.go - did the mux.Handle spelling change?")
	}
	t.Logf("registered %d unique route patterns without conflict", count)
}
