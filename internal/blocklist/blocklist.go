// Package blocklist loads community IP blocklists (e.g. public feeds) into a
// thread-safe in-memory set, used by enrichment to flag malicious IPs (design doc
// Phase 3). Supports single IPs & CIDRs; comment lines (#/;) are skipped.
package blocklist

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Set is a collection of blocked IPs & CIDRs, safe to read/replace concurrently.
type Set struct {
	mu   sync.RWMutex
	ips  map[string]struct{}
	nets []*net.IPNet
}

// NewSet creates an empty set.
func NewSet() *Set { return &Set{ips: map[string]struct{}{}} }

// Len returns the number of entries (exact IPs + CIDRs).
func (s *Set) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ips) + len(s.nets)
}

// Contains reports whether ip is in the blocklist (exact match or within a CIDR).
func (s *Set) Contains(ip string) bool {
	parsed := net.ParseIP(ip)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.ips[ip]; ok {
		return true
	}
	if parsed != nil {
		for _, n := range s.nets {
			if n.Contains(parsed) {
				return true
			}
		}
	}
	return false
}

// Replace swaps the set's contents from a list of tokens (IP or CIDR). Invalid
// tokens are skipped.
func (s *Set) Replace(tokens []string) {
	ips := make(map[string]struct{}, len(tokens))
	var nets []*net.IPNet
	for _, tok := range tokens {
		if strings.Contains(tok, "/") {
			if _, n, err := net.ParseCIDR(tok); err == nil {
				nets = append(nets, n)
			}
			continue
		}
		if net.ParseIP(tok) != nil {
			ips[tok] = struct{}{}
		}
	}
	s.mu.Lock()
	s.ips, s.nets = ips, nets
	s.mu.Unlock()
}

// ParseLines extracts IP/CIDR tokens from feed content: one per line, comments (#/;)
// and text after whitespace are ignored.
func ParseLines(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		// Take the first field (many feeds: "<ip> # comment" or "<ip>,<meta>").
		field := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' })
		if len(field) > 0 && field[0] != "" && field[0][0] != '#' {
			out = append(out, field[0])
		}
	}
	return out
}

// fetchTokens downloads & parses all URLs; returns the combined tokens + per-URL errors.
func fetchTokens(ctx context.Context, hc *http.Client, urls []string) ([]string, []error) {
	var tokens []string
	var errs []error
	for _, u := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		resp, err := hc.Do(req)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", u, err))
			continue
		}
		body, err := readAllLimited(resp)
		_ = resp.Body.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", u, err))
			continue
		}
		if resp.StatusCode != http.StatusOK {
			errs = append(errs, fmt.Errorf("%s: HTTP %d", u, resp.StatusCode))
			continue
		}
		tokens = append(tokens, ParseLines(body)...)
	}
	return tokens, errs
}

func readAllLimited(resp *http.Response) ([]byte, error) {
	var b bytes.Buffer
	_, err := b.ReadFrom(http.MaxBytesReader(nil, resp.Body, 32<<20)) // 32 MiB limit
	return b.Bytes(), err
}

// Load downloads all URLs and builds a Set. It errors only if NO tokens at all were
// successfully loaded.
func Load(ctx context.Context, hc *http.Client, urls []string) (*Set, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	tokens, errs := fetchTokens(ctx, hc, urls)
	if len(tokens) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("blocklist: all sources failed: %v", errs)
	}
	s := NewSet()
	s.Replace(tokens)
	return s, nil
}

// Refresh reloads the set every interval until ctx is cancelled. Failures are logged
// and do not clear the previous set.
func Refresh(ctx context.Context, hc *http.Client, urls []string, interval time.Duration, s *Set) {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tokens, errs := fetchTokens(ctx, hc, urls)
			if len(tokens) == 0 {
				log.Printf("blocklist: refresh failed (keeping previous set): %v", errs)
				continue
			}
			s.Replace(tokens)
			log.Printf("blocklist: refreshed — %d entries", s.Len())
		}
	}
}
