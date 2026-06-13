// Package blocklist memuat daftar blokir IP komunitas (mis. feed publik) ke dalam
// set in-memory thread-safe, lalu dipakai enrichment untuk menandai IP berbahaya
// (design doc Fase 3). Mendukung IP tunggal & CIDR; baris komentar (#/;) dilewati.
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

// Set adalah kumpulan IP & CIDR yang diblokir, aman untuk dibaca/diganti konkuren.
type Set struct {
	mu   sync.RWMutex
	ips  map[string]struct{}
	nets []*net.IPNet
}

// NewSet membuat set kosong.
func NewSet() *Set { return &Set{ips: map[string]struct{}{}} }

// Len mengembalikan jumlah entri (IP eksak + CIDR).
func (s *Set) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ips) + len(s.nets)
}

// Contains melaporkan apakah ip termasuk daftar blokir (cocok eksak atau dalam CIDR).
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

// Replace mengganti isi set dari daftar token (IP atau CIDR). Token tak valid dilewati.
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

// ParseLines mengekstrak token IP/CIDR dari isi feed: satu per baris, komentar (#/;)
// & teks setelah spasi diabaikan.
func ParseLines(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		// Ambil field pertama (banyak feed: "<ip> # komentar" atau "<ip>,<meta>").
		field := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' })
		if len(field) > 0 && field[0] != "" && field[0][0] != '#' {
			out = append(out, field[0])
		}
	}
	return out
}

// fetchTokens mengunduh & mem-parse semua URL; mengembalikan token gabungan + error per-URL.
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
	_, err := b.ReadFrom(http.MaxBytesReader(nil, resp.Body, 32<<20)) // batas 32 MiB
	return b.Bytes(), err
}

// Load mengunduh semua URL dan membangun Set. Error hanya bila TIDAK ada token sama
// sekali yang berhasil dimuat.
func Load(ctx context.Context, hc *http.Client, urls []string) (*Set, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	tokens, errs := fetchTokens(ctx, hc, urls)
	if len(tokens) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("blocklist: semua sumber gagal: %v", errs)
	}
	s := NewSet()
	s.Replace(tokens)
	return s, nil
}

// Refresh memuat ulang set tiap interval hingga ctx dibatalkan. Kegagalan di-log dan
// tidak mengosongkan set lama.
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
				log.Printf("blocklist: refresh gagal (set lama dipertahankan): %v", errs)
				continue
			}
			s.Replace(tokens)
			log.Printf("blocklist: refresh — %d entri", s.Len())
		}
	}
}
