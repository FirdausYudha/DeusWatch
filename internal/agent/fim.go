package agent

// File Integrity Monitoring (FIM) — design doc roadmap agent.
//
// Source bertipe "fim" memantau berkas/direktori: tiap interval di-hash (SHA-256)
// dan dibandingkan dengan baseline. Perubahan (dibuat/diubah/dihapus) di-emit
// sebagai Line dataset "fim" dengan payload JSON, lalu dinormalkan gateway menjadi
// Event DCS dengan field file.* (lihat ingest.normalizeFIM). Pendekatan ini menumpang
// pipeline RawLog yang sudah ada alih-alih jalur biner terpisah.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// fimScanInterval default antar-pemindaian FIM.
const fimScanInterval = 60 * time.Second

// maxHashBytes membatasi ukuran berkas yang di-hash (berkas raksasa di-skip dari hash,
// hanya metadata yang dilacak) agar pemindaian tidak membebani I/O.
const maxHashBytes = 64 << 20 // 64 MiB

// FIMChange adalah satu perubahan integritas berkas (payload JSON dataset "fim").
type FIMChange struct {
	Path   string `json:"path"`
	Action string `json:"action"` // created | modified | deleted
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size,omitempty"`
	Mode   string `json:"mode,omitempty"`
}

type fileState struct {
	sha256 string
	size   int64
	mode   string
}

// FIMScanner melacak baseline integritas untuk sekumpulan root (berkas/direktori)
// dan menghitung perubahan tiap kali Scan dipanggil.
type FIMScanner struct {
	roots    []string
	baseline map[string]fileState
	primed   bool
}

// NewFIMScanner membuat scanner untuk root yang diberikan (berkas atau direktori).
func NewFIMScanner(roots ...string) *FIMScanner {
	return &FIMScanner{roots: roots, baseline: map[string]fileState{}}
}

// splitFIMPaths memecah Path source FIM menjadi daftar root (pemisah koma).
func splitFIMPaths(path string) []string {
	var out []string
	for _, p := range strings.Split(path, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Scan memindai semua root dan mengembalikan perubahan sejak Scan sebelumnya.
// Pemanggilan PERTAMA hanya membangun baseline (mengembalikan nil) agar berkas yang
// sudah ada tidak salah dilaporkan sebagai "created".
func (s *FIMScanner) Scan() ([]FIMChange, error) {
	current := map[string]fileState{}
	for _, root := range s.roots {
		if err := s.walk(root, current); err != nil {
			return nil, err
		}
	}

	if !s.primed {
		s.baseline = current
		s.primed = true
		return nil, nil
	}

	var changes []FIMChange
	for path, cur := range current {
		prev, ok := s.baseline[path]
		switch {
		case !ok:
			changes = append(changes, change(path, "created", cur))
		case prev.sha256 != cur.sha256 || prev.size != cur.size || prev.mode != cur.mode:
			changes = append(changes, change(path, "modified", cur))
		}
	}
	for path, prev := range s.baseline {
		if _, ok := current[path]; !ok {
			changes = append(changes, change(path, "deleted", prev))
		}
	}
	s.baseline = current
	return changes, nil
}

func change(path, action string, st fileState) FIMChange {
	c := FIMChange{Path: path, Action: action, Size: st.size, Mode: st.mode}
	if action != "deleted" {
		c.SHA256 = st.sha256
	}
	return c
}

// walk mengisi dst dengan state tiap berkas reguler di bawah root (berkas tunggal
// juga didukung). Berkas yang tak terbaca dilewati dengan log, tidak menggagalkan scan.
func (s *FIMScanner) walk(root string, dst map[string]fileState) error {
	info, err := os.Lstat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // root belum ada — perubahan terdeteksi saat dibuat nanti
		}
		return err
	}
	if !info.IsDir() {
		if info.Mode().IsRegular() {
			if st, ok := stateOf(root, info); ok {
				dst[root] = st
			}
		}
		return nil
	}
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Printf("agent: fim: lewati %s: %v", p, err)
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		if st, ok := stateOf(p, fi); ok {
			dst[p] = st
		}
		return nil
	})
}

func stateOf(path string, info os.FileInfo) (fileState, bool) {
	st := fileState{size: info.Size(), mode: info.Mode().Perm().String()}
	if info.Size() <= maxHashBytes {
		if h, err := hashFile(path); err == nil {
			st.sha256 = h
		} else {
			log.Printf("agent: fim: hash %s gagal: %v", path, err)
			return fileState{}, false
		}
	}
	return st, true
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// collectFIM menjalankan pemindaian FIM periodik untuk satu source, meng-emit Line
// dataset source untuk tiap perubahan hingga ctx dibatalkan.
func collectFIM(ctx context.Context, s Source, out chan<- Line) error {
	roots := splitFIMPaths(s.Path)
	if len(roots) == 0 {
		return fmt.Errorf("source fim %q: Path kosong", s.Dataset)
	}
	scanner := NewFIMScanner(roots...)
	if _, err := scanner.Scan(); err != nil { // bangun baseline awal
		log.Printf("agent: fim %q: scan baseline: %v", s.Dataset, err)
	}

	t := time.NewTicker(fimScanInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			changes, err := scanner.Scan()
			if err != nil {
				log.Printf("agent: fim %q: scan: %v", s.Dataset, err)
				continue
			}
			for _, c := range changes {
				body, err := json.Marshal(c)
				if err != nil {
					continue
				}
				select {
				case out <- Line{Dataset: s.Dataset, Message: string(body)}:
				case <-ctx.Done():
					return nil
				}
			}
		}
	}
}
