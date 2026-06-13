package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Buffer adalah store-and-forward berbasis disk (design doc bagian 13): batch yang
// gagal dikirim disimpan sebagai berkas dan dikirim ulang saat manager kembali online.
type Buffer struct {
	dir string
	max int // jumlah berkas maksimum; yang tertua dibuang bila melebihi
	mu  sync.Mutex
}

var bufSeq atomic.Uint64

// NewBuffer membuat buffer di dir (dibuat bila belum ada).
func NewBuffer(dir string, max int) (*Buffer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if max <= 0 {
		max = 1000
	}
	return &Buffer{dir: dir, max: max}, nil
}

// Save menulis satu batch (JSON mentah) ke buffer lalu memangkas bila melebihi max.
func (b *Buffer) Save(body []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	name := fmt.Sprintf("%020d-%06d.json", time.Now().UnixNano(), bufSeq.Add(1)%1000000)
	if err := os.WriteFile(filepath.Join(b.dir, name), body, 0o600); err != nil {
		return err
	}
	return b.prune()
}

// Pending mengembalikan path berkas buffer, tertua lebih dulu.
func (b *Buffer) Pending() ([]string, error) {
	entries, err := os.ReadDir(b.dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			files = append(files, filepath.Join(b.dir, e.Name()))
		}
	}
	sort.Strings(files) // prefix timestamp -> urut tertua dulu
	return files, nil
}

// Remove menghapus satu berkas buffer (setelah berhasil dikirim ulang).
func (b *Buffer) Remove(path string) error { return os.Remove(path) }

// prune membuang berkas tertua bila jumlah melebihi max. (dipanggil saat lock dipegang)
func (b *Buffer) prune() error {
	files, err := b.Pending()
	if err != nil || len(files) <= b.max {
		return err
	}
	for _, f := range files[:len(files)-b.max] {
		_ = os.Remove(f)
	}
	return nil
}
