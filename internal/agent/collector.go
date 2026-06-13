package agent

import (
	"context"
	"fmt"
	"log"
	"sync"
)

// Line adalah satu baris log mentah dari sebuah source, beserta dataset-nya.
type Line struct {
	Dataset string
	Message string
}

// Source mendeskripsikan satu sumber log yang dikumpulkan agent.
//
// Type menentukan kolektor yang dipakai:
//   - "file"        : tail berkas (lintas-OS); Path = path berkas
//   - "journald"    : systemd journal (Linux saja); Path = unit (opsional)
//   - "wineventlog" : Windows Event Log (Windows saja); Path = nama channel
//   - "fim"         : File Integrity Monitoring (lintas-OS); Path = berkas/direktori
//                     (beberapa dipisah koma) — lihat fim.go
//
// Kolektor native dipilih saat KOMPILASI lewat build tag (lihat collect_*_*.go),
// sehingga tiap OS punya implementasi sendiri — mirip arsitektur agent Wazuh.
type Source struct {
	Dataset string `json:"dataset"`
	Type    string `json:"type"`
	Path    string `json:"path"`
}

// Collect menjalankan semua source secara konkuren, mengirim Line ke out hingga
// ctx dibatalkan. Source yang gagal dicatat tanpa menghentikan source lain.
func Collect(ctx context.Context, sources []Source, fromStart bool, out chan<- Line) {
	var wg sync.WaitGroup
	for _, src := range sources {
		wg.Add(1)
		go func(s Source) {
			defer wg.Done()
			if err := runSource(ctx, s, fromStart, out); err != nil && ctx.Err() == nil {
				log.Printf("agent: source %q (%s) berhenti: %v", s.Dataset, s.Type, err)
			}
		}(src)
	}
	wg.Wait()
}

func runSource(ctx context.Context, s Source, fromStart bool, out chan<- Line) error {
	switch s.Type {
	case "", "file":
		return followFileSource(ctx, s, fromStart, out)
	case "fim":
		return collectFIM(ctx, s, out)
	case "journald":
		return collectJournald(ctx, s, out) // impl per-OS (build tag)
	case "wineventlog":
		return collectWinEventLog(ctx, s, out) // impl per-OS (build tag)
	default:
		return fmt.Errorf("tipe source tidak didukung: %q", s.Type)
	}
}

func followFileSource(ctx context.Context, s Source, fromStart bool, out chan<- Line) error {
	lines := make(chan string, 128)
	go func() {
		_ = FollowFile(ctx, s.Path, fromStart, lines)
		close(lines)
	}()
	for l := range lines {
		select {
		case out <- Line{Dataset: s.Dataset, Message: l}:
		case <-ctx.Done():
			return nil
		}
	}
	return nil
}
