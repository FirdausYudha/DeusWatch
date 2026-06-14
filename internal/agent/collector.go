package agent

import (
	"context"
	"fmt"
	"log"
	"sync"
)

// Line is a single raw log line from a source, along with its dataset.
type Line struct {
	Dataset string
	Message string
}

// Source describes a single log source collected by the agent.
//
// Type selects the collector used:
//   - "file"        : file tail (cross-OS); Path = file path
//   - "journald"    : systemd journal (Linux only); Path = unit (optional)
//   - "wineventlog" : Windows Event Log (Windows only); Path = channel name
//   - "fim"         : File Integrity Monitoring (cross-OS); Path = file/directory
//                     (several comma-separated) — see fim.go
//
// The native collector is selected at COMPILE time via build tags (see collect_*_*.go),
// so each OS has its own implementation — similar to the Wazuh agent architecture.
type Source struct {
	Dataset string `json:"dataset"`
	Type    string `json:"type"`
	Path    string `json:"path"`
}

// Collect runs all sources concurrently, sending Lines to out until ctx is cancelled.
// A failing source is logged without stopping the others.
func Collect(ctx context.Context, sources []Source, fromStart bool, out chan<- Line) {
	var wg sync.WaitGroup
	for _, src := range sources {
		wg.Add(1)
		go func(s Source) {
			defer wg.Done()
			if err := runSource(ctx, s, fromStart, out); err != nil && ctx.Err() == nil {
				log.Printf("agent: source %q (%s) stopped: %v", s.Dataset, s.Type, err)
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
		return collectJournald(ctx, s, out) // per-OS impl (build tag)
	case "wineventlog":
		return collectWinEventLog(ctx, s, out) // per-OS impl (build tag)
	default:
		return fmt.Errorf("unsupported source type: %q", s.Type)
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
