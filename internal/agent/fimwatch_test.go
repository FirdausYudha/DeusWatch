package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// waitTrigger reports whether the watcher signalled within the timeout.
func waitTrigger(trigger <-chan struct{}, timeout time.Duration) bool {
	select {
	case <-trigger:
		return true
	case <-time.After(timeout):
		return false
	}
}

func TestFIMWatcherFiresOnFileChange(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	trigger := make(chan struct{}, 1)
	closeW, err := startFIMWatcher(ctx, []string{dir}, 30*time.Millisecond, trigger)
	if err != nil {
		t.Fatalf("start watcher: %v", err)
	}
	defer closeW()

	if err := os.WriteFile(filepath.Join(dir, "index.php"), []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !waitTrigger(trigger, 3*time.Second) {
		t.Fatal("watcher did not fire on a new file within 3s")
	}

	// A modification also fires.
	if err := os.WriteFile(filepath.Join(dir, "index.php"), []byte("<?php /* hacked */"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !waitTrigger(trigger, 3*time.Second) {
		t.Fatal("watcher did not fire on a modification within 3s")
	}
}

func TestFIMWatcherWatchesNewSubdir(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	trigger := make(chan struct{}, 1)
	closeW, err := startFIMWatcher(ctx, []string{dir}, 30*time.Millisecond, trigger)
	if err != nil {
		t.Fatalf("start watcher: %v", err)
	}
	defer closeW()

	// Create a sub-directory (fires + is added to the watch), then a file inside it.
	sub := filepath.Join(dir, "uploads")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	waitTrigger(trigger, 2*time.Second) // drain the mkdir event
	// Give the watcher a beat to add the new subdir before writing inside it.
	time.Sleep(150 * time.Millisecond)

	if err := os.WriteFile(filepath.Join(sub, "shell.php"), []byte("evil"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !waitTrigger(trigger, 3*time.Second) {
		t.Fatal("watcher did not fire for a file in a newly-created subdir within 3s")
	}
}
