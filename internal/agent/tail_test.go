package agent

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func contains(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// TestFollowFileRotation is the regression test for the bug that silenced the Linux agent: after
// logrotate renames the file away and a fresh one takes its place, the tailer must follow the NEW
// file rather than sitting on the old inode forever.
func TestFollowFileRotation(t *testing.T) {
	// logrotate's default is rename+create while the writer holds the file open — a Linux
	// filesystem semantic. Windows refuses to rename a file with an open handle, so the scenario
	// this guards against cannot even be staged there. The agent's rotation handling targets Linux.
	if runtime.GOOS == "windows" {
		t.Skip("rename-with-open-handle is a POSIX semantic; not reproducible on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, []byte("line-before-rotate\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	lines := make(chan string, 64)
	var got []string
	done := make(chan struct{})
	go func() {
		for l := range lines {
			got = append(got, l)
		}
		close(done)
	}()
	go func() { _ = FollowFile(ctx, path, true, lines); close(lines) }()

	// Let the tailer read the initial line and reach EOF.
	time.Sleep(300 * time.Millisecond)

	// Simulate logrotate: move the current file aside and create a brand-new one in its place,
	// exactly as `logrotate` does by default (rename + create).
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	// Brief gap where the path does not exist — the tailer must tolerate this.
	time.Sleep(200 * time.Millisecond)
	if err := os.WriteFile(path, []byte("line-after-rotate\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Give the tailer time to notice the rotation and read the new file.
	time.Sleep(1200 * time.Millisecond)
	cancel()
	<-done

	if !contains(got, "line-before-rotate") {
		t.Fatalf("missing pre-rotation line; got %v", got)
	}
	if !contains(got, "line-after-rotate") {
		t.Fatalf("tailer did not follow the rotated file — this is the production bug; got %v", got)
	}
}

// TestFollowFileTruncation covers copytruncate-style rotation: same inode, contents reset to empty.
// The tailer must re-read from the top rather than waiting for the file to grow back past the old
// offset (which would silently drop everything until it did).
func TestFollowFileTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, []byte("first-generation-line\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	lines := make(chan string, 64)
	var got []string
	done := make(chan struct{})
	go func() {
		for l := range lines {
			got = append(got, l)
		}
		close(done)
	}()
	go func() { _ = FollowFile(ctx, path, true, lines); close(lines) }()

	time.Sleep(300 * time.Millisecond)

	// copytruncate: truncate in place, then write a shorter line so the size is below our offset.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if err := os.WriteFile(path, []byte("post-truncate-line\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	time.Sleep(1200 * time.Millisecond)
	cancel()
	<-done

	if !contains(got, "post-truncate-line") {
		t.Fatalf("tailer did not re-read after truncation; got %v", got)
	}
}

// TestFollowFileWaitsForMissing proves a source whose file does not exist yet stays alive and picks
// the file up when it appears, instead of dying on the initial open (which killed the source until
// an agent restart).
func TestFollowFileWaitsForMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-yet.log")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	lines := make(chan string, 16)
	var got []string
	done := make(chan struct{})
	go func() {
		for l := range lines {
			got = append(got, l)
		}
		close(done)
	}()
	// fromStart=false: even seeking to "end", a file created later must be read from its start
	// because there was no end to seek to when we began waiting.
	go func() { _ = FollowFile(ctx, path, false, lines); close(lines) }()

	// The file only shows up after the tailer has already started waiting.
	time.Sleep(600 * time.Millisecond)
	if err := os.WriteFile(path, []byte("arrived-late\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	time.Sleep(1000 * time.Millisecond)
	cancel()
	<-done

	if !contains(got, "arrived-late") {
		t.Fatalf("tailer did not pick up a file that appeared after start; got %v", got)
	}
}

// TestFollowFileTailsFromEnd guards the default (fromStart=false): pre-existing content is NOT
// replayed, only lines written after the tailer attaches.
func TestFollowFileTailsFromEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "live.log")
	if err := os.WriteFile(path, []byte("old-line-should-be-skipped\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	lines := make(chan string, 16)
	var got []string
	done := make(chan struct{})
	go func() {
		for l := range lines {
			got = append(got, l)
		}
		close(done)
	}()
	go func() { _ = FollowFile(ctx, path, false, lines); close(lines) }()

	time.Sleep(300 * time.Millisecond)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("new-line-should-appear\n")
	f.Close()

	time.Sleep(800 * time.Millisecond)
	cancel()
	<-done

	if contains(got, "old-line-should-be-skipped") {
		t.Fatalf("tailing from end must not replay pre-existing content; got %v", got)
	}
	if !contains(got, "new-line-should-appear") {
		t.Fatalf("appended line not delivered; got %v", got)
	}
}
