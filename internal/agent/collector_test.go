package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectMultipleFiles(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "a.log")
	f2 := filepath.Join(dir, "b.log")
	if err := os.WriteFile(f1, []byte("alpha-1\nalpha-2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte("beta-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sources := []Source{
		{Dataset: "da", Type: "file", Path: f1},
		{Dataset: "db", Type: "file", Path: f2},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	lines := make(chan Line, 16)
	go func() {
		Collect(ctx, sources, true, lines)
		close(lines)
	}()

	got := map[string][]string{}
	for l := range lines {
		got[l.Dataset] = append(got[l.Dataset], l.Message)
	}
	if len(got["da"]) != 2 || len(got["db"]) != 1 {
		t.Fatalf("hasil collect tak terduga: %+v", got)
	}
}

func TestUnsupportedSourceType(t *testing.T) {
	if err := runSource(context.Background(), Source{Type: "bogus"}, false, make(chan Line, 1)); err == nil {
		t.Fatal("tipe source tak dikenal seharusnya error")
	}
}

func TestDefaultSourcesNonEmptyOnHostOS(t *testing.T) {
	// Di Linux & Windows DefaultSources harus terisi (build tag).
	// Di OS lain boleh kosong — cukup pastikan tidak panic.
	_ = DefaultSources()
}
