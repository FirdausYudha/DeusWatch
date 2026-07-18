package archive

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

func readZst(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	d, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	out, err := d.DecodeAll(raw, nil) // handles concatenated frames
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return string(out)
}

func TestArchiveWriteAndAppend(t *testing.T) {
	dir := t.TempDir()
	a, err := New(dir, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	day := time.Date(2026, 7, 17, 10, 0, 0, 0, time.Local)

	a.Add("opnsense-a", "modsecurity", "line one", day)
	a.Add("opnsense-a", "modsecurity", "line two\n", day) // trailing newline preserved once
	a.Flush()

	path := filepath.Join(dir, "opnsense-a", "modsecurity", "2026-07-17.log.zst")
	if got := readZst(t, path); got != "line one\nline two\n" {
		t.Fatalf("after first flush: %q", got)
	}

	// A second flush appends another frame; the reader must see BOTH frames concatenated.
	a.Add("opnsense-a", "modsecurity", "line three", day)
	a.Flush()
	if got := readZst(t, path); got != "line one\nline two\nline three\n" {
		t.Fatalf("after append: %q", got)
	}
}

func TestArchivePathSafety(t *testing.T) {
	dir := t.TempDir()
	a, _ := New(dir, time.Hour, 0)
	// A malicious source/dataset must not escape the archive dir.
	a.Add("../../etc", "a/b/../../x", "evil", time.Now())
	a.Flush()
	// Nothing should exist outside dir; the segment is sanitized to stay inside.
	escaped := filepath.Join(filepath.Dir(dir), "etc")
	if _, err := os.Stat(escaped); err == nil {
		t.Fatal("path traversal escaped the archive dir")
	}
}

func TestSafeSeg(t *testing.T) {
	cases := map[string]string{
		"wazuh-agent/web01": "wazuh-agent_web01",
		"../../etc":         "etc",
		"":                  "fallback",
		"   ":               "fallback",
		"opnsense_cabang1":  "opnsense_cabang1",
	}
	for in, want := range cases {
		if got := safeSeg(in, "fallback"); got != want {
			t.Errorf("safeSeg(%q) = %q, want %q", in, got, want)
		}
	}
}
