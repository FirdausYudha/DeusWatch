package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnifiedDiff(t *testing.T) {
	if unifiedDiff("same\ntext", "same\ntext") != "" {
		t.Fatal("identical text must produce no diff")
	}
	// A defacement: index.php line replaced.
	old := "<?php\ninclude 'header.php';\necho 'Welcome';\n"
	neu := "<?php\ninclude 'header.php';\necho 'HACKED BY X';\nsystem($_GET['c']);\n"
	d := unifiedDiff(old, neu)
	if !strings.Contains(d, "- echo 'Welcome';") {
		t.Fatalf("diff must show the removed line:\n%s", d)
	}
	if !strings.Contains(d, "+ echo 'HACKED BY X';") || !strings.Contains(d, "+ system($_GET['c']);") {
		t.Fatalf("diff must show the added malicious lines:\n%s", d)
	}
}

func TestUnifiedDiffLargeFileSummary(t *testing.T) {
	// Two large files (line counts whose product exceeds maxDiffCells) must NOT run the O(m*n)
	// LCS — they get the cheap added/removed summary instead.
	var oldB, newB strings.Builder
	for i := 0; i < 2000; i++ {
		oldB.WriteString("original config line\n")
	}
	for i := 0; i < 2100; i++ {
		newB.WriteString("changed config line\n")
	}
	d := unifiedDiff(oldB.String(), newB.String())
	if !strings.Contains(d, "large file") || !strings.Contains(d, "full diff omitted") {
		t.Fatalf("large file should get the summary, got:\n%s", d)
	}
	if strings.Contains(d, "\n- ") || strings.Contains(d, "\n+ ") {
		t.Fatalf("summary must not contain per-line diff output:\n%s", d)
	}
}

func TestShannonEntropy(t *testing.T) {
	if e := shannonEntropy([]byte("aaaaaaaaaaaaaaaa")); e > 0.01 {
		t.Fatalf("single-symbol entropy should be ~0, got %f", e)
	}
	if e := shannonEntropy([]byte("the quick brown fox jumps over the lazy dog")); e < 3 || e > 5.5 {
		t.Fatalf("english text entropy ~4, got %f", e)
	}
	all := make([]byte, 256) // every byte value once → maximum entropy 8.0
	for i := range all {
		all[i] = byte(i)
	}
	if e := shannonEntropy(all); e < 7.99 {
		t.Fatalf("uniform 256-value entropy should be 8.0, got %f", e)
	}
}

func TestScannerFlagsEncryption(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "config.php")
	if err := os.WriteFile(f, []byte("<?php $db='localhost'; // config\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sc := NewFIMScanner(dir)
	if _, err := sc.Scan(); err != nil { // baseline
		t.Fatal(err)
	}
	// Overwrite with high-entropy, non-text content (a text file "encrypted" in place).
	enc := make([]byte, 4096)
	for i := range enc {
		enc[i] = byte((i*7 + 13) % 256)
	}
	if err := os.WriteFile(f, enc, 0o644); err != nil {
		t.Fatal(err)
	}
	changes, err := sc.Scan()
	if err != nil || len(changes) != 1 {
		t.Fatalf("want 1 change, got %d err=%v", len(changes), err)
	}
	if changes[0].Action != "encrypted" {
		t.Fatalf("text->random should flag encrypted, got %q (entropy %f)", changes[0].Action, changes[0].Entropy)
	}
	if changes[0].Entropy < 7.0 {
		t.Fatalf("encrypted content entropy should be high, got %f", changes[0].Entropy)
	}
}

func TestParseSizeEnv(t *testing.T) {
	const key = "DW_TEST_SIZE"
	cases := []struct {
		val  string
		want int64
	}{
		{"", 2 << 20},          // unset → default
		{"4M", 4 << 20},        // 4 MiB
		{"2MiB", 2 << 20},      // MiB suffix
		{"512K", 512 << 10},    // 512 KiB
		{"1048576", 1 << 20},   // plain bytes
		{"bogus", 2 << 20},     // invalid → default
		{"0", 2 << 20},         // non-positive → default
	}
	for _, c := range cases {
		if c.val == "" {
			os.Unsetenv(key)
		} else {
			t.Setenv(key, c.val)
		}
		if got := parseSizeEnv(key, 2<<20); got != c.want {
			t.Fatalf("parseSizeEnv(%q) = %d, want %d", c.val, got, c.want)
		}
	}
}

func TestUnifiedDiffTruncates(t *testing.T) {
	var oldB, newB strings.Builder
	for i := 0; i < maxDiffLines+50; i++ {
		newB.WriteString("added line\n")
	}
	d := unifiedDiff(oldB.String(), newB.String())
	if !strings.Contains(d, "truncated") {
		t.Fatal("a huge diff must be truncated")
	}
}

func TestScannerEmitsDiffOnModify(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "index.php")
	if err := os.WriteFile(f, []byte("<?php echo 'ok';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sc := NewFIMScanner(dir)
	if _, err := sc.Scan(); err != nil { // baseline
		t.Fatal(err)
	}
	// Modify the file (a defacement).
	if err := os.WriteFile(f, []byte("<?php echo 'PWNED';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changes, err := sc.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Action != "modified" {
		t.Fatalf("want one modified change, got %+v", changes)
	}
	if !strings.Contains(changes[0].Diff, "+ <?php echo 'PWNED';") {
		t.Fatalf("modified change must carry the diff, got %q", changes[0].Diff)
	}
}

func TestScannerNoDiffForBinary(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "blob.bin")
	if err := os.WriteFile(f, []byte{0x00, 0x01, 0x02, 0x00}, 0o644); err != nil {
		t.Fatal(err)
	}
	sc := NewFIMScanner(dir)
	sc.Scan()
	os.WriteFile(f, []byte{0x00, 0x09, 0x09, 0x00}, 0o644)
	changes, _ := sc.Scan()
	if len(changes) != 1 {
		t.Fatalf("want one change, got %d", len(changes))
	}
	if changes[0].Diff != "" {
		t.Fatal("binary file changes must not carry a text diff")
	}
}
