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
