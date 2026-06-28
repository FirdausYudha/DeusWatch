package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemediateFile(t *testing.T) {
	tmp := t.TempDir()
	qdir := filepath.Join(tmp, "q")

	write := func(name, content string) string {
		p := filepath.Join(tmp, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// quarantine: matching hash -> moved out of place, original gone.
	bad := write("evil.sh", "malware")
	h, err := fileSHA256(bad)
	if err != nil {
		t.Fatal(err)
	}
	acted, err := RemediateFile(bad, h, "quarantine", qdir)
	if err != nil || !acted {
		t.Fatalf("quarantine should act: acted=%v err=%v", acted, err)
	}
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatal("original file should be gone after quarantine")
	}
	entries, _ := os.ReadDir(qdir)
	if len(entries) != 1 {
		t.Fatalf("expected 1 quarantined file, got %d", len(entries))
	}

	// hash mismatch -> never touched.
	keep := write("keep.sh", "clean")
	acted, err = RemediateFile(keep, "0000000000000000000000000000000000000000000000000000000000000000", "delete", qdir)
	if err != nil || acted {
		t.Fatalf("mismatched hash must be a no-op: acted=%v err=%v", acted, err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("a hash-mismatched file must not be touched")
	}

	// delete: matching hash -> removed.
	del := write("drop.bin", "evil2")
	dh, _ := fileSHA256(del)
	acted, err = RemediateFile(del, dh, "delete", qdir)
	if err != nil || !acted {
		t.Fatalf("delete should act: acted=%v err=%v", acted, err)
	}
	if _, err := os.Stat(del); !os.IsNotExist(err) {
		t.Fatal("file should be deleted")
	}

	// missing file -> safe no-op.
	if acted, err := RemediateFile(filepath.Join(tmp, "nope"), dh, "delete", qdir); err != nil || acted {
		t.Fatalf("missing file must be a no-op: acted=%v err=%v", acted, err)
	}
}
