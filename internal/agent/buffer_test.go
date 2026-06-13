package agent

import (
	"os"
	"testing"
)

func TestBufferOrderAndRemove(t *testing.T) {
	b, err := NewBuffer(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range [][]byte{[]byte("a"), []byte("b"), []byte("c")} {
		if err := b.Save(p); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	files, err := b.Pending()
	if err != nil || len(files) != 3 {
		t.Fatalf("Pending = %d (err %v), mau 3", len(files), err)
	}
	// Tertua dulu -> isi pertama "a".
	if first, _ := os.ReadFile(files[0]); string(first) != "a" {
		t.Fatalf("urutan salah: %q", first)
	}
	if err := b.Remove(files[0]); err != nil {
		t.Fatal(err)
	}
	if files, _ = b.Pending(); len(files) != 2 {
		t.Fatalf("setelah Remove = %d, mau 2", len(files))
	}
}

func TestBufferPrune(t *testing.T) {
	b, _ := NewBuffer(t.TempDir(), 2)
	for _, p := range [][]byte{[]byte("1"), []byte("2"), []byte("3"), []byte("4")} {
		_ = b.Save(p)
	}
	files, _ := b.Pending()
	if len(files) != 2 {
		t.Fatalf("prune: %d berkas tersisa, mau 2", len(files))
	}
	// Yang tersisa adalah dua terbaru: "3","4".
	c0, _ := os.ReadFile(files[0])
	c1, _ := os.ReadFile(files[1])
	if string(c0) != "3" || string(c1) != "4" {
		t.Fatalf("prune membuang yang salah: %q,%q", c0, c1)
	}
}
