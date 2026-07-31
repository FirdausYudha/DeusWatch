//go:build !cgo
// +build !cgo

package yara

import "testing"

// TestNocgoStubIsSilent guarantees the CGO_ENABLED=0 build (dev boxes without libyara, the
// api/worker/certgen static images) leaves YARA cleanly idle: LoadFromDir returns (0, nil), Scan
// returns nil, HasRules is false. If this test ever fails, a caller might be crashing on a nil
// pointer instead of the intended silent no-op.
func TestNocgoStubIsSilent(t *testing.T) {
	s := New()
	defer s.Close()
	n, err := s.LoadFromDir("anywhere")
	if n != 0 || err != nil {
		t.Fatalf("LoadFromDir(nocgo): got n=%d err=%v, want 0/nil", n, err)
	}
	if s.HasRules() {
		t.Fatalf("HasRules(nocgo) should be false")
	}
	m, err := s.Scan([]byte("payload"))
	if m != nil || err != nil {
		t.Fatalf("Scan(nocgo): got m=%v err=%v, want nil/nil", m, err)
	}
}
