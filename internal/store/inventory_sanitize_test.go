package store

import "testing"

// A NUL byte in a lockfile-named binary file previously failed the whole manifest COPY batch
// (SQLSTATE 22021), silently wiping SCA for the agent. Sanitizing must keep the rest intact.
func TestSanitizeText(t *testing.T) {
	if got := sanitizeText("clean text"); got != "clean text" {
		t.Errorf("clean input must pass through unchanged, got %q", got)
	}
	if got := sanitizeText("a\x00b"); got != "ab" {
		t.Errorf("NUL must be stripped, got %q", got)
	}
	if got := sanitizeText("a\xffb"); got != "ab" {
		t.Errorf("invalid UTF-8 must be stripped, got %q", got)
	}
}
