//go:build !cgo
// +build !cgo

// Silent no-op scanner for CGO_ENABLED=0 builds (a dev machine without libyara installed can still
// `go build ./...`). Same API as the cgo file, so callers don't need build tags.
package yara

import "time"

type Match struct {
	Rule        string `json:"rule"`
	Namespace   string `json:"namespace"`
	Description string `json:"description"`
}

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

// LoadFromDir is a no-op in nocgo builds; returns (0, nil) so the operator's start-up log reads
// "yara: not compiled in (CGO=0)" instead of an error.
func (s *Scanner) LoadFromDir(_ string) (int, error) { return 0, nil }

func (s *Scanner) Scan(_ []byte) ([]Match, error) { return nil, nil }
func (s *Scanner) HasRules() bool                 { return false }
func (s *Scanner) Loaded() (int, time.Time)       { return 0, time.Time{} }
func (s *Scanner) Close() error                   { return nil }
