package sigma

import (
	"fmt"
	"os"
	"path/filepath"
)

// Ruleset adalah kumpulan rule Sigma yang sudah di-parse.
type Ruleset []*Rule

// LoadDir memuat semua berkas *.yml / *.yaml dari dir sebagai Ruleset.
// Direktori yang tidak ada menghasilkan Ruleset kosong (bukan error).
func LoadDir(dir string) (Ruleset, error) {
	var files []string
	for _, pat := range []string{"*.yml", "*.yaml"} {
		matches, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			return nil, err
		}
		files = append(files, matches...)
	}

	var rs Ruleset
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("sigma: baca %s: %w", f, err)
		}
		r, err := ParseRule(data)
		if err != nil {
			return nil, fmt.Errorf("sigma: parse %s: %w", f, err)
		}
		rs = append(rs, r)
	}
	return rs, nil
}

// Match mengembalikan rule yang cocok dengan event (event sudah diratakan).
func (rs Ruleset) Match(event map[string]any) []*Rule {
	var hits []*Rule
	for _, r := range rs {
		if ok, err := r.Matches(event); err == nil && ok {
			hits = append(hits, r)
		}
	}
	return hits
}
