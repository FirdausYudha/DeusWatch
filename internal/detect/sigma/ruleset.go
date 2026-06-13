package sigma

import (
	"fmt"
	"os"
	"path/filepath"
)

// Ruleset adalah kumpulan rule Sigma yang sudah di-parse.
type Ruleset []*Rule

// ruleFiles mengumpulkan path *.yml / *.yaml di dir (rekursif). Direktori yang
// tidak ada menghasilkan daftar kosong (bukan error).
func ruleFiles(dir string) ([]string, error) {
	var files []string
	for _, pat := range []string{"*.yml", "*.yaml"} {
		matches, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			return nil, err
		}
		files = append(files, matches...)
		sub, err := filepath.Glob(filepath.Join(dir, "*", pat))
		if err != nil {
			return nil, err
		}
		files = append(files, sub...)
	}
	return files, nil
}

// LoadDir memuat rule Sigma SINGLE-EVENT dari dir (rekursif satu level) sebagai
// Ruleset. Berkas dengan kondisi agregasi ('|') dilewati di sini — muat lewat
// LoadAggDir. Direktori yang tidak ada menghasilkan Ruleset kosong (bukan error).
func LoadDir(dir string) (Ruleset, error) {
	files, err := ruleFiles(dir)
	if err != nil {
		return nil, err
	}
	var rs Ruleset
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("sigma: baca %s: %w", f, err)
		}
		if isAggregation(data) {
			continue // rule agregasi → jalur SQL (LoadAggDir)
		}
		r, err := ParseRule(data)
		if err != nil {
			return nil, fmt.Errorf("sigma: parse %s: %w", f, err)
		}
		rs = append(rs, r)
	}
	return rs, nil
}

// LoadAggDir memuat rule Sigma AGREGASI dari dir (rekursif satu level). Berkas
// single-event dilewati. Direktori yang tidak ada → daftar kosong (bukan error).
func LoadAggDir(dir string) ([]*AggRule, error) {
	files, err := ruleFiles(dir)
	if err != nil {
		return nil, err
	}
	var out []*AggRule
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("sigma: baca %s: %w", f, err)
		}
		if !isAggregation(data) {
			continue
		}
		r, err := ParseAggRule(data)
		if err != nil {
			return nil, fmt.Errorf("sigma: parse agregasi %s: %w", f, err)
		}
		out = append(out, r)
	}
	return out, nil
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
