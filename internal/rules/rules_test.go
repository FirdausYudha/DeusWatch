package rules

import (
	"os"
	"path/filepath"
	"testing"

	"deuswatch/internal/detect/sigma"
)

// TestBundledRulesClassify ensures every shipped rule file parses & classifies, so the
// first-run seed never silently drops a rule because of a typo.
func TestBundledRulesClassify(t *testing.T) {
	files := gather(filepath.Join("..", "..", "rules", "sigma"))
	if len(files) < 5 {
		t.Fatalf("expected several bundled rules, found %d", len(files))
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		kind, err := sigma.Classify(data)
		if err != nil {
			t.Errorf("%s does not classify: %v", filepath.Base(f), err)
			continue
		}
		if kind != sigma.KindSingle && kind != sigma.KindAggregation {
			t.Errorf("%s: unexpected kind %q", filepath.Base(f), kind)
		}
	}
	t.Logf("classified %d bundled rules", len(files))
}

func TestTitleOf(t *testing.T) {
	if got := titleOf("title: My Rule\nlevel: low\n", "fallback"); got != "My Rule" {
		t.Fatalf("titleOf = %q, want %q", got, "My Rule")
	}
	if got := titleOf("no title here", "fallback.yml"); got != "fallback.yml" {
		t.Fatalf("titleOf fallback = %q", got)
	}
}
