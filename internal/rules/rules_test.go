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
	seenCategory := map[string]bool{}
	for _, f := range files {
		seenCategory[f.category] = true
		data, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatalf("read %s: %v", f.path, err)
		}
		kind, err := sigma.Classify(data)
		if err != nil {
			t.Errorf("%s does not classify: %v", filepath.Base(f.path), err)
			continue
		}
		if kind != sigma.KindSingle && kind != sigma.KindAggregation {
			t.Errorf("%s: unexpected kind %q", filepath.Base(f.path), kind)
		}
	}
	// The generator ships category subfolders — make sure gather tags them.
	for _, want := range []string{"judi", "endpoint", "general"} {
		if !seenCategory[want] {
			t.Errorf("expected to find rules in category %q", want)
		}
	}
	t.Logf("classified %d bundled rules across %d categories", len(files), len(seenCategory))
}

func TestTitleOf(t *testing.T) {
	if got := titleOf("title: My Rule\nlevel: low\n", "fallback"); got != "My Rule" {
		t.Fatalf("titleOf = %q, want %q", got, "My Rule")
	}
	if got := titleOf("no title here", "fallback.yml"); got != "fallback.yml" {
		t.Fatalf("titleOf fallback = %q", got)
	}
}
