package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func policy(id string) *SCAPolicy {
	p := &SCAPolicy{}
	p.Policy.ID = id
	return p
}

// TestMergePoliciesLocalWins pins the one piece of authority the endpoint administrator keeps.
// Central management is the default and the convenient path; dropping a file in the local
// directory still overrides what the console serves, without having to argue with whoever runs
// it. A policy's rules execute as root, so this is not a preference.
func TestMergePoliciesLocalWins(t *testing.T) {
	local := []*SCAPolicy{policy("cis_debian10"), policy("local_only")}
	managed := []*SCAPolicy{policy("cis_debian10"), policy("cis_win2019")}

	got := mergePolicies(local, managed)
	if len(got) != 3 {
		t.Fatalf("got %d policies, want 3 (two local, one managed that does not collide)", len(got))
	}
	// The colliding id must come from the local slice, which is the first one here by identity.
	if got[0] != local[0] {
		t.Error("the managed policy overrode the local one of the same id")
	}
	ids := map[string]bool{}
	for _, p := range got {
		if ids[p.Policy.ID] {
			t.Fatalf("policy %s appears twice; it would be assessed and scored twice", p.Policy.ID)
		}
		ids[p.Policy.ID] = true
	}
	for _, want := range []string{"cis_debian10", "local_only", "cis_win2019"} {
		if !ids[want] {
			t.Errorf("%s is missing from the merge", want)
		}
	}
}

func TestMergePoliciesEdgeCases(t *testing.T) {
	if got := mergePolicies(nil, nil); len(got) != 0 {
		t.Errorf("merging nothing produced %d policies", len(got))
	}
	// A policy with no id cannot be addressed, scored or overridden, so it is dropped rather than
	// assessed under an empty name.
	if got := mergePolicies([]*SCAPolicy{policy("")}, []*SCAPolicy{policy("")}); len(got) != 0 {
		t.Errorf("a policy with no id was kept: %+v", got)
	}
	if got := mergePolicies(nil, []*SCAPolicy{policy("a")}); len(got) != 1 {
		t.Errorf("managed-only merge produced %d policies, want 1", len(got))
	}
}

// TestSafePolicyFilename is a security check, not a tidiness one. The policy id arrives from the
// manager, so it is attacker-controlled exactly in the scenario this whole feature was argued
// about, and joining it into a path unchecked writes root-owned files anywhere on the host.
func TestSafePolicyFilename(t *testing.T) {
	for _, bad := range []string{
		"", "..", "../../etc/cron.d/evil", "..\\..\\windows\\system32\\x",
		"/etc/passwd", "a/b", `a\b`, "with space", "semi;colon", "dollar$sign",
		"pipe|char", "new\nline", "null\x00byte", "quote'", strings.Repeat("a", 121),
	} {
		if got := safePolicyFilename(bad); got != "" {
			t.Errorf("safePolicyFilename(%q) = %q, want it refused", bad, got)
		}
	}
	for in, want := range map[string]string{
		"cis_debian10":           "cis_debian10.yml",
		"cis_win2019":            "cis_win2019.yml",
		"CIS-RHEL9":              "CIS-RHEL9.yml",
		"policy.v2":              "policy.v2.yml",
		strings.Repeat("a", 120): strings.Repeat("a", 120) + ".yml",
	} {
		if got := safePolicyFilename(in); got != want {
			t.Errorf("safePolicyFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestWriteCachedPoliciesReplaces: the cache is replaced wholesale, so a policy the operator
// disabled or deleted stops being assessed. Keeping it file-by-file would leave an agent that
// later lost its connection still measuring against a benchmark that had been withdrawn.
func TestWriteCachedPoliciesReplaces(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SCA_POLICY_DIR", dir)

	writeCachedPolicies([]PushedPolicy{
		{PolicyID: "one", YAML: "policy:\n  id: one\nchecks:\n  - id: 1\n    rules: ['f:/x']\n"},
		{PolicyID: "two", YAML: "policy:\n  id: two\nchecks:\n  - id: 1\n    rules: ['f:/x']\n"},
	})
	if n := len(cachedNames(t)); n != 2 {
		t.Fatalf("cached %d policies, want 2", n)
	}

	// The operator disables "two": the next fetch serves only "one".
	writeCachedPolicies([]PushedPolicy{
		{PolicyID: "one", YAML: "policy:\n  id: one\nchecks:\n  - id: 1\n    rules: ['f:/x']\n"},
	})
	names := cachedNames(t)
	if len(names) != 1 || names[0] != "one.yml" {
		t.Fatalf("cache holds %v, want just one.yml; a withdrawn policy is still being assessed", names)
	}

	// And the cache is readable back as policies, which is the fallback path when the manager is
	// unreachable.
	got := readCachedPolicies()
	if len(got) != 1 || got[0].Policy.ID != "one" {
		t.Fatalf("readCachedPolicies = %+v, want the one cached policy", got)
	}
}

// TestWriteCachedPoliciesRefusesTraversal: a malicious policy id must not escape the cache
// directory, and must not stop the other policies from being cached either.
func TestWriteCachedPoliciesRefusesTraversal(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SCA_POLICY_DIR", dir)

	writeCachedPolicies([]PushedPolicy{
		{PolicyID: "../../evil", YAML: "policy:\n  id: evil\n"},
		{PolicyID: "good", YAML: "policy:\n  id: good\nchecks:\n  - id: 1\n    rules: ['f:/x']\n"},
	})
	names := cachedNames(t)
	if len(names) != 1 || names[0] != "good.yml" {
		t.Fatalf("cache holds %v, want just good.yml", names)
	}
	// Nothing was written outside the cache directory.
	if _, err := os.Stat(filepath.Join(dir, "..", "evil.yml")); err == nil {
		t.Fatal("a policy id escaped the cache directory")
	}
}

// TestPushedAllowed: the opt-out has to be explicit and default to on, or a host that was never
// configured would silently stop following the console.
func TestPushedAllowed(t *testing.T) {
	t.Setenv("SCA_ALLOW_PUSHED", "")
	if !pushedAllowed() {
		t.Error("pushed policies are off by default")
	}
	t.Setenv("SCA_ALLOW_PUSHED", "1")
	if !pushedAllowed() {
		t.Error("SCA_ALLOW_PUSHED=1 did not allow pushed policies")
	}
	t.Setenv("SCA_ALLOW_PUSHED", "0")
	if pushedAllowed() {
		t.Error("SCA_ALLOW_PUSHED=0 did not refuse pushed policies")
	}
}

func cachedNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(cacheDir())
	if err != nil {
		t.Fatalf("read cache dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}
