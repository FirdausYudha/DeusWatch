package agent

// The parts of registry integrity monitoring that are not Windows-specific: the comparison
// between two scans, and the path spelling.
//
// Deliberately NOT behind a //go:build windows tag. The registry API calls are platform bound,
// this logic is not, and a test behind that tag would never run in CI, which is Linux. The
// comparison is where a wrong answer is dangerous (announcing a whole hive as deleted, or
// announcing it as created on startup), so the comparison is the part that is tested.

import (
	"sort"
	"strings"
)

// registryValue is one value's identity for comparison purposes.
type registryValue struct {
	hash string // SHA-256 of the rendered value, so the diffing is the same shape as a file's
	text string // rendered value, kept so a change can show what it became
}

// diffRegistry reports what moved between two scans.
//
// An EMPTY baseline means this is the first scan and nothing is reported. That is not an
// optimisation, it is the contract: an agent that has just started knows nothing about what the
// registry looked like a minute ago, so announcing every watched value as newly created would
// bury a real change under thousands of events on every restart.
func diffRegistry(baseline, current map[string]registryValue) []FIMChange {
	if len(baseline) == 0 {
		return nil
	}
	changes := make([]FIMChange, 0, 8)
	for path, now := range current {
		was, existed := baseline[path]
		switch {
		case !existed:
			changes = append(changes, registryChange(path, "created", now))
		case was.hash != now.hash:
			c := registryChange(path, "modified", now)
			c.Diff = unifiedDiff(was.text, now.text)
			changes = append(changes, c)
		}
	}
	for path := range baseline {
		if _, still := current[path]; !still {
			changes = append(changes, FIMChange{Path: path, Kind: "registry", Action: "deleted"})
		}
	}
	// Deterministic order, so a burst of changes reads the same way twice and a test can assert on
	// it. Map iteration order would otherwise shuffle it.
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Path != changes[j].Path {
			return changes[i].Path < changes[j].Path
		}
		return changes[i].Action < changes[j].Action
	})
	return changes
}

func registryChange(path, action string, v registryValue) FIMChange {
	return FIMChange{
		Path:   path,
		Kind:   "registry",
		Action: action,
		SHA256: v.hash,
		Size:   int64(len(v.text)),
	}
}

// normalizeRegPath renders an operator's path back in one spelling, so the alert and the baseline
// key agree however it was typed: forward slashes become backslashes, the hive is upper-cased and
// stray separators are dropped.
func normalizeRegPath(p string) string {
	p = strings.Trim(strings.ReplaceAll(strings.TrimSpace(p), "/", `\`), `\`)
	hiveName, sub, found := strings.Cut(p, `\`)
	out := strings.ToUpper(hiveName)
	if found {
		out += `\` + sub
	}
	return out
}
