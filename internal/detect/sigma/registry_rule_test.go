package sigma

import "testing"

// TestRegistryPersistenceRule loads the SHIPPED rule from disk and fires events at it.
//
// A detection rule that never matches is the worst kind of dead code: it looks like coverage on
// the rules page, it costs nothing to load, and nobody finds out until the incident it was
// supposed to catch. So this asserts on the real file rather than an inline copy, and checks both
// directions: the autorun key fires, and an ordinary monitored key does not.
func TestRegistryPersistenceRule(t *testing.T) {
	rs, err := LoadDir("../../../rules/sigma/windows")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	const ruleID = "6a1d4e92-7c3b-4f58-9a07-2b5e8c31d7f4"

	fires := func(event map[string]any) bool {
		for _, r := range rs.Match(event) {
			if r.ID == ruleID {
				return true
			}
		}
		return false
	}

	for _, tc := range []struct {
		name  string
		event map[string]any
		want  bool
	}{
		{
			name: "payload written to a Run key",
			event: map[string]any{
				"event.category": "registry",
				"event.action":   "registry_created",
				"file.path":      `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater`,
			},
			want: true,
		},
		{
			name: "Winlogon shell hijack",
			event: map[string]any{
				"event.category": "registry",
				"event.action":   "registry_modified",
				"file.path":      `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`,
			},
			want: true,
		},
		{
			name: "service ImagePath replaced",
			event: map[string]any{
				"event.category": "registry",
				"event.action":   "registry_modified",
				"file.path":      `HKLM\System\CurrentControlSet\Services\Spooler\ImagePath`,
			},
			want: true,
		},
		{
			// The category guard matters: a FILE named like a Run key must not fire a registry
			// persistence alert, or the rule becomes a path-substring match on the whole estate.
			name: "a file whose path merely looks like a Run key",
			event: map[string]any{
				"event.category": "file",
				"event.action":   "file_modified",
				"file.path":      `C:\backup\CurrentVersion\Run\notes.txt`,
			},
			want: false,
		},
		{
			name: "a monitored registry key that is not an autorun location",
			event: map[string]any{
				"event.category": "registry",
				"event.action":   "registry_modified",
				"file.path":      `HKLM\Software\Contoso\Settings\Theme`,
			},
			want: false,
		},
		{
			// Removing an autorun entry is what cleanup looks like, and the rule says so.
			name: "autorun entry deleted",
			event: map[string]any{
				"event.category": "registry",
				"event.action":   "registry_deleted",
				"file.path":      `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater`,
			},
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := fires(tc.event); got != tc.want {
				t.Fatalf("rule fired = %v, want %v", got, tc.want)
			}
		})
	}
}
