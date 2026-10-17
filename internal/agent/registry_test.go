package agent

import "testing"

func rv(text string) registryValue {
	return registryValue{hash: hashBytes([]byte(text)), text: text}
}

// TestDiffRegistryFirstScanIsSilent pins the baseline contract. An agent that has just started
// knows nothing about what the registry looked like a minute ago, so reporting every watched
// value as newly created would bury a real change under thousands of events on every restart,
// and a service that restarts on failure restarts often.
func TestDiffRegistryFirstScanIsSilent(t *testing.T) {
	current := map[string]registryValue{
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive`: rv("C:\\Users\\a\\OneDrive.exe"),
		`HKLM\Software\Contoso\Settings\Theme`:                        rv("dark"),
	}
	if got := diffRegistry(nil, current); len(got) != 0 {
		t.Fatalf("first scan reported %d changes, want none: %+v", len(got), got)
	}
	if got := diffRegistry(map[string]registryValue{}, current); len(got) != 0 {
		t.Fatalf("empty baseline reported %d changes, want none", len(got))
	}
}

func TestDiffRegistryDetectsEachKind(t *testing.T) {
	const runKey = `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater`
	const stable = `HKLM\Software\Contoso\Settings\Theme`
	const gone = `HKLM\Software\Contoso\Settings\Legacy`

	baseline := map[string]registryValue{
		stable: rv("dark"),
		gone:   rv("1"),
	}
	current := map[string]registryValue{
		stable: rv("dark"),
		runKey: rv(`C:\Users\Public\svchost.exe`),
	}

	got := diffRegistry(baseline, current)
	if len(got) != 2 {
		t.Fatalf("got %d changes, want 2: %+v", len(got), got)
	}
	// Sorted by path, so the assertions can be positional.
	if got[0].Path != gone || got[0].Action != "deleted" {
		t.Errorf("first change = %s %s, want %s deleted", got[0].Path, got[0].Action, gone)
	}
	if got[1].Path != runKey || got[1].Action != "created" {
		t.Errorf("second change = %s %s, want %s created", got[1].Path, got[1].Action, runKey)
	}
	for _, c := range got {
		if c.Kind != "registry" {
			t.Errorf("%s reported Kind=%q; without it the normalizer calls a registry value a file", c.Path, c.Kind)
		}
	}
	// A value present and unchanged in both scans must produce nothing, or every scan alerts on
	// the whole watched tree.
	for _, c := range got {
		if c.Path == stable {
			t.Errorf("an unchanged value was reported as %q", c.Action)
		}
	}
}

// TestDiffRegistryModifiedCarriesTheNewValue is the point of rendering values rather than only
// hashing them: a Run key whose data changed is only actionable if the alert can show the new
// command line without somebody going to the machine.
func TestDiffRegistryModifiedCarriesTheNewValue(t *testing.T) {
	const k = `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater`
	got := diffRegistry(
		map[string]registryValue{k: rv(`C:\Program Files\Updater\updater.exe`)},
		map[string]registryValue{k: rv(`powershell -enc SQBFAFgA`)},
	)
	if len(got) != 1 || got[0].Action != "modified" {
		t.Fatalf("got %+v, want one modified change", got)
	}
	if got[0].SHA256 == "" {
		t.Error("a modified value carries no hash")
	}
	if got[0].Diff == "" {
		t.Error("a modified value carries no diff; the alert cannot show what it became")
	}
}

func TestNormalizeRegPath(t *testing.T) {
	for in, want := range map[string]string{
		`HKLM\Software\Foo`:    `HKLM\Software\Foo`,
		`hklm\Software\Foo`:    `HKLM\Software\Foo`,
		`HKLM/Software/Foo`:    `HKLM\Software\Foo`,
		`  HKLM\Software\Foo `: `HKLM\Software\Foo`,
		`\HKLM\Software\Foo\`:  `HKLM\Software\Foo`,
		`hkcu`:                 `HKCU`,
		// The subkey keeps its case: registry keys are case-insensitive to Windows but an
		// operator reading an alert wants the spelling they configured.
		`HKLM\SoftWare`: `HKLM\SoftWare`,
	} {
		if got := normalizeRegPath(in); got != want {
			t.Errorf("normalizeRegPath(%q) = %q, want %q", in, got, want)
		}
	}
}
