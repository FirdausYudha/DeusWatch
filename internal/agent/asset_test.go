package agent

import "testing"

// Firmware placeholders are the reason this function exists. A register keyed on serial number
// treats "To Be Filled By O.E.M." as a real value, and every machine from that batch reports the
// identical string, so a whole batch collapses into one asset. Empty is the honest answer.
func TestCleanAssetFieldDropsFirmwarePlaceholders(t *testing.T) {
	for _, s := range []string{
		"", "   ", "0", "None", "n/a", "NA", "null", "Unknown", "Default string",
		"To Be Filled By O.E.M.", "to be filled by oem", "Not Specified", "Not Applicable",
		"System Serial Number", "System manufacturer", "System Product Name",
		"Chassis Serial Number", "OEM", "O.E.M.", "invalid",
	} {
		if got := cleanAssetField(s); got != "" {
			t.Errorf("cleanAssetField(%q) = %q, want empty", s, got)
		}
	}
	// A real value survives, including the trailing newline /sys/class/dmi/id files carry.
	for in, want := range map[string]string{
		"Dell Inc.\n":      "Dell Inc.",
		"  7MBQ2H3  ":      "7MBQ2H3",
		"ThinkCentre M70q": "ThinkCentre M70q",
	} {
		if got := cleanAssetField(in); got != want {
			t.Errorf("cleanAssetField(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseMemTotalMB(t *testing.T) {
	const meminfo = "MemTotal:       16316436 kB\nMemFree:         1234 kB\nSwapTotal: 0 kB\n"
	if got := parseMemTotalMB(meminfo); got != 15934 {
		t.Errorf("parseMemTotalMB = %d, want 15934", got)
	}
	// Absent or malformed must read as "not collected", never as a wrong number.
	for _, bad := range []string{"", "MemFree: 100 kB\n", "MemTotal:\n", "MemTotal: abc kB\n"} {
		if got := parseMemTotalMB(bad); got != 0 {
			t.Errorf("parseMemTotalMB(%q) = %d, want 0", bad, got)
		}
	}
}

// The Windows collector is one PowerShell call emitting four lines; the parsing is split out so it
// can be checked without Windows. CRLF is what PowerShell actually returns.
func TestParseWindowsAsset(t *testing.T) {
	man, model, serial, mem := parseWindowsAsset("Dell Inc.\r\nOptiPlex 7090\r\n7MBQ2H3\r\n17179869184\r\n")
	if man != "Dell Inc." || model != "OptiPlex 7090" || serial != "7MBQ2H3" {
		t.Errorf("got %q / %q / %q", man, model, serial)
	}
	if mem != 17179869184 {
		t.Errorf("memory = %d, want 17179869184", mem)
	}

	// A truncated reply must yield empty fields rather than panic or shift values up a line.
	man, model, serial, mem = parseWindowsAsset("LENOVO\n")
	if man != "LENOVO" || model != "" || serial != "" || mem != 0 {
		t.Errorf("truncated output mishandled: %q / %q / %q / %d", man, model, serial, mem)
	}

	// A placeholder serial from the firmware is dropped here too, not just on Linux.
	if _, _, serial, _ = parseWindowsAsset("ACME\nBox\nTo Be Filled By O.E.M.\n0\n"); serial != "" {
		t.Errorf("placeholder serial survived: %q", serial)
	}
}
