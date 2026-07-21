package vuln

import "testing"

// TestCompareVersions checks dpkg version ordering — the core correctness of the whole feature.
// Cases include the dpkg-documented edge cases plus the real Ubuntu/Debian versions this project
// actually sees.
func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"2.0", "1.9", 1},
		{"1.0-1", "1.0-2", -1},
		{"1.0-10", "1.0-9", 1}, // numeric, not lexical: 10 > 9
		// epoch dominates everything after it
		{"1:1.0", "2.0", 1},
		{"2.0", "1:1.0", -1},
		{"1:1.0", "1:1.0", 0},
		// '~' sorts before everything, even the empty string (pre-releases)
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~~", "1.0~", -1},
		{"1.0~", "1.0", -1},
		// letters sort before punctuation and before a following digit boundary
		{"1.0a", "1.0", 1},
		// real security-relevant pairs (the patched version is greater)
		{"3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.16", -1},
		{"1.18.0-6ubuntu14.4", "1.18.0-6ubuntu14.5", -1},
		{"1:8.9p1-3ubuntu0.6", "1:8.9p1-3ubuntu0.10", -1}, // 0.6 < 0.10 numerically
		{"3.0.11-1~deb12u2", "3.0.11-1~deb12u3", -1},
		{"1.22.1-9", "1.22.1-9", 0},
		// leading zeros don't change the value
		{"1.0-007", "1.0-7", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
		// Antisymmetry: reversing the arguments must reverse the sign.
		if got := CompareVersions(c.b, c.a); got != -c.want {
			t.Errorf("CompareVersions(%q,%q) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}
