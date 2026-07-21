// Package vuln implements Vulnerability Assessment phase 2: matching an agent's installed packages
// against vendor security advisories (Ubuntu USN / Debian) to produce CVE findings.
package vuln

import "strings"

// CompareVersions compares two Debian/Ubuntu package versions the way dpkg does, returning -1, 0 or
// +1 for a<b, a==b, a>b. This is the correctness-critical core of matching: "is the installed
// version older than the fixed version?" is a dpkg version comparison, and getting it wrong means
// either missing real vulnerabilities or flagging patched packages.
//
// A Debian version is [epoch:]upstream[-revision]; epoch defaults to 0. Each part is compared with
// dpkg's verrevcmp, where '~' sorts before everything (so 1.0~rc1 < 1.0), digit runs compare
// numerically, and letters sort before punctuation. Ported from dpkg's lib/dpkg/version.c.
func CompareVersions(a, b string) int {
	ea, ua, ra := splitVersion(a)
	eb, ub, rb := splitVersion(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

// splitVersion breaks "1:2.3.4-5ubuntu1" into epoch=1, upstream="2.3.4", revision="5ubuntu1".
// A missing epoch is 0; a missing revision is "".
func splitVersion(v string) (epoch int, upstream, revision string) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch = atoiSafe(v[:i]) // non-numeric epoch degrades to 0, matching a lenient parse
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		revision = v[i+1:]
		upstream = v[:i]
	} else {
		upstream = v
	}
	return epoch, upstream, revision
}

func atoiSafe(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return n
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// order returns dpkg's sort weight for a single character in the non-digit comparison: '~' is less
// than everything (including end-of-string, which is 0), letters keep their value, and any other
// punctuation sorts after letters.
func order(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	case c == 0:
		return 0
	default:
		return int(c) + 256
	}
}

// verrevcmp compares one version segment (upstream or revision) per dpkg's algorithm.
func verrevcmp(a, b string) int {
	ia, ib := 0, 0
	for ia < len(a) || ib < len(b) {
		// Compare the non-digit run character by character using order().
		for (ia < len(a) && !isDigit(a[ia])) || (ib < len(b) && !isDigit(b[ib])) {
			var ca, cb byte
			if ia < len(a) {
				ca = a[ia]
			}
			if ib < len(b) {
				cb = b[ib]
			}
			if oc := order(ca) - order(cb); oc != 0 {
				return sign(oc)
			}
			ia++
			ib++
		}
		// Skip leading zeros so digit runs compare by value, not by length.
		for ia < len(a) && a[ia] == '0' {
			ia++
		}
		for ib < len(b) && b[ib] == '0' {
			ib++
		}
		// Compare the digit runs: a longer run of (non-zero-led) digits is the larger number; if
		// equal length, the first differing digit decides.
		firstDiff := 0
		for ia < len(a) && isDigit(a[ia]) && ib < len(b) && isDigit(b[ib]) {
			if firstDiff == 0 {
				firstDiff = int(a[ia]) - int(b[ib])
			}
			ia++
			ib++
		}
		if ia < len(a) && isDigit(a[ia]) {
			return 1
		}
		if ib < len(b) && isDigit(b[ib]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

func sign(n int) int {
	if n < 0 {
		return -1
	}
	if n > 0 {
		return 1
	}
	return 0
}
