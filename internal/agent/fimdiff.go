package agent

import (
	"bytes"
	"strings"
)

// Content-snapshot limits: only small TEXT files are snapshotted for diffing/restore.
// Webroot files that matter for defacement (index.php, .htaccess, config, templates) are
// small text; binaries and large files are tracked by hash only (no snapshot, no diff).
const (
	maxSnapshotBytes = 256 << 10 // 256 KiB - above this, hash only
	maxDiffLines     = 200       // cap the emitted diff so one huge change can't flood
)

// isProbablyText reports whether b looks like text (no NUL byte in the sampled prefix).
func isProbablyText(b []byte) bool {
	n := len(b)
	if n > 8000 {
		n = 8000
	}
	return !bytes.Contains(b[:n], []byte{0})
}

// unifiedDiff produces a compact line diff between old and new text: each output line is
// prefixed with ' ' (context, omitted here), '-' (removed) or '+' (added). It is a
// line-level LCS diff - enough to answer "which lines changed" for a defacement/webshell,
// not a full Myers/patch. Output is capped at maxDiffLines; returns "" when identical.
func unifiedDiff(oldText, newText string) string {
	if oldText == newText {
		return ""
	}
	a := splitLines(oldText)
	b := splitLines(newText)

	// LCS table (O(len(a)*len(b)) - fine for small snapshotted files).
	m, n := len(a), len(b)
	lcs := make([][]int, m+1)
	for i := range lcs {
		lcs[i] = make([]int, n+1)
	}
	for i := m - 1; i >= 0; i-- {
		for j := n - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	var out []string
	emit := func(s string) bool {
		out = append(out, s)
		return len(out) < maxDiffLines
	}
	i, j := 0, 0
	for i < m && j < n {
		switch {
		case a[i] == b[j]:
			i, j = i+1, j+1 // common line - not emitted (only changes matter)
		case lcs[i+1][j] >= lcs[i][j+1]:
			if !emit("- " + a[i]) {
				goto done
			}
			i++
		default:
			if !emit("+ " + b[j]) {
				goto done
			}
			j++
		}
	}
	for ; i < m; i++ {
		if !emit("- " + a[i]) {
			goto done
		}
	}
	for ; j < n; j++ {
		if !emit("+ " + b[j]) {
			goto done
		}
	}
done:
	if len(out) >= maxDiffLines {
		out = append(out, "… (diff truncated)")
	}
	return strings.Join(out, "\n")
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}
