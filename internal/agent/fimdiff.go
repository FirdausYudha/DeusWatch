package agent

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

// Content-snapshot limits: only TEXT files up to maxSnapshotBytes are snapshotted for
// diffing/restore. Webroot files that matter for defacement (index.php, .htaccess, config,
// templates, larger HTML/PHP) are text; binaries and oversized files are tracked by hash only.
//
// maxSnapshotBytes defaults to 2 MiB (enterprise HTML/PHP), overridable with
// FIM_SNAPSHOT_MAX_BYTES (a plain byte count or a K/M suffix, e.g. "4M", "1536K"). Raising it
// costs agent memory (the file is read whole) and, in manager-storage mode, upload bandwidth +
// central DB space, so it is the admin's call.
var maxSnapshotBytes int64 = parseSizeEnv("FIM_SNAPSHOT_MAX_BYTES", 2<<20)

const (
	maxDiffLines = 200 // cap the emitted diff so one huge change can't flood
	// maxDiffCells bounds the O(m*n) LCS table so a large file never blows up the agent's
	// memory/CPU: above it, a cheap O(m+n) summary is emitted instead of the full line diff.
	maxDiffCells = 2_000_000
)

// parseSizeEnv reads a byte-size env value (plain integer, or a K/KiB/M/MiB suffix). Returns def
// when unset or invalid.
func parseSizeEnv(key string, def int64) int64 {
	s := strings.ToUpper(strings.TrimSpace(os.Getenv(key)))
	if s == "" {
		return def
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "MIB"):
		mult, s = 1<<20, strings.TrimSuffix(s, "MIB")
	case strings.HasSuffix(s, "M"):
		mult, s = 1<<20, strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "KIB"):
		mult, s = 1<<10, strings.TrimSuffix(s, "KIB")
	case strings.HasSuffix(s, "K"):
		mult, s = 1<<10, strings.TrimSuffix(s, "K")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n <= 0 {
		return def
	}
	return n * mult
}

// entropyThreshold: content at/above this Shannon entropy (bits/byte, max 8.0) is treated as
// encrypted/random — the ransomware signal. Encrypted (and compressed) data sits near 7.9-8.0;
// source/config text is ~4-5. Override with FIM_ENTROPY_THRESHOLD (default 7.2). Set to 0 or a
// value > 8 to disable entropy-based encryption detection.
var entropyThreshold = parseFloatEnv("FIM_ENTROPY_THRESHOLD", 7.2)

// minEntropyBytes: files smaller than this are too small for entropy to be a meaningful signal.
const minEntropyBytes = 64

// shannonEntropy returns the byte-level Shannon entropy of b in bits/byte (0..8).
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	e := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

func parseFloatEnv(key string, def float64) float64 {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			return f
		}
	}
	return def
}

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

	m, n := len(a), len(b)
	// Guard: the LCS below is O(m*n) time AND memory. For a large file that would blow up the
	// agent, so fall back to a cheap O(m+n) added/removed summary instead of the full line diff.
	if int64(m)*int64(n) > maxDiffCells {
		return diffSummary(a, b)
	}

	// LCS table (O(len(a)*len(b)) - fine for small snapshotted files).
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

// diffSummary is a cheap O(m+n) fallback for large files: it counts added/removed lines via a
// line multiset (positional context is lost, but "how much changed" is preserved) — safe to run
// on multi-megabyte files where the full LCS would exhaust memory.
func diffSummary(a, b []string) string {
	old := make(map[string]int, len(a))
	for _, l := range a {
		old[l]++
	}
	added := 0
	for _, l := range b {
		if old[l] > 0 {
			old[l]--
		} else {
			added++
		}
	}
	removed := 0
	for _, c := range old {
		removed += c
	}
	return fmt.Sprintf("… large file: ~%d line(s) added, ~%d line(s) removed (full diff omitted; %d → %d lines)",
		added, removed, len(a), len(b))
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}
