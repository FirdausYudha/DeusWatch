package assistant

import (
	"fmt"
	"sort"
	"strings"
)

// Period-over-period comparison, the thing that makes "find anomalies" answerable at all.
//
// An anomaly is a deviation from a baseline. Given one window's figures the model has no baseline,
// so asked what is unusual it produces an impression: it picks the largest number and calls it
// notable, which is not detection, it is reading the top of a list aloud.
//
// Every delta here is computed in Go and handed over already phrased ("93 -> 412, up 343%"). That
// division is deliberate. Small models are poor at arithmetic and a wrong percentage reads exactly
// as confidently as a right one, so the model's job is reduced to deciding which of these movements
// is worth mentioning and saying why. That is the part it is actually good at.

// Count mirrors report.Count without importing it, so this package stays free of the report
// package and can be tested on literals.
type Count struct {
	Label string
	Count int64
}

// Window is one period's figures.
type Window struct {
	Events, Alerts int64
	BySeverity     []Count
	TopSourceIPs   []Count
	TopRules       []Count
	TopAgents      []Count
}

// MinMovePercent is the floor for calling a change worth printing. Day-to-day noise on a live
// deployment runs to a few tens of percent, so a lower bar fills the block with movements nobody
// would act on, and a block full of non-findings teaches an operator to skim it.
const MinMovePercent = 25

// Trend renders the comparison. cur is the window asked about; prev is the equal-length window
// immediately before it.
func Trend(cur, prev Window, hours int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "COMPARISON WITH THE PRECEDING %s (this is the baseline; movements are already calculated, do not recompute them)\n",
		humanHours(hours))

	fmt.Fprintf(&b, "Events: %s. Alerts: %s.\n", delta(prev.Events, cur.Events), delta(prev.Alerts, cur.Alerts))

	if line := movedLines("Severity", prev.BySeverity, cur.BySeverity); line != "" {
		b.WriteString(line)
	}
	if line := movedLines("Rules", prev.TopRules, cur.TopRules); line != "" {
		b.WriteString(line)
	}
	if line := movedLines("Agents", prev.TopAgents, cur.TopAgents); line != "" {
		b.WriteString(line)
	}

	// Source IPs get set treatment rather than deltas: for attackers, appearing and disappearing is
	// the signal, while an existing one going from 40 to 55 hits is the same bot having a slightly
	// better day.
	if newly := missingFrom(cur.TopSourceIPs, prev.TopSourceIPs); len(newly) > 0 {
		fmt.Fprintf(&b, "Source IPs that were NOT in the previous period's top list: %s.\n", strings.Join(newly, ", "))
	}
	if gone := missingFrom(prev.TopSourceIPs, cur.TopSourceIPs); len(gone) > 0 {
		fmt.Fprintf(&b, "Source IPs that have stopped: %s.\n", strings.Join(gone, ", "))
	}
	if newly := missingFrom(cur.TopRules, prev.TopRules); len(newly) > 0 {
		fmt.Fprintf(&b, "Detections firing that were not firing before: %s.\n", strings.Join(newly, ", "))
	}
	if gone := missingFrom(prev.TopAgents, cur.TopAgents); len(gone) > 0 {
		fmt.Fprintf(&b, "Agents that were active before and are quiet now: %s. A host that stops reporting is as interesting as one that gets noisy.\n",
			strings.Join(gone, ", "))
	}

	b.WriteString("Only call something unusual if it is in this block. A big number is not an anomaly; a big CHANGE is. If nothing here moved much, say the period looks normal and leave it at that.\n")
	return b.String()
}

// delta phrases one movement. Percentages are meaningless off a zero base, so that case is worded
// rather than divided.
func delta(before, after int64) string {
	switch {
	case before == 0 && after == 0:
		return "0 in both periods"
	case before == 0:
		return fmt.Sprintf("0 -> %d (new activity; there was none before)", after)
	case after == 0:
		return fmt.Sprintf("%d -> 0 (stopped entirely)", before)
	}
	pct := float64(after-before) / float64(before) * 100
	dir := "up"
	if pct < 0 {
		dir, pct = "down", -pct
	}
	return fmt.Sprintf("%d -> %d (%s %.0f%%)", before, after, dir, pct)
}

// movedLines prints only the entries that moved past the floor, so the block stays readable.
func movedLines(title string, prev, cur []Count) string {
	p := index(prev)
	c := index(cur)
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	for k := range p {
		if _, ok := c[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	parts := make([]string, 0, 4)
	for _, k := range keys {
		before, after := p[k], c[k]
		if before == after {
			continue
		}
		if before > 0 {
			move := float64(after-before) / float64(before) * 100
			if move < 0 {
				move = -move
			}
			if move < MinMovePercent {
				continue
			}
		}
		parts = append(parts, fmt.Sprintf("%s %s", k, delta(before, after)))
	}
	if len(parts) == 0 {
		return ""
	}
	return fmt.Sprintf("%s that moved more than %d%%: %s.\n", title, MinMovePercent, strings.Join(parts, "; "))
}

// missingFrom returns labels present in a but not in b, capped so one chaotic period cannot flood
// the prompt.
func missingFrom(a, b []Count) []string {
	have := index(b)
	out := make([]string, 0, 6)
	for _, c := range a {
		if c.Label == "" {
			continue
		}
		if _, ok := have[c.Label]; !ok {
			out = append(out, fmt.Sprintf("%s (%d)", c.Label, c.Count))
			if len(out) == 6 {
				break
			}
		}
	}
	return out
}

func index(cs []Count) map[string]int64 {
	m := make(map[string]int64, len(cs))
	for _, c := range cs {
		if c.Label != "" {
			m[c.Label] = c.Count
		}
	}
	return m
}

func humanHours(h int) string {
	switch {
	case h%(24*7) == 0 && h >= 24*7:
		return fmt.Sprintf("%d week(s)", h/(24*7))
	case h%24 == 0 && h >= 24:
		return fmt.Sprintf("%d day(s)", h/24)
	default:
		return fmt.Sprintf("%d hour(s)", h)
	}
}
