// Package report produces periodic security summaries (design doc Phase 3):
// total events/alerts, severity breakdown, top source IP/rule/MITRE, and the LLM
// verdict breakdown over a time window. A pure struct (data is queried by store) plus
// a Markdown renderer so it is easy to test and to send to the UI/notifications.
package report

import (
	"fmt"
	"strings"
	"time"
)

// Count is one labeled aggregation row.
type Count struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

// Report is a summary over one time window.
type Report struct {
	Generated time.Time `json:"generated"`
	Since     time.Time `json:"since"`
	// Until bounds the window's end. Zero means "up to now" (the rolling last-N-hours report);
	// a set value means an explicit from–to range was requested (e.g. for a PDF of one month).
	Until         time.Time `json:"until,omitempty"`
	WindowHours   int       `json:"window_hours"`
	TotalEvents   int64     `json:"total_events"`
	TotalAlerts   int64     `json:"total_alerts"`
	BySeverity    []Count   `json:"by_severity"`
	TopSourceIPs  []Count   `json:"top_source_ips"`
	TopRules      []Count   `json:"top_rules"`
	TopTechniques []Count   `json:"top_techniques"`
	TopAgents     []Count   `json:"top_agents"` // most active agents/hosts (by alert count)
	ByVerdict     []Count   `json:"by_verdict"`
}

// RenderMarkdown renders the report as compact Markdown.
func RenderMarkdown(r Report) string {
	var b strings.Builder
	if !r.Until.IsZero() {
		// Explicit range: name the actual dates rather than a misleading "last N hours".
		fmt.Fprintf(&b, "# DeusWatch Report — %s to %s\n\n",
			r.Since.UTC().Format("2006-01-02 15:04"), r.Until.UTC().Format("2006-01-02 15:04"))
		fmt.Fprintf(&b, "_Generated %s (UTC)_\n\n", r.Generated.UTC().Format(time.RFC3339))
	} else {
		fmt.Fprintf(&b, "# DeusWatch Report — last %d hours\n\n", r.WindowHours)
		fmt.Fprintf(&b, "_Generated %s · since %s_\n\n",
			r.Generated.UTC().Format(time.RFC3339), r.Since.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "- **Total events:** %d\n- **Total alerts:** %d\n\n", r.TotalEvents, r.TotalAlerts)

	section(&b, "Severity", r.BySeverity)
	section(&b, "Top source IP", r.TopSourceIPs)
	section(&b, "Top agent (affected host)", r.TopAgents)
	section(&b, "Top rule", r.TopRules)
	section(&b, "Top MITRE technique", r.TopTechniques)
	section(&b, "LLM verdict", r.ByVerdict)
	return strings.TrimRight(b.String(), "\n") + "\n"
}

// SummaryPrompt renders the report data as a compact prompt for an LLM to summarize.
func SummaryPrompt(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Security data for the last %d hours.\n", r.WindowHours)
	fmt.Fprintf(&b, "Total events: %d. Total alerts: %d.\n", r.TotalEvents, r.TotalAlerts)
	promptLine(&b, "Severity breakdown", r.BySeverity)
	promptLine(&b, "Top source IPs", r.TopSourceIPs)
	promptLine(&b, "Top agents (affected hosts)", r.TopAgents)
	promptLine(&b, "Top rules", r.TopRules)
	promptLine(&b, "Top MITRE techniques", r.TopTechniques)
	promptLine(&b, "Verdicts", r.ByVerdict)
	return b.String()
}

func promptLine(b *strings.Builder, title string, rows []Count) {
	if len(rows) == 0 {
		return
	}
	parts := make([]string, 0, len(rows))
	for _, c := range rows {
		label := c.Label
		if label == "" {
			label = "(none)"
		}
		parts = append(parts, fmt.Sprintf("%s: %d", label, c.Count))
	}
	fmt.Fprintf(b, "%s - %s.\n", title, strings.Join(parts, ", "))
}

func section(b *strings.Builder, title string, rows []Count) {
	fmt.Fprintf(b, "## %s\n\n", title)
	if len(rows) == 0 {
		b.WriteString("_no data yet_\n\n")
		return
	}
	for _, c := range rows {
		label := c.Label
		if label == "" {
			label = "(empty)"
		}
		fmt.Fprintf(b, "- %s — %d\n", label, c.Count)
	}
	b.WriteByte('\n')
}
