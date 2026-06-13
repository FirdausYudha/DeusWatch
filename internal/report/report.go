// Package report menghasilkan ringkasan keamanan periodik (design doc Fase 3):
// total event/alert, sebaran severity, top source IP/rule/MITRE, dan sebaran vonis
// LLM dalam satu jendela waktu. Struktur murni (data di-query oleh store) + perender
// Markdown agar mudah diuji dan dikirim ke UI/notifikasi.
package report

import (
	"fmt"
	"strings"
	"time"
)

// Count adalah satu baris agregasi berlabel.
type Count struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

// Report adalah ringkasan satu jendela waktu.
type Report struct {
	Generated     time.Time `json:"generated"`
	Since         time.Time `json:"since"`
	WindowHours   int       `json:"window_hours"`
	TotalEvents   int64     `json:"total_events"`
	TotalAlerts   int64     `json:"total_alerts"`
	BySeverity    []Count   `json:"by_severity"`
	TopSourceIPs  []Count   `json:"top_source_ips"`
	TopRules      []Count   `json:"top_rules"`
	TopTechniques []Count   `json:"top_techniques"`
	ByVerdict     []Count   `json:"by_verdict"`
}

// RenderMarkdown merender report menjadi Markdown ringkas.
func RenderMarkdown(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Laporan DeusWatch — %d jam terakhir\n\n", r.WindowHours)
	fmt.Fprintf(&b, "_Dibuat %s · sejak %s_\n\n",
		r.Generated.UTC().Format(time.RFC3339), r.Since.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Total event:** %d\n- **Total alert:** %d\n\n", r.TotalEvents, r.TotalAlerts)

	section(&b, "Severity", r.BySeverity)
	section(&b, "Top source IP", r.TopSourceIPs)
	section(&b, "Top rule", r.TopRules)
	section(&b, "Top MITRE technique", r.TopTechniques)
	section(&b, "Vonis LLM", r.ByVerdict)
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func section(b *strings.Builder, title string, rows []Count) {
	fmt.Fprintf(b, "## %s\n\n", title)
	if len(rows) == 0 {
		b.WriteString("_tidak ada data_\n\n")
		return
	}
	for _, c := range rows {
		label := c.Label
		if label == "" {
			label = "(kosong)"
		}
		fmt.Fprintf(b, "- %s — %d\n", label, c.Count)
	}
	b.WriteByte('\n')
}
