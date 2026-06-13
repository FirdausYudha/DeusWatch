package report

import (
	"strings"
	"testing"
	"time"
)

func TestRenderMarkdown(t *testing.T) {
	r := Report{
		Generated:   time.Date(2026, 6, 14, 10, 0, 0, 0, time.UTC),
		Since:       time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC),
		WindowHours: 24,
		TotalEvents: 1234,
		TotalAlerts: 56,
		BySeverity:  []Count{{"high", 40}, {"medium", 16}},
		TopSourceIPs: []Count{{"45.155.205.99", 30}},
		TopRules:    []Count{{"SSH Brute Force", 25}},
		ByVerdict:   []Count{{"malicious", 30}, {"suspicious", 20}},
	}
	md := RenderMarkdown(r)
	for _, want := range []string{
		"Laporan DeusWatch — 24 jam", "Total event:** 1234", "Total alert:** 56",
		"high — 40", "45.155.205.99 — 30", "SSH Brute Force — 25", "malicious — 30",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown tak memuat %q:\n%s", want, md)
		}
	}
}

func TestRenderMarkdownEmptySections(t *testing.T) {
	md := RenderMarkdown(Report{WindowHours: 1})
	if !strings.Contains(md, "_tidak ada data_") {
		t.Fatalf("seksi kosong harus tampil placeholder:\n%s", md)
	}
}
