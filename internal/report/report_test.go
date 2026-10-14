package report

import (
	"strings"
	"testing"
	"time"
)

func TestRenderMarkdown(t *testing.T) {
	r := Report{
		Generated:    time.Date(2026, 6, 14, 10, 0, 0, 0, time.UTC),
		Since:        time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC),
		WindowHours:  24,
		TotalEvents:  1234,
		TotalAlerts:  56,
		BySeverity:   []Count{{"high", 40}, {"medium", 16}},
		TopSourceIPs: []Count{{"45.155.205.99", 30}},
		TopRules:     []Count{{"SSH Brute Force", 25}},
		ByVerdict:    []Count{{"malicious", 30}, {"suspicious", 20}},
	}
	md := RenderMarkdown(r)
	for _, want := range []string{
		"DeusWatch Report, last 24 hours", "Total events:** 1234", "Total alerts:** 56",
		"high, 40", "45.155.205.99, 30", "SSH Brute Force, 25", "malicious, 30",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}

// The dashboard-mirrored network widgets must appear in both the Markdown report and the LLM
// summary prompt, so the report tells the same story the live dashboard does.
func TestRenderIncludesDashboardNetworkWidgets(t *testing.T) {
	r := Report{
		WindowHours:      24,
		TopDestPorts:     []Count{{"443", 900}, {"22", 120}},
		TopDestinations:  []Count{{"10.0.0.5", 300}},
		TopCountries:     []Count{{"CN", 500}},
		TrafficDirection: []Count{{"inbound", 800}, {"lateral", 40}},
		RiskyIPs:         []Count{{"45.134.26.9 (high)", 87}},
	}
	md := RenderMarkdown(r)
	for _, want := range []string{
		"Top destination port", "443, 900", "Top destination IP", "10.0.0.5, 300",
		"Traffic direction", "inbound, 800", "Top source country", "CN, 500",
		"Top risky IP", "45.134.26.9 (high), 87",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
	prompt := SummaryPrompt(r)
	for _, want := range []string{
		"Top destination ports", "443: 900", "Traffic direction", "inbound: 800",
		"Top risky IPs", "45.134.26.9 (high): 87",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("summary prompt missing %q:\n%s", want, prompt)
		}
	}
}

func TestRenderMarkdownEmptySections(t *testing.T) {
	md := RenderMarkdown(Report{WindowHours: 1})
	if !strings.Contains(md, "_no data yet_") {
		t.Fatalf("empty section should show the placeholder:\n%s", md)
	}
}
