// Package llm adalah worker analisis LLM DeusWatch (Fase 3): mentriase alert
// menjadi vonis (benign/suspicious/malicious/needs_review) + ringkasan singkat,
// disimpan ke deuswatch.llm.*. Analyzer Claude (API Anthropic) dipakai bila
// ANTHROPIC_API_KEY diset; selain itu HeuristicAnalyzer deterministik (dev/offline).
package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"deuswatch/internal/ingest"
)

// Result adalah keluaran analisis: vonis + ringkasan.
type Result struct {
	Verdict ingest.LLMVerdict `json:"verdict"`
	Summary string            `json:"summary"`
}

// AlertInput adalah konteks alert yang dianalisis (sudah ter-enrich).
type AlertInput struct {
	Rule            string
	Severity        ingest.Severity
	SourceIP        string
	Technique       string
	Tactic          string
	Label           string
	Original        string
	Country         string
	AbuseConfidence *int
	OTXPulseCount   *int
}

// Analyzer menganalisis satu alert.
type Analyzer interface {
	Name() string
	Analyze(ctx context.Context, in AlertInput) (Result, error)
}

// validVerdict melaporkan apakah v termasuk vonis yang dikenal.
func validVerdict(v ingest.LLMVerdict) bool {
	switch v {
	case ingest.VerdictBenign, ingest.VerdictSuspicious, ingest.VerdictMalicious, ingest.VerdictNeedsReview:
		return true
	}
	return false
}

// ── HeuristicAnalyzer (fallback tanpa API) ────────────────

// HeuristicAnalyzer memberi vonis deterministik dari sinyal enrichment + severity.
type HeuristicAnalyzer struct{}

func (HeuristicAnalyzer) Name() string { return "heuristic" }

func (HeuristicAnalyzer) Analyze(_ context.Context, in AlertInput) (Result, error) {
	abuse := derefInt(in.AbuseConfidence)
	otx := derefInt(in.OTXPulseCount)

	switch {
	case abuse >= 90 || otx >= 5:
		return Result{ingest.VerdictMalicious, heuristicSummary(in, "reputasi IP buruk (CTI)")}, nil
	case in.Severity >= ingest.SeverityHigh || abuse >= 50:
		return Result{ingest.VerdictSuspicious, heuristicSummary(in, "severity tinggi / reputasi sedang")}, nil
	case in.Severity <= ingest.SeverityLow && abuse < 10:
		return Result{ingest.VerdictBenign, heuristicSummary(in, "severity rendah & IP bersih")}, nil
	default:
		return Result{ingest.VerdictNeedsReview, heuristicSummary(in, "perlu tinjauan analis")}, nil
	}
}

func heuristicSummary(in AlertInput, reason string) string {
	src := in.SourceIP
	if src == "" {
		src = "-"
	}
	return fmt.Sprintf("%s dari %s (%s): %s.", firstNonEmpty(in.Rule, in.Label, "alert"), src, in.Technique, reason)
}

// ── prompt & parsing (dipakai ClaudeAnalyzer) ─────────────

const systemPrompt = `Kamu analis SOC DeusWatch. Diberi satu alert keamanan, beri vonis triase singkat.
Balas HANYA JSON valid tanpa teks lain, bentuk:
{"verdict":"benign|suspicious|malicious|needs_review","summary":"<=2 kalimat ringkas alasan"}`

func buildUserPrompt(in AlertInput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Rule: %s\n", firstNonEmpty(in.Rule, in.Label))
	fmt.Fprintf(&b, "Severity: %s\n", in.Severity.String())
	if in.SourceIP != "" {
		fmt.Fprintf(&b, "Source IP: %s", in.SourceIP)
		if in.Country != "" {
			fmt.Fprintf(&b, " (%s)", in.Country)
		}
		b.WriteByte('\n')
	}
	if in.Technique != "" {
		fmt.Fprintf(&b, "MITRE: %s %s\n", in.Technique, in.Tactic)
	}
	if in.AbuseConfidence != nil {
		fmt.Fprintf(&b, "AbuseIPDB confidence: %d/100\n", *in.AbuseConfidence)
	}
	if in.OTXPulseCount != nil {
		fmt.Fprintf(&b, "OTX pulses: %d\n", *in.OTXPulseCount)
	}
	if in.Original != "" {
		orig := in.Original
		if len(orig) > 500 {
			orig = orig[:500]
		}
		fmt.Fprintf(&b, "Log mentah: %s\n", orig)
	}
	return strings.TrimSpace(b.String())
}

// parseResult mengekstrak JSON {verdict,summary} dari teks model (toleran terhadap
// teks pembungkus). Vonis tak dikenal → needs_review.
func parseResult(text string) (Result, error) {
	start := strings.IndexByte(text, '{')
	end := strings.LastIndexByte(text, '}')
	if start < 0 || end <= start {
		return Result{}, fmt.Errorf("llm: tak ada objek JSON di respons")
	}
	var r Result
	if err := json.Unmarshal([]byte(text[start:end+1]), &r); err != nil {
		return Result{}, fmt.Errorf("llm: parse JSON respons: %w", err)
	}
	if !validVerdict(r.Verdict) {
		r.Verdict = ingest.VerdictNeedsReview
	}
	r.Summary = strings.TrimSpace(r.Summary)
	return r, nil
}

// ── konstruksi dari env ───────────────────────────────────

// AnalyzerFromEnv mengembalikan ClaudeAnalyzer bila ANTHROPIC_API_KEY diset
// (model via ANTHROPIC_MODEL, default claude-opus-4-8), selain itu HeuristicAnalyzer
// bila LLM_ENABLED=1. (analyzer, enabled).
func AnalyzerFromEnv() (Analyzer, bool) {
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		return NewClaudeAnalyzer(key, os.Getenv("ANTHROPIC_MODEL")), true
	}
	if enabled, _ := parseBool(os.Getenv("LLM_ENABLED")); enabled {
		return HeuristicAnalyzer{}, true
	}
	return nil, false
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true, nil
	default:
		return false, nil
	}
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
