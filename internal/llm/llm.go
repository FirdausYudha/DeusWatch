// Package llm is the DeusWatch LLM analysis worker (Phase 3): it triages alerts into
// a verdict (benign/suspicious/malicious/needs_review) + a short summary, stored to
// deuswatch.llm.*. The Claude analyzer (Anthropic API) is used when ANTHROPIC_API_KEY
// is set; otherwise the deterministic HeuristicAnalyzer (dev/offline).
package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"deuswatch/internal/ingest"
)

// Result is the analysis output: verdict + summary.
type Result struct {
	Verdict ingest.LLMVerdict `json:"verdict"`
	Summary string            `json:"summary"`
}

// AlertInput is the (already-enriched) alert context being analyzed.
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

// Analyzer analyzes one alert.
type Analyzer interface {
	Name() string
	Analyze(ctx context.Context, in AlertInput) (Result, error)
}

// validVerdict reports whether v is a known verdict.
func validVerdict(v ingest.LLMVerdict) bool {
	switch v {
	case ingest.VerdictBenign, ingest.VerdictSuspicious, ingest.VerdictMalicious, ingest.VerdictNeedsReview:
		return true
	}
	return false
}

// ── HeuristicAnalyzer (fallback without an API) ───────────

// HeuristicAnalyzer gives a deterministic verdict from enrichment + severity signals.
type HeuristicAnalyzer struct{}

func (HeuristicAnalyzer) Name() string { return "heuristic" }

func (HeuristicAnalyzer) Analyze(_ context.Context, in AlertInput) (Result, error) {
	abuse := derefInt(in.AbuseConfidence)
	otx := derefInt(in.OTXPulseCount)

	switch {
	case abuse >= 90 || otx >= 5:
		return Result{ingest.VerdictMalicious, heuristicSummary(in, "bad IP reputation (CTI)")}, nil
	case in.Severity >= ingest.SeverityHigh || abuse >= 50:
		return Result{ingest.VerdictSuspicious, heuristicSummary(in, "high severity / medium reputation")}, nil
	case in.Severity <= ingest.SeverityLow && abuse < 10:
		return Result{ingest.VerdictBenign, heuristicSummary(in, "low severity & clean IP")}, nil
	default:
		return Result{ingest.VerdictNeedsReview, heuristicSummary(in, "needs analyst review")}, nil
	}
}

func heuristicSummary(in AlertInput, reason string) string {
	src := in.SourceIP
	if src == "" {
		src = "-"
	}
	return fmt.Sprintf("%s from %s (%s): %s.", firstNonEmpty(in.Rule, in.Label, "alert"), src, in.Technique, reason)
}

// ── prompt & parsing (used by ClaudeAnalyzer) ─────────────

const systemPrompt = `You are a DeusWatch SOC analyst. Given one security alert, give a short triage verdict.
Reply with ONLY valid JSON and no other text, in the form:
{"verdict":"benign|suspicious|malicious|needs_review","summary":"<=2 sentence reason"}`

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
		fmt.Fprintf(&b, "Raw log: %s\n", orig)
	}
	return strings.TrimSpace(b.String())
}

// parseResult extracts the {verdict,summary} JSON from the model's text (tolerant of
// surrounding text). An unknown verdict → needs_review.
func parseResult(text string) (Result, error) {
	start := strings.IndexByte(text, '{')
	end := strings.LastIndexByte(text, '}')
	if start < 0 || end <= start {
		return Result{}, fmt.Errorf("llm: no JSON object in response")
	}
	var r Result
	if err := json.Unmarshal([]byte(text[start:end+1]), &r); err != nil {
		return Result{}, fmt.Errorf("llm: parse response JSON: %w", err)
	}
	if !validVerdict(r.Verdict) {
		r.Verdict = ingest.VerdictNeedsReview
	}
	r.Summary = strings.TrimSpace(r.Summary)
	return r, nil
}

// ── construction from env ─────────────────────────────────

// AnalyzerFromEnv returns a ClaudeAnalyzer if ANTHROPIC_API_KEY is set (model via
// ANTHROPIC_MODEL, default claude-opus-4-8), otherwise a HeuristicAnalyzer if
// LLM_ENABLED=1. (analyzer, enabled).
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
