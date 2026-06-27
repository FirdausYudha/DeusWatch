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

// Analyzer analyzes one alert and writes a free-form executive summary for reports.
type Analyzer interface {
	Name() string
	Analyze(ctx context.Context, in AlertInput) (Result, error)
	// Summarize turns a report data prompt into a concise prose security summary.
	Summarize(ctx context.Context, prompt string) (string, error)
}

// reportSystemPrompt steers the model for the periodic/on-demand report summary.
const reportSystemPrompt = `You are a senior SOC analyst writing an executive security summary for a self-hosted security platform. Write concise plain prose (no markdown headings or bullet lists), about 4-7 sentences. Cover overall activity, the most notable threats (brute force, malware/FIM, anomalies), the most affected hosts/IPs, and 2-3 prioritized, actionable recommendations. Be specific and calm; never invent data beyond what is given.`

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

// Summarize is not supported by the heuristic analyzer — report summaries need a
// generative model (configure Ollama or another provider).
func (HeuristicAnalyzer) Summarize(_ context.Context, _ string) (string, error) {
	return "", fmt.Errorf("llm: report summary needs a generative model — configure an LLM provider (e.g. Ollama)")
}

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

// ── construction (provider-agnostic) ──────────────────────

// NewAnalyzer builds an analyzer from a provider spec (used by both the env path and
// the Integrations registry). Providers:
//
//	anthropic | claude                       -> Claude (Anthropic API, needs apiKey)
//	ollama | openai | openai-compatible | "" -> any OpenAI-compatible Chat Completions
//	                                            endpoint (Ollama/LM Studio/vLLM/…) via baseURL
//
// For "ollama" an empty baseURL defaults to http://host.docker.internal:11434/v1.
func NewAnalyzer(provider, baseURL, apiKey, model string) (Analyzer, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "anthropic", "claude":
		if apiKey == "" {
			return nil, fmt.Errorf("llm: the anthropic provider needs an api_key")
		}
		return NewClaudeAnalyzer(apiKey, model), nil
	case "ollama":
		if baseURL == "" {
			baseURL = "http://host.docker.internal:11434/v1"
		}
		return NewOpenAICompatAnalyzer(baseURL, apiKey, model), nil
	case "", "openai", "openai-compatible", "openai_compatible":
		if baseURL == "" {
			return nil, fmt.Errorf("llm: an OpenAI-compatible provider needs a base_url (e.g. http://host:11434/v1)")
		}
		return NewOpenAICompatAnalyzer(baseURL, apiKey, model), nil
	default:
		return nil, fmt.Errorf("llm: unknown provider %q (use anthropic | ollama | openai-compatible)", provider)
	}
}

// AnalyzerFromEnv selects an analyzer from environment variables (dev / fallback when no
// LLM integration is configured), in order: ANTHROPIC_API_KEY -> Claude; LLM_BASE_URL (or
// LLM_PROVIDER) -> OpenAI-compatible (Ollama etc.); LLM_ENABLED=1 -> heuristic. (analyzer, enabled).
func AnalyzerFromEnv() (Analyzer, bool) {
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		return NewClaudeAnalyzer(key, os.Getenv("ANTHROPIC_MODEL")), true
	}
	if base := os.Getenv("LLM_BASE_URL"); base != "" || os.Getenv("LLM_PROVIDER") != "" {
		provider := os.Getenv("LLM_PROVIDER")
		if a, err := NewAnalyzer(provider, base, os.Getenv("LLM_API_KEY"), os.Getenv("LLM_MODEL")); err == nil {
			return a, true
		}
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
