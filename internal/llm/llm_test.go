package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go/option"

	"deuswatch/internal/ingest"
)

func ptr(i int) *int { return &i }

func TestHeuristicVerdicts(t *testing.T) {
	a := HeuristicAnalyzer{}
	cases := []struct {
		name string
		in   AlertInput
		want ingest.LLMVerdict
	}{
		{"high abuse", AlertInput{Severity: ingest.SeverityHigh, AbuseConfidence: ptr(95)}, ingest.VerdictMalicious},
		{"otx", AlertInput{Severity: ingest.SeverityMedium, OTXPulseCount: ptr(7)}, ingest.VerdictMalicious},
		{"high severity", AlertInput{Severity: ingest.SeverityHigh, AbuseConfidence: ptr(10)}, ingest.VerdictSuspicious},
		{"benign", AlertInput{Severity: ingest.SeverityLow, AbuseConfidence: ptr(2)}, ingest.VerdictBenign},
		{"needs review", AlertInput{Severity: ingest.SeverityMedium, AbuseConfidence: ptr(20)}, ingest.VerdictNeedsReview},
	}
	for _, c := range cases {
		res, err := a.Analyze(context.Background(), c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if res.Verdict != c.want {
			t.Errorf("%s: verdict %q, want %q", c.name, res.Verdict, c.want)
		}
		if res.Summary == "" {
			t.Errorf("%s: empty summary", c.name)
		}
	}
}

func TestParseResult(t *testing.T) {
	// Tolerant of surrounding text + an unknown verdict -> needs_review.
	r, err := parseResult("Sure:\n{\"verdict\":\"malicious\",\"summary\":\"brute force\"}\ndone")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.Verdict != ingest.VerdictMalicious || r.Summary != "brute force" {
		t.Fatalf("wrong result: %+v", r)
	}
	r2, _ := parseResult(`{"verdict":"nonsense","summary":"x"}`)
	if r2.Verdict != ingest.VerdictNeedsReview {
		t.Fatalf("unknown verdict should be needs_review, got %q", r2.Verdict)
	}
	if _, err := parseResult("no json"); err == nil {
		t.Fatal("text without JSON should error")
	}
}

func TestBuildUserPrompt(t *testing.T) {
	p := buildUserPrompt(AlertInput{
		Rule: "SSH Brute Force", Severity: ingest.SeverityHigh, SourceIP: "1.2.3.4",
		Country: "RU", Technique: "T1110", AbuseConfidence: ptr(95),
	})
	for _, want := range []string{"SSH Brute Force", "1.2.3.4", "RU", "T1110", "95/100"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt missing %q:\n%s", want, p)
		}
	}
}

func TestClaudeAnalyzerHTTP(t *testing.T) {
	var gotModel, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/messages") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		gotBody = string(buf)
		if strings.Contains(gotBody, `"model":"claude-haiku-4-5"`) {
			gotModel = "claude-haiku-4-5"
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"id":"msg_1","type":"message","role":"assistant","model":"claude-haiku-4-5",
			"stop_reason":"end_turn","stop_sequence":null,
			"usage":{"input_tokens":10,"output_tokens":5},
			"content":[{"type":"text","text":"{\"verdict\":\"suspicious\",\"summary\":\"needs a check\"}"}]
		}`))
	}))
	defer srv.Close()

	a := NewClaudeAnalyzer("test-key", "claude-haiku-4-5",
		option.WithBaseURL(srv.URL), option.WithHTTPClient(srv.Client()))
	res, err := a.Analyze(context.Background(), AlertInput{Rule: "SSH Brute Force", Severity: ingest.SeverityHigh})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Verdict != ingest.VerdictSuspicious || res.Summary != "needs a check" {
		t.Fatalf("wrong result: %+v", res)
	}
	if gotModel != "claude-haiku-4-5" {
		t.Fatalf("model not forwarded: body=%s", gotBody)
	}
}

func TestAnalyzerFromEnv(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("LLM_ENABLED", "")
	if _, ok := AnalyzerFromEnv(); ok {
		t.Fatal("with no configuration it should be disabled")
	}
	t.Setenv("LLM_ENABLED", "1")
	a, ok := AnalyzerFromEnv()
	if !ok || a.Name() != "heuristic" {
		t.Fatalf("LLM_ENABLED=1 should be heuristic, got ok=%v name=%v", ok, a)
	}
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	a, ok = AnalyzerFromEnv()
	if !ok || !strings.HasPrefix(a.Name(), "claude(") {
		t.Fatalf("with an API key it should be claude, got %v", a.Name())
	}
}
