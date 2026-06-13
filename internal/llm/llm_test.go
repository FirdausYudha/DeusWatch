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
		{"abuse tinggi", AlertInput{Severity: ingest.SeverityHigh, AbuseConfidence: ptr(95)}, ingest.VerdictMalicious},
		{"otx", AlertInput{Severity: ingest.SeverityMedium, OTXPulseCount: ptr(7)}, ingest.VerdictMalicious},
		{"severity tinggi", AlertInput{Severity: ingest.SeverityHigh, AbuseConfidence: ptr(10)}, ingest.VerdictSuspicious},
		{"benign", AlertInput{Severity: ingest.SeverityLow, AbuseConfidence: ptr(2)}, ingest.VerdictBenign},
		{"perlu tinjau", AlertInput{Severity: ingest.SeverityMedium, AbuseConfidence: ptr(20)}, ingest.VerdictNeedsReview},
	}
	for _, c := range cases {
		res, err := a.Analyze(context.Background(), c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if res.Verdict != c.want {
			t.Errorf("%s: vonis %q, mau %q", c.name, res.Verdict, c.want)
		}
		if res.Summary == "" {
			t.Errorf("%s: ringkasan kosong", c.name)
		}
	}
}

func TestParseResult(t *testing.T) {
	// Toleran terhadap teks pembungkus + vonis tak dikenal -> needs_review.
	r, err := parseResult("Tentu:\n{\"verdict\":\"malicious\",\"summary\":\"brute force\"}\nselesai")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.Verdict != ingest.VerdictMalicious || r.Summary != "brute force" {
		t.Fatalf("hasil salah: %+v", r)
	}
	r2, _ := parseResult(`{"verdict":"ngawur","summary":"x"}`)
	if r2.Verdict != ingest.VerdictNeedsReview {
		t.Fatalf("vonis tak dikenal harus needs_review, dapat %q", r2.Verdict)
	}
	if _, err := parseResult("tanpa json"); err == nil {
		t.Fatal("teks tanpa JSON harus error")
	}
}

func TestBuildUserPrompt(t *testing.T) {
	p := buildUserPrompt(AlertInput{
		Rule: "SSH Brute Force", Severity: ingest.SeverityHigh, SourceIP: "1.2.3.4",
		Country: "RU", Technique: "T1110", AbuseConfidence: ptr(95),
	})
	for _, want := range []string{"SSH Brute Force", "1.2.3.4", "RU", "T1110", "95/100"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt tak memuat %q:\n%s", want, p)
		}
	}
}

func TestClaudeAnalyzerHTTP(t *testing.T) {
	var gotModel, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/messages") {
			t.Errorf("path tak terduga: %s", r.URL.Path)
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
			"content":[{"type":"text","text":"{\"verdict\":\"suspicious\",\"summary\":\"perlu cek\"}"}]
		}`))
	}))
	defer srv.Close()

	a := NewClaudeAnalyzer("test-key", "claude-haiku-4-5",
		option.WithBaseURL(srv.URL), option.WithHTTPClient(srv.Client()))
	res, err := a.Analyze(context.Background(), AlertInput{Rule: "SSH Brute Force", Severity: ingest.SeverityHigh})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Verdict != ingest.VerdictSuspicious || res.Summary != "perlu cek" {
		t.Fatalf("hasil salah: %+v", res)
	}
	if gotModel != "claude-haiku-4-5" {
		t.Fatalf("model tak diteruskan: body=%s", gotBody)
	}
}

func TestAnalyzerFromEnv(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("LLM_ENABLED", "")
	if _, ok := AnalyzerFromEnv(); ok {
		t.Fatal("tanpa konfigurasi harus nonaktif")
	}
	t.Setenv("LLM_ENABLED", "1")
	a, ok := AnalyzerFromEnv()
	if !ok || a.Name() != "heuristic" {
		t.Fatalf("LLM_ENABLED=1 harus heuristic, dapat ok=%v name=%v", ok, a)
	}
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	a, ok = AnalyzerFromEnv()
	if !ok || !strings.HasPrefix(a.Name(), "claude(") {
		t.Fatalf("dengan API key harus claude, dapat %v", a.Name())
	}
}
