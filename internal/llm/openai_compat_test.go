package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"deuswatch/internal/ingest"
)

func TestOpenAICompatAnalyzer(t *testing.T) {
	var gotPath, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"verdict\":\"malicious\",\"summary\":\"brute force from a known-bad IP\"}"}}]}`))
	}))
	defer srv.Close()

	a := NewOpenAICompatAnalyzer(srv.URL+"/v1", "secret-key", "llama3.1")
	res, err := a.Analyze(context.Background(), AlertInput{Rule: "SSH Brute Force", Severity: ingest.SeverityHigh, SourceIP: "45.155.205.99"})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Verdict != ingest.VerdictMalicious || res.Summary == "" {
		t.Fatalf("wrong result: %+v", res)
	}
	if gotPath != "/v1/chat/completions" {
		t.Fatalf("wrong path: %q", gotPath)
	}
	if gotAuth != "Bearer secret-key" {
		t.Fatalf("missing/wrong auth header: %q", gotAuth)
	}
	// The request must carry the model + a system and user message.
	var req ocRequest
	if err := json.Unmarshal([]byte(gotBody), &req); err != nil {
		t.Fatalf("request body not JSON: %v", err)
	}
	if req.Model != "llama3.1" || len(req.Messages) != 2 || req.Messages[0].Role != "system" {
		t.Fatalf("wrong request payload: %+v", req)
	}
}

func TestNewAnalyzerProviders(t *testing.T) {
	// Ollama with no base URL gets the docker-host default; no API key required.
	if a, err := NewAnalyzer("ollama", "", "", ""); err != nil {
		t.Fatalf("ollama: %v", err)
	} else if !strings.Contains(a.Name(), "openai-compat") {
		t.Fatalf("ollama should be an openai-compat analyzer: %s", a.Name())
	}
	// OpenAI-compatible requires a base URL.
	if _, err := NewAnalyzer("openai-compatible", "", "", ""); err == nil {
		t.Fatal("openai-compatible without base_url must error")
	}
	// Anthropic requires an API key.
	if _, err := NewAnalyzer("anthropic", "", "", ""); err == nil {
		t.Fatal("anthropic without api_key must error")
	}
	if _, err := NewAnalyzer("nope", "", "", ""); err == nil {
		t.Fatal("unknown provider must error")
	}
}
