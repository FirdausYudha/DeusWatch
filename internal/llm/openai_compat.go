package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// OpenAICompatAnalyzer triages alerts via any OpenAI-compatible Chat Completions API.
// This single driver covers free/open-source, self-hosted models — Ollama, LM Studio,
// vLLM, LocalAI — as well as hosted OpenAI-compatible endpoints (OpenRouter, Groq, …).
// For Ollama the base URL is like http://host:11434/v1 and no API key is needed.
type OpenAICompatAnalyzer struct {
	baseURL string // includes the /v1 prefix, e.g. http://host:11434/v1
	apiKey  string // optional (Bearer); empty for local Ollama
	model   string
	hc      *http.Client
}

// NewOpenAICompatAnalyzer builds the analyzer. An empty model defaults to "llama3.1".
func NewOpenAICompatAnalyzer(baseURL, apiKey, model string) *OpenAICompatAnalyzer {
	if model == "" {
		model = "llama3.1"
	}
	return &OpenAICompatAnalyzer{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		model:   model,
		hc:      &http.Client{Timeout: 120 * time.Second},
	}
}

func (o *OpenAICompatAnalyzer) Name() string { return "openai-compat(" + o.model + ")" }

type ocMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ocRequest struct {
	Model       string      `json:"model"`
	Messages    []ocMessage `json:"messages"`
	Stream      bool        `json:"stream"`
	Temperature float64     `json:"temperature"`
	MaxTokens   int         `json:"max_tokens,omitempty"`
}

type ocResponse struct {
	Choices []struct {
		Message ocMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// chat runs one OpenAI-compatible chat completion and returns the message content.
func (o *OpenAICompatAnalyzer) chat(ctx context.Context, system, user string, maxTokens int) (string, error) {
	reqBody, _ := json.Marshal(ocRequest{
		Model:       o.model,
		Stream:      false,
		Temperature: 0,
		MaxTokens:   maxTokens,
		Messages: []ocMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/chat/completions", bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("llm: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if o.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+o.apiKey)
	}
	resp, err := o.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("llm: call %s: %w", o.baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("llm: %s returned HTTP %d", o.baseURL, resp.StatusCode)
	}
	var out ocResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("llm: decode response: %w", err)
	}
	if out.Error != nil {
		return "", fmt.Errorf("llm: provider error: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("llm: empty response (no choices)")
	}
	return out.Choices[0].Message.Content, nil
}

func (o *OpenAICompatAnalyzer) Analyze(ctx context.Context, in AlertInput) (Result, error) {
	text, err := o.chat(ctx, systemPrompt, buildUserPrompt(in), 512)
	if err != nil {
		return Result{}, err
	}
	return parseResult(text)
}

// Summarize generates an executive report summary from the report data prompt.
func (o *OpenAICompatAnalyzer) Summarize(ctx context.Context, prompt string) (string, error) {
	text, err := o.chat(ctx, reportSystemPrompt, prompt, 700)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(text), nil
}
