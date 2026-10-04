package llm

import (
	"context"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// ClaudeAnalyzer triages alerts via the Anthropic Messages API (official SDK).
// Default model claude-opus-4-8 (most capable); change it via ANTHROPIC_MODEL.
type ClaudeAnalyzer struct {
	client anthropic.Client
	model  anthropic.Model
}

// NewClaudeAnalyzer creates an analyzer. An empty model → claude-opus-4-8. opts are
// used by tests to point the base URL at a mock server.
func NewClaudeAnalyzer(apiKey, model string, opts ...option.RequestOption) *ClaudeAnalyzer {
	m := anthropic.ModelClaudeOpus4_8
	if model != "" {
		m = anthropic.Model(model)
	}
	all := append([]option.RequestOption{option.WithAPIKey(apiKey)}, opts...)
	return &ClaudeAnalyzer{client: anthropic.NewClient(all...), model: m}
}

func (c *ClaudeAnalyzer) Name() string { return "claude(" + string(c.model) + ")" }

// Summarize generates an executive report summary from the report data prompt.
func (c *ClaudeAnalyzer) Summarize(ctx context.Context, systemPrompt, dataPrompt string) (string, error) {
	if systemPrompt == "" {
		systemPrompt = DefaultReportSystemPrompt
	}
	resp, err := c.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     c.model,
		MaxTokens: 700,
		System:    []anthropic.TextBlockParam{{Text: systemPrompt}},
		Messages:  []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(dataPrompt))},
	})
	if err != nil {
		return "", fmt.Errorf("llm: call Claude: %w", err)
	}
	var text string
	for _, block := range resp.Content {
		if tb, ok := block.AsAny().(anthropic.TextBlock); ok {
			text += tb.Text
		}
	}
	return strings.TrimSpace(text), nil
}

func (c *ClaudeAnalyzer) Chat(ctx context.Context, systemPrompt string, history []ChatTurn, user string) (string, error) {
	msgs := make([]anthropic.MessageParam, 0, len(history)+1)
	for _, t := range history {
		// Only two roles exist on the wire here, and an unrecognised one is treated as the user
		// rather than trusted, so a client cannot smuggle instructions in as another role.
		if t.Role == "assistant" {
			msgs = append(msgs, anthropic.NewAssistantMessage(anthropic.NewTextBlock(t.Content)))
			continue
		}
		msgs = append(msgs, anthropic.NewUserMessage(anthropic.NewTextBlock(t.Content)))
	}
	msgs = append(msgs, anthropic.NewUserMessage(anthropic.NewTextBlock(user)))
	resp, err := c.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:       c.model,
		MaxTokens:   800,
		Temperature: anthropic.Float(0.4),
		System:      []anthropic.TextBlockParam{{Text: systemPrompt}},
		Messages:    msgs,
	})
	if err != nil {
		return "", fmt.Errorf("llm: call Claude: %w", err)
	}
	var text string
	for _, block := range resp.Content {
		if tb, ok := block.AsAny().(anthropic.TextBlock); ok {
			text += tb.Text
		}
	}
	return strings.TrimSpace(text), nil
}

func (c *ClaudeAnalyzer) Analyze(ctx context.Context, in AlertInput) (Result, error) {
	resp, err := c.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     c.model,
		MaxTokens: 512,
		System:    []anthropic.TextBlockParam{{Text: systemPrompt}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(buildUserPrompt(in))),
		},
	})
	if err != nil {
		return Result{}, fmt.Errorf("llm: call Claude: %w", err)
	}
	var text string
	for _, block := range resp.Content {
		if tb, ok := block.AsAny().(anthropic.TextBlock); ok {
			text += tb.Text
		}
	}
	return parseResult(text)
}
