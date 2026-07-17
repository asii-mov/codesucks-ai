// Package agent runs bounded Anthropic tool-loops that triage findings and
// propose patches. All structured results arrive as tool-call inputs; the
// package never parses free-form model prose.
package agent

import (
	"context"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// LLM is the minimal surface the agent loop needs from the Anthropic client.
// The SDK's *MessageService satisfies it directly, and tests supply a scripted
// fake.
type LLM interface {
	New(ctx context.Context, params anthropic.MessageNewParams, opts ...option.RequestOption) (*anthropic.Message, error)
}

// NewLLM returns a production LLM backed by the Anthropic API.
func NewLLM(apiKey string) LLM {
	client := anthropic.NewClient(option.WithAPIKey(apiKey))
	return &client.Messages
}

// Usage accumulates token counts across the calls in one loop.
type Usage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	CacheRead    int64 `json:"cache_read_tokens"`
}

func (u *Usage) add(m anthropic.Usage) {
	u.InputTokens += m.InputTokens
	u.OutputTokens += m.OutputTokens
	u.CacheRead += m.CacheReadInputTokens
}

// Total is the billable input+output token count.
func (u Usage) Total() int64 { return u.InputTokens + u.OutputTokens }

// Add merges another usage tally into this one.
func (u *Usage) Add(other Usage) {
	u.InputTokens += other.InputTokens
	u.OutputTokens += other.OutputTokens
	u.CacheRead += other.CacheRead
}

// Budget bounds a single per-finding loop.
type Budget struct {
	MaxIterations int
	MaxTokens     int64
	Timeout       time.Duration
}

// DefaultBudget is the standard per-finding budget.
func DefaultBudget() Budget {
	return Budget{MaxIterations: 12, MaxTokens: 200000, Timeout: 5 * time.Minute}
}
