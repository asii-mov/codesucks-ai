package agent

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/asii-mov/codesucks-ai/internal/repo"
)

// ErrNoSubmission means the loop ended without the model ever calling the
// submission tool, even after a final forced attempt. The caller marks the
// finding as needing human review and continues.
var ErrNoSubmission = errors.New("agent produced no submission")

const maxTokensPerCall = 8192

// Run drives a bounded tool-loop until the model calls submitName, whose raw
// JSON input is returned. Read-only tool calls are executed against fs. On
// budget or iteration exhaustion, one final call forces the submission tool;
// if that still yields nothing, ErrNoSubmission is returned.
func Run(ctx context.Context, llm LLM, model, system, user string, tools []anthropic.ToolUnionParam, submitName string, fs *repo.Sandbox, b Budget) (json.RawMessage, Usage, error) {
	ctx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()

	var usage Usage
	sys := []anthropic.TextBlockParam{{Text: system}}
	msgs := []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock(user)),
	}

	for i := 0; i < b.MaxIterations; i++ {
		resp, err := llm.New(ctx, anthropic.MessageNewParams{
			Model:     anthropic.Model(model),
			MaxTokens: maxTokensPerCall,
			System:    sys,
			Messages:  msgs,
			Tools:     tools,
		})
		if err != nil {
			return nil, usage, err
		}
		usage.add(resp.Usage)
		msgs = append(msgs, resp.ToParam())

		submission, results := handleContent(fs, resp, submitName)
		if submission != nil {
			return submission, usage, nil
		}
		if len(results) == 0 {
			break // no tool call and no submission — force one
		}
		if usage.Total() >= b.MaxTokens {
			break
		}
		msgs = append(msgs, anthropic.NewUserMessage(results...))
	}

	// Final forced submission.
	resp, err := llm.New(ctx, anthropic.MessageNewParams{
		Model:      anthropic.Model(model),
		MaxTokens:  maxTokensPerCall,
		System:     sys,
		Messages:   msgs,
		Tools:      tools,
		ToolChoice: anthropic.ToolChoiceParamOfTool(submitName),
	})
	if err != nil {
		return nil, usage, err
	}
	usage.add(resp.Usage)
	if submission, _ := handleContent(fs, resp, submitName); submission != nil {
		return submission, usage, nil
	}
	return nil, usage, ErrNoSubmission
}

// handleContent walks a response's content blocks: it returns the submission
// tool's raw input if present, otherwise the tool_result blocks for every
// read-only tool call the model made.
func handleContent(fs *repo.Sandbox, resp *anthropic.Message, submitName string) (json.RawMessage, []anthropic.ContentBlockParamUnion) {
	var results []anthropic.ContentBlockParamUnion
	for _, block := range resp.Content {
		use, ok := block.AsAny().(anthropic.ToolUseBlock)
		if !ok {
			continue
		}
		if use.Name == submitName {
			return json.RawMessage(use.JSON.Input.Raw()), nil
		}
		out, isErr := dispatchTool(fs, use.Name, use.JSON.Input.Raw())
		results = append(results, anthropic.NewToolResultBlock(use.ID, out, isErr))
	}
	return nil, results
}
