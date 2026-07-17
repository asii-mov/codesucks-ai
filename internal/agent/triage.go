package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/asii-mov/codesucks-ai/internal/repo"
	"github.com/asii-mov/codesucks-ai/internal/scan"
)

// Verdict values from the triage agent.
const (
	VerdictTruePositive  = "true_positive"
	VerdictFalsePositive = "false_positive"
	VerdictUncertain     = "uncertain"
)

// TriageVerdict is the structured result of triaging one finding.
type TriageVerdict struct {
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	Rationale  string  `json:"rationale"`
}

// TriagedFinding pairs a finding with its verdict (or the error that prevented
// one).
type TriagedFinding struct {
	Finding scan.Finding
	Verdict TriageVerdict
	Usage   Usage
	Err     error
}

func submitTriageTool() anthropic.ToolUnionParam {
	t := anthropic.ToolParam{
		Name:        "submit_triage",
		Description: anthropic.String("Submit the final triage verdict for the finding."),
		Strict:      anthropic.Bool(true),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{
				"verdict":    map[string]any{"type": "string", "enum": []string{VerdictTruePositive, VerdictFalsePositive, VerdictUncertain}},
				"confidence": map[string]any{"type": "number", "description": "Confidence from 0 to 1."},
				"rationale":  map[string]any{"type": "string", "description": "Concise justification."},
			},
			Required:    []string{"verdict", "confidence", "rationale"},
			ExtraFields: map[string]any{"additionalProperties": false},
		},
	}
	return anthropic.ToolUnionParam{OfTool: &t}
}

// Triage classifies a single finding. fs must be a read-only sandbox over the
// cloned repository.
func Triage(ctx context.Context, llm LLM, model string, fs *repo.Sandbox, f scan.Finding, b Budget) (TriageVerdict, Usage, error) {
	tools := append(readOnlyTools(), submitTriageTool())
	raw, usage, err := Run(ctx, llm, model, triageSystem, buildTriageUser(f), tools, "submit_triage", fs, b)
	if err != nil {
		return TriageVerdict{}, usage, err
	}
	var v TriageVerdict
	if err := json.Unmarshal(raw, &v); err != nil {
		return TriageVerdict{}, usage, fmt.Errorf("parse triage verdict: %w", err)
	}
	return v, usage, nil
}

// TriageAll triages every finding using a worker pool of the given size. The
// shared sandbox is safe for concurrent reads. Results preserve input order.
func TriageAll(ctx context.Context, llm LLM, model string, fs *repo.Sandbox, findings []scan.Finding, concurrency int, b Budget) []TriagedFinding {
	if concurrency < 1 {
		concurrency = 1
	}
	out := make([]TriagedFinding, len(findings))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, f := range findings {
		wg.Add(1)
		go func(i int, f scan.Finding) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			v, u, err := Triage(ctx, llm, model, fs, f, b)
			out[i] = TriagedFinding{Finding: f, Verdict: v, Usage: u, Err: err}
		}(i, f)
	}
	wg.Wait()
	return out
}
