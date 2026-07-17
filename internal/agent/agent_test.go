package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/asii-mov/codesucks-ai/internal/repo"
	"github.com/asii-mov/codesucks-ai/internal/scan"
)

// fakeLLM returns a scripted queue of responses, one per call.
type fakeLLM struct {
	responses []*anthropic.Message
	calls     int32
}

func (f *fakeLLM) New(ctx context.Context, params anthropic.MessageNewParams, opts ...option.RequestOption) (*anthropic.Message, error) {
	n := int(atomic.AddInt32(&f.calls, 1)) - 1
	if n >= len(f.responses) {
		return nil, fmt.Errorf("fakeLLM: no scripted response for call %d", n)
	}
	return f.responses[n], nil
}

// toolUseMsg builds an assistant Message containing a single tool_use block,
// via the SDK's own JSON unmarshaling so JSON.Input.Raw() is populated.
func toolUseMsg(t *testing.T, name string, input any) *anthropic.Message {
	t.Helper()
	inputJSON, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	wire := fmt.Sprintf(`{"id":"msg_1","type":"message","role":"assistant","model":"m","stop_reason":"tool_use","content":[{"type":"tool_use","id":"toolu_1","name":%q,"input":%s}],"usage":{"input_tokens":10,"output_tokens":5}}`, name, inputJSON)
	var m anthropic.Message
	if err := json.Unmarshal([]byte(wire), &m); err != nil {
		t.Fatalf("unmarshal fake message: %v", err)
	}
	return &m
}

// textMsg builds an assistant Message with only a text block (no tool call).
func textMsg(t *testing.T, text string) *anthropic.Message {
	t.Helper()
	wire := fmt.Sprintf(`{"id":"msg_1","type":"message","role":"assistant","model":"m","stop_reason":"end_turn","content":[{"type":"text","text":%q}],"usage":{"input_tokens":10,"output_tokens":5}}`, text)
	var m anthropic.Message
	if err := json.Unmarshal([]byte(wire), &m); err != nil {
		t.Fatalf("unmarshal fake text message: %v", err)
	}
	return &m
}

func testSandbox(t *testing.T) *repo.Sandbox {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("eval(req.query.x)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb, err := repo.NewSandbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	return sb
}

func testBudget() Budget {
	return Budget{MaxIterations: 5, MaxTokens: 1_000_000, Timeout: 30 * time.Second}
}

func sampleFinding() scan.Finding {
	return scan.Finding{
		Fingerprint: "fp1", Tool: scan.ToolSemgrep, RuleID: "js.eval",
		Severity: scan.SeverityCritical, File: "app.js", StartLine: 1, EndLine: 1,
		Snippet: "eval(req.query.x)", Message: "eval injection",
	}
}

func TestTriage_ReadThenSubmit(t *testing.T) {
	llm := &fakeLLM{responses: []*anthropic.Message{
		toolUseMsg(t, toolReadFile, map[string]any{"path": "app.js"}),
		toolUseMsg(t, "submit_triage", map[string]any{
			"verdict": VerdictTruePositive, "confidence": 0.95, "rationale": "user input flows to eval",
		}),
	}}
	v, usage, err := Triage(context.Background(), llm, "m", testSandbox(t), sampleFinding(), testBudget())
	if err != nil {
		t.Fatal(err)
	}
	if v.Verdict != VerdictTruePositive || v.Confidence != 0.95 {
		t.Errorf("unexpected verdict: %+v", v)
	}
	if usage.Total() == 0 {
		t.Error("expected some token usage")
	}
	if llm.calls != 2 {
		t.Errorf("expected 2 calls (read, submit), got %d", llm.calls)
	}
}

func TestPatch_Submit(t *testing.T) {
	llm := &fakeLLM{responses: []*anthropic.Message{
		toolUseMsg(t, "submit_patch", map[string]any{
			"edits":   []map[string]any{{"path": "app.js", "old_str": "eval(req.query.x)", "new_str": "safeEval(req.query.x)"}},
			"summary": "replace eval with safeEval",
		}),
	}}
	p, _, err := Patch(context.Background(), llm, "m", testSandbox(t), sampleFinding(), "", testBudget())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Edits) != 1 || p.Edits[0].NewStr != "safeEval(req.query.x)" {
		t.Errorf("unexpected patch: %+v", p)
	}
}

func TestRun_ForcedSubmissionOnBudgetExhaustion(t *testing.T) {
	// The first (and only) normal iteration reads and exhausts the token
	// budget; the forced final call then submits.
	llm := &fakeLLM{responses: []*anthropic.Message{
		toolUseMsg(t, toolReadFile, map[string]any{"path": "app.js"}),
		toolUseMsg(t, "submit_triage", map[string]any{
			"verdict": VerdictUncertain, "confidence": 0.4, "rationale": "ran out of budget",
		}),
	}}
	// MaxTokens forces a break after the first iteration (15 tokens >= 10).
	b := Budget{MaxIterations: 5, MaxTokens: 10, Timeout: 30 * time.Second}
	v, _, err := Triage(context.Background(), llm, "m", testSandbox(t), sampleFinding(), b)
	if err != nil {
		t.Fatal(err)
	}
	if v.Verdict != VerdictUncertain {
		t.Errorf("expected forced submission verdict, got %+v", v)
	}
	// One read iteration + one forced submission = 2 calls.
	if llm.calls != 2 {
		t.Errorf("expected 2 calls, got %d", llm.calls)
	}
}

func TestRun_NeedsReviewWhenNeverSubmits(t *testing.T) {
	// The model reads once, budget breaks, and the forced call still only
	// returns text — so the loop reports ErrNoSubmission.
	llm := &fakeLLM{responses: []*anthropic.Message{
		toolUseMsg(t, toolReadFile, map[string]any{"path": "app.js"}),
		textMsg(t, "I cannot decide."),
	}}
	b := Budget{MaxIterations: 1, MaxTokens: 1_000_000, Timeout: 30 * time.Second}
	_, _, err := Triage(context.Background(), llm, "m", testSandbox(t), sampleFinding(), b)
	if !errors.Is(err, ErrNoSubmission) {
		t.Errorf("expected ErrNoSubmission, got %v", err)
	}
}

func TestRun_PropagatesAPIError(t *testing.T) {
	llm := &fakeLLM{responses: nil} // first call fails: no scripted response
	_, _, err := Triage(context.Background(), llm, "m", testSandbox(t), sampleFinding(), testBudget())
	if err == nil {
		t.Fatal("expected an error when the API call fails")
	}
}
