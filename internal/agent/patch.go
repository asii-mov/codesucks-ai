package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/asii-mov/codesucks-ai/internal/repo"
	"github.com/asii-mov/codesucks-ai/internal/scan"
)

// Edit is one exact-substring replacement in a file.
type Edit struct {
	Path   string `json:"path"`
	OldStr string `json:"old_str"`
	NewStr string `json:"new_str"`
}

// PatchProposal is the structured result of the patch agent.
type PatchProposal struct {
	Edits   []Edit `json:"edits"`
	Summary string `json:"summary"`
}

func submitPatchTool() anthropic.ToolUnionParam {
	// Not marked strict: nested array schemas validate more reliably in code,
	// and every edit is re-checked by the sandbox's exactly-one-match apply.
	t := anthropic.ToolParam{
		Name:        "submit_patch",
		Description: anthropic.String("Submit the minimal fix as a list of exact-substring edits."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{
				"edits": map[string]any{
					"type":        "array",
					"description": "Edits to apply. Each replaces old_str with new_str in one file.",
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"path":    map[string]any{"type": "string", "description": "Repository-relative file path."},
							"old_str": map[string]any{"type": "string", "description": "Exact text to replace; must be unique in the file."},
							"new_str": map[string]any{"type": "string", "description": "Replacement text."},
						},
						"required": []string{"path", "old_str", "new_str"},
					},
				},
				"summary": map[string]any{"type": "string", "description": "One-sentence description of the fix."},
			},
			Required: []string{"edits", "summary"},
		},
	}
	return anthropic.ToolUnionParam{OfTool: &t}
}

// Patch asks the patch agent for a minimal fix. feedback, when non-empty,
// carries a prior gate failure to steer a retry.
func Patch(ctx context.Context, llm LLM, model string, fs *repo.Sandbox, f scan.Finding, feedback string, b Budget) (PatchProposal, Usage, error) {
	tools := append(readOnlyTools(), submitPatchTool())
	raw, usage, err := Run(ctx, llm, model, patchSystem, buildPatchUser(f, feedback), tools, "submit_patch", fs, b)
	if err != nil {
		return PatchProposal{}, usage, err
	}
	var p PatchProposal
	if err := json.Unmarshal(raw, &p); err != nil {
		return PatchProposal{}, usage, fmt.Errorf("parse patch proposal: %w", err)
	}
	if len(p.Edits) == 0 {
		return PatchProposal{}, usage, fmt.Errorf("patch proposal contained no edits")
	}
	return p, usage, nil
}
