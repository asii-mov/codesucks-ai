package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/asii-mov/codesucks-ai/internal/agent"
	"github.com/asii-mov/codesucks-ai/internal/gates"
	"github.com/asii-mov/codesucks-ai/internal/scan"
)

// Finding outcome statuses.
const (
	StatusFalsePositive = "false-positive"
	StatusTruePositive  = "true-positive" // confirmed, not yet patched (or dry-run)
	StatusNeedsReview   = "needs-review"
	StatusPatchedPR     = "patched-pr"
	StatusPatchFailed   = "patch-failed"
	StatusSkippedCap    = "skipped-cap"
)

// FindingOutcome records what happened to one finding.
type FindingOutcome struct {
	Fingerprint string         `json:"fingerprint"`
	Tool        string         `json:"tool"`
	RuleID      string         `json:"rule_id"`
	Severity    string         `json:"severity"`
	File        string         `json:"file"`
	Line        int            `json:"line"`
	Status      string         `json:"status"`
	Detail      string         `json:"detail,omitempty"`
	PRNumber    int            `json:"pr_number,omitempty"`
	PRURL       string         `json:"pr_url,omitempty"`
	Gates       []gates.Result `json:"gates,omitempty"`
}

// RunReport is the machine- and human-readable summary of one run.
type RunReport struct {
	RunID        string           `json:"run_id"`
	Repo         string           `json:"repo"`
	Stack        string           `json:"stack"`
	StartedAt    time.Time        `json:"started_at"`
	EndedAt      time.Time        `json:"ended_at"`
	Found        int              `json:"found"`
	Triaged      int              `json:"triaged"`
	TruePositive int              `json:"true_positive"`
	Patched      int              `json:"patched"`
	PRd          int              `json:"prs_opened"`
	NeedsReview  int              `json:"needs_review"`
	Skipped      int              `json:"skipped"`
	Findings     []FindingOutcome `json:"findings"`
	TriageTokens agent.Usage      `json:"triage_tokens"`
	PatchTokens  agent.Usage      `json:"patch_tokens"`
	EstCostUSD   float64          `json:"est_cost_usd"`
}

// estimateCost applies rough per-model token pricing (Haiku $1/$5, Opus
// $5/$25 per million tokens).
func (r *RunReport) estimateCost() {
	const million = 1_000_000.0
	triage := (float64(r.TriageTokens.InputTokens)*1.0 + float64(r.TriageTokens.OutputTokens)*5.0) / million
	patch := (float64(r.PatchTokens.InputTokens)*5.0 + float64(r.PatchTokens.OutputTokens)*25.0) / million
	r.EstCostUSD = triage + patch
}

// WriteReports writes report.json and report.md into dir, scrubbing any secret
// value through the redactor first.
func WriteReports(dir string, r RunReport, red *scan.Redactor) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), []byte(red.Redact(string(raw))), 0o644); err != nil {
		return err
	}
	md := red.Redact(renderMarkdown(r))
	return os.WriteFile(filepath.Join(dir, "report.md"), []byte(md), 0o644)
}

func renderMarkdown(r RunReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# codesucks-ai report\n\n")
	fmt.Fprintf(&b, "- **Repository:** %s\n", r.Repo)
	fmt.Fprintf(&b, "- **Stack:** %s\n", r.Stack)
	fmt.Fprintf(&b, "- **Run:** %s\n", r.RunID)
	fmt.Fprintf(&b, "- **Duration:** %s\n\n", r.EndedAt.Sub(r.StartedAt).Round(time.Second))

	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "| Metric | Count |\n|---|---|\n")
	fmt.Fprintf(&b, "| Findings | %d |\n", r.Found)
	fmt.Fprintf(&b, "| Triaged | %d |\n", r.Triaged)
	fmt.Fprintf(&b, "| True positives | %d |\n", r.TruePositive)
	fmt.Fprintf(&b, "| Patched | %d |\n", r.Patched)
	fmt.Fprintf(&b, "| PRs opened | %d |\n", r.PRd)
	fmt.Fprintf(&b, "| Needs review | %d |\n", r.NeedsReview)
	fmt.Fprintf(&b, "| Skipped | %d |\n", r.Skipped)
	fmt.Fprintf(&b, "| Est. cost | $%.2f |\n\n", r.EstCostUSD)

	fmt.Fprintf(&b, "## Findings\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("_None._\n")
		return b.String()
	}
	fmt.Fprintf(&b, "| Severity | Rule | Location | Status | PR |\n|---|---|---|---|---|\n")
	for _, f := range r.Findings {
		pr := ""
		if f.PRURL != "" {
			pr = fmt.Sprintf("[#%d](%s)", f.PRNumber, f.PRURL)
		}
		fmt.Fprintf(&b, "| %s | %s | %s:%d | %s | %s |\n",
			f.Severity, f.RuleID, f.File, f.Line, f.Status, pr)
	}
	return b.String()
}
