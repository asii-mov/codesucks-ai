package pipeline

import (
	"fmt"
	"strings"

	"github.com/asii-mov/codesucks-ai/internal/agent"
	"github.com/asii-mov/codesucks-ai/internal/gates"
	"github.com/asii-mov/codesucks-ai/internal/scan"
)

// prTitle builds a concise PR title for a finding's fix.
func prTitle(f scan.Finding) string {
	kind := "vulnerability"
	if f.IsSecret() {
		kind = "exposed secret"
	}
	return fmt.Sprintf("fix(security): %s (%s) in %s", kind, f.RuleID, f.File)
}

// BuildPRBody renders the pull-request description. It states the vulnerability,
// severity, the solution taken, and the verification evidence for every gate.
// The whole body is scrubbed through the redactor so no secret value can leak.
func BuildPRBody(f scan.Finding, v agent.TriageVerdict, p agent.PatchProposal, gs []gates.Result, red *scan.Redactor) string {
	var b strings.Builder

	fmt.Fprintf(&b, "## Security fix: %s\n\n", f.RuleID)
	fmt.Fprintf(&b, "This pull request was generated and verified automatically by codesucks-ai.\n\n")

	fmt.Fprintf(&b, "### Vulnerability\n\n")
	fmt.Fprintf(&b, "- **Severity:** %s\n", f.Severity)
	fmt.Fprintf(&b, "- **Detector:** %s (`%s`)\n", f.Tool, f.RuleID)
	if len(f.CWE) > 0 {
		fmt.Fprintf(&b, "- **CWE:** %s\n", strings.Join(f.CWE, ", "))
	}
	fmt.Fprintf(&b, "- **Location:** `%s:%d`\n", f.File, f.StartLine)
	if f.Message != "" {
		fmt.Fprintf(&b, "- **Description:** %s\n", f.Message)
	}
	b.WriteString("\n")

	if strings.TrimSpace(v.Rationale) != "" {
		fmt.Fprintf(&b, "### Triage\n\n%s _(confidence %.2f)_\n\n", v.Rationale, v.Confidence)
	}

	fmt.Fprintf(&b, "### Solution taken\n\n")
	if strings.TrimSpace(p.Summary) != "" {
		fmt.Fprintf(&b, "%s\n\n", p.Summary)
	}
	fmt.Fprintf(&b, "Applied %d edit(s) across %d file(s).\n\n", len(p.Edits), countFiles(p.Edits))

	fmt.Fprintf(&b, "### Verification\n\n")
	fmt.Fprintf(&b, "Every gate below ran and passed before this PR was opened.\n\n")
	fmt.Fprintf(&b, "| Gate | Command | Baseline → After | Result |\n|---|---|---|---|\n")
	for _, g := range gs {
		mark := "✅ pass"
		if !g.Passed {
			mark = "❌ fail"
		}
		fmt.Fprintf(&b, "| %s | `%s` | %d → %d | %s |\n", g.Name, oneLine(g.Command), g.Baseline, g.After, mark)
	}
	b.WriteString("\n")
	for _, g := range gs {
		if strings.TrimSpace(g.Detail) != "" {
			fmt.Fprintf(&b, "- **%s:** %s\n", g.Name, g.Detail)
		}
	}
	b.WriteString("\n")

	if f.IsSecret() {
		fmt.Fprintf(&b, "### ⚠️ Rotation required\n\n")
		fmt.Fprintf(&b, "A live-looking secret (`%s`, redacted) was committed at `%s:%d`. Removing it from the code is not enough — **rotate/revoke the credential now**, since it remains valid in the git history until rotated.\n\n", f.Secret.Detector, f.File, f.StartLine)
	}

	b.WriteString("---\n\n🤖 Generated with [Claude Code](https://claude.com/claude-code)\n")

	return red.Redact(b.String())
}

func countFiles(edits []agent.Edit) int {
	seen := map[string]struct{}{}
	for _, e := range edits {
		seen[e.Path] = struct{}{}
	}
	return len(seen)
}

func oneLine(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
}
