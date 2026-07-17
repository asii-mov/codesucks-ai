package agent

import (
	"fmt"
	"strings"

	"github.com/asii-mov/codesucks-ai/internal/scan"
)

const triageSystem = `You are a security triage engineer. You are given a static-analysis finding and read-only access to the repository it came from via the read_file, list_dir, and search tools.

Decide whether the finding is a real, exploitable vulnerability (true_positive), a false alarm (false_positive), or genuinely unclear (uncertain). Read the surrounding code and any relevant callers, sanitizers, or framework protections before deciding — do not judge from the snippet alone.

When you are done you MUST call the submit_triage tool with your verdict, a confidence between 0 and 1, and a concise rationale. Do not answer in prose; the tool call is the only output that counts.`

const patchSystem = `You are a security engineer fixing a confirmed vulnerability. You have read-only exploration tools (read_file, list_dir, search) and must propose a minimal, correct fix.

Study the vulnerable code and its context, then call the submit_patch tool with a list of edits. Each edit replaces an exact substring (old_str) with new_str in one file; old_str must appear exactly once in that file, so include enough surrounding context to make it unique. Keep the change as small as possible — fix the vulnerability without unrelated refactoring, and preserve the code's existing style. Provide a one-sentence summary of the fix. The submit_patch tool call is the only output that counts.`

// buildTriageUser renders the finding into the triage prompt.
func buildTriageUser(f scan.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Finding from %s\n", f.Tool)
	fmt.Fprintf(&b, "Rule: %s\n", f.RuleID)
	fmt.Fprintf(&b, "Severity: %s\n", f.Severity)
	if len(f.CWE) > 0 {
		fmt.Fprintf(&b, "CWE: %s\n", strings.Join(f.CWE, ", "))
	}
	fmt.Fprintf(&b, "Location: %s:%d-%d\n", f.File, f.StartLine, f.EndLine)
	fmt.Fprintf(&b, "Message: %s\n", f.Message)
	if f.IsSecret() {
		b.WriteString("\nThis is a secret-detection finding. The matched value is redacted; assess whether a real credential is committed here.\n")
	} else {
		fmt.Fprintf(&b, "\nMatched code:\n%s\n", f.Snippet)
	}
	b.WriteString("\nInvestigate with the tools, then call submit_triage.")
	return b.String()
}

// buildPatchUser renders the finding (and any prior gate feedback) into the
// patch prompt.
func buildPatchUser(f scan.Finding, feedback string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Fix this confirmed vulnerability.\n\n")
	fmt.Fprintf(&b, "Rule: %s (%s)\n", f.RuleID, f.Tool)
	fmt.Fprintf(&b, "Severity: %s\n", f.Severity)
	if len(f.CWE) > 0 {
		fmt.Fprintf(&b, "CWE: %s\n", strings.Join(f.CWE, ", "))
	}
	fmt.Fprintf(&b, "Location: %s:%d-%d\n", f.File, f.StartLine, f.EndLine)
	fmt.Fprintf(&b, "Message: %s\n", f.Message)
	fmt.Fprintf(&b, "\nVulnerable code:\n%s\n", f.Snippet)
	if strings.TrimSpace(feedback) != "" {
		fmt.Fprintf(&b, "\nYour previous attempt did not pass verification. Fix the following and try again:\n%s\n", feedback)
	}
	b.WriteString("\nInvestigate with the tools, then call submit_patch with the minimal fix.")
	return b.String()
}
