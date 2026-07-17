package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// semgrepOut mirrors the top-level shape of `semgrep --json` output.
type semgrepOut struct {
	Results []semgrepResult `json:"results"`
}

type semgrepPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepResult struct {
	CheckID string     `json:"check_id"`
	Path    string     `json:"path"`
	Start   semgrepPos `json:"start"`
	End     semgrepPos `json:"end"`
	Extra   struct {
		Message  string `json:"message"`
		Lines    string `json:"lines"`
		Severity string `json:"severity"`
		Metadata struct {
			CWE        json.RawMessage `json:"cwe"`
			Impact     string          `json:"impact"`
			Confidence string          `json:"confidence"`
		} `json:"metadata"`
	} `json:"extra"`
}

// RunSemgrep runs semgrep over dir (optionally restricted to paths) and returns
// normalized findings. Output is written to a temp JSON file and read back —
// stdout is never scraped. Exit codes 0 (no findings) and 1 (findings) are
// success; anything else is a failure.
func RunSemgrep(ctx context.Context, semgrepPath, config, dir string, paths ...string) ([]Finding, error) {
	outFile, err := os.CreateTemp("", "semgrep-*.json")
	if err != nil {
		return nil, fmt.Errorf("semgrep: temp file: %w", err)
	}
	outPath := outFile.Name()
	outFile.Close()
	defer os.Remove(outPath)

	args := []string{
		"scan",
		"--json",
		"--output", outPath,
		"--metrics=off",
		"--config", config,
		"--timeout", "300",
	}
	if len(paths) == 0 {
		args = append(args, ".")
	} else {
		args = append(args, paths...)
	}

	cmd := exec.CommandContext(ctx, semgrepPath, args...)
	cmd.Dir = dir
	combined, runErr := cmd.CombinedOutput()
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			if code := ee.ExitCode(); code == 0 || code == 1 {
				// findings present or none — both fine
			} else {
				return nil, fmt.Errorf("semgrep: exit %d: %s", code, tail(combined))
			}
		} else {
			return nil, fmt.Errorf("semgrep: %w", runErr)
		}
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("semgrep: read output: %w", err)
	}
	return parseSemgrepJSON(data)
}

// parseSemgrepJSON converts raw semgrep JSON into normalized findings.
func parseSemgrepJSON(data []byte) ([]Finding, error) {
	var out semgrepOut
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("semgrep: parse json: %w", err)
	}
	findings := make([]Finding, 0, len(out.Results))
	for _, r := range out.Results {
		path := filepath.ToSlash(r.Path)
		// Always compute our own content-based fingerprint. Semgrep's
		// extra.fingerprint is unreliable when logged out of the registry — it
		// emits the sentinel "requires login" for every finding, which would
		// collapse all of them to one on dedup.
		fp := Fingerprint(ToolSemgrep, r.CheckID, path, r.Extra.Lines)
		findings = append(findings, Finding{
			Fingerprint: fp,
			Tool:        ToolSemgrep,
			RuleID:      r.CheckID,
			Severity:    semgrepSeverity(r.Extra.Severity, r.Extra.Metadata.Impact, r.Extra.Metadata.Confidence),
			CWE:         parseCWE(r.Extra.Metadata.CWE),
			File:        path,
			StartLine:   r.Start.Line,
			EndLine:     r.End.Line,
			Snippet:     r.Extra.Lines,
			Message:     r.Extra.Message,
		})
	}
	return findings, nil
}

// semgrepSeverity maps semgrep's severity to the normalized scale, promoting to
// CRITICAL when the rule metadata marks both impact and confidence HIGH.
func semgrepSeverity(sev, impact, confidence string) Severity {
	base := SeverityLow
	switch strings.ToUpper(sev) {
	case "ERROR":
		base = SeverityHigh
	case "WARNING":
		base = SeverityMedium
	case "INFO":
		base = SeverityLow
	}
	if strings.EqualFold(impact, "HIGH") && strings.EqualFold(confidence, "HIGH") {
		return SeverityCritical
	}
	return base
}

// parseCWE handles semgrep's cwe metadata field, which may be a single string
// or an array of strings.
func parseCWE(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil && one != "" {
		return []string{one}
	}
	return nil
}

// tail returns the last chunk of output for error messages.
func tail(b []byte) string {
	const max = 500
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return "…" + s[len(s)-max:]
	}
	return s
}
