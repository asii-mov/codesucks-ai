package scan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// thResult mirrors a single TruffleHog NDJSON finding line.
type thResult struct {
	DetectorName   string `json:"DetectorName"`
	Verified       bool   `json:"Verified"`
	Raw            string `json:"Raw"`
	Redacted       string `json:"Redacted"`
	SourceMetadata struct {
		Data struct {
			Git *struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"Git"`
			Filesystem *struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"Filesystem"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

// RunTruffleHog runs TruffleHog's filesystem scanner over dir (optionally
// restricted to paths) and returns normalized secret findings. Every raw secret
// value is fed to the redactor and then discarded; it is never stored on a
// Finding. TruffleHog emits NDJSON on stdout and logs on stderr, so the two
// streams are captured separately and only stdout is parsed.
func RunTruffleHog(ctx context.Context, trufflehogPath, dir string, red *Redactor, paths ...string) ([]Finding, error) {
	args := []string{"filesystem", "--json", "--no-update"}
	if len(paths) == 0 {
		args = append(args, ".")
	} else {
		args = append(args, paths...)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, trufflehogPath, args...)
	cmd.Dir = dir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			if code := ee.ExitCode(); code != 0 && code != 1 {
				return nil, fmt.Errorf("trufflehog: exit %d: %s", code, tail(stderr.Bytes()))
			}
		} else {
			return nil, fmt.Errorf("trufflehog: %w", err)
		}
	}
	return parseTruffleHogNDJSON(stdout.Bytes(), red)
}

// parseTruffleHogNDJSON parses NDJSON output line by line. Log lines (which
// carry level/msg/logger keys and no DetectorName) are skipped; only genuine
// findings are kept.
func parseTruffleHogNDJSON(data []byte, red *Redactor) ([]Finding, error) {
	var findings []Finding
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 || raw[0] != '{' {
			continue
		}
		var r thResult
		if err := json.Unmarshal(raw, &r); err != nil {
			continue // not a finding object we understand; skip
		}
		if r.DetectorName == "" {
			continue // log line, not a finding
		}

		if red != nil {
			red.Add(r.Raw)
		}

		file, line := thLocation(r)
		redacted := r.Redacted
		if redacted == "" {
			redacted = mask(r.Raw)
		}
		findings = append(findings, Finding{
			Fingerprint: Fingerprint(ToolTruffleHog, r.DetectorName, filepath.ToSlash(file), hashRaw(r.Raw)),
			Tool:        ToolTruffleHog,
			RuleID:      r.DetectorName,
			Severity:    truffleHogSeverity(r.Verified),
			File:        filepath.ToSlash(file),
			StartLine:   line,
			EndLine:     line,
			Snippet:     redacted,
			Message:     fmt.Sprintf("%s secret detected (verified=%t)", r.DetectorName, r.Verified),
			Secret: &SecretMeta{
				Detector: r.DetectorName,
				Verified: r.Verified,
				Redacted: redacted,
			},
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("trufflehog: scan output: %w", err)
	}
	return findings, nil
}

func thLocation(r thResult) (file string, line int) {
	switch {
	case r.SourceMetadata.Data.Filesystem != nil:
		return r.SourceMetadata.Data.Filesystem.File, r.SourceMetadata.Data.Filesystem.Line
	case r.SourceMetadata.Data.Git != nil:
		return r.SourceMetadata.Data.Git.File, r.SourceMetadata.Data.Git.Line
	default:
		return "", 0
	}
}

func truffleHogSeverity(verified bool) Severity {
	if verified {
		return SeverityCritical
	}
	return SeverityHigh
}
