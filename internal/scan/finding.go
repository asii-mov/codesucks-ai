// Package scan runs Semgrep and TruffleHog against a checked-out repository and
// normalizes their output into a single Finding model.
package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Tool identifies which scanner produced a finding.
type Tool string

const (
	ToolSemgrep    Tool = "semgrep"
	ToolTruffleHog Tool = "trufflehog"
)

// Severity is the normalized severity shared across tools.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// severityRank orders severities from most to least serious for sorting the
// patch queue. Higher is more serious.
func (s Severity) rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// MoreSevereThan reports whether s outranks other.
func (s Severity) MoreSevereThan(other Severity) bool {
	return s.rank() > other.rank()
}

// SecretMeta carries secret-specific detail. The raw secret value is never
// stored here; only a redacted form suitable for display.
type SecretMeta struct {
	Detector string `json:"detector"`
	Verified bool   `json:"verified"`
	Redacted string `json:"redacted"`
}

// Finding is the single normalized model both scanners map into.
type Finding struct {
	Fingerprint string      `json:"fingerprint"`
	Tool        Tool        `json:"tool"`
	RuleID      string      `json:"rule_id"`
	Severity    Severity    `json:"severity"`
	CWE         []string    `json:"cwe,omitempty"`
	File        string      `json:"file"`
	StartLine   int         `json:"start_line"`
	EndLine     int         `json:"end_line"`
	Snippet     string      `json:"snippet"`
	Message     string      `json:"message"`
	Secret      *SecretMeta `json:"secret,omitempty"`
}

// IsSecret reports whether the finding came from secret detection.
func (f Finding) IsSecret() bool { return f.Secret != nil }

// Fingerprint returns a stable identifier for a finding that survives line
// shifts: it is content-based, deriving from the tool, rule, path and the
// whitespace-collapsed snippet, and deliberately excludes line numbers. Because
// it is derived from the matched content, a correct patch changes the content
// and the fingerprint disappears on re-scan — that disappearance is the Gate A
// signal. Re-scanning unchanged code yields the identical fingerprint.
func Fingerprint(t Tool, ruleID, relPath, snippet string) string {
	h := sha256.New()
	h.Write([]byte(string(t)))
	h.Write([]byte{0})
	h.Write([]byte(ruleID))
	h.Write([]byte{0})
	h.Write([]byte(relPath))
	h.Write([]byte{0})
	h.Write([]byte(normalizeSnippet(snippet)))
	return hex.EncodeToString(h.Sum(nil))
}

// normalizeSnippet collapses every run of whitespace to a single space so that
// reindentation alone does not change a fingerprint.
func normalizeSnippet(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// hashRaw returns the hex sha256 of a raw value. Used as the fingerprint
// snippet input for secrets so that identical secrets fingerprint equal without
// ever storing the value itself.
func hashRaw(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
