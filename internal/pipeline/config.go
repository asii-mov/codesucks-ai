// Package pipeline wires scanning, triage, patching, gates, and PR creation
// into the single codesucks-ai run.
package pipeline

import (
	"errors"
	"strings"
	"time"
)

// Fixed behavior — deliberately constants rather than flags.
const (
	TriageModel         = "claude-haiku-4-5"
	DefaultPatchModel   = "claude-opus-4-8"
	TriageConcurrency   = 4
	ConfidenceThreshold = 0.7
	MaxIterations       = 12
	MaxTokensPerFinding = 200_000
	FindingTimeout      = 5 * time.Minute
	PatchRetries        = 2
	SemgrepConfig       = "p/default"
)

// Config is the complete run configuration: the 7 CLI flags, the positional
// repo URL, and the two required environment secrets. Nothing else exists.
type Config struct {
	RepoURL    string
	DryRun     bool
	MaxPRs     int
	PatchModel string
	LintCmd    string
	VerifyCmd  string
	Workdir    string // empty means a fresh temp dir
	OutDir     string

	GitHubToken  string
	AnthropicKey string
}

// Validate checks required inputs and normalizes defaults.
func (c *Config) Validate() error {
	if c.RepoURL == "" {
		return errors.New("a GitHub repository URL is required (usage: codesucks-ai [flags] <github-repo-url>)")
	}
	if !strings.Contains(c.RepoURL, "github.com") {
		return errors.New("only github.com repository URLs are supported")
	}
	if c.GitHubToken == "" {
		return errors.New("GITHUB_TOKEN is not set (export it or add it to .env)")
	}
	if c.AnthropicKey == "" {
		return errors.New("ANTHROPIC_API_KEY is not set (export it or add it to .env)")
	}
	if c.MaxPRs < 1 {
		return errors.New("-max-prs must be at least 1")
	}
	if c.PatchModel == "" {
		c.PatchModel = DefaultPatchModel
	}
	if c.OutDir == "" {
		c.OutDir = "out"
	}
	return nil
}
