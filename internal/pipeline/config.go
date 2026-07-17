// Package pipeline orchestrates the end-to-end flow: clone, scan, triage,
// patch, verify, and open one pull request per confirmed fix.
package pipeline

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/asii-mov/codesucks-ai/internal/agent"
)

// Hardcoded operational constants — deliberately not flags, to keep the tool's
// surface small.
const (
	TriageModel        = "claude-opus-4-8"
	DefaultPatchModel  = "claude-opus-4-8"
	TriageConcurrency  = 4
	TriageConfidence   = 0.7
	PatchRetries       = 2
	SemgrepConfig      = "p/default"
	SemgrepBinary      = "semgrep"
	TruffleHogBinary   = "trufflehog"
	semgrepMaxScanSecs = 300
)

// Config is the fully resolved run configuration.
type Config struct {
	RepoURL      string
	GitHubToken  string
	AnthropicKey string

	DryRun     bool
	MaxPRs     int
	PatchModel string
	LintCmd    string
	VerifyCmd  string
	Workdir    string
	OutDir     string
}

// Budget returns the per-finding agent budget.
func (c Config) Budget() agent.Budget {
	return agent.Budget{MaxIterations: 12, MaxTokens: 200000, Timeout: 5 * time.Minute}
}

// ParseFlags parses CLI arguments and environment variables into a Config.
func ParseFlags(args []string) (Config, error) {
	fs := flag.NewFlagSet("codesucks-ai", flag.ContinueOnError)
	var c Config
	fs.BoolVar(&c.DryRun, "dry-run", false, "scan and triage only; do not patch, push, or open PRs")
	fs.IntVar(&c.MaxPRs, "max-prs", 10, "maximum pull requests to open per run")
	fs.StringVar(&c.PatchModel, "model", DefaultPatchModel, "Anthropic model for the patch agent")
	fs.StringVar(&c.LintCmd, "lint-cmd", "", "override the Gate B lint command")
	fs.StringVar(&c.VerifyCmd, "verify-cmd", "", "override the Gate C test/build command")
	fs.StringVar(&c.Workdir, "workdir", "", "working directory for the clone (default: a temp dir)")
	fs.StringVar(&c.OutDir, "out", "./out", "directory for report output")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: codesucks-ai [flags] <github-repo-url>\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(fs.Output(), "\nEnvironment: GITHUB_TOKEN, ANTHROPIC_API_KEY (both required).\n")
	}
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if fs.NArg() != 1 {
		return Config{}, fmt.Errorf("exactly one <github-repo-url> argument is required")
	}
	c.RepoURL = fs.Arg(0)
	c.GitHubToken = os.Getenv("GITHUB_TOKEN")
	c.AnthropicKey = os.Getenv("ANTHROPIC_API_KEY")
	return c, nil
}

// Validate checks required fields.
func (c Config) Validate() error {
	if c.RepoURL == "" {
		return fmt.Errorf("repository URL is required")
	}
	if c.GitHubToken == "" {
		return fmt.Errorf("GITHUB_TOKEN is not set")
	}
	if c.AnthropicKey == "" {
		return fmt.Errorf("ANTHROPIC_API_KEY is not set")
	}
	if c.MaxPRs < 0 {
		return fmt.Errorf("-max-prs must not be negative")
	}
	return nil
}
