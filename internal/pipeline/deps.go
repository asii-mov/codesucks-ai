package pipeline

import (
	"context"

	"github.com/asii-mov/codesucks-ai/internal/agent"
	"github.com/asii-mov/codesucks-ai/internal/gates"
	"github.com/asii-mov/codesucks-ai/internal/repo"
	"github.com/asii-mov/codesucks-ai/internal/scan"
)

// Deps are the external dependencies of the pipeline, injected so the
// orchestration can be exercised end-to-end without a network, real scanners,
// or GitHub.
type Deps struct {
	Clone      func(ctx context.Context, url, token, dir string) (*repo.Repo, error)
	Semgrep    func(ctx context.Context, dir string, paths ...string) ([]scan.Finding, error)
	TruffleHog func(ctx context.Context, dir string, red *scan.Redactor, paths ...string) ([]scan.Finding, error)
	LLM        agent.LLM
	Runner     gates.CommandRunner
	OpenPR     func(ctx context.Context, in repo.PRInput) (number int, url string, err error)
}

// ProductionDeps wires the real implementations for a live run.
func ProductionDeps(cfg Config) Deps {
	return Deps{
		Clone: repo.Clone,
		Semgrep: func(ctx context.Context, dir string, paths ...string) ([]scan.Finding, error) {
			return scan.RunSemgrep(ctx, SemgrepBinary, SemgrepConfig, dir, paths...)
		},
		TruffleHog: func(ctx context.Context, dir string, red *scan.Redactor, paths ...string) ([]scan.Finding, error) {
			return scan.RunTruffleHog(ctx, TruffleHogBinary, dir, red, paths...)
		},
		LLM:    agent.NewLLM(cfg.AnthropicKey),
		Runner: gates.ExecRunner,
		OpenPR: func(ctx context.Context, in repo.PRInput) (int, string, error) {
			return repo.CreatePR(ctx, cfg.GitHubToken, in)
		},
	}
}

// rescanner returns a Gate A re-scan closure that uses the same tool that
// produced the finding.
func (d Deps) rescanner(tool scan.Tool, dir string, red *scan.Redactor) gates.Rescanner {
	return func(ctx context.Context, changed []string) ([]scan.Finding, error) {
		if tool == scan.ToolTruffleHog {
			return d.TruffleHog(ctx, dir, red, changed...)
		}
		return d.Semgrep(ctx, dir, changed...)
	}
}
