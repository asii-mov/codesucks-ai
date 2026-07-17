// Package e2e holds the opt-in live end-to-end test. It runs the real pipeline
// against a real GitHub repository using real Claude models, so it is gated
// behind E2E=1 and requires GITHUB_TOKEN and ANTHROPIC_API_KEY in the
// environment. It never runs during a normal `go test ./...`.
package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/asii-mov/codesucks-ai/internal/pipeline"
)

const targetRepo = "https://github.com/asii-mov/NodeGoat-AI-test"

func TestLive_NodeGoat_OpensOnePR(t *testing.T) {
	if os.Getenv("E2E") != "1" {
		t.Skip("set E2E=1 (with GITHUB_TOKEN and ANTHROPIC_API_KEY) to run the live end-to-end test")
	}
	if os.Getenv("GITHUB_TOKEN") == "" || os.Getenv("ANTHROPIC_API_KEY") == "" {
		t.Fatal("E2E=1 requires GITHUB_TOKEN and ANTHROPIC_API_KEY")
	}

	cfg := pipeline.Config{
		RepoURL:      targetRepo,
		GitHubToken:  os.Getenv("GITHUB_TOKEN"),
		AnthropicKey: os.Getenv("ANTHROPIC_API_KEY"),
		MaxPRs:       1,
		PatchModel:   pipeline.DefaultPatchModel,
		OutDir:       t.TempDir(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	rep, err := pipeline.Run(ctx, cfg, pipeline.ProductionDeps(cfg))
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	t.Logf("found=%d triaged=%d truePositive=%d patched=%d prs=%d needsReview=%d skipped=%d cost=$%.2f",
		rep.Found, rep.Triaged, rep.TruePositive, rep.Patched, rep.PRd, rep.NeedsReview, rep.Skipped, rep.EstCostUSD)

	if rep.Found == 0 {
		t.Error("expected the scanners to find at least one issue in the target repo")
	}
	if rep.PRd < 1 {
		t.Error("expected at least one PR to be opened (capped at 1)")
	}
	// Every opened PR must carry full gate evidence.
	for _, f := range rep.Findings {
		if f.Status == pipeline.StatusPatchedPR {
			if len(f.Gates) != 3 {
				t.Errorf("patched finding %s should record 3 gate results, got %d", f.RuleID, len(f.Gates))
			}
			if f.PRURL == "" {
				t.Errorf("patched finding %s missing PR URL", f.RuleID)
			}
		}
	}
}

func TestLive_NodeGoat_DryRun(t *testing.T) {
	if os.Getenv("E2E") != "1" {
		t.Skip("set E2E=1 to run the live dry-run test")
	}
	cfg := pipeline.Config{
		RepoURL:      targetRepo,
		GitHubToken:  os.Getenv("GITHUB_TOKEN"),
		AnthropicKey: os.Getenv("ANTHROPIC_API_KEY"),
		DryRun:       true,
		MaxPRs:       10,
		PatchModel:   pipeline.DefaultPatchModel,
		OutDir:       t.TempDir(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	rep, err := pipeline.Run(ctx, cfg, pipeline.ProductionDeps(cfg))
	if err != nil {
		t.Fatalf("dry-run failed: %v", err)
	}
	if rep.PRd != 0 || rep.Patched != 0 {
		t.Errorf("dry-run must not patch or open PRs, got patched=%d prs=%d", rep.Patched, rep.PRd)
	}
	t.Logf("dry-run: found=%d triaged=%d truePositive=%d", rep.Found, rep.Triaged, rep.TruePositive)
}
