package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/asii-mov/codesucks-ai/internal/gates"
	"github.com/asii-mov/codesucks-ai/internal/repo"
	"github.com/asii-mov/codesucks-ai/internal/scan"
)

const awsFakeKey = "AKIAIOSFODNN7EXAMPLE"

// --- scripted LLM that dispatches on request content, not call order ---

type scriptLLM struct{ t *testing.T }

func (s scriptLLM) New(ctx context.Context, params anthropic.MessageNewParams, opts ...option.RequestOption) (*anthropic.Message, error) {
	tools := map[string]bool{}
	for _, tu := range params.Tools {
		if tu.OfTool != nil {
			tools[tu.OfTool.Name] = true
		}
	}
	user := firstUserText(params)

	switch {
	case tools["submit_triage"]:
		return toolUseMsg(s.t, "submit_triage", map[string]any{
			"verdict": "true_positive", "confidence": 0.95, "rationale": "user input reaches a dangerous sink",
		}), nil
	case tools["submit_patch"]:
		if strings.Contains(user, "config.js") {
			return toolUseMsg(s.t, "submit_patch", map[string]any{
				"summary": "read the AWS key from the environment instead of hardcoding it",
				"edits": []map[string]any{{
					"path":    "config.js",
					"old_str": "awsAccessKeyId: '" + awsFakeKey + "',",
					"new_str": "awsAccessKeyId: process.env.AWS_ACCESS_KEY_ID,",
				}},
			}), nil
		}
		return toolUseMsg(s.t, "submit_patch", map[string]any{
			"summary": "parse the input as JSON instead of evaluating it",
			"edits": []map[string]any{{
				"path":    "app.js",
				"old_str": "eval(req.query.x)",
				"new_str": "JSON.parse(req.query.x)",
			}},
		}), nil
	}
	return nil, fmt.Errorf("scriptLLM: unexpected tool set %v", tools)
}

func firstUserText(params anthropic.MessageNewParams) string {
	for _, m := range params.Messages {
		for _, c := range m.Content {
			if c.OfText != nil {
				return c.OfText.Text
			}
		}
	}
	return ""
}

func toolUseMsg(t *testing.T, name string, input any) *anthropic.Message {
	t.Helper()
	inputJSON, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	wire := fmt.Sprintf(`{"id":"msg","type":"message","role":"assistant","model":"m","stop_reason":"tool_use","content":[{"type":"tool_use","id":"t1","name":%q,"input":%s}],"usage":{"input_tokens":100,"output_tokens":50}}`, name, inputJSON)
	var m anthropic.Message
	if err := json.Unmarshal([]byte(wire), &m); err != nil {
		t.Fatalf("unmarshal fake message: %v", err)
	}
	return &m
}

// --- grep-based fake scanners (deterministic, no network) ---

func fakeSemgrep(ctx context.Context, dir string, paths ...string) ([]scan.Finding, error) {
	inspect := paths
	if len(inspect) == 0 {
		inspect = []string{"app.js"}
	}
	var out []scan.Finding
	for _, p := range inspect {
		if p != "app.js" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, p))
		if err != nil {
			continue
		}
		if strings.Contains(string(data), "eval(req.query.x)") {
			out = append(out, scan.Finding{
				Fingerprint: scan.Fingerprint(scan.ToolSemgrep, "js.eval", "app.js", "eval(req.query.x)"),
				Tool:        scan.ToolSemgrep, RuleID: "js.eval", Severity: scan.SeverityHigh,
				CWE: []string{"CWE-95"}, File: "app.js", StartLine: 6, EndLine: 6,
				Snippet: "eval(req.query.x)", Message: "eval with user input",
			})
		}
	}
	return out, nil
}

func fakeTruffleHog(ctx context.Context, dir string, red *scan.Redactor, paths ...string) ([]scan.Finding, error) {
	inspect := paths
	if len(inspect) == 0 {
		inspect = []string{"config.js"}
	}
	var out []scan.Finding
	for _, p := range inspect {
		if p != "config.js" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, p))
		if err != nil {
			continue
		}
		if strings.Contains(string(data), awsFakeKey) {
			red.Add(awsFakeKey)
			out = append(out, scan.Finding{
				Fingerprint: scan.Fingerprint(scan.ToolTruffleHog, "AWS", "config.js", "aws-config-secret"),
				Tool:        scan.ToolTruffleHog, RuleID: "AWS", Severity: scan.SeverityCritical,
				File: "config.js", StartLine: 5, EndLine: 5, Snippet: "AKIA****************",
				Message: "AWS secret detected (verified=true)",
				Secret:  &scan.SecretMeta{Detector: "AWS", Verified: true, Redacted: "AKIA****************"},
			})
		}
	}
	return out, nil
}

// testRunner uses the real runner for tests but reports the (unconfigured) node
// linter as unavailable so Gate B is skipped without invoking npx over the
// network.
func testRunner(ctx context.Context, dir, name string, args ...string) gates.CmdResult {
	if name == "npx" {
		return gates.CmdResult{ExitCode: 2, Stderr: "eslint not configured (test)"}
	}
	return gates.ExecRunner(ctx, dir, name, args...)
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func runOut(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s %s: %v", name, strings.Join(args, " "), err)
	}
	return string(out)
}

// setupLocalRepo builds a git repo from the vuln-app fixture with a local bare
// origin so branch pushes succeed without a network.
func setupLocalRepo(t *testing.T) *repo.Repo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	origin := filepath.Join(root, "origin.git")
	work := filepath.Join(root, "work")

	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
	)
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}

	if out, err := exec.Command("git", "init", "--bare", "-b", "main", origin).CombinedOutput(); err != nil {
		t.Fatalf("git init bare: %v: %s", err, out)
	}
	copyDir(t, "../../testdata/vuln-app", work)
	git(work, "init", "-b", "main")
	git(work, "remote", "add", "origin", origin)
	git(work, "add", "-A")
	git(work, "commit", "-m", "initial")
	git(work, "push", "-u", "origin", "main")

	sha := strings.TrimSpace(runOut(t, work, env, "git", "rev-parse", "HEAD"))
	return &repo.Repo{Dir: work, Owner: "o", Name: "r", DefaultBranch: "main", BaseSHA: sha}
}

func TestPipeline_EndToEnd_TwoPRs(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed")
	}
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not installed")
	}
	r := setupLocalRepo(t)

	var prs []repo.PRInput
	deps := Deps{
		Clone:      func(ctx context.Context, url, token, dir string) (*repo.Repo, error) { return r, nil },
		Semgrep:    fakeSemgrep,
		TruffleHog: fakeTruffleHog,
		LLM:        scriptLLM{t: t},
		Runner:     testRunner,
		OpenPR: func(ctx context.Context, in repo.PRInput) (int, string, error) {
			prs = append(prs, in)
			return len(prs), fmt.Sprintf("https://github.com/o/r/pull/%d", len(prs)), nil
		},
	}

	cfg := Config{RepoURL: "https://github.com/o/r", GitHubToken: "x", AnthropicKey: "y", MaxPRs: 10, PatchModel: "m", OutDir: t.TempDir()}
	rep, err := Run(context.Background(), cfg, deps)
	if err != nil {
		t.Fatal(err)
	}

	if rep.Found != 2 || rep.TruePositive != 2 {
		t.Fatalf("expected 2 findings both TP, got found=%d tp=%d", rep.Found, rep.TruePositive)
	}
	if rep.PRd != 2 || rep.Patched != 2 {
		t.Fatalf("expected 2 PRs, got prd=%d patched=%d", rep.PRd, rep.Patched)
	}
	if rep.NeedsReview != 0 || rep.Skipped != 0 {
		t.Errorf("expected no review/skip, got needsReview=%d skipped=%d", rep.NeedsReview, rep.Skipped)
	}
	if len(prs) != 2 {
		t.Fatalf("expected 2 PR calls, got %d", len(prs))
	}

	// PR bodies contain required sections and never leak the raw secret.
	var sawSecretRotation bool
	for _, pr := range prs {
		for _, section := range []string{"Severity", "Verification", "Gate", "pass", "Solution taken"} {
			if !strings.Contains(pr.Body, section) {
				t.Errorf("PR body missing %q section:\n%s", section, pr.Body)
			}
		}
		if strings.Contains(pr.Body, awsFakeKey) {
			t.Errorf("raw secret leaked into PR body:\n%s", pr.Body)
		}
		if strings.Contains(pr.Body, "Rotation required") {
			sawSecretRotation = true
		}
	}
	if !sawSecretRotation {
		t.Error("expected the secret PR to include a rotation-required section")
	}

	// Report was written and carries no raw secret.
	reportJSON, err := os.ReadFile(filepath.Join(cfg.OutDir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(reportJSON), awsFakeKey) {
		t.Error("raw secret leaked into report.json")
	}
	if _, err := os.Stat(filepath.Join(cfg.OutDir, "report.md")); err != nil {
		t.Errorf("report.md not written: %v", err)
	}
}

func TestPipeline_DryRun_NoPRs(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed")
	}
	r := setupLocalRepo(t)
	opened := 0
	deps := Deps{
		Clone:      func(ctx context.Context, url, token, dir string) (*repo.Repo, error) { return r, nil },
		Semgrep:    fakeSemgrep,
		TruffleHog: fakeTruffleHog,
		LLM:        scriptLLM{t: t},
		Runner:     testRunner,
		OpenPR: func(ctx context.Context, in repo.PRInput) (int, string, error) {
			opened++
			return opened, "url", nil
		},
	}
	cfg := Config{RepoURL: "https://github.com/o/r", GitHubToken: "x", AnthropicKey: "y", DryRun: true, MaxPRs: 10, PatchModel: "m", OutDir: t.TempDir()}
	rep, err := Run(context.Background(), cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	if opened != 0 {
		t.Errorf("dry-run must not open PRs, opened %d", opened)
	}
	if rep.Found != 2 || rep.TruePositive != 2 {
		t.Errorf("dry-run should still scan+triage: found=%d tp=%d", rep.Found, rep.TruePositive)
	}
	if rep.PRd != 0 {
		t.Errorf("dry-run PRd should be 0, got %d", rep.PRd)
	}
}
