package gates

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asii-mov/codesucks-ai/internal/scan"
)

// copyVulnApp copies the fixture app into a fresh temp dir so tests can patch it.
func copyVulnApp(t *testing.T) string {
	t.Helper()
	src := "../../testdata/vuln-app"
	dst := t.TempDir()
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
	return dst
}

func TestGateA_Integration_Semgrep(t *testing.T) {
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep not installed")
	}
	dir := copyVulnApp(t)
	ctx := context.Background()
	const cfg = "p/javascript"

	rescan := func(ctx context.Context, changed []string) ([]scan.Finding, error) {
		return scan.RunSemgrep(ctx, "semgrep", cfg, dir, changed...)
	}

	all, err := scan.RunSemgrep(ctx, "semgrep", cfg, dir)
	if err != nil {
		t.Skipf("semgrep run failed (offline registry?): %v", err)
	}
	var evalF *scan.Finding
	for i := range all {
		if all[i].File == "app.js" && strings.Contains(all[i].RuleID, "eval") {
			evalF = &all[i]
			break
		}
	}
	if evalF == nil {
		t.Skip("semgrep did not flag eval (ruleset unavailable)")
	}

	pre, err := scan.RunSemgrep(ctx, "semgrep", cfg, dir, "app.js")
	if err != nil {
		t.Fatal(err)
	}

	// Unpatched: the vuln is still present → Gate A fails.
	res, err := VerifyFix(ctx, *evalF, pre, []string{"app.js"}, rescan)
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed {
		t.Errorf("Gate A must fail while the vulnerability is present, got %+v", res)
	}

	// Apply the fix and re-check → Gate A passes.
	appJS := filepath.Join(dir, "app.js")
	data, _ := os.ReadFile(appJS)
	patched := strings.Replace(string(data), "eval(req.query.x)", "JSON.parse(req.query.x)", 1)
	if patched == string(data) {
		t.Fatal("failed to apply test patch")
	}
	if err := os.WriteFile(appJS, []byte(patched), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = VerifyFix(ctx, *evalF, pre, []string{"app.js"}, rescan)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed {
		t.Errorf("Gate A must pass after the vulnerability is fixed, got %+v", res)
	}
}

func TestGateC_Integration_Node(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed")
	}
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not installed")
	}
	dir := copyVulnApp(t)
	ctx := context.Background()

	stack := DetectStack(dir)
	if stack.Kind != StackNode {
		t.Fatalf("expected node stack, got %s", stack.Kind)
	}

	base := CaptureAppBaseline(ctx, ExecRunner, dir, stack, "")
	if base.Level != levelTest || base.Failures < 1 {
		t.Fatalf("expected a test baseline with >=1 pre-existing failure, got %+v", base)
	}

	// No changes → Gate C tolerates the pre-existing failure.
	res := AppWorks(ctx, ExecRunner, dir, stack, nil, base)
	if !res.Passed {
		t.Errorf("Gate C must tolerate the pre-existing failure, got %+v", res)
	}

	// Break the passing test's function → a NEW failure appears → Gate C fails.
	appJS := filepath.Join(dir, "app.js")
	data, _ := os.ReadFile(appJS)
	broken := strings.Replace(string(data), "return a + b;", "return a - b;", 1)
	if err := os.WriteFile(appJS, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	res = AppWorks(ctx, ExecRunner, dir, stack, nil, base)
	if res.Passed {
		t.Errorf("Gate C must fail when a new test failure is introduced, got %+v", res)
	}
}
