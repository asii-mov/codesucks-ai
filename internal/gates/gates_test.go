package gates

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/asii-mov/codesucks-ai/internal/scan"
)

// queueRunner returns scripted CmdResults in order and records the commands.
type queueRunner struct {
	results []CmdResult
	i       int
	cmds    []string
}

func (q *queueRunner) run(ctx context.Context, dir, name string, args ...string) CmdResult {
	q.cmds = append(q.cmds, cmdString(name, args))
	if q.i >= len(q.results) {
		return CmdResult{ExitCode: 0}
	}
	r := q.results[q.i]
	q.i++
	return r
}

func TestDetectStack(t *testing.T) {
	cases := map[string]StackKind{
		"go.mod":           StackGo,
		"package.json":     StackNode,
		"pyproject.toml":   StackPython,
		"requirements.txt": StackPython,
	}
	for marker, want := range cases {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, marker), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := DetectStack(dir); got.Kind != want {
			t.Errorf("marker %s: got %s want %s", marker, got.Kind, want)
		}
	}
	if DetectStack(t.TempDir()).Kind != StackUnknown {
		t.Error("empty dir should be unknown")
	}
	// go.mod wins over package.json.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x"), 0o644)
	os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0o644)
	if DetectStack(dir).Kind != StackGo {
		t.Error("go.mod should win over package.json")
	}
}

func finding(fp string) scan.Finding {
	return scan.Finding{Fingerprint: fp, Tool: scan.ToolSemgrep, RuleID: "rule-" + fp}
}

func TestVerifyFix_GateA(t *testing.T) {
	f := finding("vuln")
	pre := []scan.Finding{f} // the vuln was present pre-patch on the changed file
	changed := []string{"app.js"}

	// Fix worked: the vuln is gone, nothing new.
	res, err := VerifyFix(context.Background(), f, pre, changed, func(context.Context, []string) ([]scan.Finding, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed {
		t.Errorf("expected pass when vuln gone, got %+v", res)
	}

	// Vuln still present: fail.
	res, _ = VerifyFix(context.Background(), f, pre, changed, func(context.Context, []string) ([]scan.Finding, error) {
		return []scan.Finding{f}, nil
	})
	if res.Passed {
		t.Error("expected fail when the original finding persists")
	}

	// New finding introduced: fail.
	res, _ = VerifyFix(context.Background(), f, pre, changed, func(context.Context, []string) ([]scan.Finding, error) {
		return []scan.Finding{finding("brand-new")}, nil
	})
	if res.Passed {
		t.Error("expected fail when a new finding is introduced")
	}
}

func TestLint_GateB_NoNewIssues(t *testing.T) {
	stack := Stack{Kind: StackNode}
	// baseline: 2 eslint messages; after: still 2 → pass.
	run := &queueRunner{results: []CmdResult{
		{Stdout: `[{"messages":[{},{}]}]`, ExitCode: 1},
		{Stdout: `[{"messages":[{},{}]}]`, ExitCode: 1},
	}}
	base := CaptureLintBaseline(context.Background(), run.run, "d", stack, "")
	if !base.Available || base.Count != 2 {
		t.Fatalf("baseline: %+v", base)
	}
	res := Lint(context.Background(), run.run, "d", stack, "", base)
	if !res.Passed {
		t.Errorf("expected pass with no new issues, got %+v", res)
	}
}

func TestLint_GateB_NewIssuesFail(t *testing.T) {
	stack := Stack{Kind: StackNode}
	run := &queueRunner{results: []CmdResult{
		{Stdout: `[{"messages":[{}]}]`, ExitCode: 1},       // baseline: 1
		{Stdout: `[{"messages":[{},{},{}]}]`, ExitCode: 1}, // after: 3
	}}
	base := CaptureLintBaseline(context.Background(), run.run, "d", stack, "")
	res := Lint(context.Background(), run.run, "d", stack, "", base)
	if res.Passed {
		t.Errorf("expected fail with new issues, got %+v", res)
	}
	if res.Baseline != 1 || res.After != 3 {
		t.Errorf("expected baseline 1 after 3, got %+v", res)
	}
}

func TestLint_GateB_SkippedWhenUnavailable(t *testing.T) {
	stack := Stack{Kind: StackNode}
	// eslint exits 2 (no config) → unavailable → skipped-pass.
	run := &queueRunner{results: []CmdResult{{ExitCode: 2, Stderr: "no eslint config"}}}
	base := CaptureLintBaseline(context.Background(), run.run, "d", stack, "")
	if base.Available {
		t.Fatal("baseline should be unavailable on eslint exit 2")
	}
	res := Lint(context.Background(), run.run, "d", stack, "", base)
	if !res.Passed {
		t.Errorf("unavailable lint should skip-pass, got %+v", res)
	}
}

func TestAppWorks_GateC_ToleratesPreexistingFailure(t *testing.T) {
	stack := Stack{Kind: StackGo}
	// baseline: one failing test; after: still one → pass (no new failures).
	run := &queueRunner{results: []CmdResult{
		{Stdout: "--- FAIL: TestA\n", ExitCode: 1},
		{Stdout: "--- FAIL: TestA\n", ExitCode: 1},
	}}
	base := CaptureAppBaseline(context.Background(), run.run, "d", stack, "")
	if base.Failures != 1 || base.Level != levelTest {
		t.Fatalf("baseline: %+v", base)
	}
	res := AppWorks(context.Background(), run.run, "d", stack, nil, base)
	if !res.Passed {
		t.Errorf("expected pass tolerating the pre-existing failure, got %+v", res)
	}
}

func TestAppWorks_GateC_NewFailureFails(t *testing.T) {
	stack := Stack{Kind: StackGo}
	// baseline: one failure; after: two → fail.
	run := &queueRunner{results: []CmdResult{
		{Stdout: "--- FAIL: TestA\n", ExitCode: 1},
		{Stdout: "--- FAIL: TestA\n--- FAIL: TestB\n", ExitCode: 1},
	}}
	base := CaptureAppBaseline(context.Background(), run.run, "d", stack, "")
	res := AppWorks(context.Background(), run.run, "d", stack, nil, base)
	if res.Passed {
		t.Errorf("expected fail when a new test failure appears, got %+v", res)
	}
}

func TestTestFailureCount(t *testing.T) {
	cases := []struct {
		out  string
		exit int
		want int
	}{
		{"# fail 3\n", 1, 3},
		{"Tests: 2 failed, 5 passed", 1, 2},
		{"4 passing\n1 failing", 1, 1},
		{"--- FAIL: TestX\n--- FAIL: TestY\n", 1, 2},
		{"all good", 0, 0},
		{"cryptic error", 1, 1},
	}
	for _, c := range cases {
		got := testFailureCount(CmdResult{Stdout: c.out, ExitCode: c.exit})
		if got != c.want {
			t.Errorf("testFailureCount(%q, exit=%d) = %d, want %d", c.out, c.exit, got, c.want)
		}
	}
}
