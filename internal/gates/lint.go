package gates

import (
	"context"
	"fmt"
	"strings"
)

// LintBaseline captures the pristine lint issue count so Gate B can require "no
// new issues" rather than "no issues", tolerating a target repo's pre-existing
// lint noise.
type LintBaseline struct {
	Command   string
	Count     int
	Available bool
}

// lintCommand resolves the lint command for a stack (or an override).
func lintCommand(stack Stack, override string) (name string, args []string, ok bool) {
	if strings.TrimSpace(override) != "" {
		return "sh", []string{"-c", override}, true
	}
	switch stack.Kind {
	case StackGo:
		return "go", []string{"vet", "./..."}, true
	case StackNode:
		return "npx", []string{"eslint", ".", "-f", "json"}, true
	case StackPython:
		return "ruff", []string{"check", "--output-format", "json", "."}, true
	default:
		return "", nil, false
	}
}

// lintUnavailable reports whether a lint command "ran" but only because the tool
// failed to configure itself (e.g. eslint with no config), which should not be
// treated as findable lint output.
func lintUnavailable(stack Stack, res CmdResult) bool {
	return stack.Kind == StackNode && res.ExitCode == 2
}

// CaptureLintBaseline runs the linter on the pristine repository and records the
// issue count. If no linter is available it returns an unavailable baseline and
// Gate B is later skipped.
func CaptureLintBaseline(ctx context.Context, run CommandRunner, dir string, stack Stack, override string) LintBaseline {
	name, args, ok := lintCommand(stack, override)
	if !ok {
		return LintBaseline{Available: false}
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	res := run(ctx, dir, name, args...)
	cmd := cmdString(name, args)
	if !res.ran() || lintUnavailable(stack, res) {
		return LintBaseline{Command: cmd, Available: false}
	}
	return LintBaseline{Command: cmd, Count: lintIssueCount(stack, res), Available: true}
}

// Lint is Gate B: re-run the linter and require no new issues versus the
// baseline.
func Lint(ctx context.Context, run CommandRunner, dir string, stack Stack, override string, base LintBaseline) Result {
	if !base.Available {
		return Result{Name: "lint", Passed: true, Detail: "no linter available for this stack; skipped"}
	}
	name, args, _ := lintCommand(stack, override)
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	res := run(ctx, dir, name, args...)
	after := lintIssueCount(stack, res)

	r := Result{Name: "lint", Command: base.Command, Baseline: base.Count, After: after}
	if after <= base.Count {
		r.Passed = true
		r.Detail = "no new lint issues"
	} else {
		r.Passed = false
		r.Detail = fmt.Sprintf("linting reported %d new issue(s) (baseline %d, after %d)", after-base.Count, base.Count, after)
	}
	return r
}

func cmdString(name string, args []string) string {
	if name == "sh" && len(args) == 2 && args[0] == "-c" {
		return args[1]
	}
	return strings.TrimSpace(name + " " + strings.Join(args, " "))
}
