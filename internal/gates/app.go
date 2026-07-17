package gates

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Verification levels, most to least thorough.
const (
	levelCustom = "custom"
	levelTest   = "test"
	levelBuild  = "build"
	levelSyntax = "syntax"
	levelNone   = "none"
)

// AppBaseline captures how "does the app still work" is checked and the pristine
// failure count, so Gate C requires "no new failures" rather than "all pass".
type AppBaseline struct {
	Level     string
	Command   string
	Failures  int
	Available bool // true when a test/build count baseline was captured

	name string
	args []string
}

// CaptureAppBaseline chooses a verification command for the stack (or an
// override) and records the pristine failure count.
func CaptureAppBaseline(ctx context.Context, run CommandRunner, dir string, stack Stack, override string) AppBaseline {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if strings.TrimSpace(override) != "" {
		res := run(ctx, dir, "sh", "-c", override)
		return AppBaseline{Level: levelCustom, Command: override, Failures: testFailureCount(res), Available: true, name: "sh", args: []string{"-c", override}}
	}

	switch stack.Kind {
	case StackGo:
		res := run(ctx, dir, "go", "test", "./...")
		return AppBaseline{Level: levelTest, Command: "go test ./...", Failures: testFailureCount(res), Available: true, name: "go", args: []string{"test", "./..."}}

	case StackNode:
		if hasNodeScript(dir, "test") {
			res := run(ctx, dir, "npm", "test")
			return AppBaseline{Level: levelTest, Command: "npm test", Failures: testFailureCount(res), Available: true, name: "npm", args: []string{"test"}}
		}
		if hasNodeScript(dir, "build") {
			res := run(ctx, dir, "npm", "run", "build")
			return AppBaseline{Level: levelBuild, Command: "npm run build", Failures: buildFailures(res), Available: true, name: "npm", args: []string{"run", "build"}}
		}
		return AppBaseline{Level: levelSyntax, Available: false}

	case StackPython:
		res := run(ctx, dir, "pytest")
		if res.ran() {
			return AppBaseline{Level: levelTest, Command: "pytest", Failures: testFailureCount(res), Available: true, name: "pytest"}
		}
		return AppBaseline{Level: levelSyntax, Available: false}

	default:
		return AppBaseline{Level: levelNone, Available: false}
	}
}

// AppWorks is Gate C: re-run the chosen verification and require no new
// failures versus the baseline. For the syntax fallback it checks the changed
// files directly.
func AppWorks(ctx context.Context, run CommandRunner, dir string, stack Stack, changed []string, base AppBaseline) Result {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	switch base.Level {
	case levelSyntax:
		return syntaxCheck(ctx, run, dir, stack, changed)
	case levelNone:
		return Result{Name: "app-works", Passed: true, Detail: "no tests, build, or syntax check available for this stack; skipped"}
	}

	res := run(ctx, dir, base.name, base.args...)
	var after int
	if base.Level == levelBuild {
		after = buildFailures(res)
	} else {
		after = testFailureCount(res)
	}
	r := Result{Name: "app-works (" + base.Level + ")", Command: base.Command, Baseline: base.Failures, After: after}
	if after <= base.Failures {
		r.Passed = true
		r.Detail = fmt.Sprintf("no new failures via %q (baseline %d, after %d)", base.Command, base.Failures, after)
	} else {
		r.Passed = false
		r.Detail = fmt.Sprintf("%q introduced %d new failure(s) (baseline %d, after %d)", base.Command, after-base.Failures, base.Failures, after)
	}
	return r
}

// syntaxCheck validates each changed source file compiles/parses.
func syntaxCheck(ctx context.Context, run CommandRunner, dir string, stack Stack, changed []string) Result {
	var checker func(string) CmdResult
	var cmdName string
	switch stack.Kind {
	case StackNode:
		cmdName = "node --check"
		checker = func(f string) CmdResult { return run(ctx, dir, "node", "--check", f) }
	case StackPython:
		cmdName = "python -m py_compile"
		checker = func(f string) CmdResult { return run(ctx, dir, "python", "-m", "py_compile", f) }
	default:
		return Result{Name: "app-works (syntax)", Passed: true, Detail: "no syntax checker for this stack; skipped"}
	}

	checked, failed := 0, 0
	var firstErr string
	for _, f := range changed {
		if !matchesStack(stack.Kind, f) {
			continue
		}
		checked++
		res := checker(f)
		if res.ran() && res.ExitCode != 0 {
			failed++
			if firstErr == "" {
				firstErr = strings.TrimSpace(res.combined())
			}
		}
	}
	r := Result{Name: "app-works (syntax)", Command: cmdName, Baseline: 0, After: failed}
	if failed == 0 {
		r.Passed = true
		r.Detail = fmt.Sprintf("syntax-checked %d changed file(s); no errors", checked)
	} else {
		r.Passed = false
		r.Detail = fmt.Sprintf("%d changed file(s) failed syntax check: %s", failed, firstErr)
	}
	return r
}

func matchesStack(kind StackKind, file string) bool {
	switch kind {
	case StackNode:
		return strings.HasSuffix(file, ".js") || strings.HasSuffix(file, ".jsx") ||
			strings.HasSuffix(file, ".ts") || strings.HasSuffix(file, ".tsx")
	case StackPython:
		return strings.HasSuffix(file, ".py")
	default:
		return false
	}
}

// buildFailures maps a build command result to a coarse failure count.
func buildFailures(res CmdResult) int {
	if res.ran() && res.ExitCode == 0 {
		return 0
	}
	return 1
}

// hasNodeScript reports whether package.json defines the named npm script.
func hasNodeScript(dir, script string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return false
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return false
	}
	_, ok := pkg.Scripts[script]
	return ok
}
