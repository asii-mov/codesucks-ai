package gates

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

var (
	reNodeTestFail = regexp.MustCompile(`(?m)^#\s+fail\s+(\d+)`) // node --test TAP summary
	reXFailed      = regexp.MustCompile(`(\d+)\s+failed`)        // jest / pytest
	reXFailing     = regexp.MustCompile(`(\d+)\s+failing`)       // mocha
	reDiagnostic   = regexp.MustCompile(`:\d+:\d*:?\s`)          // file:line[:col] diagnostic
)

func firstInt(re *regexp.Regexp, s string) (int, bool) {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// testFailureCount extracts the number of failing tests from command output,
// recognizing common reporters and falling back to a coarse exit-code signal so
// pre-existing failures can still be compared against a baseline.
func testFailureCount(res CmdResult) int {
	out := res.combined()
	if n, ok := firstInt(reNodeTestFail, out); ok {
		return n
	}
	if n, ok := firstInt(reXFailed, out); ok {
		return n
	}
	if n, ok := firstInt(reXFailing, out); ok {
		return n
	}
	if goFails := strings.Count(out, "--- FAIL"); goFails > 0 {
		return goFails
	}
	if res.ExitCode == 0 {
		return 0
	}
	return 1
}

// lintIssueCount extracts the number of lint issues from command output.
func lintIssueCount(stack Stack, res CmdResult) int {
	switch stack.Kind {
	case StackNode:
		if n, ok := eslintJSONCount(res.Stdout); ok {
			return n
		}
	case StackPython:
		if n, ok := ruffJSONCount(res.Stdout); ok {
			return n
		}
	}
	return diagnosticLineCount(res.combined())
}

func eslintJSONCount(stdout string) (int, bool) {
	var files []struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &files); err != nil {
		return 0, false
	}
	total := 0
	for _, f := range files {
		total += len(f.Messages)
	}
	return total, true
}

func ruffJSONCount(stdout string) (int, bool) {
	var issues []json.RawMessage
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &issues); err != nil {
		return 0, false
	}
	return len(issues), true
}

// diagnosticLineCount counts lines that look like compiler/linter diagnostics.
func diagnosticLineCount(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if reDiagnostic.MatchString(line) {
			n++
		}
	}
	return n
}
