// Package gates runs the three deterministic verification gates that a patch
// must pass before a pull request is opened: the fix is verified by re-scanning,
// linting introduces no new issues, and the application still builds/tests. All
// verdicts are computed in Go, never by model judgment.
package gates

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/asii-mov/codesucks-ai/internal/scan"
)

// capBuffer is a bounded byte buffer that discards output past a cap, so a
// runaway command cannot exhaust memory.
type capBuffer struct {
	buf []byte
}

const capBufferMax = 1 << 20 // 1 MiB

func (b *capBuffer) Write(p []byte) (int, error) {
	if room := capBufferMax - len(b.buf); room > 0 {
		if len(p) > room {
			b.buf = append(b.buf, p[:room]...)
		} else {
			b.buf = append(b.buf, p...)
		}
	}
	return len(p), nil
}

func (b *capBuffer) String() string { return string(b.buf) }

// Result is the outcome of one gate, including the exact command run and the
// baseline→after counts, for inclusion in the PR body.
type Result struct {
	Name     string `json:"name"`
	Command  string `json:"command"`
	Detail   string `json:"detail,omitempty"`
	Passed   bool   `json:"passed"`
	Baseline int    `json:"baseline"`
	After    int    `json:"after"`
}

// CmdResult is the outcome of running one external command.
type CmdResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error // set when the process could not be started (e.g. binary missing)
}

// combined returns stdout and stderr concatenated.
func (r CmdResult) combined() string { return r.Stdout + "\n" + r.Stderr }

// ran reports whether the command actually executed (vs. failing to start).
func (r CmdResult) ran() bool { return r.Err == nil }

// CommandRunner runs an external command in dir and returns its result. It is a
// seam so gate logic can be unit-tested without executing real tools.
type CommandRunner func(ctx context.Context, dir, name string, args ...string) CmdResult

// ExecRunner is the production CommandRunner.
func ExecRunner(ctx context.Context, dir, name string, args ...string) CmdResult {
	if _, err := exec.LookPath(name); err != nil {
		return CmdResult{Err: err, ExitCode: -1}
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var out, errb capBuffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	runErr := cmd.Run()
	res := CmdResult{Stdout: out.String(), Stderr: errb.String()}
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		} else {
			res.Err = runErr
			res.ExitCode = -1
		}
	}
	return res
}

// Rescanner re-runs the scanner behind a finding over the given changed files.
type Rescanner func(ctx context.Context, changed []string) ([]scan.Finding, error)

// Timeouts for gate commands.
const gateTimeout = 10 * time.Minute

func withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, gateTimeout)
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func joinRepo(dir, rel string) string { return filepath.Join(dir, rel) }
