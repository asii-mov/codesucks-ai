package repo

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Repo is a local clone of a target repository.
type Repo struct {
	Dir           string
	Owner         string
	Name          string
	DefaultBranch string
	BaseSHA       string
}

// Clone shallow-clones url into dir and returns the resulting Repo. The token,
// when set, is supplied to git through environment-based config so it never
// appears in argv, the clone URL, or any log line.
func Clone(ctx context.Context, url, token, dir string) (*Repo, error) {
	owner, name, err := ParseURL(url)
	if err != nil {
		return nil, err
	}
	if _, err := runGit(ctx, "", authEnv(token), "clone", "--depth", "1", CloneURL(owner, name), dir); err != nil {
		return nil, fmt.Errorf("clone: %w", err)
	}
	r := &Repo{Dir: dir, Owner: owner, Name: name}
	if r.BaseSHA, err = r.git(ctx, "rev-parse", "HEAD"); err != nil {
		return nil, err
	}
	if r.DefaultBranch, err = r.git(ctx, "rev-parse", "--abbrev-ref", "HEAD"); err != nil {
		return nil, err
	}
	return r, nil
}

// CutBranch creates (or resets) branch name at the base commit and checks it
// out.
func (r *Repo) CutBranch(ctx context.Context, name string) error {
	_, err := r.git(ctx, "checkout", "-B", name, r.BaseSHA)
	return err
}

// ResetToBase discards all changes and returns to a clean checkout of the base
// commit, leaving any previously created fix branches intact.
func (r *Repo) ResetToBase(ctx context.Context) error {
	if _, err := r.git(ctx, "checkout", "-f", r.BaseSHA); err != nil {
		return err
	}
	_, err := r.git(ctx, "clean", "-fd")
	return err
}

// CommitAll stages every change and commits it with a fixed bot identity
// supplied via environment so the command does not depend on global git config.
func (r *Repo) CommitAll(ctx context.Context, msg string) error {
	if _, err := r.git(ctx, "add", "-A"); err != nil {
		return err
	}
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=codesucks-ai",
		"GIT_AUTHOR_EMAIL=codesucks-ai@users.noreply.github.com",
		"GIT_COMMITTER_NAME=codesucks-ai",
		"GIT_COMMITTER_EMAIL=codesucks-ai@users.noreply.github.com",
	)
	_, err := runGit(ctx, r.Dir, env, "commit", "-m", msg)
	return err
}

// Push pushes branch to origin, force-updating it so re-runs are idempotent.
func (r *Repo) Push(ctx context.Context, token, branch string) error {
	_, err := runGit(ctx, r.Dir, authEnv(token), "push", "--force", "origin", branch)
	return err
}

// ChangedFiles returns the repo-relative paths modified in the working tree
// relative to HEAD, including newly created (untracked) files. It uses
// column-free git commands so the paths are unaffected by output trimming.
func (r *Repo) ChangedFiles(ctx context.Context) ([]string, error) {
	tracked, err := r.git(ctx, "diff", "--name-only", "HEAD")
	if err != nil {
		return nil, err
	}
	untracked, err := r.git(ctx, "ls-files", "--others", "--exclude-standard")
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var files []string
	for _, block := range []string{tracked, untracked} {
		for _, line := range strings.Split(block, "\n") {
			p := strings.TrimSpace(line)
			if p == "" {
				continue
			}
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			files = append(files, p)
		}
	}
	return files, nil
}

// git runs a git subcommand in the repo directory with the ambient environment.
func (r *Repo) git(ctx context.Context, args ...string) (string, error) {
	return runGit(ctx, r.Dir, nil, args...)
}

// runGit executes git in dir (or the current directory when empty) with extra
// environment appended, returning trimmed stdout.
func runGit(ctx context.Context, dir string, extraEnv []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if extraEnv != nil {
		cmd.Env = extraEnv
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// authEnv builds the environment for a git command that talks to the remote,
// injecting an HTTP Authorization header via git's env-based config so the
// token stays out of argv and the URL. Returns the full environment (ambient +
// auth) or nil when no token is set.
func authEnv(token string) []string {
	if token == "" {
		return nil
	}
	cred := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	return append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.extraHeader",
		"GIT_CONFIG_VALUE_0=Authorization: basic "+cred,
	)
}
