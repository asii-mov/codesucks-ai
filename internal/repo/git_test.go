package repo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// initFixtureRepo creates a git repo with one commit and returns a *Repo bound
// to it, mirroring the state Clone would leave behind.
func initFixtureRepo(t *testing.T) *Repo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	ctx := context.Background()

	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
	)
	run := func(args ...string) {
		t.Helper()
		if _, err := runGit(ctx, dir, env, args...); err != nil {
			t.Fatalf("git %s: %v", strings.Join(args, " "), err)
		}
	}
	run("init", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("eval(x)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-m", "initial")

	sha, err := runGit(ctx, dir, env, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	return &Repo{Dir: dir, Owner: "o", Name: "r", DefaultBranch: "main", BaseSHA: sha}
}

func TestRepo_BranchCommitDiffReset(t *testing.T) {
	r := initFixtureRepo(t)
	ctx := context.Background()

	if err := r.CutBranch(ctx, "fix/eval-abc123"); err != nil {
		t.Fatal(err)
	}
	branch, _ := r.git(ctx, "rev-parse", "--abbrev-ref", "HEAD")
	if branch != "fix/eval-abc123" {
		t.Fatalf("expected to be on fix branch, got %q", branch)
	}

	// modify the file
	if err := os.WriteFile(filepath.Join(r.Dir, "app.js"), []byte("safeEval(x)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := r.ChangedFiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 || changed[0] != "app.js" {
		t.Fatalf("expected [app.js] changed, got %v", changed)
	}

	if err := r.CommitAll(ctx, "fix: patch eval"); err != nil {
		t.Fatal(err)
	}
	if clean, _ := r.ChangedFiles(ctx); len(clean) != 0 {
		t.Errorf("working tree should be clean after commit, got %v", clean)
	}

	// reset returns to a clean base checkout
	if err := r.ResetToBase(ctx); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(filepath.Join(r.Dir, "app.js"))
	if strings.TrimSpace(string(content)) != "eval(x)" {
		t.Errorf("reset did not restore base content, got %q", content)
	}

	// the fix branch still exists after reset
	if _, err := r.git(ctx, "rev-parse", "--verify", "fix/eval-abc123"); err != nil {
		t.Errorf("fix branch should survive reset: %v", err)
	}
}

func TestRepo_ChangedFilesIncludesUntracked(t *testing.T) {
	r := initFixtureRepo(t)
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(r.Dir, "new.js"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := r.ChangedFiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range changed {
		if f == "new.js" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected untracked new.js in changed set, got %v", changed)
	}
}

func TestAuthEnv_KeepsTokenOutOfArgv(t *testing.T) {
	env := authEnv("supersecrettoken")
	var hasHeader bool
	for _, e := range env {
		if strings.HasPrefix(e, "GIT_CONFIG_VALUE_0=Authorization: basic ") {
			hasHeader = true
		}
		if strings.Contains(e, "supersecrettoken") && !strings.HasPrefix(e, "GIT_CONFIG_VALUE_0=") {
			t.Errorf("token appears unexpectedly in env entry: %s", e)
		}
	}
	if !hasHeader {
		t.Error("expected an Authorization extraHeader in the git env")
	}
	if authEnv("") != nil {
		t.Error("empty token should yield nil env")
	}
}
