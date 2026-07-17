package repo

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func newTestSandbox(t *testing.T) (*Sandbox, string) {
	t.Helper()
	dir := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	must := func(rel, content string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("app/index.js", "line one\nline two\neval(req.query.x)\nline four\n")
	must("app/util.js", "export const ok = 1\n")
	must("README.md", "hello\n")

	sb, err := NewSandbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	return sb, dir
}

func TestSandbox_RejectsTraversal(t *testing.T) {
	sb, _ := newTestSandbox(t)
	for _, bad := range []string{"../etc/passwd", "../../secret", "app/../../escape"} {
		if _, err := sb.ReadFile(bad, 0, 0); !errors.Is(err, ErrEscape) {
			t.Errorf("ReadFile(%q) expected ErrEscape, got %v", bad, err)
		}
	}
}

func TestSandbox_RejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	sb, dir := newTestSandbox(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("top secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := sb.ReadFile("link/secret.txt", 0, 0); !errors.Is(err, ErrEscape) {
		t.Errorf("expected ErrEscape reading through escaping symlink, got %v", err)
	}
}

func TestSandbox_ReadFileLineRange(t *testing.T) {
	sb, _ := newTestSandbox(t)
	got, err := sb.ReadFile("app/index.js", 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got != "eval(req.query.x)" {
		t.Errorf("line 3 = %q", got)
	}
	full, err := sb.ReadFile("app/index.js", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(full, "line one") || !strings.Contains(full, "line four") {
		t.Errorf("full read missing content: %q", full)
	}
}

func TestSandbox_ListDir(t *testing.T) {
	sb, _ := newTestSandbox(t)
	entries, err := sb.ListDir(".")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(entries, ",")
	if !strings.Contains(joined, "app/") || !strings.Contains(joined, "README.md") {
		t.Errorf("unexpected listing: %v", entries)
	}
}

func TestSandbox_Search(t *testing.T) {
	sb, _ := newTestSandbox(t)
	lit, err := sb.Search("eval(", false, ".", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(lit) != 1 || lit[0].File != "app/index.js" || lit[0].Line != 3 {
		t.Errorf("literal search wrong: %+v", lit)
	}
	rex, err := sb.Search(`eval\(req\.\w+`, true, ".", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rex) != 1 {
		t.Errorf("regex search wrong: %+v", rex)
	}
}

func TestSandbox_ApplyEdit(t *testing.T) {
	sb, _ := newTestSandbox(t)

	// exactly one match: succeeds
	if err := sb.ApplyEdit("app/index.js", "eval(req.query.x)", "safeEval(req.query.x)"); err != nil {
		t.Fatalf("apply edit: %v", err)
	}
	got, _ := sb.ReadFile("app/index.js", 3, 3)
	if got != "safeEval(req.query.x)" {
		t.Errorf("edit not applied: %q", got)
	}

	// zero matches: error
	if err := sb.ApplyEdit("app/index.js", "does-not-exist", "x"); err == nil {
		t.Error("expected error for missing target")
	}

	// ambiguous: error
	if err := sb.ApplyEdit("app/util.js", "1", "2"); err != nil {
		// single "1" present, ok
	}
	_ = os.WriteFile(filepath.Join(sb.Root(), "app/dup.js"), []byte("x\nx\n"), 0o644)
	if err := sb.ApplyEdit("app/dup.js", "x", "y"); err == nil {
		t.Error("expected ambiguity error for multiple matches")
	}
}

func TestSandbox_ApplyEditRejectsTraversal(t *testing.T) {
	sb, _ := newTestSandbox(t)
	if err := sb.ApplyEdit("../outside.js", "a", "b"); !errors.Is(err, ErrEscape) {
		t.Errorf("expected ErrEscape, got %v", err)
	}
}
