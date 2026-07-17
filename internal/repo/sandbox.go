package repo

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ErrEscape is returned when a requested path resolves outside the sandbox
// root, whether by traversal or a symlink.
var ErrEscape = errors.New("path escapes sandbox root")

// Sandbox exposes read and edit operations confined to a single directory
// tree. Every path an agent supplies is resolved through it, so no tool call
// can touch a file outside the clone.
type Sandbox struct {
	root string
}

// Match is a single search hit.
type Match struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

// NewSandbox roots a sandbox at dir, resolving it to a canonical absolute path.
func NewSandbox(dir string) (*Sandbox, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	return &Sandbox{root: abs}, nil
}

// Root returns the sandbox's absolute root directory.
func (s *Sandbox) Root() string { return s.root }

// resolve turns a repo-relative path into an absolute one, rejecting any path
// that would escape the root through traversal or a symlink.
func (s *Sandbox) resolve(rel string) (string, error) {
	abs := filepath.Join(s.root, rel)
	if !s.within(abs) {
		return "", fmt.Errorf("%w: %s", ErrEscape, rel)
	}
	if real, err := resolveExisting(abs); err == nil && !s.within(real) {
		return "", fmt.Errorf("%w (symlink): %s", ErrEscape, rel)
	}
	return abs, nil
}

func (s *Sandbox) within(p string) bool {
	return p == s.root || strings.HasPrefix(p, s.root+string(filepath.Separator))
}

// resolveExisting returns the fully symlink-resolved path of the deepest
// existing ancestor of p.
func resolveExisting(p string) (string, error) {
	cur := p
	for {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			return real, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", os.ErrNotExist
		}
		cur = parent
	}
}

// ReadFile returns file contents, optionally restricted to the 1-indexed line
// range [start, end]. A non-positive start or end extends to the file's edge.
func (s *Sandbox) ReadFile(rel string, start, end int) (string, error) {
	abs, err := s.resolve(rel)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return "", err
	}
	if start <= 0 && end <= 0 {
		return string(data), nil
	}
	lines := strings.Split(string(data), "\n")
	if start <= 0 {
		start = 1
	}
	if end <= 0 || end > len(lines) {
		end = len(lines)
	}
	if start > len(lines) {
		return "", nil
	}
	return strings.Join(lines[start-1:end], "\n"), nil
}

// ListDir lists the entries of a directory, appending a slash to subdirectories.
func (s *Sandbox) ListDir(rel string) ([]string, error) {
	abs, err := s.resolve(rel)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Name() == ".git" {
			continue
		}
		if e.IsDir() {
			out = append(out, e.Name()+"/")
		} else {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

const maxSearchFileBytes = 1 << 20 // 1 MiB

// Search scans text files under subdir (default: whole tree) for query, as a
// literal substring or a regular expression, returning up to max matches.
func (s *Sandbox) Search(query string, isRegex bool, subdir string, max int) ([]Match, error) {
	if max <= 0 {
		max = 100
	}
	base, err := s.resolve(subdir)
	if err != nil {
		return nil, err
	}
	var re *regexp.Regexp
	if isRegex {
		if re, err = regexp.Compile(query); err != nil {
			return nil, fmt.Errorf("invalid regex: %w", err)
		}
	}

	var matches []Match
	walkErr := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if len(matches) >= max {
			return filepath.SkipAll
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxSearchFileBytes {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(s.root, path)
		rel = filepath.ToSlash(rel)
		for i, line := range strings.Split(string(data), "\n") {
			if len(matches) >= max {
				break
			}
			hit := false
			if isRegex {
				hit = re.MatchString(line)
			} else {
				hit = strings.Contains(line, query)
			}
			if hit {
				matches = append(matches, Match{File: rel, Line: i + 1, Text: strings.TrimSpace(line)})
			}
		}
		return nil
	})
	return matches, walkErr
}

// ApplyEdit replaces exactly one occurrence of oldStr with newStr in the file
// at rel. It fails if oldStr is absent or appears more than once, so an edit is
// never applied ambiguously.
func (s *Sandbox) ApplyEdit(rel, oldStr, newStr string) error {
	abs, err := s.resolve(rel)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return err
	}
	content := string(data)
	switch strings.Count(content, oldStr) {
	case 0:
		return fmt.Errorf("edit target not found in %s", rel)
	case 1:
		// ok
	default:
		return fmt.Errorf("edit target is ambiguous in %s (appears more than once)", rel)
	}
	updated := strings.Replace(content, oldStr, newStr, 1)
	info, err := os.Stat(abs)
	if err != nil {
		return err
	}
	return os.WriteFile(abs, []byte(updated), info.Mode().Perm())
}
