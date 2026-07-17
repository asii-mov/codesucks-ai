// Package repo handles the target repository: cloning it, editing files inside
// a path-guarded sandbox, committing and pushing fix branches, and opening pull
// requests.
package repo

import (
	"fmt"
	"regexp"
	"strings"
)

var githubURLRe = regexp.MustCompile(`github\.com[/:]([^/]+)/([^/]+?)(?:\.git)?/?$`)

// ParseURL extracts the owner and repository name from a GitHub URL in HTTPS,
// SSH, or shorthand form.
func ParseURL(url string) (owner, name string, err error) {
	url = strings.TrimSpace(url)
	m := githubURLRe.FindStringSubmatch(url)
	if m == nil {
		return "", "", fmt.Errorf("not a recognizable GitHub URL: %q", url)
	}
	return m[1], m[2], nil
}

// CloneURL returns the canonical HTTPS clone URL (no embedded credentials).
func CloneURL(owner, name string) string {
	return fmt.Sprintf("https://github.com/%s/%s.git", owner, name)
}
