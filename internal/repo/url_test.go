package repo

import "testing"

func TestParseURL(t *testing.T) {
	cases := []struct {
		in          string
		owner, name string
		wantErr     bool
	}{
		{"https://github.com/asii-mov/NodeGoat-AI-test", "asii-mov", "NodeGoat-AI-test", false},
		{"https://github.com/asii-mov/NodeGoat-AI-test.git", "asii-mov", "NodeGoat-AI-test", false},
		{"https://github.com/owner/repo/", "owner", "repo", false},
		{"git@github.com:owner/repo.git", "owner", "repo", false},
		{"  https://github.com/o/r  ", "o", "r", false},
		{"https://gitlab.com/o/r", "", "", true},
		{"not a url", "", "", true},
	}
	for _, c := range cases {
		owner, name, err := ParseURL(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseURL(%q) expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseURL(%q) unexpected error: %v", c.in, err)
			continue
		}
		if owner != c.owner || name != c.name {
			t.Errorf("ParseURL(%q) = %s/%s, want %s/%s", c.in, owner, name, c.owner, c.name)
		}
	}
}

func TestCloneURL(t *testing.T) {
	if got := CloneURL("o", "r"); got != "https://github.com/o/r.git" {
		t.Errorf("CloneURL = %s", got)
	}
}
