package github

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asii-mov/codesucks-ai/common"
)

func TestIsGitInstalled(t *testing.T) {
	// This test will pass if git is installed
	isInstalled := IsGitInstalled()
	t.Logf("Git installed: %v", isInstalled)
}

func TestGetGitVersion(t *testing.T) {
	version, err := GetGitVersion()
	if err != nil {
		if IsGitInstalled() {
			t.Errorf("Failed to get git version: %v", err)
		} else {
			t.Skip("Git not installed, skipping version test")
		}
		return
	}
	
	if !strings.Contains(version, "git") {
		t.Errorf("Unexpected git version format: %s", version)
	}
	
	t.Logf("Git version: %s", version)
}

func TestBuildCloneURL(t *testing.T) {
	gc := &GitHubClient{}
	
	testCases := []struct {
		name     string
		owner    string
		repo     string
		token    string
		expected string
	}{
		{
			name:     "Public repo without token",
			owner:    "owner",
			repo:     "repo",
			token:    "",
			expected: "https://github.com/owner/repo.git",
		},
		{
			name:     "Private repo with token",
			owner:    "owner",
			repo:     "repo",
			token:    "test-token",
			expected: "https://test-token@github.com/owner/repo.git",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := gc.buildCloneURL(tc.owner, tc.repo, tc.token)
			if url != tc.expected {
				t.Errorf("Expected URL %s, got %s", tc.expected, url)
			}
		})
	}
}

func TestShouldUseGitClone(t *testing.T) {
	gc := &GitHubClient{}
	
	testCases := []struct {
		name         string
		repoInfo     *common.RepoInfo
		options      *common.Options
		shouldClone  bool
	}{
		{
			name: "Small repository",
			repoInfo: &common.RepoInfo{
				Size:      10240,  // 10 MB
				FileCount: 100,
				Stars:     10,
			},
			options: &common.Options{
				CloneSizeThreshold: 50,
				CloneFileThreshold: 1000,
			},
			shouldClone: false,
		},
		{
			name: "Large repository by size",
			repoInfo: &common.RepoInfo{
				Size:      102400, // 100 MB
				FileCount: 500,
				Stars:     10,
			},
			options: &common.Options{
				CloneSizeThreshold: 50,
				CloneFileThreshold: 1000,
			},
			shouldClone: true,
		},
		{
			name: "Large repository by file count",
			repoInfo: &common.RepoInfo{
				Size:      10240, // 10 MB
				FileCount: 2000,
				Stars:     10,
			},
			options: &common.Options{
				CloneSizeThreshold: 50,
				CloneFileThreshold: 1000,
			},
			shouldClone: true,
		},
		{
			name: "Popular repository",
			repoInfo: &common.RepoInfo{
				Size:      10240, // 10 MB
				FileCount: 100,
				Stars:     1000,
			},
			options: &common.Options{
				CloneSizeThreshold: 50,
				CloneFileThreshold: 1000,
			},
			shouldClone: true,
		},
		{
			name: "Force git clone",
			repoInfo: &common.RepoInfo{
				Size:      1024, // 1 MB
				FileCount: 10,
				Stars:     1,
			},
			options: &common.Options{
				ForceGitClone: true,
			},
			shouldClone: true,
		},
		{
			name: "Force API download",
			repoInfo: &common.RepoInfo{
				Size:      102400, // 100 MB
				FileCount: 2000,
				Stars:     1000,
			},
			options: &common.Options{
				ForceAPIDownload: true,
			},
			shouldClone: false,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := gc.ShouldUseGitClone(tc.repoInfo, tc.options)
			if result != tc.shouldClone {
				t.Errorf("Expected shouldClone=%v, got %v", tc.shouldClone, result)
			}
		})
	}
}

func TestCleanupRepository(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "test-cleanup-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	
	// Create some test files
	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	
	// Test cleanup
	err = CleanupRepository(tempDir)
	if err != nil {
		t.Errorf("Failed to cleanup repository: %v", err)
	}
	
	// Check that directory was removed
	if _, err := os.Stat(tempDir); !os.IsNotExist(err) {
		t.Error("Directory was not removed after cleanup")
	}
}

func TestCleanupRepositorySafety(t *testing.T) {
	// Test that cleanup refuses to delete non-temp directories
	nonTempPaths := []string{
		"/home/user/important",
		"/usr/bin",
		"",
		"/",
	}
	
	for _, path := range nonTempPaths {
		err := CleanupRepository(path)
		if err != nil {
			t.Errorf("CleanupRepository should not error on non-temp path %s, got: %v", path, err)
		}
		// The function should return nil without attempting deletion
	}
}

func TestSetupGitEnv(t *testing.T) {
	gc := &GitHubClient{}
	
	// Test without token
	options := &common.Options{}
	env := gc.setupGitEnv(options)
	
	hasTerminalPrompt := false
	for _, e := range env {
		if e == "GIT_TERMINAL_PROMPT=0" {
			hasTerminalPrompt = true
			break
		}
	}
	
	if !hasTerminalPrompt {
		t.Error("Expected GIT_TERMINAL_PROMPT=0 in environment")
	}
	
	// Test with token
	options = &common.Options{
		GitHubToken: "test-token",
	}
	env = gc.setupGitEnv(options)
	
	hasToken := false
	for _, e := range env {
		if strings.HasPrefix(e, "GITHUB_TOKEN=") {
			hasToken = true
			break
		}
	}
	
	if !hasToken {
		t.Error("Expected GITHUB_TOKEN in environment when token is provided")
	}
}