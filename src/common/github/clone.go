package github

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/asii-mov/codesucks-ai/common"
)

// CloneRepository clones a repository using git
func (gc *GitHubClient) CloneRepository(owner, repo, branch, tempDir string, options *common.Options) (string, error) {
	// Create temporary directory for this repository
	repoTempDir := filepath.Join(tempDir, fmt.Sprintf("%s-%s", owner, repo))

	// Clean up any existing directory
	if err := os.RemoveAll(repoTempDir); err != nil {
		return "", fmt.Errorf("failed to clean existing directory: %v", err)
	}

	if err := os.MkdirAll(repoTempDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create temp directory: %v", err)
	}

	// Build clone URL with authentication for private repos
	cloneURL := gc.buildCloneURL(owner, repo, options.GitHubToken)

	// Set timeout for clone operation
	timeout := 300 * time.Second
	if options.CloneTimeout > 0 {
		timeout = time.Duration(options.CloneTimeout) * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Use shallow clone for performance (depth=1)
	args := []string{
		"clone",
		"--quiet",
		"--depth", "1",
		"--single-branch",
		"--branch", branch,
		cloneURL,
		repoTempDir,
	}

	fmt.Printf("🔄 Cloning repository %s/%s (branch: %s)...\n", owner, repo, branch)

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = append(os.Environ(), gc.setupGitEnv(options)...)

	// Capture output for debugging
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Clean up failed clone
		os.RemoveAll(repoTempDir)

		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("git clone timed out after %v", timeout)
		}
		return "", fmt.Errorf("git clone failed: %v\nOutput: %s", err, string(output))
	}

	fmt.Printf("✅ Successfully cloned repository to %s\n", repoTempDir)
	return repoTempDir, nil
}

// buildCloneURL constructs the appropriate clone URL with authentication
func (gc *GitHubClient) buildCloneURL(owner, repo, token string) string {
	// For public repos or no token, use HTTPS without auth
	if token == "" {
		return fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
	}

	// For private repos with token, embed token in URL
	// Format: https://TOKEN@github.com/owner/repo.git
	return fmt.Sprintf("https://%s@github.com/%s/%s.git", token, owner, repo)
}

// setupGitEnv sets up environment variables for git operations
func (gc *GitHubClient) setupGitEnv(options *common.Options) []string {
	env := []string{
		"GIT_TERMINAL_PROMPT=0", // Disable password prompts
		"GIT_ASKPASS=echo",      // Return empty for password prompts
	}

	// Add token as environment variable for additional auth methods
	if options.GitHubToken != "" {
		env = append(env, fmt.Sprintf("GITHUB_TOKEN=%s", options.GitHubToken))
	}

	return env
}

// ShouldUseGitClone determines whether to use git clone based on repository size and configuration
func (gc *GitHubClient) ShouldUseGitClone(repoInfo *common.RepoInfo, options *common.Options) bool {
	// Check force flags first
	if options.ForceGitClone {
		fmt.Println("📌 Using git clone (forced by configuration)")
		return true
	}

	if options.ForceAPIDownload {
		fmt.Println("📌 Using API download (forced by configuration)")
		return false
	}

	// Set default thresholds if not configured
	sizeThreshold := options.CloneSizeThreshold
	if sizeThreshold == 0 {
		sizeThreshold = 50 // 50 MB default
	}

	fileThreshold := options.CloneFileThreshold
	if fileThreshold == 0 {
		fileThreshold = 1000 // 1000 files default
	}

	// Convert size from KB to MB
	sizeInMB := repoInfo.Size / 1024

	// Decision logic
	reasons := []string{}
	shouldClone := false

	if sizeInMB > sizeThreshold {
		reasons = append(reasons, fmt.Sprintf("size %dMB > threshold %dMB", sizeInMB, sizeThreshold))
		shouldClone = true
	}

	if repoInfo.FileCount > fileThreshold {
		reasons = append(reasons, fmt.Sprintf("~%d files > threshold %d", repoInfo.FileCount, fileThreshold))
		shouldClone = true
	}

	if repoInfo.Stars > 500 {
		reasons = append(reasons, fmt.Sprintf("%d stars (popular repo)", repoInfo.Stars))
		shouldClone = true
	}

	if shouldClone {
		fmt.Printf("🚀 Using git clone for %s/%s (%s)\n", repoInfo.Owner, repoInfo.Name, strings.Join(reasons, ", "))
	} else {
		fmt.Printf("📡 Using API download for %s/%s (size: %dMB, ~%d files)\n",
			repoInfo.Owner, repoInfo.Name, sizeInMB, repoInfo.FileCount)
	}

	return shouldClone
}

// SmartFetchContent intelligently chooses between git clone and API download
func (gc *GitHubClient) SmartFetchContent(owner, repo, branch, tempDir string, repoInfo *common.RepoInfo, options *common.Options) (string, error) {
	if gc.ShouldUseGitClone(repoInfo, options) {
		// Try git clone first
		clonedPath, err := gc.CloneRepository(owner, repo, branch, tempDir, options)
		if err != nil {
			fmt.Printf("⚠️ Git clone failed, falling back to API download: %v\n", err)
			// Fall back to API download if clone fails
			return gc.FetchRepositoryContent(owner, repo, branch, tempDir)
		}
		return clonedPath, nil
	}

	// Use API download for small repositories
	return gc.FetchRepositoryContent(owner, repo, branch, tempDir)
}

// CleanupRepository ensures the cloned repository is properly deleted
func CleanupRepository(repoPath string) error {
	if repoPath == "" || !strings.Contains(repoPath, "temp") {
		// Safety check to avoid deleting non-temp directories
		return nil
	}

	fmt.Printf("🧹 Cleaning up repository at %s\n", repoPath)

	// Try to remove the directory
	err := os.RemoveAll(repoPath)
	if err != nil {
		// On Windows, files might be locked. Try again after a short delay
		time.Sleep(100 * time.Millisecond)
		err = os.RemoveAll(repoPath)
	}

	if err != nil {
		return fmt.Errorf("failed to cleanup repository: %v", err)
	}

	return nil
}

// IsGitInstalled checks if git is available in the system
func IsGitInstalled() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// GetGitVersion returns the installed git version
func GetGitVersion() (string, error) {
	cmd := exec.Command("git", "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}
