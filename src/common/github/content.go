package github

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/asii-mov/codesucks-ai/common"
	"github.com/google/go-github/v66/github"
)

// FetchRepositoryContent downloads repository content via GitHub API
func (gc *GitHubClient) FetchRepositoryContent(owner, repo, branch, tempDir string) (string, error) {
	// Create temporary directory for this repository
	repoTempDir := filepath.Join(tempDir, fmt.Sprintf("%s-%s", owner, repo))
	if err := os.MkdirAll(repoTempDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create temp directory: %v", err)
	}

	// Recursively fetch all files from repository
	err := gc.fetchDirectoryContents(owner, repo, branch, "", repoTempDir)
	if err != nil {
		return "", fmt.Errorf("failed to fetch repository contents: %v", err)
	}

	return repoTempDir, nil
}

// fetchDirectoryContents recursively fetches directory contents
func (gc *GitHubClient) fetchDirectoryContents(owner, repo, branch, path, localDir string) error {
	// Get directory contents
	_, directoryContent, _, err := gc.Client.Repositories.GetContents(
		gc.Ctx, owner, repo, path,
		&github.RepositoryContentGetOptions{Ref: branch},
	)
	if err != nil {
		return fmt.Errorf("failed to get directory contents for path '%s': %v", path, err)
	}

	for _, content := range directoryContent {
		localPath := filepath.Join(localDir, content.GetName())

		switch content.GetType() {
		case "file":
			// Download file content
			err := gc.fetchFileContent(owner, repo, branch, content.GetPath(), localPath)
			if err != nil {
				return fmt.Errorf("failed to fetch file %s: %v", content.GetPath(), err)
			}

		case "dir":
			// Create directory and recurse
			if err := os.MkdirAll(localPath, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %v", localPath, err)
			}

			err := gc.fetchDirectoryContents(owner, repo, branch, content.GetPath(), localPath)
			if err != nil {
				return err
			}

		case "symlink":
			// Skip symlinks for security
			continue
		}
	}

	return nil
}

// fetchFileContent downloads a single file's content
func (gc *GitHubClient) fetchFileContent(owner, repo, branch, remotePath, localPath string) error {
	// Get file content
	fileContent, _, _, err := gc.Client.Repositories.GetContents(
		gc.Ctx, owner, repo, remotePath,
		&github.RepositoryContentGetOptions{Ref: branch},
	)
	if err != nil {
		return fmt.Errorf("failed to get file content: %v", err)
	}

	// Decode file content
	content, err := decodeFileContent(fileContent)
	if err != nil {
		return fmt.Errorf("failed to decode file content: %v", err)
	}

	// Write file to local filesystem
	if err := os.WriteFile(localPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	return nil
}

// decodeFileContent decodes base64-encoded file content from GitHub API
func decodeFileContent(fileContent *github.RepositoryContent) (string, error) {
	// GetContent already handles base64 decoding automatically
	return fileContent.GetContent()
}

// GetFileContent retrieves the content of a specific file
func (gc *GitHubClient) GetFileContent(owner, repo, branch, filePath string) (string, error) {
	fileContent, _, _, err := gc.Client.Repositories.GetContents(
		gc.Ctx, owner, repo, filePath,
		&github.RepositoryContentGetOptions{Ref: branch},
	)
	if err != nil {
		return "", fmt.Errorf("failed to get file content: %v", err)
	}

	content, err := decodeFileContent(fileContent)
	if err != nil {
		return "", fmt.Errorf("failed to decode file content: %v", err)
	}

	return content, nil
}

// ListRepositoryFiles lists all files in a repository (for analysis planning)
func (gc *GitHubClient) ListRepositoryFiles(owner, repo, branch string) ([]common.RepositoryFile, error) {
	var files []common.RepositoryFile
	err := gc.listFilesRecursive(owner, repo, branch, "", &files)
	if err != nil {
		return nil, fmt.Errorf("failed to list repository files: %v", err)
	}
	return files, nil
}

// listFilesRecursive recursively lists all files in a repository
func (gc *GitHubClient) listFilesRecursive(owner, repo, branch, path string, files *[]common.RepositoryFile) error {
	_, directoryContent, _, err := gc.Client.Repositories.GetContents(
		gc.Ctx, owner, repo, path,
		&github.RepositoryContentGetOptions{Ref: branch},
	)
	if err != nil {
		return fmt.Errorf("failed to get directory contents: %v", err)
	}

	for _, content := range directoryContent {
		switch content.GetType() {
		case "file":
			file := common.RepositoryFile{
				Path: content.GetPath(),
				SHA:  content.GetSHA(),
				Size: content.GetSize(),
				Type: "file",
			}
			*files = append(*files, file)

		case "dir":
			// Add directory entry
			dir := common.RepositoryFile{
				Path: content.GetPath(),
				SHA:  content.GetSHA(),
				Size: 0,
				Type: "dir",
			}
			*files = append(*files, dir)

			// Recurse into directory
			err := gc.listFilesRecursive(owner, repo, branch, content.GetPath(), files)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// GetAnalysisFiles filters repository files to only include those suitable for security analysis
func (gc *GitHubClient) GetAnalysisFiles(owner, repo, branch string) ([]common.RepositoryFile, error) {
	allFiles, err := gc.ListRepositoryFiles(owner, repo, branch)
	if err != nil {
		return nil, err
	}

	var analysisFiles []common.RepositoryFile
	for _, file := range allFiles {
		if file.Type == "file" && shouldAnalyzeFile(file.Path) {
			analysisFiles = append(analysisFiles, file)
		}
	}

	return analysisFiles, nil
}

// shouldAnalyzeFile determines if a file should be included in security analysis
func shouldAnalyzeFile(filePath string) bool {
	// Skip binary files and common non-source files
	skipExtensions := map[string]bool{
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".bmp": true,
		".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
		".zip": true, ".tar": true, ".gz": true, ".7z": true, ".rar": true,
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
		".mp3": true, ".mp4": true, ".avi": true, ".mov": true,
	}

	// Skip certain directories
	skipDirs := []string{
		".git/", "node_modules/", "vendor/", "build/", "dist/",
		"target/", "bin/", "obj/", ".vscode/", ".idea/",
		"__pycache__/", ".pytest_cache/", "coverage/",
	}

	// Check if file is in a skip directory
	for _, skipDir := range skipDirs {
		if strings.Contains(filePath, skipDir) {
			return false
		}
	}

	// Check file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	if skipExtensions[ext] {
		return false
	}

	// Include source code files and configuration files
	includeExtensions := map[string]bool{
		".js": true, ".jsx": true, ".ts": true, ".tsx": true,
		".py": true, ".rb": true, ".php": true, ".java": true,
		".c": true, ".cpp": true, ".cc": true, ".cxx": true, ".h": true, ".hpp": true,
		".cs": true, ".go": true, ".rs": true, ".swift": true, ".kt": true,
		".html": true, ".htm": true, ".xml": true, ".json": true, ".yaml": true, ".yml": true,
		".toml": true, ".ini": true, ".cfg": true, ".conf": true, ".config": true,
		".sql": true, ".sh": true, ".bash": true, ".zsh": true, ".fish": true,
		".dockerfile": true, ".tf": true, ".hcl": true,
	}

	// Check if it's a known source file extension
	if includeExtensions[ext] {
		return true
	}

	// Include files without extensions that might be configuration files
	if ext == "" {
		baseName := strings.ToLower(filepath.Base(filePath))
		configFiles := map[string]bool{
			"dockerfile": true, "makefile": true, "rakefile": true,
			"gemfile": true, "requirements.txt": true, "package.json": true,
			"composer.json": true, "pom.xml": true, "build.gradle": true,
			"cargo.toml": true, "setup.py": true, "pipfile": true,
		}
		return configFiles[baseName]
	}

	return false
}
