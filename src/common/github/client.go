package github

import (
	"context"
	"fmt"
	"strings"

	"github.com/asii-mov/codesucks-ai/common"
	"github.com/google/go-github/v66/github"
	"golang.org/x/oauth2"
)

type GitHubClient struct {
	Client *github.Client
	Ctx    context.Context
}

// NewClient creates a new GitHub client with authentication
func NewClient(options *common.Options) (*GitHubClient, error) {
	ctx := context.Background()

	var client *github.Client

	// Use personal access token authentication
	if options.GitHubToken != "" {
		client = newTokenClient(ctx, options.GitHubToken)
	} else {
		return nil, fmt.Errorf("GitHub token is required")
	}

	return &GitHubClient{
		Client: client,
		Ctx:    ctx,
	}, nil
}

// newTokenClient creates a GitHub client using a personal access token
func newTokenClient(ctx context.Context, token string) *github.Client {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
}

// ParseRepositoryURL extracts owner and repository name from GitHub URL
func ParseRepositoryURL(url string) (owner, repo string, err error) {
	// Check if it's a non-GitHub URL
	if !strings.Contains(url, "github.com") {
		return "", "", fmt.Errorf("not a GitHub URL")
	}

	// Handle SSH git URLs
	if strings.HasPrefix(url, "git@github.com:") {
		url = strings.TrimPrefix(url, "git@github.com:")
	} else {
		// Remove HTTP(S) prefixes
		url = strings.TrimPrefix(url, "https://github.com/")
		url = strings.TrimPrefix(url, "http://github.com/")
	}

	// Remove common suffixes
	url = strings.TrimSuffix(url, ".git")
	url = strings.TrimSuffix(url, "/")

	parts := strings.Split(url, "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid GitHub URL format")
	}

	return parts[0], parts[1], nil
}

// GetRepositoryInfo retrieves basic repository information
func (gc *GitHubClient) GetRepositoryInfo(owner, repo string) (*common.RepoInfo, error) {
	repository, _, err := gc.Client.Repositories.Get(gc.Ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository info: %v", err)
	}

	repoInfo := &common.RepoInfo{
		URL:           repository.GetHTMLURL(),
		Owner:         repository.GetOwner().GetLogin(),
		Name:          repository.GetName(),
		Branch:        repository.GetDefaultBranch(),
		DefaultBranch: repository.GetDefaultBranch(),
		Private:       repository.GetPrivate(),
		Language:      repository.GetLanguage(),
		Description:   repository.GetDescription(),
		Size:          repository.GetSize(), // Size in KB
		Stars:         repository.GetStargazersCount(),
		CreatedAt:     repository.GetCreatedAt().Format("2006-01-02"),
		UpdatedAt:     repository.GetUpdatedAt().Format("2006-01-02"),
	}

	// Estimate file count based on size (rough approximation)
	// Average file size assumption: 10KB
	if repoInfo.Size > 0 {
		repoInfo.FileCount = repoInfo.Size / 10
	}

	return repoInfo, nil
}

// GetLanguages retrieves language statistics for a repository
func (gc *GitHubClient) GetLanguages(owner, repo string) (*common.LanguageStats, error) {
	languages, _, err := gc.Client.Repositories.ListLanguages(gc.Ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository languages: %v", err)
	}

	// Calculate total bytes
	total := 0
	for _, bytes := range languages {
		total += bytes
	}

	return &common.LanguageStats{
		Languages: languages,
		Total:     total,
	}, nil
}

// GetRepositoryFiles retrieves a list of files in the repository (without content)
func (gc *GitHubClient) GetRepositoryFiles(owner, repo, branch string) ([]common.RepositoryFile, error) {
	if branch == "" {
		// Get default branch
		repository, _, err := gc.Client.Repositories.Get(gc.Ctx, owner, repo)
		if err != nil {
			return nil, fmt.Errorf("failed to get repository info: %v", err)
		}
		branch = repository.GetDefaultBranch()
	}

	var files []common.RepositoryFile
	err := gc.listRepositoryFiles(owner, repo, branch, "", &files, 0, 100) // Limit depth to avoid too many API calls
	if err != nil {
		return nil, fmt.Errorf("failed to list repository files: %v", err)
	}

	return files, nil
}

// listRepositoryFiles recursively lists files in the repository (limited depth for performance)
func (gc *GitHubClient) listRepositoryFiles(owner, repo, branch, path string, files *[]common.RepositoryFile, depth, maxDepth int) error {
	if depth > maxDepth {
		return nil // Stop recursion at max depth
	}

	// Get directory contents
	_, directoryContent, _, err := gc.Client.Repositories.GetContents(
		gc.Ctx, owner, repo, path,
		&github.RepositoryContentGetOptions{Ref: branch},
	)
	if err != nil {
		return fmt.Errorf("failed to get directory contents for path '%s': %v", path, err)
	}

	for _, content := range directoryContent {
		file := common.RepositoryFile{
			Path: content.GetPath(),
			Type: content.GetType(),
			Size: content.GetSize(),
		}

		// For key files, get content for framework detection
		if gc.isKeyFile(content.GetName()) && content.GetSize() < 10000 { // Only small files
			fileContent, err := gc.GetFileContent(owner, repo, branch, content.GetPath())
			if err == nil {
				file.Content = fileContent
			}
		}

		*files = append(*files, file)

		// Recurse into directories (with depth limit)
		if content.GetType() == "dir" {
			err := gc.listRepositoryFiles(owner, repo, branch, content.GetPath(), files, depth+1, maxDepth)
			if err != nil {
				// Don't fail entire operation for one directory
				continue
			}
		}
	}

	return nil
}

// isKeyFile determines if a file is important for framework detection
func (gc *GitHubClient) isKeyFile(filename string) bool {
	keyFiles := []string{
		"package.json",
		"requirements.txt",
		"pom.xml",
		"go.mod",
		"Gemfile",
		"composer.json",
		"Cargo.toml",
		"build.gradle",
		"app.py",
		"manage.py",
		"artisan",
		"next.config.js",
		"webpack.config.js",
		"tsconfig.json",
	}

	for _, key := range keyFiles {
		if filename == key {
			return true
		}
	}
	return false
}

// TestAuthentication verifies that the GitHub client is properly authenticated
func (gc *GitHubClient) TestAuthentication() error {
	// Try to get user information to test authentication
	_, _, err := gc.Client.Users.Get(gc.Ctx, "")
	if err != nil {
		return fmt.Errorf("GitHub authentication failed: %v", err)
	}
	return nil
}
