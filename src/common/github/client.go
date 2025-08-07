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
	// Remove common prefixes and suffixes
	url = strings.TrimPrefix(url, "https://github.com/")
	url = strings.TrimPrefix(url, "http://github.com/")
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
	}

	return repoInfo, nil
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
