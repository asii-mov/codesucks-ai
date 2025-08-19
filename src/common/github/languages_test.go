package github

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/go-github/v66/github"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestGetLanguages_Success(t *testing.T) {
	// Setup HTTP mock
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// Mock the GitHub API response
	httpmock.RegisterResponder("GET", "https://api.github.com/repos/owner/repo/languages",
		httpmock.NewJsonResponderOrPanic(200, map[string]int{
			"JavaScript": 85000,
			"TypeScript": 12000,
			"CSS":        3000,
		}))

	// Create client with mocked HTTP
	httpClient := &http.Client{Transport: httpmock.DefaultTransport}
	client := github.NewClient(httpClient)
	githubClient := &GitHubClient{
		Client: client,
		Ctx:    context.Background(),
	}

	// Test the method
	result, err := githubClient.GetLanguages("owner", "repo")

	assert.NoError(t, err)
	assert.Equal(t, 100000, result.Total)
	assert.Equal(t, 85000, result.Languages["JavaScript"])
	assert.Equal(t, 12000, result.Languages["TypeScript"])
	assert.Equal(t, 3000, result.Languages["CSS"])
}

func TestGetLanguages_EmptyRepository(t *testing.T) {
	// Setup HTTP mock
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// Mock empty response
	httpmock.RegisterResponder("GET", "https://api.github.com/repos/owner/empty-repo/languages",
		httpmock.NewJsonResponderOrPanic(200, map[string]int{}))

	// Create client with mocked HTTP
	httpClient := &http.Client{Transport: httpmock.DefaultTransport}
	client := github.NewClient(httpClient)
	githubClient := &GitHubClient{
		Client: client,
		Ctx:    context.Background(),
	}

	// Test the method
	result, err := githubClient.GetLanguages("owner", "empty-repo")

	assert.NoError(t, err)
	assert.Equal(t, 0, result.Total)
	assert.Empty(t, result.Languages)
}

func TestGetLanguages_SingleLanguage(t *testing.T) {
	// Setup HTTP mock
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// Mock single language response
	httpmock.RegisterResponder("GET", "https://api.github.com/repos/owner/python-repo/languages",
		httpmock.NewJsonResponderOrPanic(200, map[string]int{
			"Python": 95000,
		}))

	// Create client with mocked HTTP
	httpClient := &http.Client{Transport: httpmock.DefaultTransport}
	client := github.NewClient(httpClient)
	githubClient := &GitHubClient{
		Client: client,
		Ctx:    context.Background(),
	}

	// Test the method
	result, err := githubClient.GetLanguages("owner", "python-repo")

	assert.NoError(t, err)
	assert.Equal(t, 95000, result.Total)
	assert.Equal(t, 95000, result.Languages["Python"])
	assert.Len(t, result.Languages, 1)
}

func TestGetLanguages_APIError(t *testing.T) {
	// Setup HTTP mock
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// Mock error response
	httpmock.RegisterResponder("GET", "https://api.github.com/repos/owner/private-repo/languages",
		httpmock.NewStringResponder(404, `{"message": "Not Found"}`))

	// Create client with mocked HTTP
	httpClient := &http.Client{Transport: httpmock.DefaultTransport}
	client := github.NewClient(httpClient)
	githubClient := &GitHubClient{
		Client: client,
		Ctx:    context.Background(),
	}

	// Test the method
	result, err := githubClient.GetLanguages("owner", "private-repo")

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to get repository languages")
}

func TestGetLanguages_NetworkError(t *testing.T) {
	// Setup HTTP mock
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// Mock network error
	httpmock.RegisterResponder("GET", "https://api.github.com/repos/owner/repo/languages",
		httpmock.NewErrorResponder(http.ErrHandlerTimeout))

	// Create client with mocked HTTP
	httpClient := &http.Client{Transport: httpmock.DefaultTransport}
	client := github.NewClient(httpClient)
	githubClient := &GitHubClient{
		Client: client,
		Ctx:    context.Background(),
	}

	// Test the method
	result, err := githubClient.GetLanguages("owner", "repo")

	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestGetLanguages_MultiLanguageComplex(t *testing.T) {
	// Setup HTTP mock
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// Mock complex multi-language response
	httpmock.RegisterResponder("GET", "https://api.github.com/repos/owner/fullstack-app/languages",
		httpmock.NewJsonResponderOrPanic(200, map[string]int{
			"JavaScript": 450000,
			"Python":     300000,
			"TypeScript": 150000,
			"HTML":       75000,
			"CSS":        50000,
			"Shell":      25000,
		}))

	// Create client with mocked HTTP
	httpClient := &http.Client{Transport: httpmock.DefaultTransport}
	client := github.NewClient(httpClient)
	githubClient := &GitHubClient{
		Client: client,
		Ctx:    context.Background(),
	}

	// Test the method
	result, err := githubClient.GetLanguages("owner", "fullstack-app")

	assert.NoError(t, err)
	assert.Equal(t, 1050000, result.Total)
	assert.Equal(t, 450000, result.Languages["JavaScript"])
	assert.Equal(t, 300000, result.Languages["Python"])
	assert.Equal(t, 150000, result.Languages["TypeScript"])
	assert.Equal(t, 75000, result.Languages["HTML"])
	assert.Equal(t, 50000, result.Languages["CSS"])
	assert.Equal(t, 25000, result.Languages["Shell"])
	assert.Len(t, result.Languages, 6)
}
