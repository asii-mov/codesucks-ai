package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/asii-mov/codesucks-ai/common"
	"github.com/asii-mov/codesucks-ai/common/ai"
	"github.com/asii-mov/codesucks-ai/common/github"
)

func main() {
	var (
		repoURL      = flag.String("repo", "", "GitHub repository URL")
		issueNumber  = flag.Int("issue", 0, "GitHub issue number to monitor")
		interval     = flag.Duration("interval", 30*time.Second, "Polling interval for new comments")
		githubToken  = flag.String("github-token", "", "GitHub API token")
		anthropicKey = flag.String("anthropic-key", "", "Anthropic API key")
		debug        = flag.Bool("debug", false, "Enable debug logging")
	)
	flag.Parse()

	// Validate and configure
	owner, repo, ghClient, claudeClient, err := validateAndSetup(*repoURL, *issueNumber, *githubToken, *anthropicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
		fmt.Println("\nUsage: monitor --repo <github-url> --issue <number>")
		fmt.Println("Example: monitor --repo https://github.com/owner/repo --issue 123")
		os.Exit(1)
	}

	fmt.Printf("🤖 Starting conversation monitor for %s issue #%d\n", *repoURL, *issueNumber)
	fmt.Printf("📊 Polling interval: %v\n", *interval)
	fmt.Println("💬 Monitoring for new comments and responding with AI assistance...")

	// Create a mock fix branch for conversation context
	fixBranch := &common.FixBranch{
		RepoOwner:   owner,
		RepoName:    repo,
		IssueNumber: issueNumber,
		Fixes:       []common.SecurityFix{}, // In real usage, load from saved state
	}

	// Track last seen comment to avoid responding to old comments
	var lastCommentID int64 = 0

	// Main monitoring loop
	for {
		if *debug {
			fmt.Printf("🔍 Checking for new comments... (%s)\n", time.Now().Format("15:04:05"))
		}

		err := monitorAndRespond(ghClient, claudeClient, fixBranch, &lastCommentID)
		if err != nil {
			fmt.Printf("❌ Error monitoring comments: %v\n", err)
		}

		time.Sleep(*interval)
	}
}

// monitorAndRespond checks for new comments and generates responses
func monitorAndRespond(ghClient *github.GitHubClient, claudeClient *ai.ClaudeClient,
	fixBranch *common.FixBranch, lastCommentID *int64) error {

	// Simple callback function for generating responses
	responseCallback := func(comment string) string {
		// Analyze the comment and generate an appropriate response
		if strings.Contains(strings.ToLower(comment), "test") {
			return "Great question about testing! Please make sure to:\n" +
				"1. 🧪 Run your existing test suite\n" +
				"2. 🔍 Test the specific functionality that was changed\n" +
				"3. ✅ Verify that the security fix doesn't break any features\n\n" +
				"Let me know if you need help with specific test cases!"
		}

		if strings.Contains(strings.ToLower(comment), "concern") ||
			strings.Contains(strings.ToLower(comment), "worry") {
			return "I understand your concern. Security fixes can sometimes have unexpected side effects. " +
				"Would you like me to explain the specific changes in more detail or help you review a particular file?"
		}

		// For other comments, generate a response using Claude
		response, err := claudeClient.GenerateConversationResponse(comment, fixBranch.Fixes)
		if err != nil {
			fmt.Printf("❌ Failed to generate AI response: %v\n", err)
			return ""
		}
		return response
	}

	// Use the GitHub client's monitoring function
	return ghClient.MonitorIssueComments(fixBranch, responseCallback)
}

// validateAndSetup validates inputs and sets up clients
func validateAndSetup(repoURL string, issueNumber int, githubToken, anthropicKey string) (string, string, *github.GitHubClient, *ai.ClaudeClient, error) {
	// Validate required parameters
	if repoURL == "" || issueNumber == 0 {
		return "", "", nil, nil, fmt.Errorf("repository URL and issue number are required")
	}

	// Get tokens from environment if not provided
	if githubToken == "" {
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			githubToken = token
		} else if token := os.Getenv("GH_TOKEN"); token != "" {
			githubToken = token
		} else {
			return "", "", nil, nil, fmt.Errorf("GitHub token is required. Set GITHUB_TOKEN env var or use --github-token flag")
		}
	}

	if anthropicKey == "" {
		if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
			anthropicKey = key
		} else {
			return "", "", nil, nil, fmt.Errorf("Anthropic API key is required. Set ANTHROPIC_API_KEY env var or use --anthropic-key flag")
		}
	}

	// Parse repository URL
	owner, repo, err := github.ParseRepositoryURL(repoURL)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("invalid repository URL: %w", err)
	}

	// Initialize clients
	options := &common.Options{
		GitHubToken:     githubToken,
		AnthropicAPIKey: anthropicKey,
	}

	ghClient, err := github.NewClient(options)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("failed to initialize GitHub client: %w", err)
	}

	claudeClient := ai.NewClaudeClient(anthropicKey)

	return owner, repo, ghClient, claudeClient, nil
}
