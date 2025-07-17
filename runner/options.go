package runner

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/asii-mov/codesucks-ai/common"
)

// ParseOptions parses command line flags and environment variables
func ParseOptions() (*common.Options, error) {
	options := &common.Options{}

	// Target specification
	flag.StringVar(&options.Repo, "repo", "", "Single repository URL to scan")
	flag.StringVar(&options.Repos, "repos", "", "File containing list of repository URLs")

	// Scanning configuration
	flag.BoolVar(&options.NoSemgrep, "no-semgrep", false, "Skip Semgrep static analysis")
	flag.StringVar(&options.SemgrepPath, "semgrep-path", "semgrep", "Path to semgrep binary")
	flag.StringVar(&options.ConfigPath, "config", "comprehensive", "Semgrep config path or preset (basic, comprehensive, security-focused, compliance)")
	flag.BoolVar(&options.NoTruffleHog, "no-trufflehog", false, "Skip TruffleHog secret scanning")
	flag.StringVar(&options.TruffleHogPath, "trufflehog-path", "trufflehog", "Path to trufflehog binary")
	flag.BoolVar(&options.VerifySecrets, "verify-secrets", false, "Only return verified secrets from TruffleHog")
	flag.StringVar(&options.OutDir, "out", "./results", "Output directory for reports and results")

	// Configuration presets
	var listPresets bool
	flag.BoolVar(&listPresets, "list-presets", false, "List available configuration presets")

	// AI automation
	flag.BoolVar(&options.AutoFix, "auto-fix", false, "Enable AI-powered automatic vulnerability fixes")
	flag.BoolVar(&options.CreatePR, "create-pr", false, "Create pull request for fixes")
	flag.BoolVar(&options.CreateIssue, "create-issue", false, "Create GitHub issue for vulnerabilities")
	flag.StringVar(&options.AIModel, "ai-model", common.DefaultModel, "Claude AI model to use")
	flag.StringVar(&options.AnthropicAPIKey, "anthropic-key", "", "Anthropic API key (or use ANTHROPIC_API_KEY env var)")
	flag.Float64Var(&options.MinConfidence, "min-confidence", 0.8, "Minimum confidence threshold for AI fixes (0.0-1.0)")

	// Agent validation
	flag.Float64Var(&options.ValidationConfidence, "validation-confidence", 0.7, "Minimum confidence threshold for agent validation (0.0-1.0)")
	flag.BoolVar(&options.NoAgentValidation, "no-agent-validation", false, "Disable agent validation (default: enabled)")

	// GitHub integration
	flag.StringVar(&options.GitHubToken, "github-token", "", "GitHub personal access token (or use GITHUB_TOKEN env var)")
	flag.Int64Var(&options.GitHubAppID, "github-app-id", 0, "GitHub App ID (or use GITHUB_APP_ID env var)")
	flag.StringVar(&options.GitHubAppPrivateKey, "github-app-key", "", "GitHub App private key file path (or use GITHUB_APP_PRIVATE_KEY env var)")

	// Performance
	flag.IntVar(&options.Threads, "threads", 10, "Number of concurrent scanning threads")
	flag.BoolVar(&options.Debug, "debug", false, "Enable debug logging")

	// Help flag
	var showHelp bool
	flag.BoolVar(&showHelp, "h", false, "Show help")
	flag.BoolVar(&showHelp, "help", false, "Show help")

	flag.Parse()

	if showHelp {
		printUsage()
		os.Exit(0)
	}

	if listPresets {
		printPresets()
		os.Exit(0)
	}

	// Load environment variables if flags not provided
	loadEnvironmentVars(options)

	// Validate options
	if err := validateOptions(options); err != nil {
		return nil, err
	}

	return options, nil
}

// loadEnvironmentVars loads values from environment variables if not set via flags
func loadEnvironmentVars(options *common.Options) {
	if options.AnthropicAPIKey == "" {
		options.AnthropicAPIKey = os.Getenv("ANTHROPIC_API_KEY")
	}

	if options.GitHubToken == "" {
		options.GitHubToken = os.Getenv("GITHUB_TOKEN")
	}

	if options.GitHubAppID == 0 {
		if appID := os.Getenv("GITHUB_APP_ID"); appID != "" {
			if id, err := strconv.ParseInt(appID, 10, 64); err == nil {
				options.GitHubAppID = id
			}
		}
	}

	if options.GitHubAppPrivateKey == "" {
		options.GitHubAppPrivateKey = os.Getenv("GITHUB_APP_PRIVATE_KEY")
	}
}

// validateOptions validates the provided options
func validateOptions(options *common.Options) error {
	// At least one target must be specified
	if options.Repo == "" && options.Repos == "" {
		return fmt.Errorf("must specify either -repo or -repos")
	}

	// Both repo and repos cannot be specified
	if options.Repo != "" && options.Repos != "" {
		return fmt.Errorf("cannot specify both -repo and -repos")
	}

	// GitHub authentication is required
	if options.GitHubToken == "" && options.GitHubAppID == 0 {
		return fmt.Errorf("GitHub authentication required: provide either -github-token or -github-app-id with -github-app-key")
	}

	// GitHub App requires both ID and private key
	if options.GitHubAppID != 0 && options.GitHubAppPrivateKey == "" {
		return fmt.Errorf("GitHub App ID specified but private key missing")
	}

	// AI features require Anthropic API key
	if (options.AutoFix || options.CreatePR || options.CreateIssue || !options.NoAgentValidation) && options.AnthropicAPIKey == "" {
		return fmt.Errorf("AI features require Anthropic API key")
	}

	// Validate confidence threshold
	if options.MinConfidence < 0.0 || options.MinConfidence > 1.0 {
		return fmt.Errorf("min-confidence must be between 0.0 and 1.0")
	}

	// Validate validation confidence threshold
	if options.ValidationConfidence < 0.0 || options.ValidationConfidence > 1.0 {
		return fmt.Errorf("validation-confidence must be between 0.0 and 1.0")
	}

	// Validate thread count
	if options.Threads < 1 {
		return fmt.Errorf("threads must be at least 1")
	}

	// Validate repository URL format if single repo specified
	if options.Repo != "" {
		if !isValidGitHubURL(options.Repo) {
			return fmt.Errorf("invalid GitHub repository URL: %s", options.Repo)
		}
	}

	// Check if repos file exists if specified
	if options.Repos != "" {
		if _, err := os.Stat(options.Repos); os.IsNotExist(err) {
			return fmt.Errorf("repos file does not exist: %s", options.Repos)
		}
	}

	return nil
}

// isValidGitHubURL checks if the URL is a valid GitHub repository URL
func isValidGitHubURL(url string) bool {
	// Basic validation for GitHub URLs
	return strings.HasPrefix(url, "https://github.com/") && strings.Count(url, "/") >= 4
}

// printUsage prints the usage information
func printUsage() {
	fmt.Println("codesucks-ai - Security Analysis and Automated Fix Tool")
	fmt.Println()
	fmt.Println("USAGE:")
	fmt.Println("  codesucks-ai [OPTIONS]")
	fmt.Println()
	fmt.Println("TARGET OPTIONS:")
	fmt.Println("  -repo string        Single repository URL to scan")
	fmt.Println("  -repos string       File containing list of repository URLs")
	fmt.Println()
	fmt.Println("SCANNING OPTIONS:")
	fmt.Println("  -no-semgrep         Skip Semgrep static analysis")
	fmt.Println("  -semgrep-path string Path to semgrep binary (default \"semgrep\")")
	fmt.Println("  -config string      Semgrep config path or preset (default \"comprehensive\")")
	fmt.Println("  -no-trufflehog      Skip TruffleHog secret scanning")
	fmt.Println("  -trufflehog-path string Path to trufflehog binary (default \"trufflehog\")")
	fmt.Println("  -verify-secrets     Only return verified secrets from TruffleHog")
	fmt.Println("  -list-presets       List available configuration presets")
	fmt.Println("  -out string         Output directory for reports (default \"./results\")")
	fmt.Println()
	fmt.Println("AI AUTOMATION OPTIONS:")
	fmt.Println("  -auto-fix           Enable AI-powered automatic vulnerability fixes")
	fmt.Println("  -create-pr          Create pull request for fixes")
	fmt.Println("  -create-issue       Create GitHub issue for vulnerabilities")
	fmt.Println("  -ai-model string    Claude AI model to use (default \"claude-3-5-sonnet-20241022\")")
	fmt.Println("  -anthropic-key string Anthropic API key (or use ANTHROPIC_API_KEY env var)")
	fmt.Println("  -min-confidence float Minimum confidence threshold for AI fixes (default 0.8)")
	fmt.Println()
	fmt.Println("AGENT VALIDATION OPTIONS:")
	fmt.Println("  -validation-confidence float Minimum confidence threshold for agent validation (default 0.7)")
	fmt.Println("  -no-agent-validation         Disable agent validation (default: enabled)")
	fmt.Println()
	fmt.Println("GITHUB AUTHENTICATION:")
	fmt.Println("  -github-token string    GitHub personal access token (or use GITHUB_TOKEN env var)")
	fmt.Println("  -github-app-id int      GitHub App ID (or use GITHUB_APP_ID env var)")
	fmt.Println("  -github-app-key string  GitHub App private key file path (or use GITHUB_APP_PRIVATE_KEY env var)")
	fmt.Println()
	fmt.Println("PERFORMANCE OPTIONS:")
	fmt.Println("  -threads int        Number of concurrent scanning threads (default 10)")
	fmt.Println("  -debug              Enable debug logging")
	fmt.Println()
	fmt.Println("OTHER OPTIONS:")
	fmt.Println("  -h, -help           Show this help message")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Println("  # Scan single repository")
	fmt.Println("  codesucks-ai -repo https://github.com/owner/repo -github-token $GITHUB_TOKEN")
	fmt.Println()
	fmt.Println("  # Scan with AI auto-fix and PR creation")
	fmt.Println("  codesucks-ai -repo https://github.com/owner/repo -auto-fix -create-pr \\")
	fmt.Println("            -github-token $GITHUB_TOKEN -anthropic-key $ANTHROPIC_API_KEY")
	fmt.Println()
	fmt.Println("  # Scan multiple repositories from file")
	fmt.Println("  codesucks-ai -repos repos.txt -github-token $GITHUB_TOKEN")
	fmt.Println()
	fmt.Println("  # Use GitHub App authentication")
	fmt.Println("  codesucks-ai -repo https://github.com/owner/repo \\")
	fmt.Println("            -github-app-id 123456 -github-app-key /path/to/private-key.pem")
	fmt.Println()
	fmt.Println("  # Use configuration presets")
	fmt.Println("  codesucks-ai -repo https://github.com/owner/repo -config basic")
	fmt.Println("  codesucks-ai -repo https://github.com/owner/repo -config comprehensive")
	fmt.Println()
	fmt.Println("  # Secret scanning with TruffleHog")
	fmt.Println("  codesucks-ai -repo https://github.com/owner/repo -verify-secrets")
	fmt.Println()
	fmt.Println("  # Only TruffleHog scanning (skip Semgrep)")
	fmt.Println("  codesucks-ai -repo https://github.com/owner/repo -no-semgrep")
}

// printPresets prints available configuration presets
func printPresets() {
	fmt.Println("Available Configuration Presets:")
	fmt.Println()
	fmt.Println("📋 PRESET NAME       DESCRIPTION")
	fmt.Println("├─ basic             Minimal ruleset for fast scanning (p/trailofbits)")
	fmt.Println("├─ codesucks-ai      Default balanced configuration (recommended)")
	fmt.Println("├─ security-focused  Security vulnerabilities and secrets")
	fmt.Println("├─ comprehensive     All available rulesets for maximum coverage")
	fmt.Println("└─ compliance        Enterprise compliance focused (CWE, supply chain)")
	fmt.Println()
	fmt.Println("USAGE:")
	fmt.Println("  codesucks-ai -config <preset-name> [other options...]")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Println("  codesucks-ai -config basic -repo https://github.com/owner/repo")
	fmt.Println("  codesucks-ai -config comprehensive -repo https://github.com/owner/repo")
	fmt.Println()
	fmt.Println("You can also specify a custom .conf file path:")
	fmt.Println("  codesucks-ai -config /path/to/custom.conf -repo https://github.com/owner/repo")
}
