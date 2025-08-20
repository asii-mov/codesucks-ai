package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/asii-mov/codesucks-ai/common"
	"github.com/asii-mov/codesucks-ai/common/envloader"
	"github.com/asii-mov/codesucks-ai/runner"
)

func main() {
	// Show banner
	showBanner()

	// Load environment variables from .env file if it exists
	if err := envloader.LoadEnvFile(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Warning: Failed to load .env file: %v\n", err)
		// Continue execution - environment variables might be set directly
	}

	// Parse command line options
	options, err := runner.ParseOptions()
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
		os.Exit(1)
	}

	// Collect target repositories
	var targets []string

	if options.Repo != "" {
		// Single repository target
		targets = append(targets, normalizeRepoURL(options.Repo))
	} else if options.Repos != "" {
		// Multiple repositories from file
		fileTargets, err := loadTargetsFromFile(options.Repos)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error loading targets from file: %v\n", err)
			os.Exit(1)
		}
		targets = fileTargets
	} else {
		// Read from stdin
		stdinTargets, err := loadTargetsFromStdin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error reading targets from stdin: %v\n", err)
			os.Exit(1)
		}
		targets = stdinTargets
	}

	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "❌ No targets specified. Use -repo, -repos, or pipe URLs to stdin.\n")
		os.Exit(1)
	}

	// Show configuration summary
	showConfiguration(options, len(targets))

	// Run the scanner
	err = runner.RunScanner(targets, options)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Scanner failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("🎉 All scans completed successfully!")
}

// showBanner displays the application banner
func showBanner() {
	banner := `
🔒 ╔═══════════════════════════════════════════════════════════════╗
   ║                      codesucks-ai v1.0                       ║
   ║              AI-Powered Security Analysis Tool               ║
   ║                                                               ║
   ║  🛡️  Static Analysis  •  🤖 AI Auto-Fix  •  🔄 GitHub API   ║
   ╚═══════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}

// showConfiguration displays the current configuration
func showConfiguration(options *common.Options, targetCount int) {
	fmt.Printf("📋 Configuration:\n")
	fmt.Printf("├─ Targets: %d repositories\n", targetCount)
	fmt.Printf("├─ Output Directory: %s\n", options.OutDir)
	fmt.Printf("├─ Threads: %d\n", options.Threads)

	if options.NoSemgrep {
		fmt.Printf("├─ Static Analysis: ❌ Disabled\n")
	} else {
		fmt.Printf("├─ Static Analysis: ✅ Enabled\n")
		fmt.Printf("├─ Semgrep Config: %s\n", options.ConfigPath)
	}

	if options.AutoFix {
		fmt.Printf("├─ AI Auto-Fix: ✅ Enabled\n")
		fmt.Printf("├─ AI Model: %s\n", options.AIModel)
		fmt.Printf("├─ Min Confidence: %.2f\n", options.MinConfidence)

		if options.CreatePR {
			fmt.Printf("├─ Auto PR Creation: ✅ Enabled\n")
		}
		if options.CreateIssue {
			fmt.Printf("├─ Auto Issue Creation: ✅ Enabled\n")
		}
	} else {
		fmt.Printf("├─ AI Auto-Fix: ❌ Disabled\n")
	}

	// Show authentication method
	if options.GitHubAppID != 0 {
		fmt.Printf("└─ Authentication: GitHub App (ID: %d)\n", options.GitHubAppID)
	} else {
		fmt.Printf("└─ Authentication: GitHub Token\n")
	}

	fmt.Println()
}

// normalizeRepoURL ensures the repository URL is in the correct format
func normalizeRepoURL(url string) string {
	url = strings.TrimSpace(url)

	// Add https:// prefix if missing
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	// Convert http to https
	url = strings.Replace(url, "http://", "https://", 1)

	// Remove .git suffix if present
	url = strings.TrimSuffix(url, ".git")

	// Remove trailing slash
	url = strings.TrimSuffix(url, "/")

	return url
}

// loadTargetsFromFile loads repository URLs from a file
func loadTargetsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", filename, err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		targets = append(targets, normalizeRepoURL(line))
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	return targets, nil
}

// loadTargetsFromStdin loads repository URLs from standard input
func loadTargetsFromStdin() ([]string, error) {
	var targets []string
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("📥 Reading repository URLs from stdin (Ctrl+D to finish):")

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		targets = append(targets, normalizeRepoURL(line))
		fmt.Printf("   ✓ Added: %s\n", line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading from stdin: %v", err)
	}

	return targets, nil
}
