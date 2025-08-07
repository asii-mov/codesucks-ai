package runner

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/asii-mov/codesucks-ai/common"
	"github.com/asii-mov/codesucks-ai/common/agent"
	"github.com/asii-mov/codesucks-ai/common/ai"
	"github.com/asii-mov/codesucks-ai/common/github"
	"github.com/asii-mov/codesucks-ai/common/orchestrator"
	"github.com/asii-mov/codesucks-ai/common/report"
	"github.com/asii-mov/codesucks-ai/common/codesucks-ai"
)

// scanTarget performs security analysis on a single repository
func scanTarget(target string, options *common.Options) (*common.ScanResult, error) {
	// Check if orchestrator mode is enabled
	if options.OrchestratorMode {
		return scanWithOrchestrator(target, options)
	}
	
	// Legacy scanning mode
	return scanWithLegacyMode(target, options)
}

// scanWithOrchestrator performs security analysis using the AI orchestrator
func scanWithOrchestrator(target string, options *common.Options) (*common.ScanResult, error) {
	fmt.Printf("🤖 Starting AI Orchestrator Mode for %s\n", target)
	
	// Create orchestrator instance
	orch, err := orchestrator.NewSecurityOrchestrator(options.SessionDir, options.AgentsDir, options)
	if err != nil {
		return nil, fmt.Errorf("failed to create orchestrator: %w", err)
	}
	
	// Execute the 7-phase security analysis workflow
	result, err := orch.ExecuteSecurityAnalysis(target)
	if err != nil {
		return result, fmt.Errorf("orchestrator analysis failed: %w", err)
	}
	
	fmt.Printf("✅ Orchestrator analysis completed successfully\n")
	return result, nil
}

// scanWithLegacyMode performs security analysis using the original scanning approach
func scanWithLegacyMode(target string, options *common.Options) (*common.ScanResult, error) {
	// Set up graceful shutdown handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	go func() {
		sigCount := 0
		for sig := range sigChan {
			if sig != syscall.SIGINT {
				continue
			}
			sigCount++
			if sigCount == 2 {
				fmt.Println("\nForce shutdown...")
				os.Exit(1)
			}
			fmt.Println("\nShutdown requested... (press Ctrl+C again to force)")
		}
	}()

	result := &common.ScanResult{}

	// Parse repository URL
	owner, repo, err := github.ParseRepositoryURL(target)
	if err != nil {
		return result, fmt.Errorf("invalid repository URL: %v", err)
	}

	// Initialize GitHub client
	githubClient, err := github.NewClient(options)
	if err != nil {
		return result, fmt.Errorf("failed to create GitHub client: %v", err)
	}

	// Test GitHub authentication
	if err := githubClient.TestAuthentication(); err != nil {
		return result, fmt.Errorf("GitHub authentication failed: %v", err)
	}

	// Get repository information
	repoInfo, err := githubClient.GetRepositoryInfo(owner, repo)
	if err != nil {
		return result, fmt.Errorf("failed to get repository info: %v", err)
	}
	result.RepoInfo = *repoInfo

	// Skip analysis if both scanners are disabled
	if options.NoSemgrep && options.NoTruffleHog {
		return result, nil
	}

	// Create temporary directory for repository content
	tempDir := fmt.Sprintf("%s/temp-%s-%s", options.OutDir, owner, repo)
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return result, fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir) // Clean up temporary files

	// Fetch repository content via GitHub API
	sourcePath, err := githubClient.FetchRepositoryContent(owner, repo, repoInfo.Branch, tempDir)
	if err != nil {
		return result, fmt.Errorf("failed to fetch repository content: %v", err)
	}

	// Verify source directory exists and contains files
	if info, statErr := os.Stat(sourcePath); statErr != nil {
		return result, fmt.Errorf("source path does not exist: %s (error: %v)", sourcePath, statErr)
	} else if !info.IsDir() {
		return result, fmt.Errorf("source path is not a directory: %s", sourcePath)
	}

	// Run Semgrep analysis if not disabled
	var semgrepJson *common.SemgrepJson
	if !options.NoSemgrep {
		semgrepJson, err = codesucksai.RunSemgrep(sourcePath, options.OutDir, options.SemgrepPath, options.ConfigPath)
		if err != nil {
			return result, fmt.Errorf("semgrep analysis failed: %v", err)
		}
		result.SemgrepJson = *semgrepJson
	} else {
		semgrepJson = &common.SemgrepJson{Results: []common.Result{}, Errors: []common.Error{}}
		result.SemgrepJson = *semgrepJson
	}

	// Run TruffleHog analysis if not disabled
	var trufflehogJson *common.TruffleHogJson
	if !options.NoTruffleHog {
		trufflehogJson, err = codesucksai.RunTruffleHog(sourcePath, options.OutDir, options.TruffleHogPath, options.VerifySecrets)
		if err != nil {
			fmt.Printf("Warning: TruffleHog analysis failed: %v\n", err)
			// Continue without TruffleHog results - don't fail the entire scan
			trufflehogJson = &common.TruffleHogJson{Results: []common.TruffleHogResult{}}
		}
		result.TruffleHogJson = *trufflehogJson
		result.SecretsFound = len(trufflehogJson.Results)
	} else {
		trufflehogJson = &common.TruffleHogJson{Results: []common.TruffleHogResult{}}
		result.TruffleHogJson = *trufflehogJson
	}

	// Apply agent validation by default (unless explicitly disabled) when vulnerabilities found
	var validatedResults []common.ValidatedResult
	if !options.NoAgentValidation && !options.NoSemgrep && len(semgrepJson.Results) > 0 {
		fmt.Printf("🤖 Agent validation enabled - analyzing vulnerabilities for false positives\n")
		validatedResults, err = executeAgentValidation(target, semgrepJson, sourcePath, options, githubClient)
		if err != nil {
			fmt.Printf("Warning: Agent validation failed: %v\n", err)
			// Continue with original results if validation fails
			validatedResults = convertToValidatedResults(semgrepJson.Results)
		}
	} else {
		// Agent validation disabled, use original results
		if options.NoAgentValidation {
			fmt.Printf("ℹ️ Agent validation disabled - using raw scanner results\n")
		}
		validatedResults = convertToValidatedResults(semgrepJson.Results)
	}

	// Filter validated results based on confidence threshold
	filteredResults := filterValidatedResults(validatedResults, options)
	
	// Store validated results in scan result
	result.ValidatedResults = filteredResults
	
	// Update semgrepJson with filtered results for subsequent processing
	semgrepJson.Results = extractOriginalResults(filteredResults)

	// Execute auto-fix workflow if enabled and vulnerabilities found
	if options.AutoFix && !options.NoSemgrep && len(semgrepJson.Results) > 0 {
		fixesApplied, err := executeAutoFixWorkflow(target, semgrepJson, sourcePath, options)
		if err != nil {
			fmt.Printf("Warning: Auto-fix workflow failed: %v\n", err)
		} else {
			result.FixesApplied = fixesApplied
		}
	}

	// Generate HTML report combining Semgrep and TruffleHog results
	var reportData *common.ReportData
	if !options.NoSemgrep {
		reportData = report.ConvertValidatedResultsToReport(target, filteredResults)
	} else {
		// Create empty report data if only TruffleHog is running
		reportData = &common.ReportData{
			Target:                     target,
			VulnerabilityStats:         make(map[string]int),
			VulnerabilityStatsOrdering: []string{},
			SeverityStats:              make(map[string]int),
			SeverityStatsOrdering:      []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"},
			Findings:                   []common.SemgrepFinding{},
		}
	}
	
	if !options.NoTruffleHog {
		report.AddTruffleHogToReport(reportData, target, trufflehogJson)
	}
	reportPath, err := report.GenerateHTML(reportData, options.OutDir)
	if err != nil {
		return result, fmt.Errorf("failed to generate report: %v", err)
	}
	result.ReportPath = reportPath

	return result, nil
}

// executeAutoFixWorkflow handles the automated security fix workflow
func executeAutoFixWorkflow(target string, semgrepJson *common.SemgrepJson, sourcePath string, options *common.Options) (int, error) {
	fmt.Printf("🤖 Starting auto-fix workflow for %s\n", target)

	// Parse repository URL
	owner, repo, err := github.ParseRepositoryURL(target)
	if err != nil {
		return 0, err
	}

	// Initialize AI client
	claudeClient := ai.NewClaudeClient(options.AnthropicAPIKey)

	// Initialize GitHub client
	githubClient, err := github.NewClient(options)
	if err != nil {
		return 0, err
	}

	// Create a new branch for fixes
	fixBranch, err := githubClient.CreateFixBranch(owner, repo)
	if err != nil {
		return 0, fmt.Errorf("failed to create fix branch: %v", err)
	}

	successfulFixes := 0
	totalVulnerabilities := len(semgrepJson.Results)

	fmt.Printf("📊 Processing %d vulnerabilities...\n", totalVulnerabilities)

	for i, result := range semgrepJson.Results {
		fmt.Printf("🔍 Processing vulnerability %d/%d: %s\n",
			i+1, totalVulnerabilities, result.CheckID)

		// Get the relative file path (no need for ZIP prefix removal with GitHub API)
		relativePath := strings.TrimPrefix(result.Path, sourcePath)
		relativePath = strings.TrimPrefix(relativePath, "/")

		// Read the vulnerable file content via GitHub API
		fileContent, err := githubClient.GetFileContent(owner, repo, fixBranch.BranchName, relativePath)
		if err != nil {
			fmt.Printf("❌ Failed to read file %s: %v\n", relativePath, err)
			continue
		}

		// Generate AI-powered fix
		analysis, err := claudeClient.AnalyzeVulnerability(result, fileContent, relativePath)
		if err != nil {
			fmt.Printf("❌ Failed to analyze vulnerability in %s: %v\n", relativePath, err)
			continue
		}

		// Check confidence threshold
		if analysis.Confidence < options.MinConfidence {
			fmt.Printf("⚠️ Skipping fix for %s due to low confidence: %.2f\n",
				result.CheckID, analysis.Confidence)
			continue
		}

		// Validate the fix
		if !claudeClient.ValidateSecurityFix(result.Extra.Lines, analysis.Fix) {
			fmt.Printf("❌ Generated fix validation failed for %s\n", result.CheckID)
			continue
		}

		// Create security fix object
		securityFix := common.SecurityFix{
			FilePath:      relativePath,
			StartLine:     result.Start.Line,
			EndLine:       result.End.Line,
			OriginalCode:  result.Extra.Lines,
			FixedCode:     analysis.Fix,
			Vulnerability: result.CheckID,
			Description:   analysis.Explanation,
		}

		// Apply the fix to the branch
		err = githubClient.ApplySecurityFix(fixBranch, securityFix)
		if err != nil {
			fmt.Printf("❌ Failed to apply fix for %s: %v\n", result.CheckID, err)
			continue
		}

		successfulFixes++
		fmt.Printf("✅ Successfully applied fix for %s (confidence: %.2f)\n",
			result.CheckID, analysis.Confidence)
	}

	if successfulFixes == 0 {
		fmt.Println("ℹ️ No fixes were applied. Skipping PR creation.")
		return 0, nil
	}

	fmt.Printf("📈 Applied %d out of %d potential fixes\n", successfulFixes, totalVulnerabilities)

	// Create pull request if requested
	if options.CreatePR {
		err = githubClient.CreatePullRequest(fixBranch)
		if err != nil {
			return successfulFixes, fmt.Errorf("failed to create pull request: %v", err)
		}
		fmt.Printf("🔄 Created pull request #%d for security fixes\n", *fixBranch.PRNumber)
	}

	// Create conversation issue if requested
	if options.CreateIssue {
		err = githubClient.CreateIssueForConversation(fixBranch)
		if err != nil {
			return successfulFixes, fmt.Errorf("failed to create conversation issue: %v", err)
		}
		fmt.Printf("💬 Created conversation issue #%d for security fixes discussion\n", *fixBranch.IssueNumber)
	}

	return successfulFixes, nil
}

// RepoScanner processes repositories from a channel (for concurrent processing)
func RepoScanner(targets <-chan string, options *common.Options, wg *sync.WaitGroup, stop chan bool) {
	defer wg.Done()

	for target := range targets {
		select {
		case <-stop:
			fmt.Println("🛑 Stopping worker...")
			return
		default:
			fmt.Printf("🔍 Scanning %s\n", target)

			result, err := scanTarget(target, options)
			if err != nil {
				fmt.Printf("❌ Failed to scan %s: %v\n", target, err)
				continue
			}

			// Display results
			displayScanResults(target, result, options)
		}
	}
}

// displayScanResults shows the scan results to the user
func displayScanResults(target string, result *common.ScanResult, options *common.Options) {
	fmt.Printf("\n📊 Scan Results for %s:\n", target)
	fmt.Printf("├─ Repository: %s/%s\n", result.RepoInfo.Owner, result.RepoInfo.Name)
	fmt.Printf("├─ Branch: %s\n", result.RepoInfo.Branch)
	fmt.Printf("├─ Language: %s\n", result.RepoInfo.Language)
	fmt.Printf("├─ Private: %v\n", result.RepoInfo.Private)

	if !options.NoSemgrep {
		totalVulns := len(result.SemgrepJson.Results)
		fmt.Printf("├─ Vulnerabilities Found: %d\n", totalVulns)
		
		if len(result.ValidatedResults) > 0 {
			legitimateCount := 0
			filteredCount := 0
			for _, vr := range result.ValidatedResults {
				if vr.IsFiltered {
					filteredCount++
				} else {
					legitimateCount++
				}
			}
			
			if !options.NoAgentValidation {
				fmt.Printf("├─ Agent Validation: %d legitimate, %d filtered\n", legitimateCount, filteredCount)
			}
		}
		
		if result.FixesApplied > 0 {
			fmt.Printf("├─ Auto-fixes Applied: %d\n", result.FixesApplied)
		}
		if result.ReportPath != "" {
			fmt.Printf("└─ Report: %s\n", result.ReportPath)
		}
	}
	fmt.Println()
}

// RunScanner starts the main scanning process
func RunScanner(targets []string, options *common.Options) error {
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	// Validate Semgrep installation if not disabled
	if !options.NoSemgrep {
		if err := codesucksai.ValidateSemgrepInstallation(options.SemgrepPath); err != nil {
			return fmt.Errorf("semgrep validation failed: %v", err)
		}
	}

	// Create output directory
	if err := os.MkdirAll(options.OutDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	fmt.Printf("🚀 Starting codesucks-ai scan of %d repositories\n", len(targets))
	fmt.Printf("📁 Output directory: %s\n", options.OutDir)
	fmt.Printf("🧵 Using %d threads\n", options.Threads)
	if options.AutoFix {
		fmt.Printf("🤖 AI auto-fix enabled (min confidence: %.2f)\n", options.MinConfidence)
	}
	if !options.NoAgentValidation {
		fmt.Printf("🤖 Agent validation enabled - vulnerabilities will be analyzed for false positives\n")
	} else {
		fmt.Printf("⚠️ Agent validation disabled - raw scanner results will be used\n")
	}
	fmt.Println()

	// Set up channels for concurrent processing
	targetsChan := make(chan string, options.Threads*2)
	stop := make(chan bool)
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < options.Threads; i++ {
		wg.Add(1)
		go RepoScanner(targetsChan, options, &wg, stop)
	}

	// Send targets to workers
	go func() {
		defer close(targetsChan)
		for _, target := range targets {
			select {
			case <-stop:
				return
			case targetsChan <- target:
			}
		}
	}()

	// Wait for all workers to complete
	wg.Wait()

	fmt.Println("✅ Scanning completed!")
	return nil
}

// executeAgentValidation performs agent validation on the scan results
func executeAgentValidation(target string, semgrepJson *common.SemgrepJson, sourcePath string, options *common.Options, githubClient *github.GitHubClient) ([]common.ValidatedResult, error) {
	fmt.Printf("🤖 Starting agent validation for %s\n", target)

	// Parse repository URL
	owner, repo, err := github.ParseRepositoryURL(target)
	if err != nil {
		return nil, err
	}

	// Initialize agent validator
	agentValidator := agent.NewAgentValidator(options.AnthropicAPIKey, githubClient, options.Debug)

	// Familiarize agent with repository
	repoInfo, err := githubClient.GetRepositoryInfo(owner, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository info: %w", err)
	}

	_, err = agentValidator.FamiliarizeWithRepository(owner, repo, repoInfo.Branch, sourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to familiarize with repository: %w", err)
	}

	var validatedResults []common.ValidatedResult
	totalVulnerabilities := len(semgrepJson.Results)

	fmt.Printf("🔍 Validating %d vulnerabilities...\n", totalVulnerabilities)

	for i, result := range semgrepJson.Results {
		if options.Debug {
			fmt.Printf("🤖 Agent: Validating %d/%d: %s\n", i+1, totalVulnerabilities, result.CheckID)
		}

		// Validate vulnerability
		validation, err := agentValidator.ValidateVulnerability(result, sourcePath)
		if err != nil {
			if options.Debug {
				fmt.Printf("❌ Validation failed for %s: %v\n", result.CheckID, err)
			}
			// If validation fails, keep the original result without filtering
			validatedResults = append(validatedResults, common.ValidatedResult{
				Result:     result,
				IsFiltered: false,
			})
			continue
		}

		// Create validated result
		validatedResult := common.ValidatedResult{
			Result:          result,
			AgentValidation: validation,
			IsFiltered:      !validation.IsLegitimate || validation.Confidence < options.ValidationConfidence,
		}

		validatedResults = append(validatedResults, validatedResult)

		if options.Debug {
			status := "✅ LEGITIMATE"
			if validatedResult.IsFiltered {
				status = "❌ FILTERED"
			}
			fmt.Printf("   Result: %s (confidence: %.2f)\n", status, validation.Confidence)
		}
	}

	// Display summary
	legitimateCount := 0
	filteredCount := 0
	for _, vr := range validatedResults {
		if vr.IsFiltered {
			filteredCount++
		} else {
			legitimateCount++
		}
	}

	fmt.Printf("🎯 Agent validation complete:\n")
	fmt.Printf("├─ Total vulnerabilities analyzed: %d\n", totalVulnerabilities)
	fmt.Printf("├─ Legitimate vulnerabilities: %d\n", legitimateCount)
	fmt.Printf("├─ False positives filtered: %d\n", filteredCount)
	
	if totalVulnerabilities > 0 {
		falsePositiveRate := float64(filteredCount) / float64(totalVulnerabilities) * 100
		fmt.Printf("└─ False positive rate: %.1f%%\n", falsePositiveRate)
	}

	return validatedResults, nil
}

// convertToValidatedResults converts regular results to validated results without agent validation
func convertToValidatedResults(results []common.Result) []common.ValidatedResult {
	var validatedResults []common.ValidatedResult
	for _, result := range results {
		validatedResults = append(validatedResults, common.ValidatedResult{
			Result:     result,
			IsFiltered: false, // No filtering without agent validation
		})
	}
	return validatedResults
}

// filterValidatedResults filters validated results based on configuration
func filterValidatedResults(validatedResults []common.ValidatedResult, options *common.Options) []common.ValidatedResult {
	if options.NoAgentValidation {
		return validatedResults
	}

	var filtered []common.ValidatedResult
	for _, vr := range validatedResults {
		if !vr.IsFiltered {
			filtered = append(filtered, vr)
		}
	}
	return filtered
}

// extractOriginalResults extracts original Result objects from ValidatedResult
func extractOriginalResults(validatedResults []common.ValidatedResult) []common.Result {
	var results []common.Result
	for _, vr := range validatedResults {
		results = append(results, vr.Result)
	}
	return results
}
