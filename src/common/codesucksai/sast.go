package codesucksai

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/asii-mov/codesucks-ai/common"
)

// RunSemgrep executes Semgrep analysis on the target directory
func RunSemgrep(sourcePath, outDir, semgrepPath, configPath string) (*common.SemgrepJson, error) {
	// Create results directory
	resultsDir := filepath.Join(outDir, "semgrep")
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create results directory: %v", err)
	}

	// Generate output file path
	outputFile := filepath.Join(resultsDir, "results.json")

	// Build Semgrep command without output file - capture JSON from stdout
	args := buildSemgrepArgsForStdout(sourcePath, configPath)

	// Execute Semgrep
	cmd := exec.Command(semgrepPath, args...)
	cmd.Dir = sourcePath

	// Capture output for debugging
	output, err := cmd.CombinedOutput()

	var jsonOutput []byte
	exitCode := 0

	if err != nil {
		// Extract exit code from error
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()

			// Semgrep exit codes:
			// - Exit code 0: No findings
			// - Exit code 1: Findings detected (normal behavior with --error flag)
			// - Exit code 2: Warnings/parsing errors but scan completed
			// - Exit code 3+: Fatal errors

			if exitCode <= 2 {
				// Exit codes 0, 1, 2 are acceptable - scan completed
				fmt.Printf("⚠️ Semgrep completed with warnings (exit code %d)\n", exitCode)
				jsonOutput = output // Use the output even with warnings
			} else {
				// Exit codes 3+ indicate fatal errors
				return nil, fmt.Errorf("semgrep execution failed with exit code %d: %v\nOutput: %s", exitCode, err, string(output))
			}
		} else {
			// Non-exit error (e.g., command not found)
			return nil, fmt.Errorf("semgrep execution failed: %v\nOutput: %s", err, string(output))
		}
	} else {
		// Success case
		jsonOutput = output
	}

	// Extract JSON from the output (semgrep outputs verbose logs then JSON)
	if len(jsonOutput) > 0 && strings.Contains(string(jsonOutput), "{") {
		// Find the JSON part by looking for the first '{'
		outputStr := string(jsonOutput)
		jsonStart := strings.Index(outputStr, "{")
		if jsonStart >= 0 {
			// Extract everything from the first '{' to the end
			jsonOutput = []byte(outputStr[jsonStart:])

			// Clean up any trailing non-JSON content after the last '}'
			jsonStr := string(jsonOutput)
			lastBrace := strings.LastIndex(jsonStr, "}")
			if lastBrace >= 0 && lastBrace < len(jsonStr)-1 {
				jsonOutput = []byte(jsonStr[:lastBrace+1])
			}
		} else {
			// No JSON found, create empty results
			jsonOutput = []byte(`{"errors":[],"paths":{"scanned":[],"skipped":[]},"results":[]}`)
			fmt.Printf("ℹ️ No JSON found in semgrep output, creating empty results\n")
		}
	} else {
		// No valid output, create empty results
		jsonOutput = []byte(`{"errors":[],"paths":{"scanned":[],"skipped":[]},"results":[]}`)
		fmt.Printf("ℹ️ No output from semgrep, creating empty results\n")
	}

	// Write JSON output to file
	if writeErr := os.WriteFile(outputFile, jsonOutput, 0644); writeErr != nil {
		return nil, fmt.Errorf("failed to write semgrep output to file: %v", writeErr)
	}

	// Parse Semgrep JSON output
	semgrepJson, err := parseSemgrepOutput(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Semgrep output: %v", err)
	}

	return semgrepJson, nil
}

// buildSemgrepArgsForStdout constructs the command line arguments for Semgrep without output file
func buildSemgrepArgsForStdout(sourcePath, configPath string) []string {
	// Start with base args for stdout capture
	args := []string{
		"--json",
		"--verbose",
	}

	// Handle configuration
	if configPath == "auto" || configPath == "" {
		// Use default comprehensive configuration
		configPath = "configs/comprehensive.conf"
	}

	// Handle matrix configuration (special format)
	if strings.HasPrefix(configPath, "matrix:") {
		// Parse matrix configuration format: "matrix:--config p/javascript --config p/react ..."
		matrixConfig := strings.TrimPrefix(configPath, "matrix:")
		matrixArgs := strings.Fields(matrixConfig)
		args = append(args, matrixArgs...)
		args = append(args, "--no-git-ignore") // Always add this for consistency
	} else {
		// Check if configPath is a preset name
		if !strings.HasSuffix(configPath, ".conf") && !strings.Contains(configPath, "/") {
			configPath = fmt.Sprintf("configs/%s.conf", configPath)
		}

		// Try to read configuration file
		if configArgs := readConfigFile(configPath); len(configArgs) > 0 {
			args = append(args, configArgs...)
		} else {
			// Fallback to default configuration
			args = append(args,
				"--config", "p/trailofbits",
				"--config", "p/security-audit",
				"--config", "p/secrets",
				"--no-git-ignore",
				"--timeout", "300",
				"--max-target-bytes", "1000000",
			)
		}
	}

	// Add target path - use "." since we set cmd.Dir to sourcePath
	args = append(args, ".")

	return args
}

// buildSemgrepArgs constructs the command line arguments for Semgrep
func buildSemgrepArgs(sourcePath, outputFile, configPath string) []string {
	// Start with base args
	args := []string{
		"--json",
		"--output", outputFile,
		"--verbose",
	}

	// Handle configuration
	if configPath == "auto" || configPath == "" {
		// Use default comprehensive configuration
		configPath = "configs/comprehensive.conf"
	}

	// Check if configPath is a preset name
	if !strings.HasSuffix(configPath, ".conf") && !strings.Contains(configPath, "/") {
		configPath = fmt.Sprintf("configs/%s.conf", configPath)
	}

	// Try to read configuration file
	if configArgs := readConfigFile(configPath); len(configArgs) > 0 {
		args = append(args, configArgs...)
	} else {
		// Fallback to default configuration
		args = append(args,
			"--config", "p/trailofbits",
			"--config", "p/security-audit",
			"--config", "p/secrets",
			"--no-git-ignore",
			"--timeout", "300",
			"--max-target-bytes", "1000000",
		)
	}

	// Add target path
	args = append(args, sourcePath)

	return args
}

// readConfigFile reads a configuration file and parses the FLAGS line
func readConfigFile(configPath string) []string {
	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil
	}

	file, err := os.Open(configPath)
	if err != nil {
		return nil
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Look for FLAGS= line
		if strings.HasPrefix(line, "FLAGS=") {
			flagsStr := strings.TrimPrefix(line, "FLAGS=")
			// Split flags by spaces, handling quoted arguments
			return parseFlags(flagsStr)
		}
	}

	return nil
}

// parseFlags parses a flags string into individual arguments
func parseFlags(flagsStr string) []string {
	var args []string
	var current strings.Builder
	inQuotes := false

	for _, char := range flagsStr {
		switch char {
		case '"':
			inQuotes = !inQuotes
		case ' ':
			if !inQuotes {
				if current.Len() > 0 {
					args = append(args, current.String())
					current.Reset()
				}
			} else {
				current.WriteRune(char)
			}
		default:
			current.WriteRune(char)
		}
	}

	// Add final argument
	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}

// parseSemgrepOutput parses the JSON output from Semgrep
func parseSemgrepOutput(outputFile string) (*common.SemgrepJson, error) {
	// Read output file
	data, err := ioutil.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read Semgrep output file: %v", err)
	}

	// Parse JSON
	var semgrepJson common.SemgrepJson
	if err := json.Unmarshal(data, &semgrepJson); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Semgrep JSON: %v", err)
	}

	return &semgrepJson, nil
}

// FilterResults filters Semgrep results based on severity and confidence
func FilterResults(results []common.Result, minSeverity string) []common.Result {
	severityOrder := map[string]int{
		"INFO":     1,
		"WARNING":  2,
		"ERROR":    3,
		"CRITICAL": 4,
	}

	minLevel := severityOrder[strings.ToUpper(minSeverity)]
	if minLevel == 0 {
		minLevel = 1 // Default to INFO if unknown severity
	}

	var filtered []common.Result
	for _, result := range results {
		severity := getSeverityFromMetadata(result)
		if severityOrder[severity] >= minLevel {
			filtered = append(filtered, result)
		}
	}

	return filtered
}

// getSeverityFromMetadata extracts severity level from Semgrep result metadata
func getSeverityFromMetadata(result common.Result) string {
	impact := strings.ToUpper(result.Extra.Metadata.Impact)

	// Map impact levels to severity
	switch impact {
	case "HIGH", "CRITICAL":
		return "CRITICAL"
	case "MEDIUM":
		return "ERROR"
	case "LOW":
		return "WARNING"
	default:
		return "INFO"
	}
}

// GetVulnerabilityContext retrieves code context around a vulnerability
func GetVulnerabilityContext(filePath string, startLine, endLine, contextLines int) (string, string, error) {
	// Read file content
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read file: %v", err)
	}

	lines := strings.Split(string(content), "\n")

	// Get vulnerable code
	vulnerableCode := getCodeSnippet(lines, startLine, endLine)

	// Get context around vulnerability
	contextStart := max(1, startLine-contextLines)
	contextEnd := min(len(lines), endLine+contextLines)
	contextCode := getCodeSnippetWithLineNumbers(lines, contextStart, contextEnd)

	return vulnerableCode, contextCode, nil
}

// getCodeSnippet extracts lines between start and end (1-indexed)
func getCodeSnippet(lines []string, start, end int) string {
	if start < 1 || end > len(lines) || start > end {
		return ""
	}

	selectedLines := lines[start-1 : end]
	return strings.Join(selectedLines, "\n")
}

// getCodeSnippetWithLineNumbers extracts lines with line numbers
func getCodeSnippetWithLineNumbers(lines []string, start, end int) string {
	if start < 1 || end > len(lines) || start > end {
		return ""
	}

	var result []string
	for i := start; i <= end && i <= len(lines); i++ {
		lineContent := ""
		if i-1 < len(lines) {
			lineContent = lines[i-1]
		}
		result = append(result, fmt.Sprintf("%4d: %s", i, lineContent))
	}

	return strings.Join(result, "\n")
}

// GroupResultsByFile groups Semgrep results by file path
func GroupResultsByFile(results []common.Result) map[string][]common.Result {
	grouped := make(map[string][]common.Result)

	for _, result := range results {
		grouped[result.Path] = append(grouped[result.Path], result)
	}

	return grouped
}

// GetSeverityStats calculates statistics for vulnerability severities
func GetSeverityStats(results []common.Result) map[string]int {
	stats := make(map[string]int)

	for _, result := range results {
		severity := getSeverityFromMetadata(result)
		stats[severity]++
	}

	return stats
}

// GetVulnerabilityStats calculates statistics for vulnerability types
func GetVulnerabilityStats(results []common.Result) map[string]int {
	stats := make(map[string]int)

	for _, result := range results {
		vulnType := extractVulnerabilityType(result.CheckID)
		stats[vulnType]++
	}

	return stats
}

// extractVulnerabilityType extracts a human-readable vulnerability type from check ID
func extractVulnerabilityType(checkID string) string {
	// Remove rule source prefixes
	cleanID := strings.TrimPrefix(checkID, "javascript.")
	cleanID = strings.TrimPrefix(cleanID, "python.")
	cleanID = strings.TrimPrefix(cleanID, "java.")
	cleanID = strings.TrimPrefix(cleanID, "go.")
	cleanID = strings.TrimPrefix(cleanID, "typescript.")

	// Convert to human-readable format
	parts := strings.Split(cleanID, ".")
	if len(parts) > 0 {
		return strings.ReplaceAll(parts[len(parts)-1], "-", " ")
	}

	return cleanID
}

// DeduplicateResults removes duplicate findings based on file path and line numbers
func DeduplicateResults(results []common.Result) []common.Result {
	seen := make(map[string]bool)
	var deduplicated []common.Result

	for _, result := range results {
		// Create unique key based on path, lines, and check ID
		key := fmt.Sprintf("%s:%d-%d:%s",
			result.Path, result.Start.Line, result.End.Line, result.CheckID)

		if !seen[key] {
			seen[key] = true
			deduplicated = append(deduplicated, result)
		}
	}

	return deduplicated
}

// ValidateSemgrepInstallation checks if Semgrep is properly installed
func ValidateSemgrepInstallation(semgrepPath string) error {
	cmd := exec.Command(semgrepPath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("semgrep not found or not working: %v", err)
	}

	// Check if output contains version number (indicating valid semgrep)
	outputStr := string(output)
	if len(strings.TrimSpace(outputStr)) == 0 {
		return fmt.Errorf("invalid semgrep installation - empty version output")
	}

	// Basic check: version output should contain digits
	hasDigits := false
	for _, char := range outputStr {
		if char >= '0' && char <= '9' {
			hasDigits = true
			break
		}
	}

	if !hasDigits {
		return fmt.Errorf("invalid semgrep installation - no version number found")
	}

	return nil
}

// Helper functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
