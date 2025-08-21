package report

import (
	"bufio"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/asii-mov/codesucks-ai/common"
	"github.com/google/uuid"
)

// GenerateHTMLReport generates an HTML report using the new ReportData structure
func GenerateHTMLReport(data *ReportData, outputPath string) error {
	// Convert to common.ReportData for backward compatibility
	commonData := convertToCommonReportData(data)

	// Generate HTML using existing function
	outDir := filepath.Dir(outputPath)
	generatedPath, err := GenerateHTML(commonData, outDir)
	if err != nil {
		return err
	}

	// Rename to desired output path if different
	if generatedPath != outputPath {
		if err := os.Rename(generatedPath, outputPath); err != nil {
			// If rename fails, at least we generated the report
			fmt.Printf("Warning: Could not rename report to %s: %v\n", outputPath, err)
		}
	}

	return nil
}

// GenerateHTML generates an HTML report from the scan results
func GenerateHTML(reportData *common.ReportData, outDir string) (string, error) {
	// Validate input data
	if reportData == nil {
		return "", fmt.Errorf("report data cannot be nil")
	}

	// Ensure output directory exists
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %v", err)
	}

	// Create template with helper functions
	tmpl := template.New("report")
	tmpl.Funcs(template.FuncMap{
		"getLanguage": getLanguage,
		"toLowerCase": toLowerCase,
		"getSeverity": getSeverity,
		"getFileType": getFileType,
		"mul":         func(a, b float64) float64 { return a * b },
		"add":         func(a, b int) int { return a + b },
		"gt":          func(a, b int) bool { return a > b },
	})

	// Parse the template
	tmpl, err := tmpl.Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse HTML template: %v", err)
	}

	// Create output file with unique name
	outPath := filepath.Join(outDir, fmt.Sprintf("security-report-%s.html", uuid.New().String()))
	file, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("failed to create output file %s: %v", outPath, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			fmt.Printf("Warning: failed to close report file: %v\n", closeErr)
		}
	}()

	// Execute template with report data
	err = tmpl.Execute(file, reportData)
	if err != nil {
		// Clean up incomplete file - ignore error as it's cleanup
		_ = os.Remove(outPath)
		return "", fmt.Errorf("failed to execute HTML template: %v", err)
	}

	return outPath, nil
}

// extractCodeSnippet reads a file and extracts lines around the specified range
func extractCodeSnippet(filePath string, startLine, endLine int) string {
	// Try to open the file
	file, err := os.Open(filePath)
	if err != nil {
		// If we can't open the file, return empty string
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 1
	var lines []string

	// Read the file line by line
	for scanner.Scan() {
		if lineNum >= startLine && lineNum <= endLine {
			lines = append(lines, scanner.Text())
		}
		if lineNum > endLine {
			break
		}
		lineNum++
	}

	// Join the lines
	if len(lines) > 0 {
		return strings.Join(lines, "\n")
	}
	return ""
}

// ConvertSemgrepToReport converts Semgrep results to report format
func ConvertSemgrepToReport(target string, defaultBranch string, semgrepJson *common.SemgrepJson, sourcePath string) *common.ReportData {
	var findings []common.SemgrepFinding

	// Convert Semgrep results to report findings
	for _, result := range semgrepJson.Results {
		// Skip informational findings (only include HIGH, MEDIUM, LOW severity)
		// This filters out parsing errors and other non-security findings
		severity := strings.ToUpper(result.Extra.Metadata.Impact)
		if severity != "HIGH" && severity != "MEDIUM" && severity != "LOW" {
			continue
		}

		// Extract code snippet - fallback to reading from file if Semgrep returns "requires login"
		codeSnippet := result.Extra.Lines
		if codeSnippet == "requires login" || codeSnippet == "" {
			// Try to extract code from the actual file
			if sourcePath != "" {
				fullPath := filepath.Join(sourcePath, result.Path)
				if extracted := extractCodeSnippet(fullPath, result.Start.Line, result.End.Line); extracted != "" {
					codeSnippet = extracted
				}
			}
		}

		finding := common.SemgrepFinding{
			VulnerabilityTitle: cleanVulnerabilityTitle(result.CheckID),
			Severity:           getSeverityFromResult(result),
			Description:        result.Extra.Message,
			Code:               codeSnippet,
			StartLine:          result.Start.Line,
			StopLine:           result.End.Line,
			GithubLink:         generateGitHubLink(target, result.Path, result.Start.Line, result.End.Line, defaultBranch),
		}
		findings = append(findings, finding)
	}

	// Sort findings by severity and vulnerability type
	SortFindings(findings)

	// Calculate statistics
	vulnStats, vulnOrdering, severityStats := CalculateMetrics(findings)

	return &common.ReportData{
		Target:                     target,
		DefaultBranch:              defaultBranch,
		VulnerabilityStats:         vulnStats,
		VulnerabilityStatsOrdering: vulnOrdering,
		SeverityStats:              severityStats,
		SeverityStatsOrdering:      []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"},
		Findings:                   findings,
	}
}

// ConvertValidatedResultsToReport converts validated results to report format
func ConvertValidatedResultsToReport(target string, defaultBranch string, validatedResults []common.ValidatedResult, matrixConfig *common.MatrixConfig, sourcePath string) *common.ReportData {
	var findings []common.SemgrepFinding

	// Convert validated results to report findings
	for _, validatedResult := range validatedResults {
		result := validatedResult.Result

		// Skip informational findings (only include HIGH, MEDIUM, LOW severity)
		severity := strings.ToUpper(result.Extra.Metadata.Impact)
		if severity != "HIGH" && severity != "MEDIUM" && severity != "LOW" {
			continue
		}

		// Extract code snippet - fallback to reading from file if Semgrep returns "requires login"
		codeSnippet := result.Extra.Lines
		if codeSnippet == "requires login" || codeSnippet == "" {
			// Try to extract code from the actual file
			if sourcePath != "" {
				fullPath := filepath.Join(sourcePath, result.Path)
				if extracted := extractCodeSnippet(fullPath, result.Start.Line, result.End.Line); extracted != "" {
					codeSnippet = extracted
				}
			}
		}

		finding := common.SemgrepFinding{
			VulnerabilityTitle: cleanVulnerabilityTitle(result.CheckID),
			Severity:           getSeverityFromResult(result),
			Description:        result.Extra.Message,
			Code:               codeSnippet,
			StartLine:          result.Start.Line,
			StopLine:           result.End.Line,
			GithubLink:         generateGitHubLink(target, result.Path, result.Start.Line, result.End.Line, defaultBranch),
			AgentValidation:    validatedResult.AgentValidation,
			IsFiltered:         validatedResult.IsFiltered,
		}
		findings = append(findings, finding)
	}

	// Sort findings by severity and vulnerability type
	SortFindings(findings)

	// Calculate statistics
	vulnStats, vulnOrdering, severityStats := CalculateMetrics(findings)

	return &common.ReportData{
		Target:                     target,
		DefaultBranch:              defaultBranch,
		VulnerabilityStats:         vulnStats,
		VulnerabilityStatsOrdering: vulnOrdering,
		SeverityStats:              severityStats,
		SeverityStatsOrdering:      []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"},
		Findings:                   findings,
		MatrixConfig:               matrixConfig,
	}
}

// ConvertTruffleHogToReport converts TruffleHog results to report format
func ConvertTruffleHogToReport(target string, defaultBranch string, trufflehogJson *common.TruffleHogJson) *common.ReportData {
	var secretFindings []common.TruffleHogFinding
	secretStats := make(map[string]int)
	var secretStatsOrdering []string
	seenSecrets := make(map[string]bool)

	// Convert TruffleHog results to report findings
	for _, result := range trufflehogJson.Results {
		// Skip log entries - only process actual findings (those with SourceMetadata)
		if result.SourceMetadata == nil || result.DetectorName == "" {
			continue
		}

		// Extract file path and line number
		var filePath string
		var lineNum int

		// TruffleHog can scan filesystem or git - handle both
		if result.SourceMetadata.Data.Filesystem != nil {
			filePath = result.SourceMetadata.Data.Filesystem.File
			lineNum = result.SourceMetadata.Data.Filesystem.Line
		} else if result.SourceMetadata.Data.Git != nil {
			filePath = result.SourceMetadata.Data.Git.File
			lineNum = result.SourceMetadata.Data.Git.Line
		}

		finding := common.TruffleHogFinding{
			SecretType:    cleanSecretType(result.DetectorName),
			DetectorName:  result.DetectorName,
			Verified:      result.Verified,
			Description:   generateSecretDescription(result.DetectorName, result.Verified),
			RedactedValue: result.Redacted,
			StartLine:     lineNum,
			GithubLink:    generateGitHubLink(target, filePath, lineNum, lineNum, defaultBranch),
			File:          filePath,
		}
		secretFindings = append(secretFindings, finding)

		// Count secret types for statistics
		secretType := cleanSecretType(result.DetectorName)
		if !seenSecrets[secretType] {
			secretStatsOrdering = append(secretStatsOrdering, secretType)
			seenSecrets[secretType] = true
		}
		secretStats[secretType]++
	}

	// Sort secret findings
	SortSecretFindings(secretFindings)

	return &common.ReportData{
		Target:              target,
		DefaultBranch:       defaultBranch,
		SecretStats:         secretStats,
		SecretStatsOrdering: secretStatsOrdering,
		SecretFindings:      secretFindings,
	}
}

// AddTruffleHogToReport adds TruffleHog results to existing report data
func AddTruffleHogToReport(reportData *common.ReportData, target string, defaultBranch string, trufflehogJson *common.TruffleHogJson) {
	if reportData == nil {
		return
	}

	truffleHogData := ConvertTruffleHogToReport(target, defaultBranch, trufflehogJson)

	// Merge the TruffleHog data into the existing report
	reportData.SecretStats = truffleHogData.SecretStats
	reportData.SecretStatsOrdering = truffleHogData.SecretStatsOrdering
	reportData.SecretFindings = truffleHogData.SecretFindings
}

// cleanVulnerabilityTitle creates a human-readable vulnerability title
func cleanVulnerabilityTitle(checkID string) string {
	// Remove language prefixes and make it readable
	title := checkID
	prefixes := []string{"javascript.", "python.", "java.", "go.", "typescript.", "php.", "ruby."}

	for _, prefix := range prefixes {
		if len(title) > len(prefix) && title[:len(prefix)] == prefix {
			title = title[len(prefix):]
			break
		}
	}

	// Replace hyphens and underscores with spaces
	title = strings.ReplaceAll(title, "-", " ")
	title = strings.ReplaceAll(title, "_", " ")

	// Title case
	words := strings.Fields(title)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
		}
	}

	return strings.Join(words, " ")
}

// getSeverityFromResult extracts severity from Semgrep result
func getSeverityFromResult(result common.Result) string {
	impact := strings.ToUpper(result.Extra.Metadata.Impact)

	switch impact {
	case "HIGH", "CRITICAL":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "INFO"
	}
}

// generateGitHubLink creates a GitHub link to the vulnerable code
func generateGitHubLink(target, filePath string, startLine, endLine int, defaultBranch string) string {
	// Clean the target URL
	baseURL := strings.TrimSuffix(target, "/")
	baseURL = strings.TrimSuffix(baseURL, ".git")

	// Clean the file path by removing temporary directory prefixes
	cleanPath := filePath
	if strings.Contains(cleanPath, "/temp-") {
		// Find the part after the repo name in the temp directory
		parts := strings.Split(cleanPath, "/")
		for i, part := range parts {
			if strings.HasPrefix(part, "temp-") && i+1 < len(parts) {
				// The next part should be the repo name, start from the part after that
				if i+2 < len(parts) {
					cleanPath = strings.Join(parts[i+2:], "/")
				}
				break
			}
		}
	}

	// Create GitHub blob link
	// Use the provided default branch, or fall back to "main" if not provided
	if defaultBranch == "" {
		defaultBranch = "main"
	}
	if startLine == endLine {
		return fmt.Sprintf("%s/blob/%s/%s#L%d", baseURL, defaultBranch, cleanPath, startLine)
	}
	return fmt.Sprintf("%s/blob/%s/%s#L%d-L%d", baseURL, defaultBranch, cleanPath, startLine, endLine)
}
