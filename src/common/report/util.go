package report

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/asii-mov/codesucks-ai/common"
)

// getLanguage extracts language from file path
func getLanguage(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))

	languageMap := map[string]string{
		".js":    "javascript",
		".jsx":   "javascript",
		".ts":    "typescript",
		".tsx":   "typescript",
		".py":    "python",
		".rb":    "ruby",
		".php":   "php",
		".java":  "java",
		".c":     "c",
		".cpp":   "cpp",
		".cc":    "cpp",
		".cxx":   "cpp",
		".cs":    "csharp",
		".go":    "go",
		".rs":    "rust",
		".kt":    "kotlin",
		".swift": "swift",
		".html":  "html",
		".htm":   "html",
		".xml":   "xml",
		".json":  "json",
		".yaml":  "yaml",
		".yml":   "yaml",
		".toml":  "toml",
		".sh":    "bash",
		".bash":  "bash",
		".zsh":   "zsh",
		".fish":  "fish",
		".sql":   "sql",
	}

	if lang, exists := languageMap[ext]; exists {
		return lang
	}

	return "text"
}

// toLowerCase converts string to lowercase
func toLowerCase(s string) string {
	return strings.ToLower(s)
}

// getSeverity normalizes severity levels
func getSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "INFO"
	}
}

// getFileType extracts file type from path
func getFileType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == "" {
		return "file"
	}
	return strings.TrimPrefix(ext, ".")
}

// SortFindings sorts findings by severity and vulnerability type
func SortFindings(findings []common.SemgrepFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		severityOrder := map[string]int{
			"CRITICAL": 1,
			"HIGH":     2,
			"MEDIUM":   3,
			"LOW":      4,
			"INFO":     5,
		}

		// First sort by severity
		severityI := severityOrder[strings.ToUpper(findings[i].Severity)]
		severityJ := severityOrder[strings.ToUpper(findings[j].Severity)]

		if severityI != severityJ {
			return severityI < severityJ
		}

		// Then by vulnerability title
		return findings[i].VulnerabilityTitle < findings[j].VulnerabilityTitle
	})
}

// CalculateMetrics calculates vulnerability and severity statistics
func CalculateMetrics(findings []common.SemgrepFinding) (map[string]int, []string, map[string]int) {
	vulnerabilityStats := make(map[string]int)
	var vulnerabilityStatsOrdering []string
	severityStats := make(map[string]int)

	// Track seen vulnerabilities to maintain ordering
	seenVulns := make(map[string]bool)

	for _, finding := range findings {
		// Count vulnerability types
		if !seenVulns[finding.VulnerabilityTitle] {
			vulnerabilityStatsOrdering = append(vulnerabilityStatsOrdering, finding.VulnerabilityTitle)
			seenVulns[finding.VulnerabilityTitle] = true
		}
		vulnerabilityStats[finding.VulnerabilityTitle]++

		// Count severity levels
		severity := getSeverity(finding.Severity)
		severityStats[severity]++
	}

	// Sort vulnerability ordering by count (descending)
	sort.SliceStable(vulnerabilityStatsOrdering, func(i, j int) bool {
		return vulnerabilityStats[vulnerabilityStatsOrdering[i]] > vulnerabilityStats[vulnerabilityStatsOrdering[j]]
	})

	return vulnerabilityStats, vulnerabilityStatsOrdering, severityStats
}

// DeduplicateFindings removes duplicate findings
func DeduplicateFindings(findings []common.SemgrepFinding) []common.SemgrepFinding {
	seen := make(map[string]bool)
	var deduplicated []common.SemgrepFinding

	for _, finding := range findings {
		// Create unique key based on file, lines, and vulnerability
		key := fmt.Sprintf("%s:%d-%d:%s",
			finding.GithubLink, finding.StartLine, finding.StopLine, finding.VulnerabilityTitle)

		if !seen[key] {
			seen[key] = true
			deduplicated = append(deduplicated, finding)
		}
	}

	return deduplicated
}

// FilterFindingsBySeverity filters findings by minimum severity level
func FilterFindingsBySeverity(findings []common.SemgrepFinding, minSeverity string) []common.SemgrepFinding {
	severityOrder := map[string]int{
		"INFO":     1,
		"LOW":      2,
		"MEDIUM":   3,
		"HIGH":     4,
		"CRITICAL": 5,
	}

	minLevel := severityOrder[strings.ToUpper(minSeverity)]
	if minLevel == 0 {
		minLevel = 1 // Default to INFO if unknown severity
	}

	var filtered []common.SemgrepFinding
	for _, finding := range findings {
		severity := getSeverity(finding.Severity)
		if severityOrder[severity] >= minLevel {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

// TruffleHog utility functions

// cleanSecretType creates a human-readable secret type from detector name
func cleanSecretType(detectorName string) string {
	// Common detector name mappings
	typeMap := map[string]string{
		"githubtoken":    "GitHub Token",
		"gitlabtoken":    "GitLab Token",
		"awskey":         "AWS Access Key",
		"gcp":            "GCP Key",
		"azurekey":       "Azure Key",
		"dockerhub":      "DockerHub Token",
		"slacktoken":     "Slack Token",
		"stripekey":      "Stripe API Key",
		"twiliokey":      "Twilio Key",
		"sendgridkey":    "SendGrid Key",
		"mailchimpkey":   "MailChimp Key",
		"dropboxtoken":   "Dropbox Token",
		"huggingface":    "HuggingFace Token",
		"openaikey":      "OpenAI API Key",
		"anthropickey":   "Anthropic API Key",
		"postgresqlconn": "PostgreSQL Connection",
		"mysqlconn":      "MySQL Connection",
		"mongodbconn":    "MongoDB Connection",
		"redisconn":      "Redis Connection",
		"npmtoken":       "NPM Token",
		"pypikey":        "PyPI Key",
		"privatekey":     "Private Key",
		"certificate":    "Certificate",
		"password":       "Password",
		"webhook":        "Webhook URL",
		"api":            "API Key",
		"token":          "Token",
		"secret":         "Secret",
		"key":            "Key",
	}

	// Try exact match first
	if displayName, exists := typeMap[strings.ToLower(detectorName)]; exists {
		return displayName
	}

	// Try partial matches for common patterns
	lowerName := strings.ToLower(detectorName)
	for pattern, displayName := range typeMap {
		if strings.Contains(lowerName, pattern) {
			return displayName
		}
	}

	// Default: title case the detector name
	words := strings.Fields(strings.ReplaceAll(detectorName, "_", " "))
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
		}
	}

	return strings.Join(words, " ")
}

// generateSecretDescription creates a description for the secret finding
func generateSecretDescription(detectorName string, verified bool) string {
	secretType := cleanSecretType(detectorName)

	if verified {
		return fmt.Sprintf("✅ Verified %s detected - This secret is valid and poses a security risk", secretType)
	}

	return fmt.Sprintf("⚠️ Potential %s detected - Verification needed to confirm if this is a valid secret", secretType)
}

// SortSecretFindings sorts secret findings by verification status and type
func SortSecretFindings(findings []common.TruffleHogFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		// Verified secrets first
		if findings[i].Verified != findings[j].Verified {
			return findings[i].Verified
		}

		// Then by secret type
		return findings[i].SecretType < findings[j].SecretType
	})
}

// CalculateSecretMetrics calculates secret type statistics
func CalculateSecretMetrics(findings []common.TruffleHogFinding) (map[string]int, []string) {
	secretStats := make(map[string]int)
	var secretStatsOrdering []string
	seenSecrets := make(map[string]bool)

	for _, finding := range findings {
		// Count secret types
		if !seenSecrets[finding.SecretType] {
			secretStatsOrdering = append(secretStatsOrdering, finding.SecretType)
			seenSecrets[finding.SecretType] = true
		}
		secretStats[finding.SecretType]++
	}

	// Sort ordering by count (descending)
	sort.SliceStable(secretStatsOrdering, func(i, j int) bool {
		return secretStats[secretStatsOrdering[i]] > secretStats[secretStatsOrdering[j]]
	})

	return secretStats, secretStatsOrdering
}

// DeduplicateSecretFindings removes duplicate secret findings
func DeduplicateSecretFindings(findings []common.TruffleHogFinding) []common.TruffleHogFinding {
	seen := make(map[string]bool)
	var deduplicated []common.TruffleHogFinding

	for _, finding := range findings {
		// Create unique key based on file, line, and detector
		key := fmt.Sprintf("%s:%d:%s:%s",
			finding.File, finding.StartLine, finding.DetectorName, finding.RedactedValue)

		if !seen[key] {
			seen[key] = true
			deduplicated = append(deduplicated, finding)
		}
	}

	return deduplicated
}
