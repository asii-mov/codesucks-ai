package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/asii-mov/codesucks-ai/common"
)

// JSONReport represents the structure of the JSON security report
type JSONReport struct {
	Metadata    JSONMetadata        `json:"metadata"`
	Summary     JSONSummary         `json:"summary"`
	Results     []JSONVulnerability `json:"vulnerabilities"`
	Secrets     []JSONSecret        `json:"secrets,omitempty"`
	Patterns    []JSONPattern       `json:"patterns,omitempty"`
	Metrics     JSONMetrics         `json:"metrics"`
	Remediation JSONRemediation     `json:"remediation"`
}

// JSONMetadata contains report metadata
type JSONMetadata struct {
	ReportID      string    `json:"report_id"`
	ReportVersion string    `json:"report_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	Repository    string    `json:"repository"`
	Branch        string    `json:"branch,omitempty"`
	Commit        string    `json:"commit,omitempty"`
	ScanType      string    `json:"scan_type"`
	ScanConfig    string    `json:"scan_config"`
}

// JSONSummary contains the executive summary
type JSONSummary struct {
	TotalVulnerabilities int            `json:"total_vulnerabilities"`
	BySeverity           map[string]int `json:"by_severity"`
	ByType               map[string]int `json:"by_type"`
	FixedCount           int            `json:"fixed_count"`
	FalsePositives       int            `json:"false_positives"`
	TruePositives        int            `json:"true_positives"`
	RiskScore            float64        `json:"risk_score"`
}

// JSONVulnerability represents a single vulnerability
type JSONVulnerability struct {
	ID               string  `json:"id"`
	Type             string  `json:"type"`
	Severity         string  `json:"severity"`
	Confidence       float64 `json:"confidence"`
	File             string  `json:"file"`
	StartLine        int     `json:"start_line"`
	EndLine          int     `json:"end_line"`
	VulnerableCode   string  `json:"vulnerable_code"`
	Description      string  `json:"description"`
	CWE              string  `json:"cwe,omitempty"`
	OWASP            string  `json:"owasp,omitempty"`
	ExploitExample   string  `json:"exploit_example,omitempty"`
	SecureFix        string  `json:"secure_fix,omitempty"`
	FixExplanation   string  `json:"fix_explanation,omitempty"`
	ValidationStatus string  `json:"validation_status"`
	AutoFixed        bool    `json:"auto_fixed"`
}

// JSONSecret represents a detected secret
type JSONSecret struct {
	Type     string  `json:"type"`
	File     string  `json:"file"`
	Line     int     `json:"line"`
	Redacted string  `json:"redacted"`
	Verified bool    `json:"verified"`
	Entropy  float64 `json:"entropy,omitempty"`
}

// JSONPattern represents a vulnerability pattern
type JSONPattern struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Instances   []string `json:"instances"`
	SystemicFix string   `json:"systemic_fix"`
}

// JSONMetrics contains code metrics
type JSONMetrics struct {
	FilesAnalyzed        int            `json:"files_analyzed"`
	LinesOfCode          int            `json:"lines_of_code"`
	VulnerabilityDensity float64        `json:"vulnerability_density"`
	SecurityScore        float64        `json:"security_score"`
	TopVulnerableFiles   []string       `json:"top_vulnerable_files"`
	LanguageBreakdown    map[string]int `json:"language_breakdown,omitempty"`
}

// JSONRemediation contains remediation information
type JSONRemediation struct {
	EstimatedEffort   string   `json:"estimated_effort"`
	Priority          []string `json:"priority_fixes"`
	AutoFixAvailable  int      `json:"auto_fix_available"`
	ManualFixRequired int      `json:"manual_fix_required"`
	Resources         []string `json:"resources,omitempty"`
}

// GenerateJSONReport generates a JSON format security report
func GenerateJSONReport(reportData *ReportData, outputPath string) error {
	report := &JSONReport{
		Metadata: JSONMetadata{
			ReportID:      reportData.ReportID,
			ReportVersion: "1.0",
			GeneratedAt:   time.Now(),
			Repository:    reportData.Repository,
			Branch:        reportData.Branch,
			Commit:        reportData.Commit,
			ScanType:      determineScanType(reportData),
			ScanConfig:    reportData.ScanConfig,
		},
		Summary: JSONSummary{
			TotalVulnerabilities: reportData.TotalVulnerabilities,
			BySeverity:           reportData.SeverityDistribution,
			ByType:               calculateTypeDistribution(reportData),
			FixedCount:           reportData.FixedCount,
			FalsePositives:       reportData.FalsePositives,
			TruePositives:        reportData.TruePositives,
			RiskScore:            calculateRiskScore(reportData),
		},
		Results:     convertToJSONVulnerabilities(reportData.Vulnerabilities),
		Secrets:     convertToJSONSecrets(reportData.Secrets),
		Patterns:    convertToJSONPatterns(reportData.Patterns),
		Metrics:     createJSONMetrics(reportData),
		Remediation: createJSONRemediation(reportData),
	}

	// Marshal to JSON with indentation
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON report: %w", err)
	}

	// Ensure output directory exists
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write JSON file
	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}

	return nil
}

// Helper functions

func determineScanType(data *ReportData) string {
	if data.OrchestratorMode {
		return "AI Orchestrator Analysis"
	} else if data.MatrixBuild {
		return "Matrix Build Analysis"
	}
	return "Standard Security Scan"
}

func calculateTypeDistribution(data *ReportData) map[string]int {
	typeCount := make(map[string]int)
	for _, vuln := range data.Vulnerabilities {
		typeCount[vuln.CheckID]++
	}
	return typeCount
}

func calculateRiskScore(data *ReportData) float64 {
	// Calculate risk score based on severity distribution
	score := 100.0
	score -= float64(data.SeverityDistribution["CRITICAL"]) * 15.0
	score -= float64(data.SeverityDistribution["HIGH"]) * 10.0
	score -= float64(data.SeverityDistribution["MEDIUM"]) * 5.0
	score -= float64(data.SeverityDistribution["LOW"]) * 2.0

	if score < 0 {
		score = 0
	}
	return score
}

func convertToJSONVulnerabilities(vulns []common.ValidatedResult) []JSONVulnerability {
	var jsonVulns []JSONVulnerability
	for i, vuln := range vulns {
		jsonVuln := JSONVulnerability{
			ID:               fmt.Sprintf("VULN-%04d", i+1),
			Type:             vuln.CheckID,
			Severity:         vuln.Extra.Metadata.Impact,
			Confidence:       getConfidence(vuln),
			File:             vuln.Path,
			StartLine:        vuln.Start.Line,
			EndLine:          vuln.End.Line,
			VulnerableCode:   vuln.Extra.Lines,
			Description:      vuln.Extra.Message,
			ValidationStatus: getValidationStatus(vuln),
			AutoFixed:        false, // This field doesn't exist in ValidatedResult
		}

		if vuln.AgentValidation != nil {
			// These fields are not in AgentValidation, using available fields
			jsonVuln.FixExplanation = vuln.AgentValidation.RecommendedAction
		}

		jsonVulns = append(jsonVulns, jsonVuln)
	}
	return jsonVulns
}

func convertToJSONSecrets(secrets []common.Secret) []JSONSecret {
	var jsonSecrets []JSONSecret
	for _, secret := range secrets {
		jsonSecrets = append(jsonSecrets, JSONSecret{
			Type:     secret.Type,
			File:     secret.File,
			Line:     secret.Line,
			Redacted: "",    // Field not available
			Verified: false, // Field not available
			Entropy:  0.0,   // Field not available
		})
	}
	return jsonSecrets
}

func convertToJSONPatterns(patterns []common.VulnerabilityPattern) []JSONPattern {
	var jsonPatterns []JSONPattern
	for _, pattern := range patterns {
		jsonPatterns = append(jsonPatterns, JSONPattern{
			ID:          pattern.PatternID,
			Description: pattern.Description,
			Instances:   pattern.Instances,
			SystemicFix: pattern.SystemicFix,
		})
	}
	return jsonPatterns
}

func createJSONMetrics(data *ReportData) JSONMetrics {
	return JSONMetrics{
		FilesAnalyzed:        data.FilesAnalyzed,
		LinesOfCode:          data.LinesOfCode,
		VulnerabilityDensity: data.VulnerabilityDensity,
		SecurityScore:        calculateRiskScore(data),
		TopVulnerableFiles:   data.TopVulnerableFiles,
		LanguageBreakdown:    data.LanguageBreakdown,
	}
}

func createJSONRemediation(data *ReportData) JSONRemediation {
	return JSONRemediation{
		EstimatedEffort:   estimateEffort(data.TotalVulnerabilities),
		Priority:          getPriorityFixes(data),
		AutoFixAvailable:  data.AutoFixableCount,
		ManualFixRequired: data.TotalVulnerabilities - data.AutoFixableCount,
		Resources: []string{
			"https://owasp.org/www-project-top-ten/",
			"https://cwe.mitre.org/top25/",
		},
	}
}

func estimateEffort(vulnCount int) string {
	if vulnCount <= 5 {
		return "1-2 hours"
	} else if vulnCount <= 20 {
		return "1-2 days"
	} else if vulnCount <= 50 {
		return "3-5 days"
	}
	return "1-2 weeks"
}

func getPriorityFixes(data *ReportData) []string {
	var priorities []string

	// Add critical vulnerabilities first
	for _, vuln := range data.Vulnerabilities {
		if vuln.Extra.Metadata.Impact == "CRITICAL" {
			priorities = append(priorities, fmt.Sprintf("%s in %s", vuln.CheckID, vuln.Path))
			if len(priorities) >= 5 {
				break
			}
		}
	}

	return priorities
}

func getConfidence(vuln common.ValidatedResult) float64 {
	if vuln.AgentValidation != nil {
		return vuln.AgentValidation.Confidence
	}
	return 0.75 // Default confidence
}

func getValidationStatus(vuln common.ValidatedResult) string {
	if vuln.AgentValidation != nil {
		if vuln.AgentValidation.IsLegitimate {
			return "confirmed"
		}
		return "false_positive"
	}
	return "unvalidated"
}
