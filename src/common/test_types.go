package common

import "time"

// Test-specific types that may not be fully implemented yet
// These types are used by the test infrastructure

// Vulnerability represents a security vulnerability found in code
type Vulnerability struct {
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
	File        string  `json:"file"`
	Line        int     `json:"line"`
	Code        string  `json:"code"`
	CWE         string  `json:"cwe"`
	OWASP       string  `json:"owasp"`
}

// VulnerabilityLocation represents the location of a vulnerability
type VulnerabilityLocation struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Function  string `json:"function"`
}

// Secret represents a detected secret or credential
type Secret struct {
	Type       string  `json:"type"`
	File       string  `json:"file"`
	Line       int     `json:"line"`
	Value      string  `json:"value"`
	Verified   bool    `json:"verified"`
	Confidence float64 `json:"confidence"`
}

// Summary represents a summary of analysis results
type Summary struct {
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	CriticalCount        int `json:"critical_count"`
	HighCount            int `json:"high_count"`
	MediumCount          int `json:"medium_count"`
	LowCount             int `json:"low_count"`
	SecretsFound         int `json:"secrets_found"`
}

// AnalysisResult represents the complete result of a security analysis
type AnalysisResult struct {
	Repository      string          `json:"repository"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Secrets         []Secret        `json:"secrets"`
	Timestamp       time.Time       `json:"timestamp"`
	Duration        time.Duration   `json:"duration"`
	Summary         Summary         `json:"summary"`
}

// SemgrepResult represents the result of a Semgrep scan
type SemgrepResult struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Summary         SemgrepSummary  `json:"summary"`
}

// SemgrepSummary represents Semgrep scan summary
type SemgrepSummary struct {
	TotalFindings int    `json:"total_findings"`
	FilesScanned  int    `json:"files_scanned"`
	RulesRun      int    `json:"rules_run"`
	Duration      string `json:"duration"`
	CriticalCount int    `json:"critical_count"`
	HighCount     int    `json:"high_count"`
	MediumCount   int    `json:"medium_count"`
	LowCount      int    `json:"low_count"`
}
