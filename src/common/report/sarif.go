package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/asii-mov/codesucks-ai/common"
)

// SARIF structures according to SARIF 2.1.0 specification
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

// SARIFReport represents the root of a SARIF log file
type SARIFReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run of an analysis tool
type SARIFRun struct {
	Tool         SARIFTool          `json:"tool"`
	Results      []SARIFResult      `json:"results"`
	Artifacts    []SARIFArtifact    `json:"artifacts,omitempty"`
	Taxonomies   []SARIFTaxonomy    `json:"taxonomies,omitempty"`
	Properties   map[string]interface{} `json:"properties,omitempty"`
}

// SARIFTool represents the analysis tool that was run
type SARIFTool struct {
	Driver SARIFToolComponent `json:"driver"`
}

// SARIFToolComponent represents a component of the tool
type SARIFToolComponent struct {
	Name            string         `json:"name"`
	Version         string         `json:"version"`
	SemanticVersion string         `json:"semanticVersion"`
	InformationURI  string         `json:"informationUri"`
	Rules           []SARIFRule    `json:"rules"`
}

// SARIFRule represents a rule used by the analysis tool
type SARIFRule struct {
	ID               string                   `json:"id"`
	Name             string                   `json:"name"`
	ShortDescription SARIFMultiformatMessage  `json:"shortDescription"`
	FullDescription  SARIFMultiformatMessage  `json:"fullDescription"`
	DefaultConfig    SARIFReportingConfig     `json:"defaultConfiguration"`
	Properties       map[string]interface{}   `json:"properties,omitempty"`
}

// SARIFMultiformatMessage represents a message in multiple formats
type SARIFMultiformatMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

// SARIFReportingConfig represents the default configuration for a rule
type SARIFReportingConfig struct {
	Level string `json:"level"`
}

// SARIFResult represents a single result from the analysis
type SARIFResult struct {
	RuleID    string             `json:"ruleId"`
	RuleIndex int                `json:"ruleIndex"`
	Level     string             `json:"level"`
	Message   SARIFMessage       `json:"message"`
	Locations []SARIFLocation    `json:"locations"`
	Fixes     []SARIFFix         `json:"fixes,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFMessage represents a message
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation represents a location in the code
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation represents a physical location in a file
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

// SARIFArtifactLocation represents the location of an artifact
type SARIFArtifactLocation struct {
	URI        string `json:"uri"`
	URIBaseID  string `json:"uriBaseId,omitempty"`
	Index      int    `json:"index,omitempty"`
}

// SARIFRegion represents a region in a file
type SARIFRegion struct {
	StartLine   int    `json:"startLine"`
	StartColumn int    `json:"startColumn,omitempty"`
	EndLine     int    `json:"endLine"`
	EndColumn   int    `json:"endColumn,omitempty"`
	Snippet     *SARIFArtifactContent `json:"snippet,omitempty"`
}

// SARIFArtifactContent represents the content of an artifact
type SARIFArtifactContent struct {
	Text string `json:"text"`
}

// SARIFFix represents a proposed fix for a result
type SARIFFix struct {
	Description    SARIFMessage           `json:"description"`
	ArtifactChanges []SARIFArtifactChange `json:"artifactChanges"`
}

// SARIFArtifactChange represents a change to an artifact
type SARIFArtifactChange struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Replacements     []SARIFReplacement    `json:"replacements"`
}

// SARIFReplacement represents a replacement in a file
type SARIFReplacement struct {
	DeletedRegion SARIFRegion          `json:"deletedRegion"`
	InsertedContent SARIFArtifactContent `json:"insertedContent"`
}

// SARIFArtifact represents an artifact (file) analyzed
type SARIFArtifact struct {
	Location SARIFArtifactLocation `json:"location"`
	Roles    []string              `json:"roles,omitempty"`
}

// SARIFTaxonomy represents a taxonomy (e.g., CWE)
type SARIFTaxonomy struct {
	Name             string        `json:"name"`
	GUID             string        `json:"guid"`
	Organization     string        `json:"organization"`
	ShortDescription SARIFMultiformatMessage `json:"shortDescription"`
	Taxa             []SARIFTaxon  `json:"taxa"`
}

// SARIFTaxon represents a single taxon in a taxonomy
type SARIFTaxon struct {
	ID               string                  `json:"id"`
	Name             string                  `json:"name"`
	ShortDescription SARIFMultiformatMessage `json:"shortDescription"`
}

// GenerateSARIFReport generates a SARIF format security report
func GenerateSARIFReport(reportData *ReportData, outputPath string) error {
	// Create rules from vulnerabilities
	rules, ruleIndex := createSARIFRules(reportData.Vulnerabilities)
	
	// Create results
	results := createSARIFResults(reportData.Vulnerabilities, ruleIndex)
	
	// Create artifacts
	artifacts := createSARIFArtifacts(reportData.Vulnerabilities)
	
	report := &SARIFReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFToolComponent{
						Name:            "codesucks-ai",
						Version:         "1.0.0",
						SemanticVersion: "1.0.0",
						InformationURI:  "https://github.com/asii-mov/codesucks-ai",
						Rules:           rules,
					},
				},
				Results:    results,
				Artifacts:  artifacts,
				Taxonomies: createSARIFTaxonomies(),
				Properties: map[string]interface{}{
					"repository":   reportData.Repository,
					"branch":       reportData.Branch,
					"commit":       reportData.Commit,
					"scanType":     determineScanType(reportData),
					"generatedAt":  time.Now().Format(time.RFC3339),
				},
			},
		},
	}

	// Marshal to JSON with indentation
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SARIF report: %w", err)
	}

	// Ensure output directory exists
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write SARIF file
	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write SARIF report: %w", err)
	}

	return nil
}

// Helper functions for SARIF generation

func createSARIFRules(vulnerabilities []common.ValidatedResult) ([]SARIFRule, map[string]int) {
	ruleMap := make(map[string]SARIFRule)
	ruleIndex := make(map[string]int)
	
	for _, vuln := range vulnerabilities {
		ruleID := vuln.CheckID
		if _, exists := ruleMap[ruleID]; !exists {
			rule := SARIFRule{
				ID:   ruleID,
				Name: getRuleName(ruleID),
				ShortDescription: SARIFMultiformatMessage{
					Text: getShortDescription(ruleID),
				},
				FullDescription: SARIFMultiformatMessage{
					Text:     getFullDescription(vuln),
					Markdown: getMarkdownDescription(vuln),
				},
				DefaultConfig: SARIFReportingConfig{
					Level: severityToSARIFLevel(vuln.Extra.Metadata.Impact),
				},
				Properties: map[string]interface{}{
					"category": getCategoryFromRuleID(ruleID),
					"cwe":      getCWEFromRuleID(ruleID),
				},
			}
			ruleMap[ruleID] = rule
		}
	}
	
	// Convert map to slice and build index
	var rules []SARIFRule
	index := 0
	for ruleID, rule := range ruleMap {
		rules = append(rules, rule)
		ruleIndex[ruleID] = index
		index++
	}
	
	return rules, ruleIndex
}

func createSARIFResults(vulnerabilities []common.ValidatedResult, ruleIndex map[string]int) []SARIFResult {
	var results []SARIFResult
	
	for _, vuln := range vulnerabilities {
		result := SARIFResult{
			RuleID:    vuln.CheckID,
			RuleIndex: ruleIndex[vuln.CheckID],
			Level:     severityToSARIFLevel(vuln.Extra.Metadata.Impact),
			Message: SARIFMessage{
				Text: vuln.Extra.Message,
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: vuln.Path,
						},
						Region: SARIFRegion{
							StartLine:   vuln.Start.Line,
							StartColumn: vuln.Start.Col,
							EndLine:     vuln.End.Line,
							EndColumn:   vuln.End.Col,
							Snippet: &SARIFArtifactContent{
								Text: vuln.Extra.Lines,
							},
						},
					},
				},
			},
			Properties: map[string]interface{}{
				"confidence": getConfidence(vuln),
				"validated":  vuln.AgentValidation != nil,
				"autoFixed":  false, // Field not available in ValidatedResult
			},
		}
		
		// Add fix if available
		if vuln.AgentValidation != nil && vuln.AgentValidation.RecommendedAction != "" {
			result.Fixes = []SARIFFix{
				{
					Description: SARIFMessage{
						Text: vuln.AgentValidation.RecommendedAction,
					},
					ArtifactChanges: []SARIFArtifactChange{
						{
							ArtifactLocation: SARIFArtifactLocation{
								URI: vuln.Path,
							},
							Replacements: []SARIFReplacement{
								{
									DeletedRegion: SARIFRegion{
										StartLine: vuln.Start.Line,
										EndLine:   vuln.End.Line,
									},
									InsertedContent: SARIFArtifactContent{
										Text: vuln.AgentValidation.RecommendedAction, // Using available field
									},
								},
							},
						},
					},
				},
			}
		}
		
		results = append(results, result)
	}
	
	return results
}

func createSARIFArtifacts(vulnerabilities []common.ValidatedResult) []SARIFArtifact {
	artifactMap := make(map[string]bool)
	var artifacts []SARIFArtifact
	
	for _, vuln := range vulnerabilities {
		if !artifactMap[vuln.Path] {
			artifacts = append(artifacts, SARIFArtifact{
				Location: SARIFArtifactLocation{
					URI: vuln.Path,
				},
				Roles: []string{"analysisTarget"},
			})
			artifactMap[vuln.Path] = true
		}
	}
	
	return artifacts
}

func createSARIFTaxonomies() []SARIFTaxonomy {
	return []SARIFTaxonomy{
		{
			Name:         "CWE",
			GUID:         "A9282C88-F1FE-4A01-8137-E8D2A037AB82",
			Organization: "MITRE",
			ShortDescription: SARIFMultiformatMessage{
				Text: "Common Weakness Enumeration",
			},
			Taxa: []SARIFTaxon{
				{
					ID:   "79",
					Name: "CWE-79",
					ShortDescription: SARIFMultiformatMessage{
						Text: "Cross-site Scripting (XSS)",
					},
				},
				{
					ID:   "89",
					Name: "CWE-89",
					ShortDescription: SARIFMultiformatMessage{
						Text: "SQL Injection",
					},
				},
				{
					ID:   "78",
					Name: "CWE-78",
					ShortDescription: SARIFMultiformatMessage{
						Text: "OS Command Injection",
					},
				},
			},
		},
	}
}

func severityToSARIFLevel(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW", "INFO":
		return "note"
	default:
		return "none"
	}
}

func getRuleName(ruleID string) string {
	// Generate a human-readable name from the rule ID
	parts := strings.Split(ruleID, "-")
	if len(parts) > 0 {
		return strings.Title(strings.ReplaceAll(parts[len(parts)-1], "_", " "))
	}
	return ruleID
}

func getShortDescription(ruleID string) string {
	descriptions := map[string]string{
		"injection": "Potential injection vulnerability",
		"xss":       "Cross-site scripting vulnerability",
		"auth":      "Authentication/authorization issue",
		"crypto":    "Cryptographic weakness",
		"path":      "Path traversal vulnerability",
		"deserial":  "Deserialization vulnerability",
		"xxe":       "XML External Entity vulnerability",
		"race":      "Race condition vulnerability",
	}
	
	for key, desc := range descriptions {
		if strings.Contains(strings.ToLower(ruleID), key) {
			return desc
		}
	}
	
	return "Security vulnerability"
}

func getFullDescription(vuln common.ValidatedResult) string {
	if vuln.AgentValidation != nil && vuln.AgentValidation.Reasoning != "" {
		return vuln.AgentValidation.Reasoning
	}
	return vuln.Extra.Message
}

func getMarkdownDescription(vuln common.ValidatedResult) string {
	var md strings.Builder
	
	md.WriteString("## Vulnerability Details\n\n")
	md.WriteString(vuln.Extra.Message)
	md.WriteString("\n\n")
	
	if vuln.AgentValidation != nil {
		// ExploitExample field not available in AgentValidation
		if false {
			md.WriteString("### Exploit Example\n\n")
			md.WriteString("```\n")
			md.WriteString("") // Field not available
			md.WriteString("\n```\n\n")
		}
		
		// SecureFix field not available in AgentValidation
		if false {
			md.WriteString("### Secure Fix\n\n")
			md.WriteString("```\n")
			md.WriteString("") // Field not available
			md.WriteString("\n```\n\n")
		}
		
		if vuln.AgentValidation.RecommendedAction != "" {
			md.WriteString("### Fix Explanation\n\n")
			md.WriteString(vuln.AgentValidation.RecommendedAction)
			md.WriteString("\n")
		}
	}
	
	return md.String()
}

func getCategoryFromRuleID(ruleID string) string {
	categories := map[string]string{
		"injection": "Injection",
		"xss":       "Cross-Site Scripting",
		"auth":      "Broken Authentication",
		"crypto":    "Cryptographic Failures",
		"path":      "Path Traversal",
		"deserial":  "Insecure Deserialization",
		"xxe":       "XML External Entities",
		"race":      "Race Conditions",
	}
	
	for key, cat := range categories {
		if strings.Contains(strings.ToLower(ruleID), key) {
			return cat
		}
	}
	
	return "Security"
}

func getCWEFromRuleID(ruleID string) string {
	cweMap := map[string]string{
		"sql":      "CWE-89",
		"xss":      "CWE-79",
		"command":  "CWE-78",
		"path":     "CWE-22",
		"crypto":   "CWE-327",
		"auth":     "CWE-287",
		"deserial": "CWE-502",
		"xxe":      "CWE-611",
		"race":     "CWE-362",
	}
	
	for key, cwe := range cweMap {
		if strings.Contains(strings.ToLower(ruleID), key) {
			return cwe
		}
	}
	
	return ""
}