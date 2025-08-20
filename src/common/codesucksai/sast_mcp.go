package codesucksai

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/asii-mov/codesucks-ai/common"
	"github.com/asii-mov/codesucks-ai/common/mcp"
)

// MCPSemgrepScanner implements Semgrep scanning via MCP
type MCPSemgrepScanner struct {
	client  *mcp.SemgrepMCPClient
	options *common.Options
	config  *mcp.SemgrepMCPConfig
}

// NewMCPSemgrepScanner creates a new MCP-based Semgrep scanner
func NewMCPSemgrepScanner(options *common.Options) (*MCPSemgrepScanner, error) {
	// Get MCP server URL from environment or options
	serverURL := os.Getenv("SEMGREP_MCP_SERVER")
	if serverURL == "" {
		serverURL = "http://localhost:3000"
	}

	// Create MCP configuration
	config := &mcp.SemgrepMCPConfig{
		ServerURL:      serverURL,
		Timeout:        30,
		EnableAST:      options.EnableAST,
		EnableCustom:   options.EnableCustomRules,
		EnableRealTime: false,
		DefaultConfig:  options.ConfigPath,
	}

	// Create MCP client
	client, err := mcp.NewSemgrepMCPClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create MCP client: %w", err)
	}

	return &MCPSemgrepScanner{
		client:  client,
		options: options,
		config:  config,
	}, nil
}

// RunSemgrepMCP runs Semgrep analysis using MCP
func (s *MCPSemgrepScanner) RunSemgrepMCP(repoPath string) (*common.SemgrepResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.config.Timeout)*time.Second)
	defer cancel()

	// Check if MCP server is available
	if err := s.client.Ping(ctx); err != nil {
		return nil, fmt.Errorf("MCP server not available: %w", err)
	}

	// Determine scan target
	scanPath := repoPath
	if s.options.TargetPath != "" {
		scanPath = filepath.Join(repoPath, s.options.TargetPath)
	}

	// Get config to use
	config := s.determineConfig()

	// Perform scan
	fmt.Printf("🔍 Running Semgrep scan via MCP (config: %s)...\n", config)

	scanResult, err := s.client.ScanWithConfig(ctx, scanPath, config)
	if err != nil {
		return nil, fmt.Errorf("MCP scan failed: %w", err)
	}

	// Convert to common format
	result := s.convertToCommonResult(scanResult)

	// Apply filters if needed
	if s.options.MinSeverity != "" {
		result = s.filterBySeverity(result, s.options.MinSeverity)
	}

	// Print summary
	s.printSummary(result)

	return result, nil
}

// determineConfig determines which Semgrep config to use
func (s *MCPSemgrepScanner) determineConfig() string {
	config := s.options.ConfigPath

	// Check if it's a preset
	presets := map[string]string{
		"basic":            "p/default",
		"comprehensive":    "p/security-audit p/secrets p/owasp-top-ten",
		"security-focused": "p/security-audit p/owasp-top-ten p/cwe-top-25",
	}

	if preset, ok := presets[config]; ok {
		return preset
	}

	// Check if it's a file path
	if strings.HasSuffix(config, ".yaml") || strings.HasSuffix(config, ".yml") {
		if _, err := os.Stat(config); err == nil {
			return config
		}
	}

	// Default to auto
	return "auto"
}

// convertToCommonResult converts MCP scan result to common format
func (s *MCPSemgrepScanner) convertToCommonResult(scanResult *mcp.SemgrepScanResult) *common.SemgrepResult {
	result := &common.SemgrepResult{
		Vulnerabilities: make([]common.Vulnerability, 0),
		Summary: common.SemgrepSummary{
			TotalFindings: len(scanResult.Findings),
			FilesScanned:  scanResult.Stats.FilesScanned,
			RulesRun:      scanResult.Stats.RulesRun,
			Duration:      scanResult.Stats.Duration,
		},
	}

	// Count by severity
	severityCount := make(map[string]int)

	for _, finding := range scanResult.Findings {
		vuln := common.Vulnerability{
			Type:        finding.RuleID,
			Severity:    finding.Severity,
			Description: finding.Message,
			File:        finding.Path,
			Line:        finding.StartLine,
			Code:        finding.Code,
			Confidence:  0.9,
		}

		// Add metadata
		if cwe, ok := finding.Metadata["cwe"].(string); ok {
			vuln.CWE = cwe
		}
		if owasp, ok := finding.Metadata["owasp"].(string); ok {
			vuln.OWASP = owasp
		}

		result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		severityCount[finding.Severity]++
	}

	// Update severity counts
	result.Summary.CriticalCount = severityCount["CRITICAL"]
	result.Summary.HighCount = severityCount["HIGH"]
	result.Summary.MediumCount = severityCount["MEDIUM"]
	result.Summary.LowCount = severityCount["LOW"]

	return result
}

// filterBySeverity filters vulnerabilities by minimum severity
func (s *MCPSemgrepScanner) filterBySeverity(result *common.SemgrepResult, minSeverity string) *common.SemgrepResult {
	severityOrder := map[string]int{
		"CRITICAL": 4,
		"HIGH":     3,
		"MEDIUM":   2,
		"LOW":      1,
	}

	minLevel := severityOrder[strings.ToUpper(minSeverity)]
	if minLevel == 0 {
		return result
	}

	filtered := &common.SemgrepResult{
		Summary:         result.Summary,
		Vulnerabilities: make([]common.Vulnerability, 0),
	}

	for _, vuln := range result.Vulnerabilities {
		if severityOrder[vuln.Severity] >= minLevel {
			filtered.Vulnerabilities = append(filtered.Vulnerabilities, vuln)
		}
	}

	filtered.Summary.TotalFindings = len(filtered.Vulnerabilities)
	return filtered
}

// printSummary prints scan summary
func (s *MCPSemgrepScanner) printSummary(result *common.SemgrepResult) {
	fmt.Printf("\n📊 Semgrep MCP Scan Summary:\n")
	fmt.Printf("   Files scanned: %d\n", result.Summary.FilesScanned)
	fmt.Printf("   Rules run: %d\n", result.Summary.RulesRun)
	fmt.Printf("   Total findings: %d\n", result.Summary.TotalFindings)

	if result.Summary.TotalFindings > 0 {
		fmt.Printf("   Severity breakdown:\n")
		if result.Summary.CriticalCount > 0 {
			fmt.Printf("     🔴 Critical: %d\n", result.Summary.CriticalCount)
		}
		if result.Summary.HighCount > 0 {
			fmt.Printf("     🟠 High: %d\n", result.Summary.HighCount)
		}
		if result.Summary.MediumCount > 0 {
			fmt.Printf("     🟡 Medium: %d\n", result.Summary.MediumCount)
		}
		if result.Summary.LowCount > 0 {
			fmt.Printf("     🟢 Low: %d\n", result.Summary.LowCount)
		}
	}

	fmt.Printf("   Duration: %s\n", result.Summary.Duration)
}

// RunWithFallback runs MCP scan with fallback to CLI mode
func RunSemgrepWithFallback(repoPath string, options *common.Options) (*common.SemgrepResult, error) {
	// Check if MCP mode is enabled
	if options.UseMCPMode {
		// Try MCP mode first
		scanner, err := NewMCPSemgrepScanner(options)
		if err == nil {
			result, err := scanner.RunSemgrepMCP(repoPath)
			if err == nil {
				return result, nil
			}
			// Log MCP failure but continue with fallback
			fmt.Printf("⚠️  MCP mode failed: %v\n", err)
			fmt.Printf("🔄 Falling back to CLI mode...\n")
		}
	}

	// Fallback to CLI mode - call with proper arguments
	semgrepJSON, err := RunSemgrep(repoPath, options.OutDir, options.SemgrepPath, options.ConfigPath)
	if err != nil {
		return nil, err
	}

	// Convert SemgrepJson to SemgrepResult
	return convertSemgrepJSONToResult(semgrepJSON), nil
}

// convertSemgrepJSONToResult converts the legacy SemgrepJson to new SemgrepResult format
func convertSemgrepJSONToResult(json *common.SemgrepJson) *common.SemgrepResult {
	if json == nil {
		return &common.SemgrepResult{}
	}

	result := &common.SemgrepResult{
		Vulnerabilities: make([]common.Vulnerability, 0),
		Summary: common.SemgrepSummary{
			TotalFindings: len(json.Results),
		},
	}

	// Count by severity
	severityCount := make(map[string]int)

	for _, r := range json.Results {
		// Determine severity from impact or default to MEDIUM
		severity := "MEDIUM"
		if r.Extra.Metadata.Impact != "" {
			switch strings.ToUpper(r.Extra.Metadata.Impact) {
			case "CRITICAL", "HIGH", "MEDIUM", "LOW":
				severity = strings.ToUpper(r.Extra.Metadata.Impact)
			}
		}

		vuln := common.Vulnerability{
			Type:        r.CheckID,
			Severity:    severity,
			Description: r.Extra.Message,
			File:        r.Path,
			Line:        r.Start.Line,
			Code:        extractCode(r.Extra.Lines),
			Confidence:  0.9,
		}

		result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		severityCount[severity]++
	}

	// Update summary counts
	result.Summary.CriticalCount = severityCount["CRITICAL"]
	result.Summary.HighCount = severityCount["HIGH"]
	result.Summary.MediumCount = severityCount["MEDIUM"]
	result.Summary.LowCount = severityCount["LOW"]

	return result
}

// extractCode extracts code snippet from lines
func extractCode(lines string) string {
	// Return first non-empty line as code sample
	for _, line := range strings.Split(lines, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

// GetASTAnalysis performs AST analysis on code
func (s *MCPSemgrepScanner) GetASTAnalysis(ctx context.Context, code string) (*mcp.ASTResult, error) {
	if !s.config.EnableAST {
		return nil, fmt.Errorf("AST analysis is not enabled")
	}

	return s.client.GetAST(ctx, code)
}

// ScanWithCustomRule scans with a custom Semgrep rule
func (s *MCPSemgrepScanner) ScanWithCustomRule(ctx context.Context, path, rule string) (*common.SemgrepResult, error) {
	if !s.config.EnableCustom {
		return nil, fmt.Errorf("custom rules are not enabled")
	}

	scanResult, err := s.client.ScanWithCustomRule(ctx, path, rule)
	if err != nil {
		return nil, err
	}

	return s.convertToCommonResult(scanResult), nil
}

// Close closes the MCP scanner
func (s *MCPSemgrepScanner) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}
