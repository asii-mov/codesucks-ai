package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/asii-mov/codesucks-ai/common"
)

// SemgrepMCPClient wraps the MCP client for Semgrep-specific operations
type SemgrepMCPClient struct {
	client *Client
	config *SemgrepMCPConfig
}

// SemgrepMCPConfig represents Semgrep MCP configuration
type SemgrepMCPConfig struct {
	ServerURL       string
	Timeout         int // seconds
	EnableAST       bool
	EnableCustom    bool
	EnableRealTime  bool
	DefaultConfig   string
}

// SemgrepScanResult represents the result of a Semgrep scan via MCP
type SemgrepScanResult struct {
	Findings []SemgrepFinding `json:"findings"`
	Errors   []string         `json:"errors,omitempty"`
	Stats    ScanStats        `json:"stats"`
}

// SemgrepFinding represents a single Semgrep finding
type SemgrepFinding struct {
	RuleID      string         `json:"rule_id"`
	Path        string         `json:"path"`
	Message     string         `json:"message"`
	Severity    string         `json:"severity"`
	StartLine   int            `json:"start_line"`
	EndLine     int            `json:"end_line"`
	StartColumn int            `json:"start_column"`
	EndColumn   int            `json:"end_column"`
	Code        string         `json:"code"`
	Fix         string         `json:"fix,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ScanStats represents scan statistics
type ScanStats struct {
	FilesScanned   int    `json:"files_scanned"`
	RulesRun       int    `json:"rules_run"`
	FindingsCount  int    `json:"findings_count"`
	Duration       string `json:"duration"`
}

// ASTResult represents an Abstract Syntax Tree result
type ASTResult struct {
	Language string                 `json:"language"`
	AST      map[string]interface{} `json:"ast"`
}

// NewSemgrepMCPClient creates a new Semgrep MCP client
func NewSemgrepMCPClient(config *SemgrepMCPConfig) (*SemgrepMCPClient, error) {
	if config == nil {
		config = &SemgrepMCPConfig{
			ServerURL:     "http://localhost:3000",
			Timeout:       30,
			DefaultConfig: "auto",
		}
	}
	
	clientConfig := ClientConfig{
		ServerURL: config.ServerURL,
		Timeout:   timeDuration(config.Timeout),
	}
	
	client, err := NewClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create MCP client: %w", err)
	}
	
	// Verify Semgrep tools are available
	if err := verifySemgrepTools(client); err != nil {
		return nil, fmt.Errorf("Semgrep tools not available: %w", err)
	}
	
	return &SemgrepMCPClient{
		client: client,
		config: config,
	}, nil
}

// verifySemgrepTools checks if required Semgrep tools are available
func verifySemgrepTools(client *Client) error {
	requiredTools := []string{
		"security_check",
		"semgrep_scan",
	}
	
	tools := client.ListTools()
	toolMap := make(map[string]bool)
	for _, tool := range tools {
		toolMap[tool.Name] = true
	}
	
	for _, required := range requiredTools {
		if !toolMap[required] {
			return fmt.Errorf("required tool %s not found", required)
		}
	}
	
	return nil
}

// SecurityCheck performs a security check on code
func (s *SemgrepMCPClient) SecurityCheck(ctx context.Context, code string) (*SemgrepScanResult, error) {
	result, err := s.client.CallTool(ctx, "security_check", map[string]interface{}{
		"code": code,
	})
	
	if err != nil {
		return nil, fmt.Errorf("security check failed: %w", err)
	}
	
	return parseScanResult(result)
}

// ScanFile scans a file with Semgrep
func (s *SemgrepMCPClient) ScanFile(ctx context.Context, filePath string) (*SemgrepScanResult, error) {
	return s.ScanWithConfig(ctx, filePath, s.config.DefaultConfig)
}

// ScanWithConfig scans with a specific Semgrep configuration
func (s *SemgrepMCPClient) ScanWithConfig(ctx context.Context, path, config string) (*SemgrepScanResult, error) {
	result, err := s.client.CallTool(ctx, "semgrep_scan", map[string]interface{}{
		"path":   path,
		"config": config,
	})
	
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}
	
	return parseScanResult(result)
}

// ScanWithCustomRule scans using a custom Semgrep rule
func (s *SemgrepMCPClient) ScanWithCustomRule(ctx context.Context, path, rule string) (*SemgrepScanResult, error) {
	if !s.config.EnableCustom {
		return nil, fmt.Errorf("custom rules are disabled")
	}
	
	result, err := s.client.CallTool(ctx, "semgrep_scan_with_custom_rule", map[string]interface{}{
		"path": path,
		"rule": rule,
	})
	
	if err != nil {
		return nil, fmt.Errorf("custom rule scan failed: %w", err)
	}
	
	return parseScanResult(result)
}

// GetAST gets the Abstract Syntax Tree of code
func (s *SemgrepMCPClient) GetAST(ctx context.Context, code string) (*ASTResult, error) {
	if !s.config.EnableAST {
		return nil, fmt.Errorf("AST analysis is disabled")
	}
	
	result, err := s.client.CallTool(ctx, "get_abstract_syntax_tree", map[string]interface{}{
		"code": code,
	})
	
	if err != nil {
		return nil, fmt.Errorf("AST analysis failed: %w", err)
	}
	
	return parseASTResult(result)
}

// ScanDirectory scans an entire directory
func (s *SemgrepMCPClient) ScanDirectory(ctx context.Context, dir string) (*SemgrepScanResult, error) {
	pattern := filepath.Join(dir, "**")
	return s.ScanWithConfig(ctx, pattern, s.config.DefaultConfig)
}

// ConvertToCommonFormat converts MCP findings to common vulnerability format
func (s *SemgrepMCPClient) ConvertToCommonFormat(findings []SemgrepFinding) []common.Vulnerability {
	vulnerabilities := make([]common.Vulnerability, 0, len(findings))
	
	for _, finding := range findings {
		vuln := common.Vulnerability{
			Type:        finding.RuleID,
			Severity:    normalizeSeverity(finding.Severity),
			Description: finding.Message,
			File:        finding.Path,
			Line:        finding.StartLine,
			Code:        finding.Code,
			Confidence:  0.9, // Default high confidence for Semgrep
		}
		
		// Extract CWE if available
		if cwe, ok := finding.Metadata["cwe"].(string); ok {
			vuln.CWE = cwe
		}
		
		// Extract OWASP if available
		if owasp, ok := finding.Metadata["owasp"].(string); ok {
			vuln.OWASP = owasp
		}
		
		vulnerabilities = append(vulnerabilities, vuln)
	}
	
	return vulnerabilities
}

// parseScanResult parses the tool result into SemgrepScanResult
func parseScanResult(result *ToolResult) (*SemgrepScanResult, error) {
	if result.IsError {
		return nil, fmt.Errorf("scan error: %v", result.Content)
	}
	
	data, err := json.Marshal(result.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %w", err)
	}
	
	var scanResult SemgrepScanResult
	if err := json.Unmarshal(data, &scanResult); err != nil {
		return nil, fmt.Errorf("failed to parse scan result: %w", err)
	}
	
	return &scanResult, nil
}

// parseASTResult parses the tool result into ASTResult
func parseASTResult(result *ToolResult) (*ASTResult, error) {
	if result.IsError {
		return nil, fmt.Errorf("AST error: %v", result.Content)
	}
	
	data, err := json.Marshal(result.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %w", err)
	}
	
	var astResult ASTResult
	if err := json.Unmarshal(data, &astResult); err != nil {
		return nil, fmt.Errorf("failed to parse AST result: %w", err)
	}
	
	return &astResult, nil
}

// normalizeSeverity normalizes severity levels
func normalizeSeverity(severity string) string {
	switch severity {
	case "ERROR", "CRITICAL":
		return "CRITICAL"
	case "WARNING", "HIGH":
		return "HIGH"
	case "INFO", "MEDIUM":
		return "MEDIUM"
	case "NOTE", "LOW":
		return "LOW"
	default:
		return "MEDIUM"
	}
}

// timeDuration converts seconds to time.Duration
func timeDuration(seconds int) time.Duration {
	return time.Duration(seconds) * time.Second
}

// Close closes the Semgrep MCP client
func (s *SemgrepMCPClient) Close() error {
	return s.client.Close()
}

// Ping checks if the Semgrep MCP server is responsive
func (s *SemgrepMCPClient) Ping(ctx context.Context) error {
	return s.client.Ping(ctx)
}