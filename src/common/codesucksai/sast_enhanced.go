package codesucksai

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/asii-mov/codesucks-ai/common"
)

// EnhancedSASTScanner implements a resilient SAST scanner with fallback chain
type EnhancedSASTScanner struct {
	options       *common.Options
	mcpScanner    *MCPSemgrepScanner
	cliScanner    *CLISemgrepScanner
	basicScanner  *BasicScanner
	fallbackChain []ScannerInterface
}

// ScannerInterface defines the interface for all scanners
type ScannerInterface interface {
	Scan(ctx context.Context, repoPath string) (*common.SemgrepResult, error)
	Name() string
	IsAvailable() bool
}

// CLISemgrepScanner wraps the traditional CLI semgrep
type CLISemgrepScanner struct {
	options     *common.Options
	semgrepPath string
}

// BasicScanner provides basic pattern matching when Semgrep is unavailable
type BasicScanner struct {
	options *common.Options
}

// NewEnhancedSASTScanner creates a new enhanced scanner with fallback chain
func NewEnhancedSASTScanner(options *common.Options) (*EnhancedSASTScanner, error) {
	scanner := &EnhancedSASTScanner{
		options:       options,
		fallbackChain: []ScannerInterface{},
	}

	// Try to initialize MCP scanner
	if options.UseMCPMode || os.Getenv("CODESUCKS_USE_MCP") == "true" {
		mcpScanner, err := NewMCPSemgrepScanner(options)
		if err == nil {
			scanner.mcpScanner = mcpScanner
			scanner.fallbackChain = append(scanner.fallbackChain, mcpScanner)
			fmt.Println("✅ MCP scanner initialized")
		} else {
			fmt.Printf("⚠️ MCP scanner unavailable: %v\n", err)
		}
	}

	// Initialize CLI scanner
	cliScanner := NewCLISemgrepScanner(options)
	if cliScanner.IsAvailable() {
		scanner.cliScanner = cliScanner
		scanner.fallbackChain = append(scanner.fallbackChain, cliScanner)
		fmt.Println("✅ CLI scanner initialized")
	} else {
		fmt.Println("⚠️ CLI scanner unavailable: semgrep not found")
	}

	// Always add basic scanner as last resort
	basicScanner := NewBasicScanner(options)
	scanner.basicScanner = basicScanner
	scanner.fallbackChain = append(scanner.fallbackChain, basicScanner)
	fmt.Println("✅ Basic scanner initialized (fallback)")

	if len(scanner.fallbackChain) == 0 {
		return nil, fmt.Errorf("no scanners available")
	}

	return scanner, nil
}

// Scan performs SAST analysis with automatic fallback
func (s *EnhancedSASTScanner) Scan(repoPath string) (*common.SemgrepResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var lastError error
	for _, scanner := range s.fallbackChain {
		if !scanner.IsAvailable() {
			continue
		}

		fmt.Printf("🔍 Attempting scan with %s...\n", scanner.Name())
		
		result, err := scanner.Scan(ctx, repoPath)
		if err != nil {
			fmt.Printf("⚠️ %s failed: %v\n", scanner.Name(), err)
			lastError = err
			continue
		}

		fmt.Printf("✅ Scan completed successfully with %s\n", scanner.Name())
		return result, nil
	}

	if lastError != nil {
		return nil, fmt.Errorf("all scanners failed, last error: %w", lastError)
	}
	return nil, fmt.Errorf("no available scanners")
}

// MCP Scanner implementation

func (m *MCPSemgrepScanner) Scan(ctx context.Context, repoPath string) (*common.SemgrepResult, error) {
	// Check MCP availability
	if err := m.client.Ping(ctx); err != nil {
		return nil, fmt.Errorf("MCP server not responding: %w", err)
	}

	return m.RunSemgrepMCP(repoPath)
}

func (m *MCPSemgrepScanner) Name() string {
	return "MCP Semgrep Scanner"
}

func (m *MCPSemgrepScanner) IsAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	return m.client.Ping(ctx) == nil
}

// CLI Scanner implementation

func NewCLISemgrepScanner(options *common.Options) *CLISemgrepScanner {
	semgrepPath := options.SemgrepPath
	if semgrepPath == "" {
		semgrepPath = "semgrep"
	}
	
	return &CLISemgrepScanner{
		options:     options,
		semgrepPath: semgrepPath,
	}
}

func (c *CLISemgrepScanner) Scan(ctx context.Context, repoPath string) (*common.SemgrepResult, error) {
	// Create output directory
	outDir := filepath.Join(c.options.OutDir, "cli-scan")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Run traditional semgrep
	semgrepJson, err := RunSemgrep(repoPath, outDir, c.semgrepPath, c.options.ConfigPath)
	if err != nil {
		return nil, err
	}

	// Convert to SemgrepResult
	return convertToSemgrepResult(semgrepJson), nil
}

func (c *CLISemgrepScanner) Name() string {
	return "CLI Semgrep Scanner"
}

func (c *CLISemgrepScanner) IsAvailable() bool {
	// Check if semgrep is in PATH
	_, err := os.Stat(c.semgrepPath)
	if err == nil {
		return true
	}
	
	// Try to find in PATH
	paths := strings.Split(os.Getenv("PATH"), string(os.PathListSeparator))
	for _, path := range paths {
		fullPath := filepath.Join(path, "semgrep")
		if _, err := os.Stat(fullPath); err == nil {
			c.semgrepPath = fullPath
			return true
		}
	}
	
	return false
}

// Basic Scanner implementation

func NewBasicScanner(options *common.Options) *BasicScanner {
	return &BasicScanner{
		options: options,
	}
}

func (b *BasicScanner) Scan(ctx context.Context, repoPath string) (*common.SemgrepResult, error) {
	fmt.Println("⚠️ Using basic pattern scanner (limited detection)")
	
	result := &common.SemgrepResult{
		Vulnerabilities: []common.Vulnerability{},
		Summary: common.SemgrepSummary{
			TotalFindings: 0,
			FilesScanned:  0,
		},
	}

	// Perform basic pattern matching for common vulnerabilities
	patterns := b.getBasicPatterns()
	
	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		
		if info.IsDir() || !b.isSourceFile(path) {
			return nil
		}
		
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		
		// Read file and check patterns
		content, err := os.ReadFile(path)
		if err != nil {
			return nil // Skip unreadable files
		}
		
		findings := b.checkPatterns(path, string(content), patterns)
		for _, finding := range findings {
			result.Vulnerabilities = append(result.Vulnerabilities, convertResultToVulnerability(finding))
		}
		result.Summary.FilesScanned++
		
		return nil
	})
	
	if err != nil {
		return nil, fmt.Errorf("basic scan failed: %w", err)
	}
	
	// Update summary
	result.Summary.TotalFindings = len(result.Vulnerabilities)
	
	return result, nil
}

func (b *BasicScanner) Name() string {
	return "Basic Pattern Scanner"
}

func (b *BasicScanner) IsAvailable() bool {
	return true // Always available as fallback
}

func (b *BasicScanner) isSourceFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	sourceExts := map[string]bool{
		".go": true, ".java": true, ".py": true, ".js": true,
		".ts": true, ".jsx": true, ".tsx": true, ".php": true,
		".rb": true, ".cs": true, ".cpp": true, ".c": true,
	}
	return sourceExts[ext]
}

func (b *BasicScanner) getBasicPatterns() map[string][]string {
	return map[string][]string{
		"sql-injection": {
			"SELECT.*FROM.*WHERE.*\\+",
			"\"SELECT.*\" \\+.*request\\.",
			"query\\(.*\\+.*request",
		},
		"command-injection": {
			"exec\\(.*request\\.",
			"system\\(.*\\$_GET",
			"eval\\(.*request\\.",
		},
		"hardcoded-secret": {
			"password\\s*=\\s*[\"'][^\"']+[\"']",
			"api[_-]?key\\s*=\\s*[\"'][^\"']+[\"']",
			"secret\\s*=\\s*[\"'][^\"']+[\"']",
		},
		"path-traversal": {
			"\\.\\.[\\/\\\\]",
			"open\\(.*request\\.",
			"readFile\\(.*\\+",
		},
	}
}

func (b *BasicScanner) checkPatterns(filePath, content string, patterns map[string][]string) []common.Result {
	var results []common.Result
	lines := strings.Split(content, "\n")
	
	for vulnType, patternList := range patterns {
		for _, pattern := range patternList {
			for lineNum, line := range lines {
				if strings.Contains(line, pattern) || b.matchesPattern(line, pattern) {
					results = append(results, common.Result{
						CheckID: fmt.Sprintf("basic-%s", vulnType),
						Path:    filePath,
						Start: struct {
							Line int `json:"line"`
							Col  int `json:"col"`
						}{
							Line: lineNum + 1,
							Col:  1,
						},
						End: struct {
							Line int `json:"line"`
							Col  int `json:"col"`
						}{
							Line: lineNum + 1,
							Col:  len(line),
						},
						Extra: struct {
							Message  string `json:"message"`
							Lines    string `json:"lines"`
							Metadata struct {
								Impact string `json:"impact"`
							} `json:"metadata"`
						}{
							Message: fmt.Sprintf("Potential %s vulnerability detected", vulnType),
							Lines:   line,
							Metadata: struct {
								Impact string `json:"impact"`
							}{
								Impact: "MEDIUM",
							},
						},
					})
				}
			}
		}
	}
	
	return results
}

func (b *BasicScanner) matchesPattern(line, pattern string) bool {
	// Simple pattern matching - can be enhanced with regex
	return strings.Contains(strings.ToLower(line), strings.ToLower(pattern))
}

// Helper function to convert SemgrepJson to SemgrepResult
func convertToSemgrepResult(json *common.SemgrepJson) *common.SemgrepResult {
	if json == nil {
		return &common.SemgrepResult{}
	}
	
	// Convert Results to Vulnerabilities
	var vulnerabilities []common.Vulnerability
	for _, result := range json.Results {
		vulnerabilities = append(vulnerabilities, convertResultToVulnerability(result))
	}
	
	return &common.SemgrepResult{
		Vulnerabilities: vulnerabilities,
		Summary: common.SemgrepSummary{
			TotalFindings: len(vulnerabilities),
			FilesScanned:  0, // Paths field not available in current SemgrepJson
		},
	}
}

// Helper function to convert Result to Vulnerability
func convertResultToVulnerability(result common.Result) common.Vulnerability {
	return common.Vulnerability{
		Type:        result.CheckID,
		Severity:    result.Extra.Metadata.Impact,
		File:        result.Path,
		Line:        result.Start.Line,
		Description: result.Extra.Message,
		Code:        result.Extra.Lines,
	}
}