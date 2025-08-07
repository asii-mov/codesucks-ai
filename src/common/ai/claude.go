package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/asii-mov/codesucks-ai/common"
)

type ClaudeClient struct {
	APIKey     string
	Model      string
	HTTPClient *http.Client
}

// NewClaudeClient creates a new Claude AI client
func NewClaudeClient(apiKey string) *ClaudeClient {
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}

	return &ClaudeClient{
		APIKey: apiKey,
		Model:  common.DefaultModel,
		HTTPClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// AnalyzeVulnerability analyzes a semgrep finding and generates a security fix
func (c *ClaudeClient) AnalyzeVulnerability(finding common.Result, fileContent, filePath string) (*common.SecurityAnalysis, error) {
	if c.APIKey == "" {
		return nil, fmt.Errorf("Anthropic API key is required")
	}

	// Extract the vulnerable code lines
	lines := strings.Split(fileContent, "\n")
	startLine := finding.Start.Line - 1
	endLine := finding.End.Line - 1

	if startLine < 0 || endLine >= len(lines) {
		return nil, fmt.Errorf("invalid line range in file")
	}

	vulnerableCode := strings.Join(lines[startLine:endLine+1], "\n")

	// Get surrounding context (5 lines before and after)
	contextStart := max(0, startLine-5)
	contextEnd := min(len(lines)-1, endLine+5)
	contextCode := strings.Join(lines[contextStart:contextEnd+1], "\n")

	// Create the prompt for Claude
	prompt := fmt.Sprintf("You are a security expert analyzing and fixing code vulnerabilities.\n\n"+
		"**File:** %s\n"+
		"**Vulnerability:** %s\n"+
		"**Description:** %s\n"+
		"**Severity:** %s\n\n"+
		"**Vulnerable Code (lines %d-%d):**\n"+
		"```\n%s\n```\n\n"+
		"**Context (with surrounding lines):**\n"+
		"```\n%s\n```\n\n"+
		"Please provide:\n"+
		"1. A secure fix for this vulnerability\n"+
		"2. An explanation of why it's vulnerable and how the fix addresses it\n"+
		"3. A confidence level (0.0-1.0) for your fix\n\n"+
		"Respond in JSON format:\n"+
		"{\n"+
		`  "vulnerability": "vulnerability type",`+"\n"+
		`  "severity": "severity level",`+"\n"+
		`  "fix": "corrected code that replaces the vulnerable lines",`+"\n"+
		`  "explanation": "detailed explanation of the vulnerability and fix",`+"\n"+
		`  "confidence": 0.95`+"\n"+
		"}\n\n"+
		"Important: The \"fix\" should contain ONLY the corrected code that will replace lines %d-%d, with proper indentation preserved.",
		filePath,
		finding.CheckID,
		finding.Extra.Message,
		finding.Extra.Metadata.Impact,
		finding.Start.Line,
		finding.End.Line,
		vulnerableCode,
		contextCode,
		finding.Start.Line,
		finding.End.Line,
	)

	response, err := c.sendRequest(prompt)
	if err != nil {
		return nil, fmt.Errorf("failed to get AI response: %w", err)
	}

	// Parse the JSON response
	var analysis common.SecurityAnalysis
	err = json.Unmarshal([]byte(response), &analysis)
	if err != nil {
		// If JSON parsing fails, try to extract the fix manually
		return c.parseManualResponse(response, finding)
	}

	// Validate the confidence score
	if analysis.Confidence < 0.5 {
		return nil, fmt.Errorf("AI confidence too low: %.2f", analysis.Confidence)
	}

	return &analysis, nil
}

// GenerateConversationResponse generates a response to user comments in GitHub issues
func (c *ClaudeClient) GenerateConversationResponse(userComment string, fixes []common.SecurityFix) (string, error) {
	if c.APIKey == "" {
		return "", fmt.Errorf("Anthropic API key is required")
	}

	// Create context about the fixes
	var fixContext strings.Builder
	fixContext.WriteString("Security fixes applied:\n")
	for i, fix := range fixes {
		fixContext.WriteString(fmt.Sprintf("%d. %s in %s (lines %d-%d)\n   %s\n",
			i+1, fix.Vulnerability, fix.FilePath, fix.StartLine, fix.EndLine, fix.Description))
	}

	prompt := fmt.Sprintf(`You are an AI security assistant helping developers with automated security fixes. 

Context about the security fixes:
%s

User comment/question:
"%s"

Please provide a helpful, professional response that:
1. Addresses their specific question or concern
2. Provides technical details if requested
3. Suggests next steps if appropriate
4. Maintains a friendly, supportive tone

Keep the response concise but informative. If the user is asking about a specific fix, reference the file and vulnerability type.`,
		fixContext.String(), userComment)

	response, err := c.sendRequest(prompt)
	if err != nil {
		return "", fmt.Errorf("failed to generate conversation response: %w", err)
	}

	return response, nil
}

// sendRequest sends a request to Claude API
func (c *ClaudeClient) sendRequest(prompt string) (string, error) {
	reqBody := common.ClaudeRequest{
		Model:     c.Model,
		MaxTokens: common.MaxTokens,
		Messages: []common.Message{
			{
				Role:    "user",
				Content: prompt,
			},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", common.ClaudeAPIEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var claudeResp common.ClaudeResponse
	err = json.Unmarshal(body, &claudeResp)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if len(claudeResp.Content) == 0 {
		return "", fmt.Errorf("empty response from Claude API")
	}

	return claudeResp.Content[0].Text, nil
}

// parseManualResponse attempts to parse a non-JSON response manually
func (c *ClaudeClient) parseManualResponse(response string, finding common.Result) (*common.SecurityAnalysis, error) {
	return &common.SecurityAnalysis{
		Vulnerability: finding.CheckID,
		Severity:      finding.Extra.Metadata.Impact,
		Fix:           "// Manual parsing failed - please review the AI response",
		Explanation:   response,
		Confidence:    0.6, // Lower confidence for manual parsing
	}, nil
}

// ValidateSecurityFix performs basic validation on the generated fix
func (c *ClaudeClient) ValidateSecurityFix(original, fixed string) bool {
	// Basic validation checks
	if strings.TrimSpace(fixed) == "" {
		return false
	}

	if strings.TrimSpace(fixed) == strings.TrimSpace(original) {
		return false // No changes made
	}

	// Check if the fix looks like actual code (not just comments)
	lines := strings.Split(strings.TrimSpace(fixed), "\n")
	hasCode := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "#") {
			hasCode = true
			break
		}
	}

	return hasCode
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
