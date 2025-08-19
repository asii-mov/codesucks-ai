package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/asii-mov/codesucks-ai/common"
	"github.com/google/uuid"
)

// ClaudeSDKClient wraps the Claude Code SDK for agent management
type ClaudeSDKClient struct {
	SessionDir   string
	AgentsDir    string
	APIKey       string
	LogLevel     string
	activeAgents map[string]*AgentProcess
	mu           sync.RWMutex
}

// AgentProcess represents a running Claude Code sub-agent
type AgentProcess struct {
	ID          string
	Type        string
	SessionPath string
	StateFile   string
	Process     *exec.Cmd
	Status      string
	StartTime   time.Time
	Files       []string
	Results     []common.ValidatedResult
}

// AgentConfig represents the configuration for a Claude Code sub-agent
type AgentConfig struct {
	Name         string   `yaml:"name"`
	Description  string   `yaml:"description"`
	Tools        []string `yaml:"tools"`
	SystemPrompt string   `yaml:"system_prompt"`
	MaxTokens    int      `yaml:"max_tokens,omitempty"`
	Model        string   `yaml:"model,omitempty"`
}

// NewClaudeSDKClient creates a new Claude Code SDK client wrapper
func NewClaudeSDKClient(sessionDir, agentsDir string) (*ClaudeSDKClient, error) {
	// Ensure directories exist
	if err := os.MkdirAll(sessionDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create session directory: %w", err)
	}
	if err := os.MkdirAll(agentsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create agents directory: %w", err)
	}

	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY environment variable is required")
	}

	logLevel := os.Getenv("CLAUDE_CODE_LOG_LEVEL")
	if logLevel == "" {
		logLevel = "INFO"
	}

	return &ClaudeSDKClient{
		SessionDir:   sessionDir,
		AgentsDir:    agentsDir,
		APIKey:       apiKey,
		LogLevel:     logLevel,
		activeAgents: make(map[string]*AgentProcess),
	}, nil
}

// CreateAgentSession initializes a new session for a security analysis agent
func (c *ClaudeSDKClient) CreateAgentSession(agentType, analysisID string, files []string) (*AgentProcess, error) {
	agentID := fmt.Sprintf("agent_%s_%s", agentType, uuid.New().String()[:8])
	return c.CreateAgentSessionWithID(agentID, agentType, analysisID, files)
}

// CreateAgentSessionWithID initializes a new session with a predefined agent ID
func (c *ClaudeSDKClient) CreateAgentSessionWithID(agentID, agentType, analysisID string, files []string) (*AgentProcess, error) {
	sessionPath := filepath.Join(c.SessionDir, agentID)
	stateFile := filepath.Join(sessionPath, "state.json")

	// Create session directory
	if err := os.MkdirAll(sessionPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create agent session directory: %w", err)
	}

	// Initialize agent state
	agentState := common.AgentState{
		AgentID:    agentID,
		AgentType:  agentType,
		AnalysisID: analysisID,
		Status:     "pending",
		Files:      files,
		StartTime:  time.Now(),
		Progress:   0,
		Results:    []common.SecurityFinding{},
	}

	stateData, err := json.MarshalIndent(agentState, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal agent state: %w", err)
	}

	if err := os.WriteFile(stateFile, stateData, 0644); err != nil {
		return nil, fmt.Errorf("failed to write agent state file: %w", err)
	}

	agent := &AgentProcess{
		ID:          agentID,
		Type:        agentType,
		SessionPath: sessionPath,
		StateFile:   stateFile,
		Status:      "pending",
		StartTime:   time.Now(),
		Files:       files,
	}

	c.mu.Lock()
	c.activeAgents[agentID] = agent
	c.mu.Unlock()

	return agent, nil
}

// SpawnAgent starts a Claude Code sub-agent process for security analysis
func (c *ClaudeSDKClient) SpawnAgent(agent *AgentProcess, codebaseContext *common.RepositoryContext) error {
	agentConfigPath := filepath.Join(c.AgentsDir, fmt.Sprintf("%s.md", agent.Type))

	// Check if agent configuration exists
	if _, err := os.Stat(agentConfigPath); os.IsNotExist(err) {
		// Create default agent configuration
		if err := c.createDefaultAgentConfig(agent.Type, agentConfigPath); err != nil {
			return fmt.Errorf("failed to create agent config: %w", err)
		}
	}

	// Prepare the analysis prompt
	prompt := c.buildAnalysisPrompt(agent, codebaseContext)

	// Read agent configuration to append as system prompt
	agentConfig, err := os.ReadFile(agentConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read agent config: %w", err)
	}

	// Create the claude command with headless automation flags
	args := []string{
		"-p", prompt, // Print mode with prompt as first argument
		"--output-format", "json",
		"--append-system-prompt", string(agentConfig),
		"--add-dir", codebaseContext.SourcePath, // Allow access to source code directory
	}

	if c.LogLevel == "DEBUG" {
		args = append(args, "--verbose")
	}

	cmd := exec.Command("claude", args...)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("ANTHROPIC_API_KEY=%s", c.APIKey),
	)

	// Set working directory to the source code path
	if codebaseContext != nil && codebaseContext.SourcePath != "" {
		cmd.Dir = codebaseContext.SourcePath
	}

	// Capture stdout and stderr
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute agent command: %w", err)
	}

	// Save the Claude CLI output to results file
	resultsFile := filepath.Join(agent.SessionPath, "results.json")
	if err := os.WriteFile(resultsFile, output, 0644); err != nil {
		return fmt.Errorf("failed to save agent results: %w", err)
	}

	agent.Status = "completed"

	// Update agent state
	if err := c.updateAgentState(agent.ID, map[string]interface{}{
		"status":       "completed",
		"completed_at": time.Now(),
	}); err != nil {
		return fmt.Errorf("failed to update agent state: %w", err)
	}

	return nil
}

// buildAnalysisPrompt creates the analysis prompt for the security agent
func (c *ClaudeSDKClient) buildAnalysisPrompt(agent *AgentProcess, context *common.RepositoryContext) string {
	var prompt strings.Builder

	prompt.WriteString(fmt.Sprintf("# Security Analysis Task for %s\n\n", agent.Type))
	prompt.WriteString(fmt.Sprintf("Agent ID: %s\n", agent.ID))
	prompt.WriteString(fmt.Sprintf("Analysis Focus: %s\n\n", getAgentFocus(agent.Type)))

	// Add codebase context
	if context != nil {
		prompt.WriteString("## Codebase Context\n")
		prompt.WriteString(fmt.Sprintf("Primary Language: %s\n", context.ProjectStructure.Language))
		prompt.WriteString(fmt.Sprintf("Framework: %s\n", context.TechnologyStack.Framework))
		if len(context.TechnologyStack.SecurityLibraries) > 0 {
			prompt.WriteString(fmt.Sprintf("Security Libraries: %s\n", strings.Join(context.TechnologyStack.SecurityLibraries, ", ")))
		}
		prompt.WriteString("\n")

		// Add source code location
		prompt.WriteString("## Source Code Location\n")
		prompt.WriteString(fmt.Sprintf("Code Path: %s\n", context.SourcePath))
		prompt.WriteString("You have access to the repository source code at the path provided above.\n")
		prompt.WriteString("Use file reading tools to examine the code for security vulnerabilities.\n")
		prompt.WriteString("Focus on files relevant to your specialization.\n\n")
	}

	// Add file list
	prompt.WriteString("## Files to Analyze\n")
	for _, file := range agent.Files {
		prompt.WriteString(fmt.Sprintf("- %s\n", file))
	}
	prompt.WriteString("\n")

	// Add specific analysis instructions
	prompt.WriteString("## Analysis Instructions\n")
	prompt.WriteString(getAgentInstructions(agent.Type))
	prompt.WriteString("\n")

	// Add output format requirements
	prompt.WriteString("## Output Format\n")
	prompt.WriteString("Please provide results in JSON format with the following structure:\n")
	prompt.WriteString("```json\n")
	prompt.WriteString(`{
  "agent_id": "` + agent.ID + `",
  "analysis_type": "` + agent.Type + `",
  "files_analyzed": [],
  "vulnerabilities": [
    {
      "type": "vulnerability_type",
      "file": "file_path",
      "line_start": 0,
      "line_end": 0,
      "severity": "HIGH|MEDIUM|LOW",
      "confidence": 0.95,
      "description": "detailed description",
      "vulnerable_code": "code snippet",
      "exploit_example": "how to exploit",
      "secure_fix": "corrected code",
      "fix_explanation": "why this fix works"
    }
  ],
  "patterns": [
    {
      "pattern": "systemic issue description",
      "instances": ["file1:line", "file2:line"],
      "recommendation": "how to fix systematically"
    }
  ]
}`)
	prompt.WriteString("\n```\n")

	return prompt.String()
}

// MonitorAgent checks the status and progress of a running agent
func (c *ClaudeSDKClient) MonitorAgent(agentID string) (*common.AgentStatus, error) {
	c.mu.RLock()
	agent, exists := c.activeAgents[agentID]
	c.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("agent %s not found", agentID)
	}

	// Read current state from file
	stateData, err := os.ReadFile(agent.StateFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read agent state: %w", err)
	}

	var state common.AgentState
	if err := json.Unmarshal(stateData, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal agent state: %w", err)
	}

	// Check process status
	processStatus := "unknown"
	if agent.Process != nil {
		if agent.Process.ProcessState == nil {
			processStatus = "running"
		} else if agent.Process.ProcessState.Exited() {
			processStatus = "completed"
			if !agent.Process.ProcessState.Success() {
				processStatus = "failed"
			}
		}
	}

	status := &common.AgentStatus{
		AgentID:         agentID,
		Type:            agent.Type,
		Status:          processStatus,
		Progress:        state.Progress,
		FilesAnalyzed:   len(state.FilesProcessed),
		TotalFiles:      len(agent.Files),
		Vulnerabilities: len(state.Results),
		StartTime:       agent.StartTime,
		LastUpdate:      state.LastUpdate,
	}

	return status, nil
}

// CollectResults gathers the analysis results from a completed agent
func (c *ClaudeSDKClient) CollectResults(agentID string) (*common.AgentResults, error) {
	c.mu.RLock()
	agent, exists := c.activeAgents[agentID]
	c.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("agent %s not found", agentID)
	}

	resultsFile := filepath.Join(agent.SessionPath, "results.json")

	// Check if results file exists
	if _, err := os.Stat(resultsFile); os.IsNotExist(err) {
		return &common.AgentResults{
			AgentID:         agentID,
			Type:            agent.Type,
			Status:          "no_results",
			Vulnerabilities: []common.SecurityFinding{},
		}, nil
	}

	// Read results
	resultsData, err := os.ReadFile(resultsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read results file: %w", err)
	}

	// First try to parse as Claude CLI response format
	var claudeResponse struct {
		Type     string `json:"type"`
		Content  string `json:"content,omitempty"`
		Messages []struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"messages,omitempty"`
	}

	var actualContent string
	if err := json.Unmarshal(resultsData, &claudeResponse); err == nil {
		// Extract actual content from Claude CLI response
		if claudeResponse.Content != "" {
			actualContent = claudeResponse.Content
		} else if len(claudeResponse.Messages) > 0 && len(claudeResponse.Messages[0].Content) > 0 {
			actualContent = claudeResponse.Messages[0].Content[0].Text
		} else {
			// Fallback to raw data as string
			actualContent = string(resultsData)
		}
	} else {
		// If not Claude CLI format, use raw data
		actualContent = string(resultsData)
	}

	// Try to extract JSON from the content (Claude often puts JSON in code blocks)
	jsonStart := strings.Index(actualContent, "{")
	jsonEnd := strings.LastIndex(actualContent, "}")

	var results common.AgentResults
	if jsonStart >= 0 && jsonEnd > jsonStart {
		jsonContent := actualContent[jsonStart : jsonEnd+1]
		if err := json.Unmarshal([]byte(jsonContent), &results); err != nil {
			// If JSON parsing fails, create results from text analysis
			results = common.AgentResults{
				AgentID:         agentID,
				Type:            agent.Type,
				Status:          "completed",
				Vulnerabilities: []common.SecurityFinding{},
				// Note: Claude provided analysis but not in expected JSON format
			}
		}
	} else {
		// No JSON found, create empty results
		results = common.AgentResults{
			AgentID:         agentID,
			Type:            agent.Type,
			Status:          "completed",
			Vulnerabilities: []common.SecurityFinding{},
		}
	}

	return &results, nil
}

// TerminateAgent stops a running agent process
func (c *ClaudeSDKClient) TerminateAgent(agentID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	agent, exists := c.activeAgents[agentID]
	if !exists {
		return fmt.Errorf("agent %s not found", agentID)
	}

	if agent.Process != nil && agent.Process.ProcessState == nil {
		if err := agent.Process.Process.Kill(); err != nil {
			return fmt.Errorf("failed to kill agent process: %w", err)
		}
	}

	agent.Status = "terminated"

	// Update state file
	return c.updateAgentState(agentID, map[string]interface{}{
		"status":        "terminated",
		"terminated_at": time.Now(),
	})
}

// updateAgentState updates the agent's state file
func (c *ClaudeSDKClient) updateAgentState(agentID string, updates map[string]interface{}) error {
	agent, exists := c.activeAgents[agentID]
	if !exists {
		return fmt.Errorf("agent %s not found", agentID)
	}

	// Read current state
	stateData, err := os.ReadFile(agent.StateFile)
	if err != nil {
		return fmt.Errorf("failed to read agent state: %w", err)
	}

	var state map[string]interface{}
	if err := json.Unmarshal(stateData, &state); err != nil {
		return fmt.Errorf("failed to unmarshal agent state: %w", err)
	}

	// Apply updates
	for key, value := range updates {
		state[key] = value
	}
	state["last_update"] = time.Now()

	// Write back to file
	updatedData, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal updated state: %w", err)
	}

	return os.WriteFile(agent.StateFile, updatedData, 0644)
}

// Helper functions for agent configuration

func getAgentFocus(agentType string) string {
	focusMap := map[string]string{
		"code-injection-analyser": "SQL, NoSQL, LDAP, OS Command, Expression Language injection",
		"code-xss-analyser":       "Reflected, Stored, and DOM-based XSS",
		"code-path-analyser":      "Path traversal and file inclusion vulnerabilities",
		"code-crypto-analyser":    "Cryptographic implementation flaws",
		"code-auth-analyser":      "Authentication and authorization flaws",
		"code-deserial-analyser":  "Insecure deserialization vulnerabilities",
		"code-xxe-analyser":       "XML external entity (XXE) vulnerabilities",
		"code-race-analyser":      "Race conditions and concurrency vulnerabilities",
	}

	if focus, exists := focusMap[agentType]; exists {
		return focus
	}
	return "General security analysis"
}

func getAgentInstructions(agentType string) string {
	instructionsMap := map[string]string{
		"code-injection-analyser": `
1. Find all database query construction and command execution functions
2. Trace user input to these dangerous sinks
3. Check for parameterization, prepared statements, and input validation
4. Look for string concatenation in SQL queries and shell commands
5. Identify dynamic query building patterns
6. Check for eval() and similar code execution functions`,

		"code-xss-analyser": `
1. Find HTML/JavaScript output points and template rendering
2. Trace user input to output without proper encoding
3. Identify unsafe DOM manipulation (innerHTML, document.write)
4. Check for unescaped template variables
5. Look for JSON embedding in HTML without proper escaping
6. Analyze client-side JavaScript for DOM-based XSS`,

		"code-crypto-analyser": `
1. Identify cryptographic function usage and implementations
2. Check for weak algorithms (MD5, SHA1 for passwords, DES, RC4)
3. Verify proper randomness sources and entropy
4. Analyze key management and storage practices
5. Look for hardcoded keys, salts, and initialization vectors
6. Check for proper encryption modes (avoid ECB)`,

		"code-auth-analyser": `
1. Map authentication flows and session management
2. Check authorization on all protected endpoints
3. Verify session generation and validation logic
4. Analyze password policies and storage mechanisms
5. Look for privilege escalation opportunities
6. Check for missing authentication on sensitive operations`,
	}

	if instructions, exists := instructionsMap[agentType]; exists {
		return instructions
	}
	return "Perform comprehensive security analysis on the assigned files."
}

// createDefaultAgentConfig creates a default configuration for an agent type
func (c *ClaudeSDKClient) createDefaultAgentConfig(agentType, configPath string) error {
	config := fmt.Sprintf(`---
name: %s
description: %s
tools: Read, Edit, Bash, Glob, Grep, LS, Task, Write
---

You are a specialized security analysis agent focused on %s.

Your role is to:
1. Analyze the assigned source code files for security vulnerabilities
2. Trace data flow from input sources to dangerous operations
3. Identify exploitable conditions and attack vectors
4. Provide concrete exploit examples and secure code fixes
5. Report findings in the specified JSON format

Focus on practical, exploitable vulnerabilities with high confidence.
Always provide working secure code alternatives with explanations.
`, agentType, getAgentFocus(agentType), getAgentFocus(agentType))

	return os.WriteFile(configPath, []byte(config), 0644)
}
