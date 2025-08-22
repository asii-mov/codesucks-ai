package orchestrator

import (
	"os"
	"testing"
	"time"

	"github.com/asii-mov/codesucks-ai/common"
)

// setupTestEnvironment sets up a clean test environment with fake API key
func setupTestEnvironment(t *testing.T) func() {
	// Save original environment
	originalKey := os.Getenv("ANTHROPIC_API_KEY")
	
	// Set fake API key for testing
	os.Setenv("ANTHROPIC_API_KEY", "sk-ant-test-fake-key-for-unit-tests-only")
	
	// Return cleanup function
	return func() {
		if originalKey != "" {
			os.Setenv("ANTHROPIC_API_KEY", originalKey)
		} else {
			os.Unsetenv("ANTHROPIC_API_KEY")
		}
	}
}

func TestNewSecurityOrchestrator(t *testing.T) {
	// Set required environment variable for test
	originalKey := os.Getenv("ANTHROPIC_API_KEY")
	os.Setenv("ANTHROPIC_API_KEY", "test-key")
	defer func() {
		if originalKey != "" {
			os.Setenv("ANTHROPIC_API_KEY", originalKey)
		} else {
			os.Unsetenv("ANTHROPIC_API_KEY")
		}
	}()

	options := &common.Options{
		Repo:       "https://github.com/test/repo",
		OutDir:     "/tmp/test",
		AgentsDir:  "/tmp/agents",
		SessionDir: "/tmp/sessions",
	}

	orchestrator, err := NewSecurityOrchestrator("/tmp/sessions", "/tmp/agents", options)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	if orchestrator.SessionID == "" {
		t.Error("SessionID should not be empty")
	}

	if orchestrator.State == nil {
		t.Error("State should not be nil")
	}

	if orchestrator.State.CurrentPhase != common.PhaseInitialization {
		t.Errorf("Expected initial phase to be %s, got %s", common.PhaseInitialization, orchestrator.State.CurrentPhase)
	}
}

func TestPhase4_DecomposeIntoParallelAnalyses(t *testing.T) {
	// Set required environment variable for test
	originalKey := os.Getenv("ANTHROPIC_API_KEY")
	os.Setenv("ANTHROPIC_API_KEY", "test-key")
	defer func() {
		if originalKey != "" {
			os.Setenv("ANTHROPIC_API_KEY", originalKey)
		} else {
			os.Unsetenv("ANTHROPIC_API_KEY")
		}
	}()

	options := &common.Options{
		Repo:       "https://github.com/test/repo",
		OutDir:     "/tmp/test",
		AgentsDir:  "/tmp/agents",
		SessionDir: "/tmp/sessions",
	}

	orchestrator, err := NewSecurityOrchestrator("/tmp/sessions", "/tmp/agents", options)
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	// Execute phase 4
	err = orchestrator.phase4_DecomposeIntoParallelAnalyses()
	if err != nil {
		t.Fatalf("Phase 4 failed: %v", err)
	}

	// Check that 8 analyses were created (including the new ones)
	if len(orchestrator.State.DecomposedAnalyses) != 8 {
		t.Errorf("Expected 8 analyses, got %d", len(orchestrator.State.DecomposedAnalyses))
	}

	// Check that all agent types are present
	expectedTypes := map[string]bool{
		common.AgentTypeInjection: false,
		common.AgentTypeXSS:       false,
		common.AgentTypePath:      false,
		common.AgentTypeCrypto:    false,
		common.AgentTypeAuth:      false,
		common.AgentTypeDeserial:  false,
		common.AgentTypeXXE:       false,
		common.AgentTypeRace:      false,
	}

	for _, analysis := range orchestrator.State.DecomposedAnalyses {
		expectedTypes[analysis.AssignedAgent] = true
	}

	for agentType, found := range expectedTypes {
		if !found {
			t.Errorf("Agent type %s not found in analyses", agentType)
		}
	}
}

func TestAgentResultParsing(t *testing.T) {
	options := &common.Options{}
	orchestrator, _ := NewSecurityOrchestrator("/tmp/sessions", "/tmp/agents", options)

	// Test various Claude response formats
	testCases := []struct {
		name     string
		input    []byte
		expected int // expected number of vulnerabilities
	}{
		{
			name: "Direct JSON format",
			input: []byte(`{
				"agent_id": "test-agent",
				"vulnerabilities": [
					{"type": "SQL Injection", "file": "test.py", "line_start": 10, "line_end": 12}
				]
			}`),
			expected: 1,
		},
		{
			name:     "JSON in markdown code block",
			input:    []byte("Some text\n```json\n{\"vulnerabilities\": [{\"type\": \"XSS\"}]}\n```\nMore text"),
			expected: 1,
		},
		{
			name: "Alternative format with findings",
			input: []byte(`{
				"findings": [
					{"type": "Path Traversal", "file": "app.js"}
				]
			}`),
			expected: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			content := orchestrator.extractContentFromClaudeResponse(tc.input)
			agent := common.AnalysisAgent{AgentID: "test", AgentType: "test-type"}
			results := orchestrator.parseAgentVulnerabilities(content, agent)

			if len(results.Vulnerabilities) != tc.expected {
				t.Errorf("Expected %d vulnerabilities, got %d", tc.expected, len(results.Vulnerabilities))
			}
		})
	}
}

func TestAgentMetrics(t *testing.T) {
	metrics := &AgentMetrics{
		AgentID:       "test-agent",
		AgentType:     "code-injection-analyser",
		StartTime:     time.Now(),
		EndTime:       time.Now().Add(5 * time.Minute),
		ExecutionTime: 5 * time.Minute,
		VulnsFound:    10,
		Status:        "completed",
	}

	if metrics.ExecutionTime != 5*time.Minute {
		t.Errorf("Expected execution time of 5 minutes, got %v", metrics.ExecutionTime)
	}

	if metrics.VulnsFound != 10 {
		t.Errorf("Expected 10 vulnerabilities found, got %d", metrics.VulnsFound)
	}

	if metrics.Status != "completed" {
		t.Errorf("Expected status 'completed', got %s", metrics.Status)
	}
}

func TestCountSecrets(t *testing.T) {
	options := &common.Options{}
	orchestrator, _ := NewSecurityOrchestrator("/tmp/sessions", "/tmp/agents", options)

	// Add some test vulnerabilities
	orchestrator.State.Vulnerabilities = []common.EnhancedVulnerability{
		{Type: "hardcoded_secret"},
		{Type: "api_key_exposure"},
		{Type: "SQL Injection"},
		{Type: "password_in_code"},
	}

	count := orchestrator.countSecrets()
	expectedCount := 3 // hardcoded_secret, api_key_exposure, password_in_code

	if count != expectedCount {
		t.Errorf("Expected %d secrets, got %d", expectedCount, count)
	}
}
