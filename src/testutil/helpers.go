package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/asii-mov/codesucks-ai/common"
	"github.com/asii-mov/codesucks-ai/common/envloader"
	"github.com/stretchr/testify/require"
)

// SetupTestEnvironment sets up a clean test environment
func SetupTestEnvironment(t *testing.T) {
	t.Helper()
	
	// Load test environment variables
	_ = envloader.LoadEnvForTesting()
	
	// Create temp directory for test outputs
	tempDir := t.TempDir()
	os.Setenv("TEST_OUTPUT_DIR", tempDir)
}

// CreateTestConfig creates a test configuration with defaults
func CreateTestConfig() *common.Config {
	config := &common.Config{
		Target: common.TargetConfig{
			Repo: "https://github.com/test/repo",
		},
		Scanning: common.ScanningConfig{
			Semgrep: common.SemgrepConfig{
				Enabled: true,
				Path:    "semgrep",
				Config:  "basic",
			},
			TruffleHog: common.TruffleHogConfig{
				Enabled:       true,
				Path:          "trufflehog",
				VerifySecrets: false,
			},
		},
		AIAutomation: common.AIAutomationConfig{
			Enabled:       false,
			Model:         common.DefaultModel,
			MinConfidence: 0.8,
		},
		Performance: common.PerformanceConfig{
			Threads:   5,
			OutputDir: "./test-results",
			Debug:     false,
		},
	}
	return config
}

// CreateTestOptions creates test options with defaults
func CreateTestOptions() *common.Options {
	return &common.Options{
		Repo:                "https://github.com/test/repo",
		ConfigPath:          "basic",
		OutDir:              "./test-results",
		Threads:             5,
		Debug:               false,
		MinConfidence:       0.8,
		ValidationConfidence: 0.7,
	}
}

// CreateTempFile creates a temporary file with content for testing
func CreateTempFile(t *testing.T, name, content string) string {
	t.Helper()
	
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, name)
	
	err := os.WriteFile(filePath, []byte(content), 0644)
	require.NoError(t, err)
	
	return filePath
}

// CreateTempYAMLConfig creates a temporary YAML config file
func CreateTempYAMLConfig(t *testing.T) string {
	t.Helper()
	
	content := `
target:
  repo: "https://github.com/test/repo"

scanning:
  semgrep:
    enabled: true
    config: "basic"
  trufflehog:
    enabled: true

performance:
  threads: 5
  output_dir: "./test-results"
`
	
	return CreateTempFile(t, "test-config.yaml", content)
}

// MockEnvVars sets mock environment variables for testing
func MockEnvVars(t *testing.T, vars map[string]string) func() {
	t.Helper()
	
	// Store original values
	original := make(map[string]string)
	for key := range vars {
		original[key] = os.Getenv(key)
	}
	
	// Set test values
	for key, value := range vars {
		os.Setenv(key, value)
	}
	
	// Return cleanup function
	return func() {
		for key, value := range original {
			if value == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, value)
			}
		}
	}
}

// AssertFileExists checks if a file exists
func AssertFileExists(t *testing.T, path string) {
	t.Helper()
	
	_, err := os.Stat(path)
	require.NoError(t, err, "file should exist: %s", path)
}

// AssertFileContains checks if a file contains expected content
func AssertFileContains(t *testing.T, path, expected string) {
	t.Helper()
	
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(content), expected)
}