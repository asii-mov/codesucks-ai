package common

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name          string
		configPath    string
		configContent string
		expectError   bool
		validate      func(t *testing.T, config *Config)
	}{
		{
			name:       "loads valid config file",
			configPath: "test-config.yaml",
			configContent: `
target:
  repo: "https://github.com/test/repo"

scanning:
  semgrep:
    enabled: true
    config: "comprehensive"
  trufflehog:
    enabled: false

ai_automation:
  enabled: true
  model: "claude-3-5-sonnet-20241022"
  min_confidence: 0.9

performance:
  threads: 20
  output_dir: "./custom-results"
`,
			expectError: false,
			validate: func(t *testing.T, config *Config) {
				assert.Equal(t, "https://github.com/test/repo", config.Target.Repo)
				assert.True(t, config.Scanning.Semgrep.Enabled)
				assert.Equal(t, "comprehensive", config.Scanning.Semgrep.Config)
				assert.False(t, config.Scanning.TruffleHog.Enabled)
				assert.True(t, config.AIAutomation.Enabled)
				assert.Equal(t, "claude-3-5-sonnet-20241022", config.AIAutomation.Model)
				assert.Equal(t, 0.9, config.AIAutomation.MinConfidence)
				assert.Equal(t, 20, config.Performance.Threads)
				assert.Equal(t, "./custom-results", config.Performance.OutputDir)
			},
		},
		{
			name:        "returns defaults when no config file specified",
			configPath:  "",
			expectError: false,
			validate: func(t *testing.T, config *Config) {
				// Check defaults are set
				assert.True(t, config.Scanning.Semgrep.Enabled)
				assert.Equal(t, "comprehensive", config.Scanning.Semgrep.Config)
				assert.True(t, config.Scanning.TruffleHog.Enabled)
				assert.False(t, config.AIAutomation.Enabled)
				assert.Equal(t, DefaultModel, config.AIAutomation.Model)
				assert.Equal(t, 10, config.Performance.Threads)
			},
		},
		{
			name:       "handles invalid YAML",
			configPath: "invalid.yaml",
			configContent: `
invalid yaml content
  indentation: wrong
    - list item without key
`,
			expectError: true,
		},
		{
			name:       "validates missing target",
			configPath: "no-target.yaml",
			configContent: `
scanning:
  semgrep:
    enabled: true
`,
			expectError: true,
		},
		{
			name:       "validates confidence threshold range",
			configPath: "invalid-confidence.yaml",
			configContent: `
target:
  repo: "https://github.com/test/repo"

ai_automation:
  min_confidence: 1.5
`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			var configPath string
			if tt.configPath != "" && tt.configContent != "" {
				tempDir := t.TempDir()
				configPath = filepath.Join(tempDir, tt.configPath)
				err := os.WriteFile(configPath, []byte(tt.configContent), 0644)
				require.NoError(t, err)
			}

			// Test
			config, err := LoadConfig(configPath)

			// Validate
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, config)
				if tt.validate != nil {
					tt.validate(t, config)
				}
			}
		})
	}
}

func TestSetConfigDefaults(t *testing.T) {
	config := &Config{}
	setConfigDefaults(config)

	// Verify defaults are set
	assert.True(t, config.Scanning.Semgrep.Enabled)
	assert.Equal(t, "semgrep", config.Scanning.Semgrep.Path)
	assert.Equal(t, "comprehensive", config.Scanning.Semgrep.Config)

	assert.True(t, config.Scanning.TruffleHog.Enabled)
	assert.Equal(t, "trufflehog", config.Scanning.TruffleHog.Path)
	assert.False(t, config.Scanning.TruffleHog.VerifySecrets)

	assert.False(t, config.AIAutomation.Enabled)
	assert.Equal(t, DefaultModel, config.AIAutomation.Model)
	assert.Equal(t, 0.8, config.AIAutomation.MinConfidence)

	assert.Equal(t, "token", config.GitHub.AuthMethod)
	assert.Equal(t, 10, config.Performance.Threads)
	assert.Equal(t, "./results", config.Performance.OutputDir)
	assert.False(t, config.Performance.Debug)
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config with repo",
			config: &Config{
				Target: TargetConfig{
					Repo: "https://github.com/test/repo",
				},
				AIAutomation: AIAutomationConfig{
					MinConfidence: 0.8,
				},
				AgentValidation: AgentValidationConfig{
					ConfidenceThreshold: 0.7,
				},
				Performance: PerformanceConfig{
					Threads: 10,
				},
			},
			expectError: false,
		},
		{
			name: "valid config with repos file",
			config: &Config{
				Target: TargetConfig{
					ReposFile: filepath.Join(t.TempDir(), "repos.txt"),
				},
				AIAutomation: AIAutomationConfig{
					MinConfidence: 0.8,
				},
				AgentValidation: AgentValidationConfig{
					ConfidenceThreshold: 0.7,
				},
				Performance: PerformanceConfig{
					Threads: 10,
				},
			},
			expectError: false,
		},
		{
			name: "missing target specification",
			config: &Config{
				Target: TargetConfig{},
			},
			expectError: true,
			errorMsg:    "must specify either target.repo or target.repos_file",
		},
		{
			name: "both repo and repos_file specified",
			config: &Config{
				Target: TargetConfig{
					Repo:      "https://github.com/test/repo",
					ReposFile: "repos.txt",
				},
			},
			expectError: true,
			errorMsg:    "cannot specify both target.repo and target.repos_file",
		},
		{
			name: "invalid min_confidence too high",
			config: &Config{
				Target: TargetConfig{
					Repo: "https://github.com/test/repo",
				},
				AIAutomation: AIAutomationConfig{
					MinConfidence: 1.5,
				},
			},
			expectError: true,
			errorMsg:    "min_confidence must be between 0.0 and 1.0",
		},
		{
			name: "invalid min_confidence negative",
			config: &Config{
				Target: TargetConfig{
					Repo: "https://github.com/test/repo",
				},
				AIAutomation: AIAutomationConfig{
					MinConfidence: -0.1,
				},
			},
			expectError: true,
			errorMsg:    "min_confidence must be between 0.0 and 1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create repos file if needed
			if tt.config.Target.ReposFile != "" && !tt.expectError {
				err := os.WriteFile(tt.config.Target.ReposFile, []byte("https://github.com/test/repo"), 0644)
				require.NoError(t, err)
			}

			err := validateConfig(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMergeConfigWithOptions(t *testing.T) {
	// Create base config
	config := &Config{
		Target: TargetConfig{
			Repo: "https://github.com/config/repo",
		},
		Scanning: ScanningConfig{
			Semgrep: SemgrepConfig{
				Enabled: true,
				Config:  "basic",
			},
		},
		AIAutomation: AIAutomationConfig{
			Enabled: false,
			Model:   "claude-3-opus",
		},
		Performance: PerformanceConfig{
			Threads:   5,
			OutputDir: "./config-results",
		},
	}

	// Create options that override some values
	options := &Options{
		Repo:            "https://github.com/options/repo",
		ConfigPath:      "security-focused",
		Threads:         20,
		OutDir:          "./options-results",
		AutoFix:         true,
		AnthropicAPIKey: "test-key",
	}

	// Merge
	MergeConfigWithOptions(config, options)

	// Verify CLI options take precedence
	assert.Equal(t, "https://github.com/options/repo", config.Target.Repo)
	assert.Equal(t, "security-focused", config.Scanning.Semgrep.Config)
	assert.Equal(t, 20, config.Performance.Threads)
	assert.Equal(t, "./options-results", config.Performance.OutputDir)
	assert.True(t, config.AIAutomation.AutoFix)
	assert.Equal(t, "test-key", config.AIAutomation.APIKey)

	// Verify config values are preserved when not overridden
	assert.Equal(t, "claude-3-opus", config.AIAutomation.Model)
}

func TestGenerateDefaultConfig(t *testing.T) {
	config := GenerateDefaultConfig()

	assert.NotNil(t, config)
	assert.True(t, config.Scanning.Semgrep.Enabled)
	assert.True(t, config.Scanning.TruffleHog.Enabled)
	assert.Equal(t, DefaultModel, config.AIAutomation.Model)
	assert.Equal(t, 10, config.Performance.Threads)
	assert.Equal(t, "./results", config.Performance.OutputDir)
}
