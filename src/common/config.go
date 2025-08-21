package common

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadConfig loads configuration from YAML file with defaults
func LoadConfig(configPath string) (*Config, error) {
	config := &Config{}

	// Set defaults
	setConfigDefaults(config)

	// If no config file specified, return defaults
	if configPath == "" {
		return config, nil
	}

	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file does not exist: %s", configPath)
	}

	// Read the file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Parse YAML
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %v", err)
	}

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return config, nil
}

// setConfigDefaults sets default values for the configuration
func setConfigDefaults(config *Config) {
	// Scanning defaults
	config.Scanning.Semgrep.Enabled = true
	config.Scanning.Semgrep.Path = "semgrep"
	config.Scanning.Semgrep.Config = "comprehensive"

	config.Scanning.TruffleHog.Enabled = true
	config.Scanning.TruffleHog.Path = "trufflehog"
	config.Scanning.TruffleHog.VerifySecrets = false

	// AI automation defaults
	config.AIAutomation.Enabled = false
	config.AIAutomation.Model = DefaultModel
	config.AIAutomation.MinConfidence = 0.8
	config.AIAutomation.AutoFix = false
	config.AIAutomation.CreatePR = false
	config.AIAutomation.CreateIssue = false

	// GitHub defaults
	config.GitHub.AuthMethod = "token"

	// Performance defaults
	config.Performance.Threads = 10
	config.Performance.OutputDir = "./scans"
	config.Performance.Debug = false

	// Agent validation defaults
	config.AgentValidation.Enabled = true
	config.AgentValidation.ConfidenceThreshold = 0.7

	// Orchestrator defaults (missing defaults that were causing the bug!)
	config.Orchestrator.Enabled = false
	config.Orchestrator.SessionDir = "./sessions"
	config.Orchestrator.AgentsDir = "./agents"
	config.Orchestrator.Timeout = 3600
	config.Orchestrator.MaxAgents = 8

	// Matrix Build defaults
	config.MatrixBuild.Enabled = true           // Default to enabled
	config.MatrixBuild.AutoDetect = true        // Default to auto-detect
	config.MatrixBuild.LanguageThreshold = 10.0 // Default 10% threshold

	// Repository Download Strategy defaults
	// Note: These aren't in the Config struct, they're in Options
	// We'll handle them in the runner's option parsing
}

// validateConfig validates the configuration structure
func validateConfig(config *Config) error {
	// Validate target specification
	if config.Target.Repo == "" && config.Target.ReposFile == "" {
		return fmt.Errorf("must specify either target.repo or target.repos_file")
	}

	if config.Target.Repo != "" && config.Target.ReposFile != "" {
		return fmt.Errorf("cannot specify both target.repo and target.repos_file")
	}

	// Validate repos file exists if specified
	if config.Target.ReposFile != "" {
		if _, err := os.Stat(config.Target.ReposFile); os.IsNotExist(err) {
			return fmt.Errorf("repos file does not exist: %s", config.Target.ReposFile)
		}
	}

	// Validate confidence thresholds
	if config.AIAutomation.MinConfidence < 0.0 || config.AIAutomation.MinConfidence > 1.0 {
		return fmt.Errorf("ai_automation.min_confidence must be between 0.0 and 1.0")
	}

	if config.AgentValidation.ConfidenceThreshold < 0.0 || config.AgentValidation.ConfidenceThreshold > 1.0 {
		return fmt.Errorf("agent_validation.confidence_threshold must be between 0.0 and 1.0")
	}

	// Validate thread count
	if config.Performance.Threads < 1 {
		return fmt.Errorf("performance.threads must be at least 1")
	}

	// Validate GitHub auth method
	if config.GitHub.AuthMethod != "" && config.GitHub.AuthMethod != "token" && config.GitHub.AuthMethod != "app" {
		return fmt.Errorf("github.auth_method must be 'token' or 'app'")
	}

	// Validate GitHub App configuration
	if config.GitHub.AuthMethod == "app" {
		if config.GitHub.AppID == 0 {
			return fmt.Errorf("github.app_id is required when using app authentication")
		}
		if config.GitHub.AppKeyFile != "" {
			if _, err := os.Stat(config.GitHub.AppKeyFile); os.IsNotExist(err) {
				return fmt.Errorf("github app key file does not exist: %s", config.GitHub.AppKeyFile)
			}
		}
	}

	return nil
}

// MergeConfigWithOptions merges YAML config with CLI options, giving precedence to CLI
func MergeConfigWithOptions(config *Config, options *Options) {
	// Target specification (CLI takes precedence)
	if options.Repo != "" {
		config.Target.Repo = options.Repo
		config.Target.ReposFile = ""
	} else if options.Repos != "" {
		config.Target.ReposFile = options.Repos
		config.Target.Repo = ""
	}

	// Scanning configuration
	if options.NoSemgrep {
		config.Scanning.Semgrep.Enabled = false
	}
	if options.SemgrepPath != "" && options.SemgrepPath != "semgrep" {
		config.Scanning.Semgrep.Path = options.SemgrepPath
	}
	if options.ConfigPath != "" && options.ConfigPath != "comprehensive" {
		config.Scanning.Semgrep.Config = options.ConfigPath
	}

	if options.NoTruffleHog {
		config.Scanning.TruffleHog.Enabled = false
	}
	if options.TruffleHogPath != "" && options.TruffleHogPath != "trufflehog" {
		config.Scanning.TruffleHog.Path = options.TruffleHogPath
	}
	if options.VerifySecrets {
		config.Scanning.TruffleHog.VerifySecrets = true
	}

	// AI automation
	if options.AutoFix {
		config.AIAutomation.Enabled = true
		config.AIAutomation.AutoFix = true
	}
	if options.CreatePR {
		config.AIAutomation.CreatePR = true
	}
	if options.CreateIssue {
		config.AIAutomation.CreateIssue = true
	}
	if options.AIModel != "" && options.AIModel != DefaultModel {
		config.AIAutomation.Model = options.AIModel
	}
	if options.MinConfidence != 0.8 {
		config.AIAutomation.MinConfidence = options.MinConfidence
	}
	if options.AnthropicAPIKey != "" {
		config.AIAutomation.APIKey = options.AnthropicAPIKey
	}

	// Agent validation
	if options.NoAgentValidation {
		config.AgentValidation.Enabled = false
	}
	if options.ValidationConfidence != 0.7 {
		config.AgentValidation.ConfidenceThreshold = options.ValidationConfidence
	}

	// GitHub integration
	if options.GitHubAppID != 0 {
		config.GitHub.AuthMethod = "app"
		config.GitHub.AppID = options.GitHubAppID
	}
	if options.GitHubAppPrivateKey != "" {
		config.GitHub.AppKeyFile = options.GitHubAppPrivateKey
	}

	// Performance
	if options.Threads != 10 {
		config.Performance.Threads = options.Threads
	}
	if options.OutDir != "" && options.OutDir != "./scans" {
		config.Performance.OutputDir = options.OutDir
	}
	if options.Debug {
		config.Performance.Debug = true
	}

	// Orchestrator mode (missing fields that were causing the bug!)
	if options.OrchestratorMode {
		config.Orchestrator.Enabled = true
	}
	if options.SessionDir != "" && options.SessionDir != "./sessions" {
		config.Orchestrator.SessionDir = options.SessionDir
	}
	if options.AgentsDir != "" && options.AgentsDir != "./agents" {
		config.Orchestrator.AgentsDir = options.AgentsDir
	}

	// Matrix Build options
	if options.MatrixBuild {
		config.MatrixBuild.Enabled = true
	}
	if options.DisableAutoDetect {
		config.MatrixBuild.AutoDetect = false
	}
	if options.ForceLanguage != "" {
		config.MatrixBuild.ForceLanguage = options.ForceLanguage
	}
	if options.ForceFramework != "" {
		config.MatrixBuild.ForceFramework = options.ForceFramework
	}
	if options.AdditionalRulesets != "" {
		config.MatrixBuild.AdditionalRulesets = options.AdditionalRulesets
	}
	if options.LanguageThreshold != 10.0 {
		config.MatrixBuild.LanguageThreshold = options.LanguageThreshold
	}
}

// ConvertConfigToOptions converts Config struct to Options for backward compatibility
func ConvertConfigToOptions(config *Config) *Options {
	options := &Options{
		// Target
		Repo:  config.Target.Repo,
		Repos: config.Target.ReposFile,

		// Scanning
		NoSemgrep:      !config.Scanning.Semgrep.Enabled,
		SemgrepPath:    config.Scanning.Semgrep.Path,
		ConfigPath:     config.Scanning.Semgrep.Config,
		NoTruffleHog:   !config.Scanning.TruffleHog.Enabled,
		TruffleHogPath: config.Scanning.TruffleHog.Path,
		VerifySecrets:  config.Scanning.TruffleHog.VerifySecrets,

		// AI automation
		AutoFix:       config.AIAutomation.AutoFix,
		CreatePR:      config.AIAutomation.CreatePR,
		CreateIssue:   config.AIAutomation.CreateIssue,
		AIModel:       config.AIAutomation.Model,
		MinConfidence: config.AIAutomation.MinConfidence,

		// Agent validation
		NoAgentValidation:    !config.AgentValidation.Enabled,
		ValidationConfidence: config.AgentValidation.ConfidenceThreshold,

		// Performance
		Threads: config.Performance.Threads,
		OutDir:  config.Performance.OutputDir,
		Debug:   config.Performance.Debug,

		// Orchestrator mode (missing fields that were causing the bug!)
		OrchestratorMode: config.Orchestrator.Enabled,
		SessionDir:       config.Orchestrator.SessionDir,
		AgentsDir:        config.Orchestrator.AgentsDir,

		// Matrix Build options
		MatrixBuild:        config.MatrixBuild.Enabled,
		DisableAutoDetect:  !config.MatrixBuild.AutoDetect,
		ForceLanguage:      config.MatrixBuild.ForceLanguage,
		ForceFramework:     config.MatrixBuild.ForceFramework,
		AdditionalRulesets: config.MatrixBuild.AdditionalRulesets,
		LanguageThreshold:  config.MatrixBuild.LanguageThreshold,
	}

	// GitHub configuration
	if config.GitHub.AuthMethod == "app" {
		options.GitHubAppID = config.GitHub.AppID
		options.GitHubAppPrivateKey = config.GitHub.AppKeyFile
	}

	return options
}

// GenerateDefaultConfig generates a default YAML configuration file
func GenerateDefaultConfig() *Config {
	config := &Config{}
	setConfigDefaults(config)
	return config
}

// SaveConfigToFile saves a Config struct to a YAML file
func SaveConfigToFile(config *Config, filename string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config to YAML: %v", err)
	}

	// Write to file
	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}
