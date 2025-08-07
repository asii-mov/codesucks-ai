# YAML Configuration Guide

## Overview

The codesucks-ai tool now supports YAML configuration files to simplify complex scanning configurations. YAML configurations provide better readability, maintainability, and team collaboration compared to long command-line arguments.

## Quick Start

### Copy an Example Configuration

```bash
# Copy a preset configuration to customize
cp configs/comprehensive.yaml my-config.yaml

# Or choose from other presets
cp configs/basic.yaml quick-scan.yaml
cp configs/enterprise.yaml production-config.yaml
```

### Use a Configuration File

```bash
./codesucks-ai -config-file config.yaml
```

## Configuration Structure

The YAML configuration is organized into logical sections:

```yaml
target:
  repo: "https://github.com/owner/repo"     # Single repository
  repos_file: "repos.txt"                  # Or file with multiple repos

scanning:
  semgrep:
    enabled: true
    path: "semgrep"
    config: "comprehensive"
    custom_flags: "--timeout 300"
  trufflehog:
    enabled: true
    path: "trufflehog"
    verify_secrets: true

ai_automation:
  enabled: true
  model: "claude-3-5-sonnet-20241022"
  min_confidence: 0.8
  auto_fix: true
  create_pr: true
  create_issue: false

github:
  auth_method: "token"                      # "token" or "app"
  app_id: 123456                           # For GitHub App auth
  app_key_file: "/path/to/private-key.pem"

performance:
  threads: 10
  output_dir: "./results"
  debug: false

agent_validation:
  enabled: true
  confidence_threshold: 0.7
```

## Configuration Precedence

Settings are applied in this order (later overrides earlier):

1. **Default values**
2. **YAML configuration file**
3. **Environment variables**
4. **Command-line flags**

This means you can use a YAML file for base settings and override specific values with CLI flags.

## Available Presets

Pre-configured YAML files are available in the `configs/` directory:

- **`basic.yaml`** - Fast scanning with minimal rules
- **`comprehensive.yaml`** - Maximum coverage with AI automation
- **`security-focused.yaml`** - Security vulnerabilities with high confidence
- **`batch-processing.yaml`** - Optimized for multiple repositories
- **`enterprise.yaml`** - Compliance-focused with conservative settings

### Using Presets

```bash
./codesucks-ai -config-file configs/comprehensive.yaml
```

## Configuration Sections

### Target Configuration

Specify what to scan:

```yaml
target:
  repo: "https://github.com/owner/repo"     # Single repository
  # OR
  repos_file: "repos.txt"                  # File with repository list
```

### Scanning Configuration

Control scanning tools:

```yaml
scanning:
  semgrep:
    enabled: true                          # Enable/disable Semgrep
    path: "semgrep"                        # Binary path
    config: "comprehensive"                # Preset or custom config
    custom_flags: "--timeout 300"         # Additional Semgrep flags
  
  trufflehog:
    enabled: true                          # Enable/disable TruffleHog
    path: "trufflehog"                     # Binary path
    verify_secrets: true                   # Only verified secrets
```

#### Semgrep Config Options

- `basic` - Minimal ruleset (fast)
- `codesucks-ai` - Balanced default
- `comprehensive` - Maximum coverage
- `security-focused` - Security-focused rules
- `compliance` - Enterprise compliance
- `/path/to/custom.conf` - Custom configuration file

### AI Automation

Configure AI-powered features:

```yaml
ai_automation:
  enabled: true                            # Enable AI features
  model: "claude-3-5-sonnet-20241022"     # Claude model
  min_confidence: 0.8                     # Minimum fix confidence
  auto_fix: true                          # Generate vulnerability fixes
  create_pr: true                         # Create pull requests
  create_issue: false                     # Create GitHub issues
```

### GitHub Authentication

Configure GitHub access:

```yaml
github:
  auth_method: "token"                     # "token" or "app"
  
  # For GitHub App authentication:
  app_id: 123456
  app_key_file: "/path/to/private-key.pem"
```

**Environment Variables:**
- `GITHUB_TOKEN` - Personal access token
- `GITHUB_APP_ID` - GitHub App ID
- `GITHUB_APP_PRIVATE_KEY` - Path to private key file
- `ANTHROPIC_API_KEY` - Claude AI API key

### Performance Settings

Control execution parameters:

```yaml
performance:
  threads: 10                             # Concurrent scanning threads
  output_dir: "./results"                 # Output directory
  debug: false                           # Enable debug logging
```

### Agent Validation

Configure AI-powered result validation:

```yaml
agent_validation:
  enabled: true                           # Enable agent validation
  confidence_threshold: 0.7               # Minimum validation confidence
```

## Mixed Usage Examples

### Example 1: Base Config with CLI Override

```yaml
# config.yaml
target:
  repo: "https://github.com/myorg/myapp"
scanning:
  semgrep:
    config: "basic"
performance:
  threads: 5
```

```bash
# Override to use comprehensive scanning
./codesucks-ai -config-file config.yaml -config comprehensive
```

### Example 2: Team Configuration

```yaml
# team-config.yaml - Shared team settings
scanning:
  semgrep:
    config: "security-focused"
  trufflehog:
    verify_secrets: true
ai_automation:
  enabled: true
  min_confidence: 0.9
github:
  auth_method: "app"
  app_id: 123456
performance:
  threads: 8
  debug: false
```

Team members can use this with different repositories:

```bash
./codesucks-ai -config-file team-config.yaml -repo https://github.com/team/project1
./codesucks-ai -config-file team-config.yaml -repo https://github.com/team/project2
```

### Example 3: CI/CD Pipeline

```yaml
# ci-config.yaml
target:
  repos_file: "repos-to-scan.txt"
scanning:
  semgrep:
    config: "security-focused"
  trufflehog:
    verify_secrets: true
ai_automation:
  enabled: false  # Disable in CI for speed
github:
  auth_method: "app"
performance:
  threads: 20
  output_dir: "/tmp/scan-results"
  debug: true
agent_validation:
  enabled: false
```

## Migration from CLI-only

If you're currently using long command lines, convert them to YAML:

**Before:**
```bash
./codesucks-ai -repo https://github.com/org/repo -config comprehensive \
  -auto-fix -create-pr -threads 15 -verify-secrets \
  -github-app-id 123456 -github-app-key /key.pem \
  -min-confidence 0.9 -out /results -debug
```

**After:**
```yaml
# config.yaml
target:
  repo: "https://github.com/org/repo"
scanning:
  semgrep:
    config: "comprehensive"
  trufflehog:
    verify_secrets: true
ai_automation:
  enabled: true
  auto_fix: true
  create_pr: true
  min_confidence: 0.9
github:
  auth_method: "app"
  app_id: 123456
  app_key_file: "/key.pem"
performance:
  threads: 15
  output_dir: "/results"
  debug: true
```

```bash
./codesucks-ai -config-file config.yaml
```

## Validation and Troubleshooting

### Configuration Validation

The tool validates your configuration and provides helpful error messages:

```bash
$ ./codesucks-ai -config-file config.yaml
❌ Error: failed to load config file: invalid configuration: ai_automation.min_confidence must be between 0.0 and 1.0
```

### Common Issues

1. **File Not Found**
   ```
   Error: config file does not exist: config.yaml
   ```
   Make sure the path is correct and the file exists.

2. **Invalid YAML Syntax**
   ```
   Error: failed to parse YAML config: yaml: line 10: found character that cannot start any token
   ```
   Check YAML syntax, especially indentation and quotes.

3. **Validation Errors**
   ```
   Error: invalid configuration: must specify either target.repo or target.repos_file
   ```
   Ensure required fields are provided and values are valid.

### Debug Mode

Enable debug logging to see configuration loading:

```bash
./codesucks-ai -config-file config.yaml -debug
```

## Best Practices

1. **Version Control**: Store configuration files in your repository for team sharing
2. **Environment-Specific**: Use different configs for development, staging, production
3. **Security**: Never commit API keys; use environment variables
4. **Documentation**: Comment your configuration files for team understanding
5. **Validation**: Test configurations with `-debug` flag before automation

## Examples Directory

See the `configs/` directory for complete working examples:
- Basic scanning
- Comprehensive analysis
- Security-focused scanning
- Batch processing
- Enterprise compliance