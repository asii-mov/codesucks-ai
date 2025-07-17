# codesucks-ai - Claude AI Assistant Reference

## Repository Overview
**codesucks-ai** is an AI-powered security analysis tool that combines static code analysis with automated vulnerability remediation. It integrates Semgrep for SAST, TruffleHog for secret detection, and Claude AI for generating fixes.

**Key Features:**
- Static analysis via Semgrep with configurable rulesets
- Secret detection via TruffleHog with verification
- **AI-powered vulnerability validation** - Claude AI analyzes each finding for false positives
- AI-powered vulnerability fixes using Claude AI
- GitHub integration (PR creation, issue generation)
- No repository cloning required (uses GitHub API)
- Rich HTML reporting with executive summaries and validation results

## Enhanced Workflow with Agent Validation (Default)

The default workflow now includes AI-powered vulnerability validation that dramatically reduces false positives:

1. **Repository Analysis**: Fetch and scan repository with Semgrep/TruffleHog using **comprehensive** ruleset
2. **Repository Familiarization**: Claude AI analyzes codebase structure, dependencies, and security patterns
3. **Vulnerability Validation**: Each finding is evaluated by Claude for false positives using repository context
4. **Context-Aware Filtering**: Remove vulnerabilities that aren't exploitable in specific context
5. **Enhanced Reporting**: Rich HTML reports with validation results, confidence scores, and reasoning
6. **Intelligent Fixes**: Only legitimate vulnerabilities proceed to auto-fix workflow

**Key Improvements:**
- **Comprehensive scanning by default** (23+ vulnerabilities vs 3 with basic)
- **Agent validation enabled by default** (requires Anthropic API key)
- **Smart false positive detection** with detailed reasoning
- **Rich HTML reports** showing validation analysis and confidence scores

## Architecture & Structure

```
├── cmd/
│   ├── codesucks-ai/     # Main application entry point
│   │   └── sastsweep.go  # Main function and CLI handling
│   └── monitor/          # Monitoring utilities
│       └── monitor.go
├── common/               # Shared libraries and utilities
│   ├── ai/              # AI integration (Claude)
│   │   └── claude.go
│   ├── agent/           # AI agent validation system
│   │   └── validator.go # Repository-aware vulnerability validation
│   ├── codesucks-ai/    # Core scanning logic
│   │   ├── sast.go      # Static analysis handling
│   │   └── secrets.go   # Secret detection handling
│   ├── github/          # GitHub API integration
│   │   ├── client.go    # GitHub client
│   │   ├── content.go   # File content handling
│   │   └── automation.go # PR/issue automation
│   ├── report/          # Report generation
│   │   ├── html.go      # HTML report generation
│   │   ├── template.go  # Report templates
│   │   └── util.go      # Report utilities
│   └── types.go         # Common data structures
├── runner/              # Command execution and orchestration
│   ├── options.go       # CLI option parsing
│   └── runner.go        # Main runner logic
├── configs/             # Configuration presets
│   ├── basic.conf       # Fast scanning
│   ├── codesucks-ai.conf # Default balanced
│   ├── security-focused.conf # Security-focused
│   ├── comprehensive.conf # Maximum coverage
│   └── compliance.conf  # Enterprise compliance
└── docs/               # Documentation
    ├── CONFIGURATION.md # Config guide
    ├── EXAMPLES.md     # Usage examples
    └── TROUBLESHOOTING.md # Common issues
```

## Build & Development

### Prerequisites
- Go 1.23+
- Python 3 (for Semgrep)
- Semgrep (`pip install semgrep`)
- TruffleHog (optional, for secret scanning)

### Build Commands
```bash
# Build the main binary
go build -o codesucks-ai ./cmd/codesucks-ai

# Or use Makefile
make build

# Install dependencies
make deps

# Run tests
make test

# Run linter
make lint

# Full build pipeline
make all
```

### Development Setup
```bash
# Set up development environment
make dev-setup

# Check installation
make check

# Clean build artifacts
make clean
```

## Configuration System

### Available Presets
- **basic**: Minimal ruleset for fast scanning (`p/trailofbits`)
- **codesucks-ai**: Balanced configuration for moderate coverage
- **security-focused**: Security vulnerabilities and secrets
- **comprehensive**: All available rulesets for maximum coverage (default)
- **compliance**: Enterprise compliance focused (CWE, supply chain)

### Configuration Format
Configuration files contain `FLAGS=` line with Semgrep arguments:
```bash
# Example config
FLAGS=--config p/security-audit --config p/secrets --no-git-ignore --timeout 300
```

### List Available Presets
```bash
./run-codesucks-ai.sh --list-presets
# or
make presets
```

## Key Commands

### Basic Usage
```bash
# Default comprehensive scan with agent validation (RECOMMENDED)
./codesucks-ai -github-token $GITHUB_TOKEN -anthropic-key $ANTHROPIC_API_KEY -repo https://github.com/owner/repo

# With auto-fix and PR creation
./codesucks-ai -github-token $GITHUB_TOKEN -anthropic-key $ANTHROPIC_API_KEY -repo https://github.com/owner/repo --auto-fix --create-pr

# Disable agent validation for raw comprehensive results
./codesucks-ai -github-token $GITHUB_TOKEN -repo https://github.com/owner/repo -no-agent-validation

# Fast scan with basic ruleset (minimal coverage)
./codesucks-ai -github-token $GITHUB_TOKEN -repo https://github.com/owner/repo -config basic -no-agent-validation
```

### Configuration Options
```bash
# Use specific preset
./codesucks-ai -config security-focused -repo $REPO -github-token $TOKEN

# Custom configuration file
./codesucks-ai -config ./custom.conf -repo $REPO -github-token $TOKEN

# Skip certain scans
./codesucks-ai -no-semgrep -repo $REPO -github-token $TOKEN  # Only secrets
./codesucks-ai -no-trufflehog -repo $REPO -github-token $TOKEN  # Only SAST
```

### Batch Processing
```bash
# Multiple repositories from file
./codesucks-ai -repos repos.txt -github-token $TOKEN

# With concurrent processing
./codesucks-ai -repos repos.txt -github-token $TOKEN -threads 10
```

## Dependencies

### Runtime Dependencies
- **Semgrep**: Static analysis engine
- **TruffleHog**: Secret detection (optional)
- **GitHub API**: Repository access
- **Claude AI**: Vulnerability fix generation (optional)

### Go Dependencies (go.mod)
- `github.com/google/go-github/v66`: GitHub API client
- `github.com/google/uuid`: UUID generation
- `golang.org/x/oauth2`: OAuth authentication

### Environment Variables
```bash
export GITHUB_TOKEN="github_pat_xxx"        # GitHub access
export ANTHROPIC_API_KEY="sk-ant-api03-xxx" # Claude AI
export GITHUB_APP_ID="123456"               # GitHub App (optional)
export GITHUB_APP_PRIVATE_KEY="/path/to/key" # GitHub App key
```

## Testing & Validation

### Running Tests
```bash
# Run all tests
go test -v ./...

# Or use Makefile
make test
```

### Example Scan
```bash
# Run example scan (requires GITHUB_TOKEN)
make run-example

# Performance benchmark
make benchmark
```

### Validation
```bash
# Check installation
make check

# Verify dependencies
semgrep --version
trufflehog --version
```

## Troubleshooting

### Common Issues

1. **Semgrep not found**
   ```bash
   # Install with pip
   python3 -m pip install --user semgrep
   
   # Or use system package manager
   brew install semgrep  # macOS
   ```

2. **Build failures**
   ```bash
   # Clean and rebuild
   make clean
   make build
   ```

3. **Rate limiting**
   ```bash
   # Use GitHub App for higher limits
   ./codesucks-ai -github-app-id $APP_ID -github-app-key ./key.pem
   
   # Or reduce concurrent threads
   ./codesucks-ai -threads 2
   ```

4. **Memory issues**
   ```bash
   # Use memory-optimized config
   FLAGS=--config p/security-audit --max-target-bytes 500000 --exclude="*.min.js"
   ```

### Debug Mode
```bash
# Enable debug logging
./codesucks-ai -debug -repo $REPO -github-token $TOKEN
```

## Important Notes

- **Security Tool**: This is a defensive security tool for vulnerability detection and remediation
- **API Keys**: Never commit API keys to version control
- **Default Behavior**: Comprehensive scanning + agent validation enabled by default (requires ANTHROPIC_API_KEY)
- **Performance**: Agent validation adds ~30s per vulnerability but dramatically improves accuracy
- **Rate Limits**: Claude API has rate limits; agent validation may fail with HTTP 529 during peak usage
- **GitHub API**: Has rate limits; use GitHub Apps for higher limits  
- **File Size**: Large files may timeout; adjust `--max-target-bytes` as needed
- **Configuration**: Test configurations on small repos before large-scale deployment

## Quick Reference

### Most Common Commands
```bash
# Default comprehensive scan with agent validation (RECOMMENDED)
./codesucks-ai -github-token $GITHUB_TOKEN -anthropic-key $ANTHROPIC_API_KEY -repo $REPO_URL

# Raw comprehensive scan (no agent validation)
./codesucks-ai -github-token $GITHUB_TOKEN -repo $REPO_URL -no-agent-validation

# Auto-fix with PR creation
./codesucks-ai -github-token $GITHUB_TOKEN -anthropic-key $ANTHROPIC_API_KEY -repo $REPO_URL --auto-fix --create-pr

# Batch processing (agent validation disabled for speed)
./codesucks-ai -repos list.txt -github-token $GITHUB_TOKEN -no-agent-validation

# Debug agent validation issues
./codesucks-ai -debug -github-token $GITHUB_TOKEN -anthropic-key $ANTHROPIC_API_KEY -repo $REPO_URL
```

### Key Files for Development
- `cmd/codesucks-ai/sastsweep.go` - Main application logic
- `runner/runner.go` - Core execution logic with agent validation workflow
- `common/agent/validator.go` - Repository-aware vulnerability validation system
- `common/types.go` - Data structures including ValidatedResult
- `common/ai/claude.go` - AI integration for fixes
- `common/github/client.go` - GitHub API integration
- `common/report/html.go` - Enhanced HTML reports with validation display
- `configs/comprehensive.conf` - Default comprehensive ruleset configuration

## Recent Major Changes (Current Session)

### ✅ Enhanced Vulnerability Validation Workflow
- **Agent validation enabled by default** (was opt-in, now opt-out with `--no-agent-validation`)
- **Comprehensive scanning by default** (was basic, now finds 23+ vulnerabilities vs 3)
- **Rich HTML reports** with agent validation results, confidence scores, and reasoning
- **False positive filtering** with detailed context analysis

### ✅ Default Configuration Changes
- Default config changed from `basic` to `comprehensive` for thorough security analysis
- CLI flag changed from `--enable-agent-validation` to `--no-agent-validation`
- Enhanced console output showing validation progress and false positive rates

### ✅ Enhanced Reporting
- HTML reports now display agent validation sections with confidence bars
- Visual indicators for legitimate vs filtered vulnerabilities
- Detailed reasoning and context analysis for each finding
- Summary statistics showing validation effectiveness