# codesucks-ai 🔒

**AI-Powered Security Analysis Tool** - Advanced static analysis with automated vulnerability fixes

[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-%20%20GNU%20GPLv3%20-green)](LICENSE)

## Overview

codesucks-ai is a comprehensive security analysis tool that combines static code analysis with AI-powered vulnerability remediation and secret detection. Built as an independent alternative to codesucks-ai, it scans repositories via GitHub API (no cloning required) and provides automated fixes using Claude AI.

## ✨ Features

- 🔍 **Static Analysis**: Powered by Semgrep with configurable rulesets
- 🔐 **Secret Detection**: TruffleHog integration for comprehensive secret scanning
- 🤖 **AI Auto-Fix**: Claude AI generates fixes for detected vulnerabilities  
- 🔄 **GitHub Integration**: Automatic PR creation with fixes
- 📊 **Rich Reports**: Unified HTML reports with vulnerabilities and secrets
- ⚡ **No Repository Cloning**: Uses GitHub API for direct file access
- 🛠️ **Configurable Presets**: Multiple security scanning configurations
- ✅ **Secret Verification**: Validates found secrets to confirm active threats
- 📝 **Issue Creation**: Automatic GitHub issue generation
- 🧵 **Concurrent Processing**: Multi-threaded scanning for performance

## 🚀 Quick Start

### Installation

1. **Install Dependencies**:
   ```bash
   # Install Semgrep
   python3 -m pip install --user semgrep
   
   # Install TruffleHog (choose one method)
   brew install trufflehog  # macOS
   # OR download binary from https://github.com/trufflesecurity/trufflehog/releases
   
   # Clone the repository
   git clone https://github.com/asii-mov/codesucks-ai.git
   cd codesucks-ai
   ```

2. **Build the Tool**:
   ```bash
   go build -o codesucks-ai ./cmd/codesucks-ai
   ```

### Basic Usage

```bash
# Quick scan with shell script
./run-codesucks-ai.sh \
  -g $GITHUB_TOKEN \
  -a $ANTHROPIC_API_KEY \
  -r https://github.com/owner/repo

# Direct binary usage
./codesucks-ai \
  -github-token $GITHUB_TOKEN \
  -anthropic-key $ANTHROPIC_API_KEY \
  -repo https://github.com/owner/repo
```

### Configuration Presets

View available presets:
```bash
./run-codesucks-ai.sh --list-presets
```

Use specific presets:
```bash
# Fast scanning
./run-codesucks-ai.sh -c basic -g $GITHUB_TOKEN -r https://github.com/owner/repo

# Comprehensive analysis
./run-codesucks-ai.sh -c comprehensive -g $GITHUB_TOKEN -r https://github.com/owner/repo

# Security-focused
./run-codesucks-ai.sh -c security-focused -g $GITHUB_TOKEN -r https://github.com/owner/repo

# Secret scanning with verification
./codesucks-ai -repo https://github.com/owner/repo -verify-secrets -github-token $GITHUB_TOKEN

# Only secret scanning (skip Semgrep)
./codesucks-ai -repo https://github.com/owner/repo -no-semgrep -github-token $GITHUB_TOKEN
```

## 📋 Configuration Presets

| Preset | Description | Rules |
|--------|-------------|-------|
| **basic** | Minimal ruleset for fast scanning | p/trailofbits |
| **codesucks-ai** | Default balanced configuration | p/trailofbits + p/security-audit + p/secrets |
| **security-focused** | Security vulnerabilities and secrets | p/security-audit + p/secrets + p/owasp-top-ten |
| **comprehensive** | Maximum coverage | All available rulesets |
| **compliance** | Enterprise compliance focused | p/cwe-top-25 + p/supply-chain + p/security-audit |

## 🔐 Secret Scanning

codesucks-ai integrates TruffleHog for comprehensive secret detection alongside vulnerability scanning.

### Supported Secret Types

TruffleHog can detect 800+ secret types including:
- **Cloud Providers**: AWS keys, GCP keys, Azure credentials
- **Development Platforms**: GitHub tokens, GitLab tokens, Docker Hub
- **Communication**: Slack tokens, Discord webhooks
- **Payment**: Stripe API keys, PayPal credentials
- **AI Services**: OpenAI keys, Anthropic keys, Hugging Face tokens
- **Databases**: PostgreSQL, MySQL, MongoDB connection strings
- **And many more...**

### Secret Scanning Modes

```bash
# Complete security scan (vulnerabilities + secrets)
./codesucks-ai -repo https://github.com/owner/repo -github-token $GITHUB_TOKEN

# Only verified secrets (reduces false positives)
./codesucks-ai -repo https://github.com/owner/repo -verify-secrets -github-token $GITHUB_TOKEN

# Only secret scanning (skip static analysis)
./codesucks-ai -repo https://github.com/owner/repo -no-semgrep -github-token $GITHUB_TOKEN

# Custom TruffleHog binary path
./codesucks-ai -repo https://github.com/owner/repo -trufflehog-path /path/to/trufflehog -github-token $GITHUB_TOKEN
```

### Understanding Secret Verification

- **✅ Verified**: Secret is confirmed active and poses immediate risk
- **⚠️ Unverified**: Potential secret found but not confirmed active
- **Secret Types**: Automatically classified (Private Key, API Key, etc.)
- **Location Details**: Exact file path and line number provided

## 🔧 Advanced Usage

### AI Auto-Fix with PR Creation

```bash
./run-codesucks-ai.sh \
  -g $GITHUB_TOKEN \
  -a $ANTHROPIC_API_KEY \
  -r https://github.com/owner/repo \
  --auto-fix \
  --create-pr \
  -c comprehensive
```

### Multiple Repository Scanning

```bash
# Create repos.txt with one repository URL per line
echo "https://github.com/owner/repo1" > repos.txt
echo "https://github.com/owner/repo2" >> repos.txt

./codesucks-ai \
  -repos repos.txt \
  -github-token $GITHUB_TOKEN \
  -anthropic-key $ANTHROPIC_API_KEY
```

### Custom Configuration

```bash
# Create custom.conf
echo "FLAGS=--config p/security-audit --config p/secrets --timeout 600" > custom.conf

./codesucks-ai \
  -config ./custom.conf \
  -repo https://github.com/owner/repo \
  -github-token $GITHUB_TOKEN
```

## 📊 Output

codesucks-ai generates comprehensive HTML reports including:

- **Executive Summary**: High-level statistics for vulnerabilities and secrets
- **Vulnerability Details**: Code snippets, severity levels, and descriptions
- **Secret Findings**: Detected secrets with verification status and types
- **AI Fix Suggestions**: Automated remediation recommendations
- **GitHub Integration**: Direct links to affected files and secret locations

Reports are saved to the output directory (default: `./results/`).

## 🔑 Authentication

### GitHub Personal Access Token

```bash
export GITHUB_TOKEN="github_pat_xxxxxxxxxxxxx"
```

Required scopes: `repo`, `pull_request` (for PR creation)

### GitHub App (Enterprise)

```bash
export GITHUB_APP_ID="123456"
export GITHUB_APP_PRIVATE_KEY="/path/to/private-key.pem"
```

### Claude AI

```bash
export ANTHROPIC_API_KEY="sk-ant-api03-xxxxxxxxxxxxx"
```

## 🛠️ CLI Options

```
TARGET OPTIONS:
  -repo string        Single repository URL to scan
  -repos string       File containing list of repository URLs

SCANNING OPTIONS:
  -config string      Configuration preset or path (default: codesucks-ai)
  -list-presets       List available configuration presets
  -no-semgrep         Skip Semgrep static analysis
  -semgrep-path string Path to semgrep binary
  -no-trufflehog      Skip TruffleHog secret scanning
  -trufflehog-path string Path to trufflehog binary
  -verify-secrets     Only return verified secrets from TruffleHog
  -out string         Output directory (default: ./results)

AI AUTOMATION:
  -auto-fix           Enable AI-powered vulnerability fixes
  -create-pr          Create pull request with fixes
  -create-issue       Create GitHub issue for vulnerabilities
  -anthropic-key string Anthropic API key

GITHUB AUTHENTICATION:
  -github-token string GitHub personal access token
  -github-app-id int   GitHub App ID
  -github-app-key string GitHub App private key file

PERFORMANCE:
  -threads int        Concurrent scanning threads (default: 10)
  -debug              Enable debug logging
```

## 📖 Documentation

- [Configuration Guide](docs/CONFIGURATION.md)
- [Examples](docs/EXAMPLES.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Development Guide](docs/blueprint.md)

## NodeGoat Testing

For comprehensive testing and validation, we used [NodeGoat-AI-test](https://github.com/asii-mov/NodeGoat-AI-test) - a deliberately vulnerable Node.js application. You can view the automated pull request fixes and security improvements generated by codesucks-ai in that repository.

## 🙏 Acknowledgments

- [SASTSweep](https://github.com/chebuya/sastsweep) Inspired by cheb
- [Semgrep](https://semgrep.dev/) for static analysis engine
- [TruffleHog](https://trufflesecurity.com/trufflehog) for comprehensive secret detection
- [Anthropic Claude](https://anthropic.com/) for AI-powered fixes

---
