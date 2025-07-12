# Usage Examples

This document provides practical examples for different use cases and scenarios.

## Table of Contents

- [Basic Scanning](#basic-scanning)
- [AI-Powered Fixes](#ai-powered-fixes)
- [Batch Processing](#batch-processing)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting Scenarios](#troubleshooting-scenarios)

## Basic Scanning

### Quick Security Check

Perform a fast security scan on a public repository:

```bash
./run-codesucks-ai.sh \
  -g $GITHUB_TOKEN \
  -r https://github.com/owner/public-repo \
  -c basic
```

### Comprehensive Analysis

Deep security analysis with all available rules:

```bash
./run-codesucks-ai.sh \
  -g $GITHUB_TOKEN \
  -r https://github.com/owner/repo \
  -c comprehensive \
  -o ./detailed-results
```

### Private Repository Scanning

Scan a private repository with proper authentication:

```bash
./codesucks-ai \
  -github-token $GITHUB_PRIVATE_TOKEN \
  -repo https://github.com/company/private-repo \
  -config security-focused \
  -out ./private-scan-results
```

## AI-Powered Fixes

### Basic Auto-Fix

Generate AI fixes for detected vulnerabilities:

```bash
./run-codesucks-ai.sh \
  -g $GITHUB_TOKEN \
  -a $ANTHROPIC_API_KEY \
  -r https://github.com/owner/repo \
  --auto-fix
```

### Auto-Fix with Pull Request

Generate fixes and create a pull request automatically:

```bash
./run-codesucks-ai.sh \
  -g $GITHUB_TOKEN \
  -a $ANTHROPIC_API_KEY \
  -r https://github.com/owner/repo \
  --auto-fix \
  --create-pr \
  -c security-focused
```

### Conservative Auto-Fix

Use higher confidence threshold for more reliable fixes:

```bash
./codesucks-ai \
  -github-token $GITHUB_TOKEN \
  -anthropic-key $ANTHROPIC_API_KEY \
  -repo https://github.com/owner/repo \
  -auto-fix \
  -min-confidence 0.9 \
  -create-pr
```

### Issue Creation

Create GitHub issues for vulnerabilities instead of fixes:

```bash
./codesucks-ai \
  -github-token $GITHUB_TOKEN \
  -anthropic-key $ANTHROPIC_API_KEY \
  -repo https://github.com/owner/repo \
  -create-issue \
  -config comprehensive
```

## Batch Processing

### Multiple Repositories from File

Create a file with repository URLs:

```bash
# repos.txt
https://github.com/company/frontend
https://github.com/company/backend
https://github.com/company/api
https://github.com/company/mobile
```

Scan all repositories:

```bash
./codesucks-ai \
  -repos repos.txt \
  -github-token $GITHUB_TOKEN \
  -config security-focused \
  -threads 5
```


### Parallel Processing

Process multiple repositories concurrently:

```bash
#!/bin/bash
declare -a REPOS=(
  "https://github.com/company/repo1"
  "https://github.com/company/repo2"
  "https://github.com/company/repo3"
)

for repo in "${REPOS[@]}"; do
  (
    ./codesucks-ai \
      -repo "$repo" \
      -github-token $GITHUB_TOKEN \
      -config basic \
      -out "./parallel-results/$(basename $repo)"
  ) &
done

wait # Wait for all background jobs to complete
```

## CI/CD Integration

### GitHub Actions Workflow

```yaml
name: Security Scan
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Go
      uses: actions/setup-go@v3
      with:
        go-version: 1.21
    
    - name: Install Semgrep
      run: python3 -m pip install semgrep
    
    - name: Build codesucks-ai
      run: go build -o codesucks-ai ./cmd/codesucks-ai
    
    - name: Run Security Scan
      run: |
        ./codesucks-ai \
          -repo ${{ github.repository }} \
          -github-token ${{ secrets.GITHUB_TOKEN }} \
          -config security-focused \
          -out ./security-results
    
    - name: Upload Results
      uses: actions/upload-artifact@v3
      with:
        name: security-report
        path: ./security-results/
```

## Troubleshooting Scenarios

### Large Repository Handling

For repositories with many files or large files:

```bash
# Use basic config with increased timeout
./codesucks-ai \
  -repo https://github.com/large/monorepo \
  -github-token $GITHUB_TOKEN \
  -config basic \
  -out ./large-repo-results

# Create custom config for large repos
cat > large-repo.conf << EOF
FLAGS=--config p/security-audit --timeout 1800 --max-target-bytes 10000000 --exclude="node_modules/*" --exclude="vendor/*"
EOF

./codesucks-ai \
  -repo https://github.com/large/monorepo \
  -github-token $GITHUB_TOKEN \
  -config ./large-repo.conf \
  -threads 20
```

### Rate Limit Handling

When hitting GitHub API rate limits:

```bash
# Reduce concurrent threads
./codesucks-ai \
  -repo https://github.com/owner/repo \
  -github-token $GITHUB_TOKEN \
  -threads 2 \
  -config basic

# Use GitHub App for higher rate limits
./codesucks-ai \
  -repo https://github.com/owner/repo \
  -github-app-id $GITHUB_APP_ID \
  -github-app-key ./private-key.pem \
  -config comprehensive
```

### Memory Optimization

For memory-constrained environments:

```bash
# Create memory-optimized config
cat > memory-optimized.conf << EOF
FLAGS=--config p/security-audit --max-target-bytes 500000 --exclude="*.min.js" --exclude="*.bundle.js"
EOF

./codesucks-ai \
  -repo https://github.com/owner/repo \
  -github-token $GITHUB_TOKEN \
  -config ./memory-optimized.conf \
  -threads 2
```

### False Positive Reduction

Minimize false positives in results:

```bash
# Use high-confidence rules only
cat > high-confidence.conf << EOF
FLAGS=--config p/trailofbits --confidence=HIGH --severity=ERROR
EOF

./codesucks-ai \
  -repo https://github.com/owner/repo \
  -github-token $GITHUB_TOKEN \
  -config ./high-confidence.conf \
  -min-confidence 0.95
```

### Debug Mode Examples

Troubleshoot configuration issues:

```bash
# Enable debug logging
./codesucks-ai \
  -repo https://github.com/owner/repo \
  -github-token $GITHUB_TOKEN \
  -config comprehensive \
  -debug \
  -out ./debug-results

# Test custom configuration
./codesucks-ai \
  -repo https://github.com/owner/small-test-repo \
  -github-token $GITHUB_TOKEN \
  -config ./test-config.conf \
  -debug
```

## Integration Patterns

### Scheduled Scanning

Regular automated scanning with cron:

```bash
# Add to crontab: 0 2 * * * /path/to/nightly-scan.sh
#!/bin/bash
# nightly-scan.sh

cd /path/to/codesucks-ai

# Scan all repositories in organization
./codesucks-ai \
  -repos ./org-repos.txt \
  -github-token $GITHUB_TOKEN \
  -config comprehensive \
  -out ./nightly-results/$(date +%Y-%m-%d) \
  -create-issue
```
