# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with codesucks-ai.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Orchestrator Mode Issues](#orchestrator-mode-issues)
- [MCP Integration Issues](#mcp-integration-issues)
- [Authentication Problems](#authentication-problems)
- [Scanning Issues](#scanning-issues)
- [Performance Problems](#performance-problems)
- [AI Integration Issues](#ai-integration-issues)
- [Configuration Problems](#configuration-problems)
- [GitHub Integration Issues](#github-integration-issues)
- [Common Error Messages](#common-error-messages)

## Installation Issues

### Semgrep Installation Failed

**Problem**: Error installing Semgrep
```
❌ Failed to install Semgrep
pip3 failed, trying pip...
```

**Solutions**:

1. **Manual Installation**:
   ```bash
   # Try different installation methods
   python3 -m pip install --user semgrep
   pip install --user semgrep
   brew install semgrep  # macOS
   ```

2. **Using break-system-packages** (Ubuntu/Debian):
   ```bash
   python3 -m pip install --user --break-system-packages semgrep
   ```

3. **Docker Installation**:
   ```bash
   docker pull returntocorp/semgrep
   alias semgrep="docker run --rm -v \${PWD}:/src returntocorp/semgrep --config=auto"
   ```

4. **Verify Installation**:
   ```bash
   which semgrep
   semgrep --version
   ```

### Go Build Issues

**Problem**: Build failures
```
go: module github.com/asii-mov/codesucks-ai: cannot find module
```

**Solutions**:

1. **Initialize Go Module**:
   ```bash
   go mod tidy
   go mod download
   ```

2. **Check Go Version**:
   ```bash
   go version  # Should be 1.21+
   ```

3. **Clean Build**:
   ```bash
   go clean -cache
   go build -o codesucks-ai ./cmd/codesucks-ai
   ```

### Path Issues

**Problem**: Binary not found
```
./codesucks-ai: command not found
```

**Solutions**:

1. **Make Executable**:
   ```bash
   chmod +x codesucks-ai
   ```

2. **Use Full Path**:
   ```bash
   /full/path/to/codesucks-ai [options]
   ```

3. **Add to PATH**:
   ```bash
   export PATH=$PATH:/path/to/codesucks-ai
   ```

## Orchestrator Mode Issues

### Claude CLI Not Found

**Problem**: Orchestrator mode falls back to legacy mode
```
Warning: Claude CLI not found in PATH
Falling back to legacy mode due to missing Claude CLI
```

**Solutions**:

1. **Install Claude Code CLI**:
   - Download from [Claude Code releases](https://docs.anthropic.com/en/docs/claude-code)
   - Ensure `claude` command is available in PATH
   - Test: `claude --version`

2. **Check PATH Configuration**:
   ```bash
   which claude
   echo $PATH
   ```

3. **Verify Installation**:
   ```bash
   claude --help
   # Should show Claude Code CLI help
   ```

### Orchestrator Mode Not Triggering

**Problem**: Orchestrator mode flag not working
```
Checking orchestrator mode - OrchestratorMode: false
Entering legacy scanning mode
```

**Solutions**:

1. **Recently Fixed**: Configuration merging bug that reset orchestrator mode
2. **Verify Flag Usage**:
   ```bash
   ./build/codesucks-ai -orchestrator-mode -repo https://github.com/owner/repo
   ```

3. **Check for Config File Conflicts**:
   ```bash
   # Ensure config file doesn't override CLI flags
   ./build/codesucks-ai -orchestrator-mode -repo https://github.com/owner/repo -config-file ""
   ```

### Agent Spawning Failures

**Problem**: Agents fail to start
```
Failed to create orchestrator: failed to initialize Claude SDK client
```

**Solutions**:

1. **Check ANTHROPIC_API_KEY**:
   ```bash
   echo $ANTHROPIC_API_KEY | head -c 20
   # Should show: sk-ant-api03-...
   ```

2. **Verify Agents Directory**:
   ```bash
   ls -la agents/
   # Should contain *.md agent configuration files
   ```

3. **Check Session Directory Permissions**:
   ```bash
   mkdir -p sessions
   chmod 755 sessions
   ```

### Session Creation Failures

**Problem**: Session directory errors
```
Failed to create session directory
```

**Solutions**:

1. **Check Disk Space**:
   ```bash
   df -h .
   ```

2. **Verify Write Permissions**:
   ```bash
   touch sessions/test.tmp && rm sessions/test.tmp
   ```

3. **Manual Session Directory**:
   ```bash
   mkdir -p sessions
   chmod 755 sessions
   ```

## MCP Integration Issues

### MCP Server Won't Start

**Problem**: Semgrep MCP server fails to start
```
error: externally-managed-environment
```

**Solutions**:

1. **Use Virtual Environment with uv**:
   ```bash
   uv venv mcp-env
   source mcp-env/bin/activate
   uv pip install semgrep-mcp semgrep
   ```

2. **Start MCP Server**:
   ```bash
   source mcp-env/bin/activate
   python -m semgrep_mcp.server
   ```

3. **Check Server Health**:
   ```bash
   curl http://localhost:3000/health
   ```

### MCP Version Compatibility

**Problem**: FastMCP version errors
```
TypeError: FastMCP.__init__() got an unexpected keyword argument 'version'
```

**Solutions**:

1. **Use Isolated Environment**:
   ```bash
   # Clean environment with uv
   rm -rf mcp-env
   uv venv mcp-env
   source mcp-env/bin/activate
   uv pip install semgrep-mcp
   ```

2. **Fallback to CLI Mode**:
   ```bash
   # Tool automatically falls back if MCP unavailable
   ./build/codesucks-ai -repo https://github.com/owner/repo
   ```

## Authentication Problems

### GitHub Token Issues

**Problem**: Authentication failed
```
❌ Error: GitHub authentication required
```

**Solutions**:

1. **Check Token Format**:
   ```bash
   # Classic tokens start with ghp_
   # Fine-grained tokens start with github_pat_
   echo $GITHUB_TOKEN | grep -E '^(ghp_|github_pat_)'
   ```

2. **Verify Token Permissions**:
   - Required scopes: `repo`, `read:org`
   - For PR creation: `pull_request`
   - For issues: `issues`

3. **Test Token**:
   ```bash
   curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user
   ```

4. **Environment Variable**:
   ```bash
   export GITHUB_TOKEN="your_token_here"
   ./codesucks-ai -repo https://github.com/owner/repo
   ```

### GitHub App Authentication

**Problem**: GitHub App authentication failed
```
❌ Error: GitHub App ID specified but private key missing
```

**Solutions**:

1. **Check Private Key File**:
   ```bash
   ls -la /path/to/private-key.pem
   cat /path/to/private-key.pem | head -1  # Should show -----BEGIN
   ```

2. **Correct Usage**:
   ```bash
   ./codesucks-ai \
     -github-app-id 123456 \
     -github-app-key /path/to/private-key.pem \
     -repo https://github.com/owner/repo
   ```

3. **Environment Variables**:
   ```bash
   export GITHUB_APP_ID="123456"
   export GITHUB_APP_PRIVATE_KEY="/path/to/private-key.pem"
   ```

### Anthropic API Issues

**Problem**: Claude AI authentication failed
```
❌ Error: AI features require Anthropic API key
```

**Solutions**:

1. **Check API Key Format**:
   ```bash
   # Should start with sk-ant-api03-
   echo $ANTHROPIC_API_KEY | grep '^sk-ant-api03-'
   ```

2. **Test API Access**:
   ```bash
   curl -H "Authorization: Bearer $ANTHROPIC_API_KEY" \
        -H "Content-Type: application/json" \
        https://api.anthropic.com/v1/messages
   ```

3. **Environment Variable**:
   ```bash
   export ANTHROPIC_API_KEY="sk-ant-api03-..."
   ```

## Scanning Issues

### Repository Access Problems

**Problem**: Cannot access repository
```
❌ Error: repository not found or access denied
```

**Solutions**:

1. **Check Repository URL**:
   ```bash
   # Correct format
   https://github.com/owner/repo
   
   # Not supported
   git@github.com:owner/repo.git
   ```

2. **Verify Repository Exists**:
   ```bash
   curl -H "Authorization: token $GITHUB_TOKEN" \
        https://api.github.com/repos/owner/repo
   ```

3. **Check Permissions**:
   - Public repos: Basic token access
   - Private repos: Token with repo scope
   - Organization repos: May need org membership

### Semgrep Execution Issues

**Problem**: Semgrep command failed
```
⚠️ Semgrep completed with warnings: exit status 2
```

**Solutions**:

1. **Check Semgrep Path**:
   ```bash
   which semgrep
   /home/user/.local/bin/semgrep --version
   ```

2. **Update PATH**:
   ```bash
   export PATH=$HOME/.local/bin:$PATH
   ./run-codesucks-ai.sh -s /home/user/.local/bin/semgrep
   ```

3. **Debug Semgrep**:
   ```bash
   ./codesucks-ai -debug -repo https://github.com/owner/repo
   ```

### Configuration Loading Issues

**Problem**: Configuration file not found
```
Using fallback configuration
```

**Solutions**:

1. **Check Config File**:
   ```bash
   ls -la configs/
   cat configs/codesucks-ai.conf
   ```

2. **Use Absolute Path**:
   ```bash
   ./codesucks-ai -config /full/path/to/config.conf
   ```

3. **Verify Config Format**:
   ```bash
   # configs/test.conf
   FLAGS=--config p/security-audit --timeout 300
   ```

## Performance Problems

### Slow Scanning

**Problem**: Scans taking too long
```
Scan running for over 30 minutes...
```

**Solutions**:

1. **Use Faster Configuration**:
   ```bash
   ./codesucks-ai -config basic -repo https://github.com/owner/repo
   ```

2. **Increase Timeout**:
   ```bash
   # Custom config with longer timeout
   echo "FLAGS=--config p/basic --timeout 1800" > fast.conf
   ./codesucks-ai -config fast.conf
   ```

3. **Exclude Large Directories**:
   ```bash
   # Create optimized config
   cat > optimized.conf << EOF
   FLAGS=--config p/security-audit --exclude="node_modules/*" --exclude="vendor/*" --exclude="*.min.js"
   EOF
   ```

4. **Reduce Threads**:
   ```bash
   ./codesucks-ai -threads 2 -repo https://github.com/owner/repo
   ```

### Memory Issues

**Problem**: Out of memory errors
```
runtime: out of memory
```

**Solutions**:

1. **Limit File Size**:
   ```bash
   echo "FLAGS=--config p/basic --max-target-bytes 500000" > memory-safe.conf
   ./codesucks-ai -config memory-safe.conf
   ```

2. **Exclude Binary Files**:
   ```bash
   cat > no-binaries.conf << EOF
   FLAGS=--config p/security-audit --exclude="*.jpg" --exclude="*.png" --exclude="*.pdf" --exclude="*.zip"
   EOF
   ```

3. **Process in Chunks**:
   ```bash
   # Scan different parts separately
   ./codesucks-ai -config basic -repo https://github.com/owner/repo
   ```

### Rate Limiting

**Problem**: GitHub API rate limits
```
❌ Error: API rate limit exceeded
```

**Solutions**:

1. **Check Rate Limit Status**:
   ```bash
   curl -H "Authorization: token $GITHUB_TOKEN" \
        https://api.github.com/rate_limit
   ```

2. **Reduce Concurrent Requests**:
   ```bash
   ./codesucks-ai -threads 1 -repo https://github.com/owner/repo
   ```

3. **Use GitHub App** (Higher limits):
   ```bash
   ./codesucks-ai \
     -github-app-id $APP_ID \
     -github-app-key private-key.pem \
     -repo https://github.com/owner/repo
   ```

4. **Wait and Retry**:
   ```bash
   # Rate limits reset every hour
   sleep 3600
   ./codesucks-ai [options]
   ```

## AI Integration Issues

### Claude API Errors

**Problem**: AI features not working
```
❌ Error: Claude API request failed
```

**Solutions**:

1. **Check API Key**:
   ```bash
   curl -H "Authorization: Bearer $ANTHROPIC_API_KEY" \
        https://api.anthropic.com/v1/messages
   ```

2. **Verify Usage Limits**:
   - Check Anthropic console for usage
   - Ensure sufficient credits/quota

3. **Test with Simple Request**:
   ```bash
   ./codesucks-ai \
     -repo https://github.com/owner/small-repo \
     -auto-fix \
     -anthropic-key $ANTHROPIC_API_KEY
   ```

### Fix Quality Issues

**Problem**: Poor quality AI fixes
```
AI generated fixes seem incorrect
```

**Solutions**:

1. **Increase Confidence Threshold**:
   ```bash
   ./codesucks-ai -min-confidence 0.95 -auto-fix
   ```

2. **Use Comprehensive Config**:
   ```bash
   ./codesucks-ai -config comprehensive -auto-fix
   ```

3. **Review Before Applying**:
   ```bash
   # Generate fixes without PR creation
   ./codesucks-ai -auto-fix
   # Review fixes manually before creating PR
   ```

## Configuration Problems

### Invalid Configuration

**Problem**: Configuration parsing errors
```
Error: invalid configuration format
```

**Solutions**:

1. **Validate Config Format**:
   ```bash
   # Correct format
   FLAGS=--config p/security-audit --timeout 300
   
   # Not: CONFIG=... or ARGS=...
   ```

2. **Check for Special Characters**:
   ```bash
   # Escape quotes if needed
   FLAGS=--config p/security-audit --exclude="test/*"
   ```

3. **Test Configuration**:
   ```bash
   # Test with debug mode
   ./codesucks-ai -debug -config test.conf
   ```

### Missing Presets

**Problem**: Preset not found
```
Configuration preset 'custom' not found
```

**Solutions**:

1. **List Available Presets**:
   ```bash
   ./run-codesucks-ai.sh --list-presets
   ./codesucks-ai -list-presets
   ```

2. **Check Config Directory**:
   ```bash
   ls -la configs/
   ```

3. **Use Full Path**:
   ```bash
   ./codesucks-ai -config ./my-custom.conf
   ```

## GitHub Integration Issues

### Pull Request Creation Failed

**Problem**: Cannot create pull requests
```
❌ Error: failed to create pull request
```

**Solutions**:

1. **Check Repository Permissions**:
   - Token needs `pull_request` scope
   - User must have write access to repo

2. **Verify Branch State**:
   ```bash
   # Ensure main branch exists and is accessible
   curl -H "Authorization: token $GITHUB_TOKEN" \
        https://api.github.com/repos/owner/repo/branches/main
   ```

3. **Test PR Creation Manually**:
   ```bash
   # Use GitHub CLI to test
   gh pr create --title "Test" --body "Test PR"
   ```

### Issue Creation Failed

**Problem**: Cannot create issues
```
❌ Error: failed to create GitHub issue
```

**Solutions**:

1. **Check Issues Enabled**:
   - Repository settings → Features → Issues

2. **Verify Token Permissions**:
   - Token needs `issues` scope

3. **Test Issue Creation**:
   ```bash
   curl -X POST \
     -H "Authorization: token $GITHUB_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"title":"Test","body":"Test issue"}' \
     https://api.github.com/repos/owner/repo/issues
   ```

## Common Error Messages

### "repository not found or access denied"

**Cause**: Invalid repository URL or insufficient permissions
**Solution**: Verify repository URL and token permissions

### "semgrep not found or not working"

**Cause**: Semgrep not installed or not in PATH
**Solution**: Install Semgrep and update PATH

### "GitHub authentication required"

**Cause**: Missing or invalid GitHub token
**Solution**: Set GITHUB_TOKEN environment variable

### "AI features require Anthropic API key"

**Cause**: Missing Anthropic API key when using AI features
**Solution**: Set ANTHROPIC_API_KEY environment variable

### "failed to parse Semgrep output"

**Cause**: Semgrep execution failed or invalid output
**Solution**: Check Semgrep configuration and target repository

### "invalid GitHub repository URL"

**Cause**: Malformed repository URL
**Solution**: Use format: https://github.com/owner/repo

## Debug Mode

Enable debug logging to get detailed information:

```bash
./codesucks-ai -debug [other options]
```

Debug mode shows:
- Configuration loading process
- GitHub API requests and responses
- Semgrep command execution
- File processing details
- Error stack traces

## Getting Help

If you continue to experience issues:

1. **Check Documentation**:
   - [Configuration Guide](CONFIGURATION.md)
   - [Examples](EXAMPLES.md)

2. **Enable Debug Mode**:
   ```bash
   ./codesucks-ai -debug [options] > debug.log 2>&1
   ```

3. **Create Issue**:
   - Include debug output
   - Describe exact steps to reproduce
   - Include system information (OS, Go version, Semgrep version)

4. **Test with Minimal Example**:
   ```bash
   # Test with small public repository
   ./codesucks-ai \
     -repo https://github.com/octocat/Hello-World \
     -github-token $GITHUB_TOKEN \
     -config basic \
     -debug
   ```

## System Requirements

**Minimum Requirements**:
- Go 1.21+
- Python 3.7+ (for Semgrep)
- 2GB RAM
- 1GB disk space

**Recommended**:
- Go 1.21+
- Python 3.9+
- 4GB RAM
- 5GB disk space
- Fast internet connection

**Supported Platforms**:
- Linux (Ubuntu, CentOS, Alpine)
- macOS (Intel, Apple Silicon)
- Windows (WSL recommended)