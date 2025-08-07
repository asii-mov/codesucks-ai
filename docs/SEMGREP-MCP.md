# Semgrep MCP Integration

## Overview

The Semgrep Model Context Protocol (MCP) integration provides an advanced, AI-native interface for security scanning. Instead of executing Semgrep via command-line, the MCP mode communicates with a Semgrep MCP server that offers enhanced features and better integration with AI assistants.

## Benefits of MCP Mode

### Traditional CLI Mode vs MCP Mode

| Feature | CLI Mode | MCP Mode |
|---------|----------|----------|
| **Execution** | Process spawn | HTTP/JSON API |
| **Performance** | New process per scan | Persistent server |
| **AI Integration** | Limited | Native |
| **AST Analysis** | Not available | Built-in |
| **Custom Rules** | File-based | Dynamic |
| **Real-time Updates** | No | Possible |
| **Error Handling** | Exit codes | Structured errors |
| **Resource Usage** | Higher | Lower (server reuse) |

### Key Advantages

1. **Better AI Integration** - Native support for AI assistants like Claude
2. **Enhanced Features** - AST analysis, dynamic rules, incremental scanning
3. **Improved Performance** - Server persistence, connection pooling
4. **Structured Communication** - JSON-based protocol with typed responses
5. **Extensibility** - Easy to add new analysis capabilities

## Installation

### Quick Setup

Run the automated setup script:

```bash
./scripts/setup-mcp.sh
```

This will:
- Install Python dependencies (`semgrep-mcp`)
- Create configuration files
- Set up start/stop scripts
- Configure systemd service (optional)

### Manual Installation

1. **Install Semgrep MCP Server**
   ```bash
   pip3 install --user semgrep-mcp
   ```

2. **Install Semgrep** (if not already installed)
   ```bash
   pip3 install --user semgrep
   ```

3. **Start the MCP Server**
   ```bash
   python3 -m semgrep_mcp.server
   ```

   The server will start on `http://localhost:3000` by default.

## Usage

### Basic Usage

Enable MCP mode with the `-use-mcp-semgrep` flag:

```bash
# Standard scan using MCP
./build/codesucks-ai -use-mcp-semgrep -repo https://github.com/owner/repo

# With custom MCP server URL
./build/codesucks-ai -use-mcp-semgrep -mcp-server http://localhost:8080 -repo https://github.com/owner/repo

# Enable additional features
./build/codesucks-ai -use-mcp-semgrep -enable-ast -enable-custom-rules -repo https://github.com/owner/repo
```

### Configuration

#### Environment Variables

```bash
# Set MCP server URL (optional)
export SEMGREP_MCP_SERVER=http://localhost:3000

# Enable MCP mode by default
export CODESUCKS_USE_MCP=true
```

#### YAML Configuration

Add MCP settings to your YAML config file:

```yaml
# configs/mcp-enabled.yaml
target:
  repo: "https://github.com/owner/repo"

mcp:
  enabled: true
  server_url: "http://localhost:3000"
  timeout: 30
  features:
    ast_analysis: true
    custom_rules: true
    real_time: false

scanning:
  semgrep:
    mode: "mcp"  # "cli" or "mcp"
    config: "comprehensive"
```

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `-use-mcp-semgrep` | Enable MCP mode | `false` |
| `-mcp-server` | MCP server URL | `http://localhost:3000` |
| `-enable-ast` | Enable AST analysis | `false` |
| `-enable-custom-rules` | Enable custom rules | `false` |
| `-min-severity` | Minimum severity level | (all) |

## Features

### 1. Security Check

Quick security analysis of code snippets:

```go
// Internally uses the 'security_check' MCP tool
result := mcp.SecurityCheck(ctx, codeSnippet)
```

### 2. AST Analysis

Get Abstract Syntax Tree for code understanding:

```go
// Requires -enable-ast flag
ast := mcp.GetAST(ctx, code)
```

### 3. Custom Rules

Apply custom Semgrep rules dynamically:

```go
// Requires -enable-custom-rules flag
result := mcp.ScanWithCustomRule(ctx, path, customRule)
```

### 4. Incremental Scanning

Scan only changed files (future feature):

```go
// Coming soon: Real-time incremental analysis
result := mcp.ScanIncremental(ctx, changedFiles)
```

## Fallback Mechanism

The MCP integration includes automatic fallback to CLI mode:

1. **Try MCP Mode** - Attempts connection to MCP server
2. **Check Availability** - Pings server to verify it's running
3. **Fallback if Needed** - Automatically switches to CLI mode if MCP fails
4. **Log Transition** - Reports the fallback for debugging

```bash
# Output when fallback occurs:
⚠️  MCP mode failed: connection refused
🔄 Falling back to CLI mode...
🔍 Running Semgrep scan (CLI mode)...
```

## Troubleshooting

### Server Not Starting

1. **Check Python Version**
   ```bash
   python3 --version  # Should be 3.8+
   ```

2. **Verify Installation**
   ```bash
   pip3 list | grep semgrep-mcp
   ```

3. **Check Logs**
   ```bash
   tail -f /tmp/semgrep-mcp.log
   ```

### Connection Issues

1. **Verify Server is Running**
   ```bash
   curl http://localhost:3000/health
   ```

2. **Check Firewall**
   ```bash
   sudo ufw status  # Linux
   ```

3. **Test with Script**
   ```bash
   test-semgrep-mcp  # Created by setup script
   ```

### Performance Issues

1. **Increase Timeout**
   ```bash
   ./build/codesucks-ai -use-mcp-semgrep -mcp-timeout 60
   ```

2. **Check Server Resources**
   ```bash
   top -p $(pgrep -f semgrep_mcp)
   ```

3. **Restart Server**
   ```bash
   pkill -f semgrep_mcp
   start-semgrep-mcp
   ```

## Architecture

### Component Diagram

```
┌─────────────────┐
│  codesucks-ai   │
│   CLI Client    │
└────────┬────────┘
         │
    HTTP/JSON
         │
┌────────▼────────┐
│  MCP Protocol   │
│     Layer       │
└────────┬────────┘
         │
┌────────▼────────┐
│ Semgrep MCP     │
│    Server       │
└────────┬────────┘
         │
┌────────▼────────┐
│    Semgrep      │
│     Engine      │
└─────────────────┘
```

### Request Flow

1. **Client Request** - codesucks-ai sends MCP request
2. **Protocol Translation** - MCP server translates to Semgrep commands
3. **Analysis Execution** - Semgrep performs security analysis
4. **Result Formatting** - Results converted to MCP format
5. **Response Delivery** - Structured JSON response to client

## Advanced Configuration

### Custom MCP Server Configuration

Create `~/.config/mcp/semgrep-config.json`:

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 3000,
    "timeout": 30,
    "max_connections": 100
  },
  "semgrep": {
    "default_config": "auto",
    "max_file_size": 1048576,
    "timeout": 60,
    "metrics": true,
    "cache_results": true
  },
  "features": {
    "security_check": true,
    "semgrep_scan": true,
    "custom_rules": true,
    "ast_analysis": true,
    "platform_api": false
  },
  "logging": {
    "level": "INFO",
    "file": "/var/log/semgrep-mcp.log",
    "max_size": "100MB",
    "max_backups": 5
  }
}
```

### Running in Production

#### Docker Deployment

```dockerfile
FROM python:3.11-slim

RUN pip install semgrep-mcp semgrep

EXPOSE 3000

CMD ["python", "-m", "semgrep_mcp.server"]
```

```bash
docker build -t semgrep-mcp .
docker run -d -p 3000:3000 --name semgrep-mcp-server semgrep-mcp
```

#### Systemd Service

```ini
# /etc/systemd/system/semgrep-mcp.service
[Unit]
Description=Semgrep MCP Server
After=network.target

[Service]
Type=simple
User=semgrep
ExecStart=/usr/local/bin/python3 -m semgrep_mcp.server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable semgrep-mcp
sudo systemctl start semgrep-mcp
```

## API Reference

### MCP Tools Available

| Tool | Description | Parameters |
|------|-------------|------------|
| `security_check` | Quick security scan | `code` (string) |
| `semgrep_scan` | Full file/directory scan | `path`, `config` |
| `semgrep_scan_with_custom_rule` | Scan with custom rule | `path`, `rule` |
| `get_abstract_syntax_tree` | Get code AST | `code` |
| `semgrep_findings` | Get findings from platform | `deployment_id` |

### Error Codes

| Code | Description |
|------|-------------|
| 1001 | Server not available |
| 1002 | Invalid request format |
| 1003 | Tool not found |
| 1004 | Scan timeout |
| 1005 | Invalid configuration |

## Migration Guide

### From CLI to MCP

1. **Install MCP Server**
   ```bash
   ./scripts/setup-mcp.sh
   ```

2. **Update Command**
   ```bash
   # Old (CLI)
   ./build/codesucks-ai -repo https://github.com/owner/repo
   
   # New (MCP)
   ./build/codesucks-ai -use-mcp-semgrep -repo https://github.com/owner/repo
   ```

3. **Update CI/CD**
   ```yaml
   # GitHub Actions
   - name: Start MCP Server
     run: |
       pip install semgrep-mcp
       python -m semgrep_mcp.server &
       sleep 5
   
   - name: Run Security Scan
     run: ./build/codesucks-ai -use-mcp-semgrep -repo ${{ github.repository }}
   ```

## Future Enhancements

- **WebSocket Support** - Real-time scanning updates
- **Distributed Scanning** - Multiple MCP servers for large codebases
- **Custom Tool Extensions** - Add project-specific analysis tools
- **AI Model Integration** - Direct LLM integration for intelligent analysis
- **Incremental Analysis** - Scan only changed code
- **Result Caching** - Improved performance for repeated scans

## Resources

- [Semgrep MCP GitHub](https://github.com/semgrep/mcp)
- [Model Context Protocol Spec](https://modelcontextprotocol.io)
- [Semgrep Documentation](https://semgrep.dev/docs)
- [MCP Integration Examples](https://github.com/semgrep/mcp/examples)