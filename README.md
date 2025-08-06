# codesucks-ai

AI-Powered Security Analysis Tool with Advanced Orchestration

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org/)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue.svg)](https://www.docker.com/)

## Overview

codesucks-ai is a comprehensive security analysis tool that combines static code analysis (SAST) with AI-powered vulnerability detection and remediation. It uses Claude AI to provide intelligent analysis, reduce false positives, and automatically generate secure code fixes.

## Features

### Three-Layer Analysis Architecture

1. **Static Analysis** - Traditional SAST scanning powered by Semgrep with configurable rulesets
2. **Secret Detection** - TruffleHog integration for finding exposed credentials and API keys
3. **AI Deep Analysis** - Eight specialized security agents for advanced vulnerability detection

### Core Capabilities

- Intelligent false positive reduction using repository context analysis
- Automated vulnerability fixes with GitHub pull request creation
- Comprehensive HTML reports with executive summaries
- Docker containerization for secure, isolated execution
- Flexible YAML-based configuration system

## Quick Start

### Prerequisites

- Go 1.21 or higher
- Python 3 (required for Semgrep)
- Docker (optional, for containerized execution)
- GitHub Personal Access Token
- Anthropic API Key

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/codesucks-ai.git
cd codesucks-ai

# Build the project
cd src && make build

# Install dependencies
make deps
```

### Environment Setup

Set the following environment variables:

```bash
export GITHUB_TOKEN="github_pat_your_token_here"
export ANTHROPIC_API_KEY="sk-ant-api03-your_key_here"
```

### Basic Usage

```bash
# Standard security scan (SAST + Secret detection)
./build/codesucks-ai -repo https://github.com/owner/repo

# Full analysis with AI-powered deep scanning
./build/codesucks-ai -repo https://github.com/owner/repo -orchestrator-mode

# Using configuration file (recommended)
./build/codesucks-ai -config-file configs/comprehensive.yaml
```

## Configuration

### Using YAML Configuration Files

Create a configuration file to customize the analysis:

```yaml
target:
  repo: "https://github.com/owner/repo"

scanning:
  semgrep:
    enabled: true
    config: "comprehensive"
  trufflehog:
    enabled: true
    verify_secrets: true

ai_automation:
  enabled: true
  auto_fix: true
  create_pr: true

orchestrator:
  enabled: true
  agents_dir: "./agents"
  session_dir: "./sessions"

performance:
  threads: 10
  output_dir: "./results"
```

### Available Configuration Presets

- `comprehensive.yaml` - Complete analysis with all security layers
- `security-focused.yaml` - High-confidence security-prioritized scanning
- `orchestrator.yaml` - AI deep analysis configuration
- `enterprise.yaml` - Compliance-focused with conservative settings
- `batch-processing.yaml` - Optimized for analyzing multiple repositories

## Advanced Features

### AI Orchestrator Mode

The orchestrator mode enables deep security analysis using eight specialized AI agents:

1. **Injection Analyzer** - SQL, NoSQL, LDAP, and OS command injection detection
2. **XSS Analyzer** - Reflected, stored, and DOM-based cross-site scripting
3. **Path Traversal Analyzer** - File inclusion and directory traversal vulnerabilities
4. **Cryptographic Analyzer** - Weak algorithms and implementation flaws
5. **Authentication Analyzer** - Authentication bypass and session management issues
6. **Deserialization Analyzer** - Insecure deserialization patterns
7. **XXE Analyzer** - XML external entity vulnerabilities
8. **Race Condition Analyzer** - Concurrency and threading issues

To run with orchestrator mode:

```bash
# Using the main binary
./build/codesucks-ai -repo https://github.com/owner/repo -orchestrator-mode

# Using the convenience script
./scripts/run-orchestrator.sh -r https://github.com/owner/repo

# With Docker isolation
./scripts/run-orchestrator.sh -r https://github.com/owner/repo --docker
```

### Docker Execution

Run the tool in a containerized environment for enhanced security:

```bash
# Build Docker image
cd src && make docker-build

# Run with Docker Compose
docker-compose -f docker/docker-compose.orchestrator.yml up

# Or use the runner script
./scripts/run-orchestrator.sh -r https://github.com/owner/repo --docker
```

## Project Structure

```
codesucks-ai/
├── src/                    # Go source code
│   ├── cmd/               # Main application entry points
│   ├── common/            # Shared libraries and utilities
│   ├── runner/            # CLI and execution logic
│   └── Makefile          # Build automation
├── agents/                # Security analysis agent specifications
├── configs/               # YAML configuration templates
├── docs/                  # Documentation
├── scripts/               # Automation and helper scripts
├── docker/                # Docker configuration files
└── build/                 # Compiled binaries (gitignored)
```

## Development

### Building from Source

```bash
cd src
make build      # Build binary
make test       # Run tests
make lint       # Run linters
make clean      # Clean build artifacts
make all        # Complete build pipeline
```

### Testing

```bash
# Run unit tests
cd src && make test

# Test orchestrator implementation
./scripts/test-orchestrator.sh

# Run example scan
cd src && make run-example

# Performance benchmarking
cd src && make benchmark
```

## Documentation

- [Orchestrator Mode Guide](docs/ORCHESTRATOR-MODE.md) - Detailed orchestrator documentation
- [YAML Configuration Reference](docs/YAML-CONFIG.md) - Complete configuration options
- [Examples](docs/EXAMPLES.md) - Usage examples and patterns
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues and solutions

## Security Considerations

- This tool is designed exclusively for defensive security testing and remediation
- Never commit API keys or tokens to version control
- AI analysis runs in isolated Docker containers when using Docker mode
- Configure appropriate resource limits for your environment
- Agent configurations are mounted as read-only for security

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Support

- Documentation: [docs/](docs/)
- Issues: [GitHub Issues](https://github.com/your-org/codesucks-ai/issues)
- Releases: [GitHub Releases](https://github.com/your-org/codesucks-ai/releases)

---

Built for security researchers and developers to identify and remediate vulnerabilities in their codebases.