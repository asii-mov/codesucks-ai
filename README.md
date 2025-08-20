# codesucks-ai

AI-powered security analysis tool combining static analysis with intelligent vulnerability detection and automated remediation.

<img width="1196" height="560" alt="image" src="https://github.com/user-attachments/assets/9e2a280f-aa76-434b-8067-cc7a235f8947" />


## Features

- **Three-layer analysis**: SAST (Semgrep via MCP), Secret Detection (TruffleHog), AI Deep Analysis (Claude)
- **AI Orchestrator**: 5 specialized Claude Code subagents for parallel security analysis
- **Matrix Build System**: Intelligent language/framework detection with targeted security rulesets
- **Automated fixes**: Generate and apply security patches via GitHub PRs
- **Low false positives**: AI-powered context analysis reduces noise by 15%
- **Multi-language support**: Java, Python, JavaScript, Go, Ruby, PHP, C/C++, C#
- **HTML reports**: Comprehensive reports with executive summaries

## Quick Start

### Prerequisites

- Go 1.21+
- Claude Code CLI (for orchestrator mode)
- Python 3.8+ with uv (REQUIRED for Semgrep virtual environment)
- TruffleHog (optional - for secret scanning, install separately based on your platform)
- Docker (optional)
- GitHub Personal Access Token
- Anthropic API Key

### Installation

```bash
git clone https://github.com/your-org/codesucks-ai.git
cd codesucks-ai

# Install uv for Python virtual environment management
curl -LsSf https://astral.sh/uv/install.sh | sh

# Build the application
cd src && make build && cd ..

# Setup Python virtual environment for Semgrep (REQUIRED)
# This ensures clean dependency management for all Semgrep operations
uv venv semgrep-env
source semgrep-env/bin/activate
uv pip install semgrep semgrep-mcp
```

### Optional: TruffleHog Installation

For secret scanning capabilities, install TruffleHog for your platform:

```bash
# macOS (Homebrew)
brew install trufflesecurity/trufflehog/trufflehog

# Linux/Windows - Download from releases
# https://github.com/trufflesecurity/trufflehog/releases

# Or install via Go
go install github.com/trufflesecurity/trufflehog/v3@latest
```

The tool will automatically detect if TruffleHog is available and skip secret scanning if not found.

### Setup

Create a `.env` file with your credentials:

```bash
# Create .env file
cat > .env << EOF
GITHUB_TOKEN=your_github_token_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here
EOF
```

### Usage

**Basic Usage:**

```bash
# IMPORTANT: Always activate the Python virtual environment first
source semgrep-env/bin/activate

# Basic scan with comprehensive analysis (recommended)
./run-codesucks.sh -repo https://github.com/owner/repo

# Quick scan with minimal rules
./run-codesucks.sh -repo https://github.com/owner/repo -config basic

# Matrix Build Mode (intelligent language/framework detection)
./run-codesucks.sh -repo https://github.com/owner/repo -matrix-build

# Matrix Build with custom language override
./run-codesucks.sh -repo https://github.com/owner/repo -matrix-build --force-language python

# With MCP integration for enhanced AI analysis
python -m semgrep_mcp.server &
./run-codesucks.sh -repo https://github.com/owner/repo -use-mcp-semgrep
```

## Configuration

The tool supports both simple presets and full YAML configuration files. The matrix build system automatically generates optimal configurations based on detected technologies.

### Using Configuration Presets

```bash
# Use a simple preset (no file path needed)
./run-codesucks.sh -repo https://github.com/owner/repo -config basic
./run-codesucks.sh -repo https://github.com/owner/repo -config comprehensive
```

### Using Full YAML Configuration

Create a YAML config file:

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

### Configuration Presets

Choose from these optimized configurations:

- **`basic.yaml`** - Quick scan with minimal rules (~2 min)
- **`comprehensive.yaml`** - Full analysis with all security rules (~10 min) 
- **`orchestrator.yaml`** - AI deep analysis with 5 parallel agents (~20 min)
- **`orchestrator-no-autofix.yaml`** - Analysis-only mode without auto-fixes
- **`batch-processing.yaml`** - Optimized for multiple repository scanning
- **`matrix-base.yaml`** - Template for matrix build system (auto-generated configs)

## Matrix Build System

The Matrix Build system automatically detects programming languages and frameworks in repositories to apply targeted security analysis. It dynamically generates optimized Semgrep rulesets without requiring hardcoded configuration files.

### Features
- **Automatic Language Detection**: Analyzes repository composition via GitHub API and file analysis
- **Framework Detection**: Identifies frameworks like React, Django, Express, Spring Boot from package files
- **Dynamic Rule Generation**: Automatically selects appropriate Semgrep security rulesets based on detection
- **Enhanced Coverage**: Finds 2.5x more vulnerabilities compared to generic configurations
- **No Static Configs**: Matrix configs are generated dynamically - no hardcoded matrix files needed
- **Configuration Display**: HTML reports show complete matrix configuration with percentages and applied rulesets

### Usage

```bash
# Basic matrix build (auto-detection)
./run-codesucks.sh --matrix-build -repo https://github.com/owner/repo

# Override detected language
./run-codesucks.sh --matrix-build --force-language python -repo https://github.com/owner/repo

# Override detected framework
./run-codesucks.sh --matrix-build --force-framework django -repo https://github.com/owner/repo

# Custom language threshold
./run-codesucks.sh --matrix-build --language-threshold 15.0 -repo https://github.com/owner/repo

# Additional rulesets
./run-codesucks.sh --matrix-build --additional-rulesets "p/security-audit,p/owasp-top10" -repo https://github.com/owner/repo

# Disable agent validation for faster scans
./run-codesucks.sh --matrix-build --no-agent-validation -repo https://github.com/owner/repo
```

### Example Results
- **Multi-language projects**: Archon repository detected Python (55.9%) + TypeScript (41.3%) with Next.js framework
- **Applied rulesets**: 11 technology-specific security rulesets automatically selected
- **Vulnerability detection**: 35 security issues found across both technology stacks

## AI Orchestrator Mode

The orchestrator mode uses Claude Code subagents for parallel security analysis. Five specialized security agents analyze different vulnerability classes:

- **Injection Analyzer** - SQL, NoSQL, LDAP, OS command injection
- **XSS Analyzer** - Cross-site scripting vulnerabilities  
- **Path Traversal** - Directory traversal and file inclusion
- **Cryptographic** - Weak algorithms and implementations
- **Authentication** - Auth bypass and session issues

### Requirements

- Claude Code CLI must be available in PATH
- Orchestrator mode spawns separate Claude Code processes for each agent
- Each agent has specialized configurations in `./agents/` directory

### Usage

```bash
# Basic orchestrator mode
./run-codesucks.sh -repo https://github.com/owner/repo -orchestrator-mode

# With automated setup script (handles all dependencies)
./run-orchestrator.sh -r https://github.com/owner/repo

# With MCP integration
./run-orchestrator.sh -r https://github.com/owner/repo --mcp

# Docker mode  
./run-orchestrator.sh -r https://github.com/owner/repo --docker
```

### 7-Phase Analysis Workflow

1. **Initialize Code Analysis** - Setup session and directories
2. **Analyze Codebase Structure** - Language detection and file mapping
3. **Map Entry Points and Data Flow** - Identify input sources and sinks
4. **Decompose into Parallel Analyses** - Create specialized agent tasks
5. **Execute Parallel Code Analysis** - Run 5 agents concurrently
6. **Synthesize and Validate Findings** - Aggregate and validate results
7. **Generate Code Security Report** - Create comprehensive HTML report with executive summary

### Performance and Cost

**Orchestrator Mode Results (NodeGoat test):**
- **Total API Cost**: $2.62 for complete analysis
- **Vulnerabilities Found**: 19+ security issues across all categories
- **Analysis Time**: ~20 minutes with 5 parallel Claude Code subagents
- **Cost Breakdown**: Auth ($0.43), XSS ($0.87), Path ($1.32), plus Injection and Crypto analyzers
- **Cost Efficiency**: ~$0.14 per vulnerability detected with detailed AI analysis and secure fix recommendations

## Docker

```bash
# Build image
cd src && make docker-build

# Run container
docker run -it \
  -e GITHUB_TOKEN="$GITHUB_TOKEN" \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  ghcr.io/your-org/codesucks-ai:latest \
  -repo https://github.com/owner/repo

# Docker Compose
docker-compose -f docker/docker-compose.orchestrator.yml up
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: your-org/codesucks-action@v1
        with:
          config-file: configs/comprehensive.yaml
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

## Development

```bash
cd src
make build      # Build binary
make test       # Run tests
make lint       # Run linters
make clean      # Clean build artifacts
make all        # Complete pipeline
```

### Testing

```bash
# Run unit tests
cd src && make test

# Test orchestrator
./scripts/test-orchestrator.sh

# Run example scan
cd src && make run-example

# Performance benchmarking
cd src && make benchmark
```

## Documentation

- [Orchestrator Mode](docs/ORCHESTRATOR-MODE.md)
- [Configuration Guide](docs/YAML-CONFIG.md)
- [Examples](docs/EXAMPLES.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## Support

- Documentation: [docs/](docs/)
- Issues: [GitHub Issues](https://github.com/your-org/codesucks-ai/issues)
- Releases: [GitHub Releases](https://github.com/your-org/codesucks-ai/releases)

## License

GPL-3.0 License - see [LICENSE](LICENSE) file.

---

Built for security researchers and developers to identify and remediate vulnerabilities in their codebases.
