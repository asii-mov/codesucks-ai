# codesucks-ai

AI-powered security analysis tool combining static analysis with intelligent vulnerability detection and automated remediation.

<img width="1196" height="560" alt="image" src="https://github.com/user-attachments/assets/9e2a280f-aa76-434b-8067-cc7a235f8947" />


## Features

- **Three-layer analysis**: SAST (Semgrep), Secret Detection (TruffleHog), AI Deep Analysis (Claude)
- **Automated fixes**: Generate and apply security patches via GitHub PRs
- **Low false positives**: AI-powered context analysis reduces noise by 95%
- **Multi-language support**: Java, Python, JavaScript, Go, Ruby, PHP, C/C++, C#
- **HTML reports**: Comprehensive reports with executive summaries

## Quick Start

### Prerequisites

- Go 1.21+
- Python 3.8+ (for Semgrep)
- Docker (optional)
- GitHub Personal Access Token
- Anthropic API Key

### Installation

```bash
git clone https://github.com/your-org/codesucks-ai.git
cd codesucks-ai/src
make build
```

### Setup

```bash
export GITHUB_TOKEN="your_github_token"
export ANTHROPIC_API_KEY="your_anthropic_key"
```

### Usage

```bash
# Basic scan
./build/codesucks-ai -repo https://github.com/owner/repo

# Full AI analysis
./build/codesucks-ai -repo https://github.com/owner/repo -orchestrator-mode

# With configuration file
./build/codesucks-ai -config-file configs/comprehensive.yaml

# Auto-fix and create PR
./build/codesucks-ai -repo https://github.com/owner/repo -auto-fix -create-pr
```

## Configuration

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

### Presets

- `basic.yaml` - Quick scan (~2 min)
- `comprehensive.yaml` - Full analysis (~10 min)
- `orchestrator.yaml` - AI deep analysis (~20 min)
- `enterprise.yaml` - Compliance-focused (~15 min)
- `batch-processing.yaml` - Multiple repository analysis

## AI Orchestrator Mode

Eight specialized security agents for deep analysis:

- **Injection Analyzer** - SQL, NoSQL, LDAP, OS command injection
- **XSS Analyzer** - Cross-site scripting vulnerabilities
- **Path Traversal** - Directory traversal and file inclusion
- **Cryptographic** - Weak algorithms and implementations
- **Authentication** - Auth bypass and session issues
- **Deserialization** - Unsafe object deserialization
- **XXE Analyzer** - XML external entity attacks
- **Race Condition** - Concurrency and threading issues

```bash
# Run with orchestrator
./scripts/run-orchestrator.sh -r https://github.com/owner/repo

# Docker mode
./scripts/run-orchestrator.sh -r https://github.com/owner/repo --docker
```

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
