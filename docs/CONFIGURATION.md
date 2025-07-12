# Configuration Guide

This guide explains how to configure codesucks-ai for different use cases and environments.

## Configuration Files

codesucks-ai uses `.conf` files to define Semgrep scanning parameters. These files contain a `FLAGS=` line with Semgrep command-line arguments.

### Configuration File Format

```bash
# Comment lines start with #
# Configuration files must contain a FLAGS= line
FLAGS=--config p/security-audit --config p/secrets --no-git-ignore --timeout 300
```

### Built-in Presets

codesucks-ai includes several predefined configurations in the `configs/` directory:

#### `basic.conf`
- **Use case**: Fast scanning, CI/CD pipelines
- **Rules**: `p/trailofbits`
- **Performance**: Fastest
- **Coverage**: Minimal

```bash
FLAGS=--config p/trailofbits --no-git-ignore --timeout 300 --max-target-bytes 1000000
```

#### `codesucks-ai.conf` (Default)
- **Use case**: Balanced security scanning
- **Rules**: `p/trailofbits`, `p/security-audit`, `p/secrets`
- **Performance**: Good
- **Coverage**: Balanced

```bash
FLAGS=--config p/trailofbits --config p/security-audit --config p/secrets --no-git-ignore --timeout 300 --max-target-bytes 1000000
```

#### `security-focused.conf`
- **Use case**: Security team analysis
- **Rules**: `p/security-audit`, `p/secrets`, `p/owasp-top-ten`
- **Performance**: Moderate
- **Coverage**: Security-focused

```bash
FLAGS=--config p/security-audit --config p/secrets --config p/owasp-top-ten --no-git-ignore --timeout 300 --max-target-bytes 1000000
```

#### `comprehensive.conf`
- **Use case**: Thorough analysis, compliance
- **Rules**: All available rulesets
- **Performance**: Slower
- **Coverage**: Maximum

```bash
FLAGS=--config p/trailofbits --config p/security-audit --config p/secrets --config p/owasp-top-ten --config p/cwe-top-25 --config p/supply-chain --no-git-ignore --timeout 300 --max-target-bytes 1000000
```

#### `compliance.conf`
- **Use case**: Enterprise compliance scanning
- **Rules**: `p/cwe-top-25`, `p/supply-chain`, `p/security-audit`
- **Performance**: Moderate
- **Coverage**: Compliance-focused

```bash
FLAGS=--config p/cwe-top-25 --config p/supply-chain --config p/security-audit --no-git-ignore --timeout 300 --max-target-bytes 1000000
```

## Semgrep Rulesets

Understanding the available Semgrep rulesets helps you choose the right configuration:

### Core Rulesets

| Ruleset | Description | Focus |
|---------|-------------|-------|
| `p/trailofbits` | Trail of Bits security rules | High-confidence security issues |
| `p/security-audit` | General security audit rules | Common security vulnerabilities |
| `p/secrets` | Secret detection | API keys, passwords, tokens |
| `p/owasp-top-ten` | OWASP Top 10 vulnerabilities | Web application security |
| `p/cwe-top-25` | CWE Top 25 dangerous errors | Software security weaknesses |
| `p/supply-chain` | Supply chain security | Dependency vulnerabilities |

### Language-Specific Rules

Semgrep automatically applies language-specific rules based on detected file types:

- **JavaScript/TypeScript**: XSS, injection, prototype pollution
- **Python**: SQL injection, command injection, pickle vulnerabilities
- **Java**: Deserialization, injection, crypto issues
- **Go**: Race conditions, crypto misuse, injection
- **C/C++**: Buffer overflows, memory safety
- **PHP**: SQL injection, XSS, file inclusion

## Custom Configurations

### Creating Custom Configurations

1. Create a new `.conf` file:
   ```bash
   # myproject.conf
   FLAGS=--config p/security-audit --config p/secrets --timeout 600 --exclude="test/*"
   ```

2. Use the custom configuration:
   ```bash
   ./codesucks-ai -config myproject.conf -repo https://github.com/owner/repo
   ```

### Advanced Semgrep Options

Common Semgrep flags you can include in configuration files:

| Flag | Description | Example |
|------|-------------|---------|
| `--timeout` | Maximum scan time in seconds | `--timeout 600` |
| `--max-target-bytes` | Maximum file size to scan | `--max-target-bytes 5000000` |
| `--exclude` | Exclude file patterns | `--exclude="test/*"` |
| `--include` | Include only file patterns | `--include="*.js"` |
| `--severity` | Filter by severity | `--severity=ERROR` |
| `--confidence` | Filter by confidence | `--confidence=HIGH` |
| `--no-git-ignore` | Ignore .gitignore files | `--no-git-ignore` |
| `--max-chars-per-line` | Skip long lines | `--max-chars-per-line 1000` |

### Environment-Specific Configurations

#### Development Environment
```bash
# dev.conf - Fast feedback for developers
FLAGS=--config p/security-audit --timeout 120 --exclude="node_modules/*" --exclude="vendor/*"
```

#### CI/CD Pipeline
```bash
# ci.conf - Balanced for automated testing
FLAGS=--config p/trailofbits --config p/secrets --timeout 300 --no-git-ignore
```

#### Production Security Review
```bash
# production.conf - Comprehensive analysis
FLAGS=--config p/comprehensive --timeout 1800 --no-git-ignore --severity=ERROR
```

## Configuration Selection

### Command Line Usage

```bash
# Use preset by name
./codesucks-ai -config basic -repo https://github.com/owner/repo

# Use custom configuration file
./codesucks-ai -config ./myproject.conf -repo https://github.com/owner/repo

# Use absolute path
./codesucks-ai -config /path/to/custom.conf -repo https://github.com/owner/repo
```

### Shell Script Usage

```bash
# Use preset
./run-codesucks-ai.sh -c comprehensive -g $GITHUB_TOKEN -r https://github.com/owner/repo

# List available presets
./run-codesucks-ai.sh --list-presets
```

## Performance Tuning

### Fast Scanning
- Use `basic` preset
- Increase `--timeout` for large repositories
- Exclude test directories: `--exclude="test/*"`
- Limit file size: `--max-target-bytes 1000000`

### Comprehensive Scanning
- Use `comprehensive` preset
- Increase timeout: `--timeout 1800`
- Include all files: `--no-git-ignore`
- No file size limits

### Memory Optimization
- Reduce `--max-target-bytes`
- Exclude large directories
- Use multiple smaller scans instead of one large scan

## Troubleshooting

### Common Issues

1. **Timeout Errors**
   - Increase `--timeout` value
   - Exclude large directories
   - Use faster presets for large repositories

2. **Memory Issues**
   - Reduce `--max-target-bytes`
   - Exclude binary files
   - Scan directories separately

3. **False Positives**
   - Use higher confidence rules: `--confidence=HIGH`
   - Exclude test files: `--exclude="*test*"`
   - Use more targeted rulesets

4. **Missing Vulnerabilities**
   - Use `comprehensive` preset
   - Check if files are being excluded
   - Verify language support

### Debug Mode

Enable debug logging to troubleshoot configuration issues:

```bash
./codesucks-ai -debug -config myconfig.conf -repo https://github.com/owner/repo
```

This will show:
- Configuration file loading
- Semgrep command construction
- Rule application
- File processing

## Best Practices

1. **Start with presets**: Use built-in presets before creating custom configurations
2. **Test configurations**: Validate on known vulnerable code
3. **Document custom configs**: Add comments explaining rule choices
4. **Version control configs**: Store configurations in your repository
5. **Regular updates**: Update Semgrep regularly for new rules
6. **Monitor performance**: Balance thoroughness with scan time

## Integration Examples

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    ./codesucks-ai \
      -config security-focused \
      -repo ${{ github.repository }} \
      -github-token ${{ secrets.GITHUB_TOKEN }}
```

### Jenkins Pipeline

```groovy
stage('Security Scan') {
    steps {
        sh './codesucks-ai -config comprehensive -repo ${env.GIT_URL} -github-token ${env.GITHUB_TOKEN}'
    }
}
```

### Docker

```dockerfile
FROM golang:1.21-alpine
RUN apk add --no-cache python3 py3-pip
RUN pip3 install semgrep
COPY . /app
WORKDIR /app
RUN go build -o codesucks-ai ./cmd/codesucks-ai
ENTRYPOINT ["./codesucks-ai"]
```