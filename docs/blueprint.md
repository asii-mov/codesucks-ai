# codesucks-ai Technical Implementation Guide

This document provides comprehensive technical details for reproducing codesucks-ai's functionality. Use this as a reference for implementing similar security automation tools.

## 🏗️ Core Architecture

### Technology Stack
- **Language**: Go 1.23+ (required for build)
- **Static Analysis Engine**: Semgrep (external binary dependency)
- **AI Integration**: Anthropic Claude API (claude-3-5-sonnet-20241022 default)
- **Version Control**: GitHub API v4 (REST)
- **Build System**: Go modules with `go.mod`

### Project Structure
```
cmd/
├── codesucks-ai/codesucks-ai.go          # Main CLI entry point
└── monitor/monitor.go              # GitHub issue monitoring daemon
common/
├── ai/claude.go                    # Anthropic Claude API client
├── github/automation.go           # GitHub automation (branches, PRs, issues)
├── codesucks-ai/
│   ├── sast.go                     # Semgrep execution and parsing
│   ├── downloader.go               # GitHub ZIP download and extraction
│   ├── extractor.go                # Repository metadata extraction
│   └── display.go                  # Terminal output formatting
├── report/                         # HTML report generation
├── feed/repos.go                   # Input processing (stdin, files)
├── logger/logger.go                # Structured logging
└── types.go                        # Shared data structures
runner/
├── runner.go                       # Core scanning orchestration
├── options.go                      # CLI argument parsing
└── banner.go                       # Terminal banner display
```

## 🔧 Core Implementation Details

### CLI Framework
```go
// Use standard library flag package
import "flag"

type Options struct {
    // Target specification
    Repo  string    // Single repository URL
    Repos string    // File containing repository list
    
    // Scanning configuration
    NoSemgrep       bool
    SemgrepPath     string
    ConfigPath      string
    OutDir          string
    
    // AI automation
    AutoFix         bool
    CreatePR        bool
    CreateIssue     bool
    AIModel         string
    AnthropicAPIKey string
    MinConfidence   float64
    
    // GitHub integration
    GitHubToken     string
    
    // Performance
    Threads         int
    Debug           bool
}
```

### Semgrep Integration
```bash
# Required semgrep installation
pip install semgrep

# Default rule configuration (embedded or external)
semgrep --config=auto --json --output=/tmp/results.json /path/to/source
```

#### Semgrep Rule Categories Used
- **Security Rules**: `--config=p/security-audit`
- **OWASP Top 10**: `--config=p/owasp-top-ten`
- **Language-Specific**: `--config=p/javascript`, `--config=p/python`
- **Framework Rules**: `--config=p/django`, `--config=p/react`
- **Supply Chain**: `--config=p/supply-chain`

### GitHub Repository Processing
```go
// Repository download process
func DownloadSource(client *http.Client, targetURL, branch, outDir string) (string, error) {
    // 1. Construct GitHub ZIP archive URL
    zipURL := targetURL + "/archive/refs/heads/" + branch + ".zip"
    
    // 2. Download ZIP with proper User-Agent
    zipBytes, err := HTTPGet(client, zipURL, headers)
    
    // 3. Extract with security controls
    return UnzipBytes(zipBytes, outDir)
}

// Critical: Handle GitHub ZIP structure
// GitHub ZIPs contain: repo-branch-name/actual-files/
// Must strip prefix for GitHub API compatibility
func NormalizePath(path, sourcePath string) string {
    relativePath := strings.TrimPrefix(path, sourcePath)
    relativePath = strings.TrimPrefix(relativePath, "/")
    
    // Strip GitHub ZIP prefix (universal for all repos)
    pathParts := strings.Split(relativePath, "/")
    if len(pathParts) > 1 {
        relativePath = strings.Join(pathParts[1:], "/")
    }
    return relativePath
}
```

### Semgrep Output Parsing
```go
type SemgrepJson struct {
    Results []Result `json:"results"`
    Errors  []Error  `json:"errors"`
}

type Result struct {
    CheckID string `json:"check_id"`
    Path    string `json:"path"`
    Start   struct {
        Line int `json:"line"`
        Col  int `json:"col"`
    } `json:"start"`
    End struct {
        Line int `json:"line"`
        Col  int `json:"col"`
    } `json:"end"`
    Extra struct {
        Message  string `json:"message"`
        Lines    string `json:"lines"`
        Metadata struct {
            Impact string `json:"impact"`
        } `json:"metadata"`
    } `json:"extra"`
}
```

## 🤖 AI Integration Implementation

### Claude API Client
```go
const (
    ClaudeAPIEndpoint = "https://api.anthropic.com/v1/messages"
    DefaultModel      = "claude-3-5-sonnet-20241022"
    MaxTokens         = 4096
)

type ClaudeRequest struct {
    Model     string    `json:"model"`
    MaxTokens int       `json:"max_tokens"`
    Messages  []Message `json:"messages"`
}

type SecurityAnalysis struct {
    Vulnerability string  `json:"vulnerability"`
    Severity      string  `json:"severity"`
    Fix           string  `json:"fix"`
    Explanation   string  `json:"explanation"`
    Confidence    float64 `json:"confidence"`
}
```

### AI Prompting Strategy
```go
func GenerateSecurityPrompt(finding Result, context string) string {
    return fmt.Sprintf(`You are a security expert analyzing and fixing code vulnerabilities.

**File:** %s
**Vulnerability:** %s
**Description:** %s
**Severity:** %s

**Vulnerable Code (lines %d-%d):**
```
%s
```

**Context (with surrounding lines):**
```
%s
```

Please provide:
1. A secure fix for this vulnerability
2. An explanation of why it's vulnerable and how the fix addresses it
3. A confidence level (0.0-1.0) for your fix

Respond in JSON format:
{
  "vulnerability": "vulnerability type",
  "severity": "severity level", 
  "fix": "corrected code that replaces the vulnerable lines",
  "explanation": "detailed explanation of the vulnerability and fix",
  "confidence": 0.95
}

Important: The "fix" should contain ONLY the corrected code that will replace lines %d-%d, with proper indentation preserved.`,
        filePath, finding.CheckID, finding.Extra.Message, finding.Extra.Metadata.Impact,
        finding.Start.Line, finding.End.Line, vulnerableCode, contextCode,
        finding.Start.Line, finding.End.Line)
}
```

## 🔀 GitHub Automation Implementation

### GitHub API Integration
```go
import (
    "github.com/google/go-github/v66/github"
    "golang.org/x/oauth2"
)

type GitHubAutomation struct {
    client *github.Client
    ctx    context.Context
}

// Branch creation with timestamp
func (ga *GitHubAutomation) CreateFixBranch(owner, repo string) (*FixBranch, error) {
    timestamp := time.Now().Format("20060102-150405")
    branchName := fmt.Sprintf("security-fixes-%s", timestamp)
    
    // Get default branch SHA
    ref, _, err := ga.client.Git.GetRef(ga.ctx, owner, repo, "refs/heads/"+defaultBranch)
    
    // Create new branch
    newRef := &github.Reference{
        Ref: github.String("refs/heads/" + branchName),
        Object: &github.GitObject{SHA: ref.Object.SHA},
    }
    
    _, _, err = ga.client.Git.CreateRef(ga.ctx, owner, repo, newRef)
    return &FixBranch{BranchName: branchName, RepoOwner: owner, RepoName: repo}, err
}

// Apply security fix as commit
func (ga *GitHubAutomation) ApplySecurityFix(branch *FixBranch, fix SecurityFix) error {
    // Get current file content
    fileContent, _, _, err := ga.client.Repositories.GetContents(
        ga.ctx, branch.RepoOwner, branch.RepoName, fix.FilePath,
        &github.RepositoryContentGetOptions{Ref: branch.BranchName})
    
    // Apply line-level changes
    content, _ := fileContent.GetContent()
    lines := strings.Split(content, "\n")
    
    // Replace vulnerable lines with fix
    var newLines []string
    newLines = append(newLines, lines[:fix.StartLine-1]...)
    newLines = append(newLines, strings.Split(fix.FixedCode, "\n")...)
    newLines = append(newLines, lines[fix.EndLine:]...)
    
    newContent := strings.Join(newLines, "\n")
    
    // Commit the fix
    commitMessage := fmt.Sprintf("🔒 Fix %s vulnerability in %s\n\n%s", 
        fix.Vulnerability, fix.FilePath, fix.Description)
    
    _, _, err = ga.client.Repositories.UpdateFile(ga.ctx, branch.RepoOwner, branch.RepoName, fix.FilePath,
        &github.RepositoryContentFileOptions{
            Message: github.String(commitMessage),
            Content: []byte(newContent),
            SHA:     fileContent.SHA,
            Branch:  github.String(branch.BranchName),
        })
    
    return err
}
```

### Pull Request Generation
```go
func (ga *GitHubAutomation) CreatePullRequest(branch *FixBranch) error {
    title := fmt.Sprintf("🔒 Security fixes (%d vulnerabilities)", len(branch.Fixes))
    
    var bodyBuilder strings.Builder
    bodyBuilder.WriteString("## 🔒 Automated Security Fixes\n\n")
    bodyBuilder.WriteString("This PR contains automated security fixes generated by codesucks-ai.\n\n")
    bodyBuilder.WriteString("### Vulnerabilities Fixed:\n\n")
    
    for i, fix := range branch.Fixes {
        bodyBuilder.WriteString(fmt.Sprintf("%d. **%s** in `%s` (lines %d-%d)\n", 
            i+1, fix.Vulnerability, fix.FilePath, fix.StartLine, fix.EndLine))
        bodyBuilder.WriteString(fmt.Sprintf("   - %s\n\n", fix.Description))
    }
    
    pr, _, err := ga.client.PullRequests.Create(ga.ctx, branch.RepoOwner, branch.RepoName,
        &github.NewPullRequest{
            Title: github.String(title),
            Head:  github.String(branch.BranchName),
            Base:  github.String(defaultBranch),
            Body:  github.String(bodyBuilder.String()),
        })
    
    return err
}
```

## 📊 Report Generation

### HTML Report Structure
```go
type ReportData struct {
    Target                     string
    VulnerabilityStats         map[string]int
    VulnerabilityStatsOrdering []string
    SeverityStats              map[string]int
    SeverityStatsOrdering      []string
    Findings                   []SemgrepFinding
}

type SemgrepFinding struct {
    VulnerabilityTitle string
    Severity           string
    Description        string
    Code               string
    StartLine          int
    StopLine           int
    GithubLink         string
}
```

### Deduplication Logic
```go
func deduplicateFindings(findings []SemgrepFinding) []SemgrepFinding {
    seen := make(map[string]bool)
    fileFindings := make(map[string][]SemgrepFinding)
    
    for _, finding := range findings {
        // Create exact match key
        exactKey := fmt.Sprintf("%s:%d-%d:%s", 
            finding.GithubLink, finding.StartLine, finding.StopLine, finding.VulnerabilityTitle)
        
        if seen[exactKey] {
            continue
        }
        
        // Check for overlapping findings
        shouldSkip := false
        for _, existing := range fileFindings[finding.GithubLink] {
            if hasOverlappingLines(finding, existing) && isSimilarVulnerability(finding, existing) {
                if shouldPreferExisting(existing, finding) {
                    shouldSkip = true
                    break
                }
            }
        }
        
        if !shouldSkip {
            seen[exactKey] = true
            deduplicated = append(deduplicated, finding)
            fileFindings[finding.GithubLink] = append(fileFindings[finding.GithubLink], finding)
        }
    }
    
    return deduplicated
}
```

## 🔄 Workflow Orchestration

### Main Scanning Pipeline
```go
func scanTarget(target string, options *Options, httpClient *http.Client) (RepoInfo, error) {
    // 1. Extract repository metadata
    repoDoc, err := GetRepoDocument(httpClient, target)
    repoInfo, err := ExtractRepoInfo(repoDoc, options)
    
    // 2. Download source code
    sourcePath, err := DownloadSource(httpClient, target, repoInfo.Branch, options.OutDir)
    defer os.RemoveAll(sourcePath) // Cleanup unless --save-repo
    
    // 3. Run semgrep analysis
    semgrepJson, err := RunSemgrep(sourcePath, options.OutDir)
    
    // 4. AI-powered auto-fix workflow (if enabled)
    if options.AutoFix && len(semgrepJson.Results) > 0 {
        err := executeAutoFixWorkflow(target, semgrepJson, sourcePath, options)
    }
    
    // 5. Generate reports
    reportPath, err := GenerateHTML(reportData, options.OutDir)
    
    return repoInfo, nil
}
```

### Auto-Fix Workflow
```go
func executeAutoFixWorkflow(target string, semgrepJson SemgrepJson, sourcePath string, options *Options) error {
    // Parse repository URL
    owner, repo, err := ParseRepositoryURL(target)
    
    // Initialize clients
    claudeClient := NewClaudeClient(options.AnthropicAPIKey)
    ghClient, err := NewGitHubAutomation(options.GitHubToken)
    
    // Create fix branch
    fixBranch, err := ghClient.CreateFixBranch(owner, repo)
    
    successfulFixes := 0
    
    for _, result := range semgrepJson.Results {
        // Read vulnerable file
        fileContent, err := ReadFileAsString(result.Path)
        
        // Get relative path (critical: strip GitHub ZIP prefix)
        relativePath := NormalizePath(result.Path, sourcePath)
        
        // Generate AI fix
        analysis, err := claudeClient.AnalyzeVulnerability(result, fileContent, relativePath)
        
        // Check confidence threshold
        if analysis.Confidence < options.MinConfidence {
            continue
        }
        
        // Validate fix
        if !claudeClient.ValidateSecurityFix(result.Extra.Lines, analysis.Fix) {
            continue
        }
        
        // Apply fix to GitHub
        securityFix := SecurityFix{
            FilePath:      relativePath,
            StartLine:     result.Start.Line,
            EndLine:       result.End.Line,
            OriginalCode:  result.Extra.Lines,
            FixedCode:     analysis.Fix,
            Vulnerability: result.CheckID,
            Description:   analysis.Explanation,
        }
        
        err = ghClient.ApplySecurityFix(fixBranch, securityFix)
        if err == nil {
            successfulFixes++
        }
    }
    
    // Create PR and issue
    if options.CreatePR && successfulFixes > 0 {
        err = ghClient.CreatePullRequest(fixBranch)
    }
    
    if options.CreateIssue {
        err = ghClient.CreateIssueForConversation(fixBranch)
    }
    
    return nil
}
```

## 🏃‍♂️ Performance Optimizations

### Concurrent Processing
```go
func main() {
    targets := make(chan string, options.Threads*20)
    stop := make(chan bool)
    
    var wg sync.WaitGroup
    for i := 0; i < options.Threads; i++ {
        wg.Add(1)
        go RepoScanner(targets, options, &wg, stop)
    }
    
    // Feed targets from stdin/file
    go feed.FromStdIn(targets, stop)
    
    wg.Wait()
}
```

### Security Controls
```go
// ZIP bomb protection
if len(zipReader.File) > 500000 {
    return errors.New("ZIP Contains more than 500k files")
}

// File size limits
if totalSize > 1024*1024*1024*60 { // 60GB limit
    return errors.New("ZIP contains more than 60gb of uncompressed data")
}

// Path traversal protection
if strings.Contains(path, "..") {
    return false
}

if !strings.HasPrefix(path, filepath.Clean(dest)+string(os.PathSeparator)) {
    return false
}
```

## 📋 Required Dependencies

### Go Dependencies (go.mod)
```go
module github.com/chebuya/codesucks-ai

go 1.23

require (
    github.com/PuerkitoBio/goquery v1.10.0
    github.com/charmbracelet/log v0.4.0
    github.com/fatih/color v1.17.0
    github.com/google/go-github/v66 v66.0.0
    github.com/google/uuid v1.6.0
    github.com/savioxavier/termlink v1.4.1
    golang.org/x/oauth2 v0.23.0
)
```

### External Dependencies
- **Semgrep**: `pip install semgrep` or Docker image
- **Git**: For repository operations (optional)

### API Requirements
- **GitHub Personal Access Token**: `repo`, `write:repo_hook` scopes minimum
- **Anthropic API Key**: Claude access with sufficient credits

This technical implementation guide provides all necessary details to reproduce codesucks-ai's functionality using Go, Semgrep, and the specified APIs.%      
