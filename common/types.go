package common

import (
	"encoding/json"
)

// CLI Options structure
type Options struct {
	// Target specification
	Repo  string // Single repository URL
	Repos string // File containing repository list

	// Scanning configuration
	NoSemgrep     bool
	SemgrepPath   string
	ConfigPath    string
	NoTruffleHog  bool
	TruffleHogPath string
	VerifySecrets bool
	OutDir        string

	// AI automation
	AutoFix         bool
	CreatePR        bool
	CreateIssue     bool
	AIModel         string
	AnthropicAPIKey string
	MinConfidence   float64

	// GitHub integration
	GitHubToken         string
	GitHubAppID         int64
	GitHubAppPrivateKey string

	// Performance
	Threads int
	Debug   bool
}

// Semgrep output structures
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

type Error struct {
	Type    json.RawMessage `json:"type"`
	Level   string          `json:"level"`
	Message string          `json:"message"`
	Code    int             `json:"code,omitempty"`
	Path    string          `json:"path,omitempty"`
}

// TruffleHog output structures (matching actual TruffleHog output format)
type TruffleHogJson struct {
	Results []TruffleHogResult `json:"results"`
}

type TruffleHogResult struct {
	// Check if this is a log entry or a finding
	Level   string `json:"level,omitempty"`
	Msg     string `json:"msg,omitempty"`
	Logger  string `json:"logger,omitempty"`
	
	// Actual finding fields
	DetectorName        string                    `json:"DetectorName,omitempty"`
	DetectorType        int                       `json:"DetectorType,omitempty"`
	DetectorDescription string                    `json:"DetectorDescription,omitempty"`
	Verified            bool                      `json:"Verified"`
	Raw                 string                    `json:"Raw,omitempty"`
	Redacted            string                    `json:"Redacted,omitempty"`
	SourceMetadata      *TruffleHogSourceMetadata `json:"SourceMetadata,omitempty"`
	ExtraData           map[string]interface{}    `json:"ExtraData,omitempty"`
}

type TruffleHogSourceMetadata struct {
	Data struct {
		Git *struct {
			Commit     string `json:"commit"`
			File       string `json:"file"`
			Email      string `json:"email"`
			Repository string `json:"repository"`
			Timestamp  string `json:"timestamp"`
			Line       int    `json:"line"`
		} `json:"Git,omitempty"`
		Filesystem *struct {
			File string `json:"file"`
			Line int    `json:"line"`
		} `json:"Filesystem,omitempty"`
	} `json:"Data"`
}

// AI Analysis structures
type SecurityAnalysis struct {
	Vulnerability string  `json:"vulnerability"`
	Severity      string  `json:"severity"`
	Fix           string  `json:"fix"`
	Explanation   string  `json:"explanation"`
	Confidence    float64 `json:"confidence"`
}

// GitHub authentication structures
type GitHubAuth struct {
	Token          string
	AppID          int64
	PrivateKey     string
	InstallationID int64
}

type FixBranch struct {
	BranchName  string
	RepoOwner   string
	RepoName    string
	Fixes       []SecurityFix
	PRNumber    *int
	IssueNumber *int
}

type SecurityFix struct {
	FilePath      string
	StartLine     int
	EndLine       int
	OriginalCode  string
	FixedCode     string
	Vulnerability string
	Description   string
}

// Repository information
type RepoInfo struct {
	URL           string
	Owner         string
	Name          string
	Branch        string
	DefaultBranch string
	Private       bool
	Language      string
	Description   string
}

// Report generation structures
type ReportData struct {
	Target                     string
	VulnerabilityStats         map[string]int
	VulnerabilityStatsOrdering []string
	SeverityStats              map[string]int
	SeverityStatsOrdering      []string
	SecretStats                map[string]int
	SecretStatsOrdering        []string
	Findings                   []SemgrepFinding
	SecretFindings             []TruffleHogFinding
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

type TruffleHogFinding struct {
	SecretType    string
	DetectorName  string
	Verified      bool
	Description   string
	RedactedValue string
	StartLine     int
	GithubLink    string
	File          string
}

// GitHub API content structures
type RepositoryFile struct {
	Path    string
	Content string
	SHA     string
	Size    int
	Type    string // "file" or "dir"
}

type ScanResult struct {
	RepoInfo        RepoInfo
	SemgrepJson     SemgrepJson
	TruffleHogJson  TruffleHogJson
	ReportPath      string
	FixesApplied    int
	SecretsFound    int
	Error           error
}

// Constants
const (
	ClaudeAPIEndpoint = "https://api.anthropic.com/v1/messages"
	DefaultModel      = "claude-3-5-sonnet-20241022"
	MaxTokens         = 4096
)

// Claude API structures
type ClaudeRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	Messages  []Message `json:"messages"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ClaudeResponse struct {
	Content []ContentBlock `json:"content"`
	Usage   Usage          `json:"usage"`
}

type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}
