package common

import (
	"encoding/json"
	"time"
)

// ScanResults represents the results of a security scan
type ScanResults struct {
	Repository           string         `json:"repository"`
	TotalVulnerabilities int            `json:"total_vulnerabilities"`
	SeverityDistribution map[string]int `json:"severity_distribution"`
	FilesAnalyzed        int            `json:"files_analyzed"`
	LinesOfCode          int            `json:"lines_of_code"`
	VulnerabilityDensity float64        `json:"vulnerability_density"`
	TopVulnerableFiles   []string       `json:"top_vulnerable_files"`
	TruePositives        int            `json:"true_positives"`
	FalsePositives       int            `json:"false_positives"`
	FixedCount           int            `json:"fixed_count"`
}

// CLI Options structure (for backward compatibility)
type Options struct {
	// Target specification
	Repo  string // Single repository URL
	Repos string // File containing repository list

	// Scanning configuration
	NoSemgrep      bool
	SemgrepPath    string
	ConfigPath     string
	NoTruffleHog   bool
	TruffleHogPath string
	VerifySecrets  bool
	OutDir         string

	// AI automation
	AutoFix         bool
	CreatePR        bool
	CreateIssue     bool
	AIModel         string
	AnthropicAPIKey string
	MinConfidence   float64

	// Agent validation
	ValidationConfidence float64
	NoAgentValidation    bool

	// Orchestrator mode
	OrchestratorMode bool
	SessionDir       string
	AgentsDir        string

	// GitHub integration
	GitHubToken         string
	GitHubAppID         int64
	GitHubAppPrivateKey string

	// Performance
	Threads int
	Debug   bool

	// Configuration file
	ConfigFile string

	// MCP Mode
	UseMCPMode        bool
	MCPServerURL      string
	EnableAST         bool
	EnableCustomRules bool
	TargetPath        string
	MinSeverity       string

	// Matrix Build Options
	MatrixBuild        bool
	ForceLanguage      string
	ForceFramework     string
	AdditionalRulesets string
	LanguageThreshold  float64
	DisableAutoDetect  bool

	// Repository Download Strategy
	ForceGitClone      bool // Always use git clone
	ForceAPIDownload   bool // Always use API download
	CloneSizeThreshold int  // Size in MB to trigger clone (default: 50)
	CloneFileThreshold int  // File count to trigger clone (default: 1000)
	CloneTimeout       int  // Timeout for git operations in seconds (default: 300)
}

// Configuration sub-structures
type TargetConfig struct {
	Repo      string `yaml:"repo,omitempty"`
	ReposFile string `yaml:"repos_file,omitempty"`
}

type SemgrepConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Path        string `yaml:"path,omitempty"`
	Config      string `yaml:"config,omitempty"`
	CustomFlags string `yaml:"custom_flags,omitempty"`
}

type TruffleHogConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Path          string `yaml:"path,omitempty"`
	VerifySecrets bool   `yaml:"verify_secrets"`
}

type ScanningConfig struct {
	Semgrep    SemgrepConfig    `yaml:"semgrep"`
	TruffleHog TruffleHogConfig `yaml:"trufflehog"`
}

type AIAutomationConfig struct {
	Enabled       bool    `yaml:"enabled"`
	Model         string  `yaml:"model,omitempty"`
	APIKey        string  `yaml:"api_key,omitempty"`
	MinConfidence float64 `yaml:"min_confidence,omitempty"`
	AutoFix       bool    `yaml:"auto_fix"`
	CreatePR      bool    `yaml:"create_pr"`
	CreateIssue   bool    `yaml:"create_issue"`
}

type GitHubConfig struct {
	AuthMethod string `yaml:"auth_method,omitempty"` // "token" or "app"
	AppID      int64  `yaml:"app_id,omitempty"`
	AppKeyFile string `yaml:"app_key_file,omitempty"`
}

type PerformanceConfig struct {
	Threads   int    `yaml:"threads,omitempty"`
	OutputDir string `yaml:"output_dir,omitempty"`
	Debug     bool   `yaml:"debug"`
}

type AgentValidationConfig struct {
	Enabled             bool    `yaml:"enabled"`
	ConfidenceThreshold float64 `yaml:"confidence_threshold,omitempty"`
}

type OrchestratorConfig struct {
	Enabled    bool   `yaml:"enabled"`
	SessionDir string `yaml:"session_dir,omitempty"`
	AgentsDir  string `yaml:"agents_dir,omitempty"`
	Timeout    int    `yaml:"timeout,omitempty"`
	MaxAgents  int    `yaml:"max_agents,omitempty"`
}

type MatrixBuildConfig struct {
	Enabled            bool    `yaml:"enabled"`
	AutoDetect         bool    `yaml:"auto_detect"`
	ForceLanguage      string  `yaml:"force_language,omitempty"`
	ForceFramework     string  `yaml:"force_framework,omitempty"`
	AdditionalRulesets string  `yaml:"additional_rulesets,omitempty"`
	LanguageThreshold  float64 `yaml:"language_threshold,omitempty"`
}

// YAML Configuration structure
type Config struct {
	Target          TargetConfig          `yaml:"target"`
	Scanning        ScanningConfig        `yaml:"scanning"`
	AIAutomation    AIAutomationConfig    `yaml:"ai_automation"`
	GitHub          GitHubConfig          `yaml:"github"`
	Performance     PerformanceConfig     `yaml:"performance"`
	AgentValidation AgentValidationConfig `yaml:"agent_validation"`
	Orchestrator    OrchestratorConfig    `yaml:"orchestrator"`
	MatrixBuild     MatrixBuildConfig     `yaml:"matrix_build"`

	AgentSettings struct {
		InjectionAnalyser AgentConfig `yaml:"injection_analyser,omitempty"`
		XSSAnalyser       AgentConfig `yaml:"xss_analyser,omitempty"`
		PathAnalyser      AgentConfig `yaml:"path_analyser,omitempty"`
		CryptoAnalyser    AgentConfig `yaml:"crypto_analyser,omitempty"`
		AuthAnalyser      AgentConfig `yaml:"auth_analyser,omitempty"`
		DeserialAnalyser  AgentConfig `yaml:"deserial_analyser,omitempty"`
		XXEAnalyser       AgentConfig `yaml:"xxe_analyser,omitempty"`
		RaceAnalyser      AgentConfig `yaml:"race_analyser,omitempty"`
	} `yaml:"agent_settings,omitempty"`
}

// AgentConfig represents configuration for individual agents
type AgentConfig struct {
	Enabled             bool     `yaml:"enabled"`
	Model               string   `yaml:"model,omitempty"`
	MaxTokens           int      `yaml:"max_tokens,omitempty"`
	Timeout             int      `yaml:"timeout,omitempty"`
	FilePatterns        []string `yaml:"file_patterns,omitempty"`
	ExcludePatterns     []string `yaml:"exclude_patterns,omitempty"`
	ConfidenceThreshold float64  `yaml:"confidence_threshold,omitempty"`
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
	Level  string `json:"level,omitempty"`
	Msg    string `json:"msg,omitempty"`
	Logger string `json:"logger,omitempty"`

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

// Agent Validation structures
type AgentValidation struct {
	IsLegitimate        bool    `json:"is_legitimate"`
	Confidence          float64 `json:"confidence"`
	Reasoning           string  `json:"reasoning"`
	ContextAnalysis     string  `json:"context_analysis"`
	RecommendedAction   string  `json:"recommended_action"`
	FalsePositiveReason string  `json:"false_positive_reason,omitempty"`
	ValidatedAt         string  `json:"validated_at"`
}

type RepositoryContext struct {
	SourcePath            string                 `json:"source_path"` // Path to downloaded source code
	ProjectStructure      ProjectStructure       `json:"project_structure"`
	TechnologyStack       TechnologyStack        `json:"technology_stack"`
	SecurityPatterns      []SecurityPattern      `json:"security_patterns"`
	FrameworkMitigations  []FrameworkMitigation  `json:"framework_mitigations"`
	DocumentationInsights []DocumentationInsight `json:"documentation_insights"`
}

type ProjectStructure struct {
	Language        string            `json:"language"`
	MainEntryPoints []string          `json:"main_entry_points"`
	ConfigFiles     []string          `json:"config_files"`
	TestDirectories []string          `json:"test_directories"`
	Documentation   []string          `json:"documentation"`
	Dependencies    map[string]string `json:"dependencies"`
	Architecture    string            `json:"architecture"`
}

type TechnologyStack struct {
	Framework         string   `json:"framework"`
	Libraries         []string `json:"libraries"`
	DatabaseTech      []string `json:"database_tech"`
	WebServer         string   `json:"web_server"`
	SecurityLibraries []string `json:"security_libraries"`
	BuildTools        []string `json:"build_tools"`
}

type SecurityPattern struct {
	Pattern     string  `json:"pattern"`
	Description string  `json:"description"`
	Location    string  `json:"location"`
	Confidence  float64 `json:"confidence"`
}

type FrameworkMitigation struct {
	Framework    string `json:"framework"`
	VulnType     string `json:"vuln_type"`
	Mitigation   string `json:"mitigation"`
	IsApplicable bool   `json:"is_applicable"`
}

type DocumentationInsight struct {
	Source    string  `json:"source"`
	Content   string  `json:"content"`
	Relevance float64 `json:"relevance"`
}

// Extended Result structure with agent validation
type ValidatedResult struct {
	Result
	AgentValidation *AgentValidation `json:"agent_validation,omitempty"`
	IsFiltered      bool             `json:"is_filtered"`
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
	Size          int    // Repository size in KB
	Stars         int    // Number of stars
	FileCount     int    // Approximate number of files
	CreatedAt     string // Repository creation date
	UpdatedAt     string // Last update date
}

// Report generation structures
type ReportData struct {
	Target                     string
	DefaultBranch              string
	VulnerabilityStats         map[string]int
	VulnerabilityStatsOrdering []string
	SeverityStats              map[string]int
	SeverityStatsOrdering      []string
	SecretStats                map[string]int
	SecretStatsOrdering        []string
	Findings                   []SemgrepFinding
	SecretFindings             []TruffleHogFinding
	MatrixConfig               *MatrixConfig `json:"matrix_config,omitempty"`
}

type SemgrepFinding struct {
	VulnerabilityTitle string
	Severity           string
	Description        string
	Code               string
	StartLine          int
	StopLine           int
	GithubLink         string
	AgentValidation    *AgentValidation `json:"agent_validation,omitempty"`
	IsFiltered         bool             `json:"is_filtered,omitempty"`
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
	RepoInfo         RepoInfo
	SemgrepJson      SemgrepJson
	TruffleHogJson   TruffleHogJson
	ValidatedResults []ValidatedResult
	ReportPath       string
	FixesApplied     int
	SecretsFound     int
	MatrixConfig     *MatrixConfig `json:"matrix_config,omitempty"`
	Error            error
}

// Agent-related structures for Claude Code SDK integration
type OrchestratorState struct {
	SessionID             string                  `json:"session_id"`
	CreatedAt             time.Time               `json:"created_at"`
	CurrentPhase          string                  `json:"current_phase"`
	SourcePath            string                  `json:"source_path"`      // Path to downloaded source code
	DefaultBranch         string                  `json:"default_branch"`   // Default branch of the repository
	FilesDownloaded       int                     `json:"files_downloaded"` // Number of files fetched
	CodebaseContext       CodebaseContext         `json:"codebase_context"`
	CodePatterns          CodePatterns            `json:"code_patterns"`
	DecomposedAnalyses    []DecomposedAnalysis    `json:"decomposed_analyses"`
	AnalysisAgents        []AnalysisAgent         `json:"analysis_agents"`
	Vulnerabilities       []EnhancedVulnerability `json:"vulnerabilities"`
	VulnerabilityPatterns []VulnerabilityPattern  `json:"vulnerability_patterns"`
	CodeMetrics           CodeMetrics             `json:"code_metrics"`
	FinalReportPath       *string                 `json:"final_report_path"`
	CompletedAt           *time.Time              `json:"completed_at"`
}

type CodebaseContext struct {
	PrimaryLanguage       string   `json:"primary_language"`
	Frameworks            []string `json:"frameworks"`
	EntryPoints           []string `json:"entry_points"`
	TotalFiles            int      `json:"total_files"`
	TotalLOC              int      `json:"total_loc"`
	SecurityRelevantFiles []string `json:"security_relevant_files"`
}

type CodePatterns struct {
	InputSources     []InputSource     `json:"input_sources"`
	DangerousSinks   []DangerousSink   `json:"dangerous_sinks"`
	SecurityControls []SecurityControl `json:"security_controls"`
}

type InputSource struct {
	Type     string `json:"type"`
	Location string `json:"location"`
	DataType string `json:"data_type"`
}

type DangerousSink struct {
	Type     string `json:"type"`
	Location string `json:"location"`
	Function string `json:"function"`
}

type SecurityControl struct {
	Type     string `json:"type"`
	Location string `json:"location"`
}

type DecomposedAnalysis struct {
	AnalysisID     string   `json:"analysis_id"`
	Focus          string   `json:"focus"`
	TargetPatterns []string `json:"target_patterns"`
	FileScope      []string `json:"file_scope"`
	AssignedAgent  string   `json:"assigned_agent"`
}

type AnalysisAgent struct {
	AgentID              string   `json:"agent_id"`
	AgentType            string   `json:"agent_type"`
	AnalysisID           string   `json:"analysis_id"`
	StateFile            string   `json:"state_file"`
	Status               string   `json:"status"`
	Files                []string `json:"files"` // Files assigned to this agent
	FilesAnalyzed        int      `json:"files_analyzed"`
	VulnerabilitiesFound int      `json:"vulnerabilities_found"`
}

type EnhancedVulnerability struct {
	VulnID         string       `json:"vuln_id"`
	Type           string       `json:"type"`
	CweID          string       `json:"cwe_id"`
	Severity       string       `json:"severity"`
	Confidence     string       `json:"confidence"`
	Location       VulnLocation `json:"location"`
	DataFlow       DataFlow     `json:"data_flow"`
	VulnerableCode string       `json:"vulnerable_code"`
	ExploitExample string       `json:"exploit_example"`
	SecureCode     string       `json:"secure_code"`
	FixExplanation string       `json:"fix_explanation"`
}

type VulnLocation struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Function  string `json:"function"`
}

type DataFlow struct {
	Source          string   `json:"source"`
	Transformations []string `json:"transformations"`
	Sink            string   `json:"sink"`
}

type VulnerabilityPattern struct {
	PatternID   string   `json:"pattern_id"`
	Description string   `json:"description"`
	Instances   []string `json:"instances"`
	SystemicFix string   `json:"systemic_fix"`
}

type CodeMetrics struct {
	FilesAnalyzed            int            `json:"files_analyzed"`
	FunctionsAnalyzed        int            `json:"functions_analyzed"`
	TotalVulnerabilities     int            `json:"total_vulnerabilities"`
	SeverityDistribution     map[string]int `json:"severity_distribution"`
	VulnerabilityDensity     float64        `json:"vulnerability_density"`
	MostVulnerableComponents []string       `json:"most_vulnerable_components"`
}

type AgentState struct {
	AgentID        string            `json:"agent_id"`
	AgentType      string            `json:"agent_type"`
	AnalysisID     string            `json:"analysis_id"`
	Status         string            `json:"status"`
	Files          []string          `json:"files"`
	FilesProcessed []string          `json:"files_processed"`
	StartTime      time.Time         `json:"start_time"`
	LastUpdate     time.Time         `json:"last_update"`
	Progress       float64           `json:"progress"`
	Results        []SecurityFinding `json:"results"`
	Errors         []string          `json:"errors"`
}

type AgentStatus struct {
	AgentID         string    `json:"agent_id"`
	Type            string    `json:"type"`
	Status          string    `json:"status"`
	Progress        float64   `json:"progress"`
	FilesAnalyzed   int       `json:"files_analyzed"`
	TotalFiles      int       `json:"total_files"`
	Vulnerabilities int       `json:"vulnerabilities"`
	StartTime       time.Time `json:"start_time"`
	LastUpdate      time.Time `json:"last_update"`
}

type AgentResults struct {
	AgentID         string            `json:"agent_id"`
	Type            string            `json:"type"`
	Status          string            `json:"status"`
	FilesAnalyzed   []string          `json:"files_analyzed"`
	Vulnerabilities []SecurityFinding `json:"vulnerabilities"`
	Patterns        []SystemicPattern `json:"patterns"`
	Metrics         AgentMetrics      `json:"metrics"`
	CompletedAt     time.Time         `json:"completed_at"`
}

type SecurityFinding struct {
	Type           string  `json:"type"`
	File           string  `json:"file"`
	LineStart      int     `json:"line_start"`
	LineEnd        int     `json:"line_end"`
	Severity       string  `json:"severity"`
	Confidence     float64 `json:"confidence"`
	Description    string  `json:"description"`
	VulnerableCode string  `json:"vulnerable_code"`
	ExploitExample string  `json:"exploit_example"`
	SecureFix      string  `json:"secure_fix"`
	FixExplanation string  `json:"fix_explanation"`
}

type SystemicPattern struct {
	Pattern        string   `json:"pattern"`
	Instances      []string `json:"instances"`
	Recommendation string   `json:"recommendation"`
}

type AgentMetrics struct {
	ProcessingTime       time.Duration `json:"processing_time"`
	FilesScanned         int           `json:"files_scanned"`
	LinesAnalyzed        int           `json:"lines_analyzed"`
	VulnerabilitiesFound int           `json:"vulnerabilities_found"`
	FalsePositives       int           `json:"false_positives"`
}

// Matrix Build Types
type LanguageStats struct {
	Languages map[string]int `json:"languages"` // language -> bytes
	Total     int            `json:"total"`
}

type LanguagePercentages struct {
	Primary   LanguageInfo   `json:"primary"`
	Secondary LanguageInfo   `json:"secondary,omitempty"`
	All       []LanguageInfo `json:"all"`
	Threshold float64        `json:"threshold"`
}

type LanguageInfo struct {
	Name       string  `json:"name"`
	Bytes      int     `json:"bytes"`
	Percentage float64 `json:"percentage"`
}

type FrameworkDetection struct {
	Primary    string            `json:"primary"`
	Secondary  []string          `json:"secondary"`
	BuildTools []string          `json:"build_tools"`
	WebServer  string            `json:"web_server,omitempty"`
	Database   []string          `json:"database,omitempty"`
	Security   []string          `json:"security,omitempty"`
	Indicators map[string]string `json:"indicators"` // file -> framework
}

type MatrixConfig struct {
	Languages     LanguagePercentages `json:"languages"`
	Frameworks    FrameworkDetection  `json:"frameworks"`
	Rulesets      []string            `json:"rulesets"`
	BaseRulesets  []string            `json:"base_rulesets"`
	SecurityRules []string            `json:"security_rules"`
	ConfigPath    string              `json:"config_path,omitempty"`
	AutoDetected  bool                `json:"auto_detected"`
}

type DetectionResult struct {
	Languages  LanguagePercentages `json:"languages"`
	Frameworks FrameworkDetection  `json:"frameworks"`
	Confidence float64             `json:"confidence"`
	Source     string              `json:"source"` // "github-api", "file-analysis", "mixed"
}

// Constants
const (
	ClaudeAPIEndpoint = "https://api.anthropic.com/v1/messages"
	DefaultModel      = "claude-3-5-sonnet-20241022"
	MaxTokens         = 4096

	// Orchestrator phases
	PhaseInitialization             = "INITIALIZATION"
	PhaseCodebaseAnalysis           = "CODEBASE_ANALYSIS"
	PhaseEntryPointMapping          = "ENTRY_POINT_MAPPING"
	PhaseVulnerabilityDecomposition = "VULNERABILITY_DECOMPOSITION"
	PhaseParallelAnalysis           = "PARALLEL_ANALYSIS"
	PhaseSynthesis                  = "SYNTHESIS"
	PhaseReporting                  = "REPORTING"
	PhaseCompleted                  = "COMPLETED"

	// Agent types
	AgentTypeInjection = "code-injection-analyser"
	AgentTypeXSS       = "code-xss-analyser"
	AgentTypePath      = "code-path-analyser"
	AgentTypeCrypto    = "code-crypto-analyser"
	AgentTypeAuth      = "code-auth-analyser"
	AgentTypeDeserial  = "code-deserial-analyser"
	AgentTypeXXE       = "code-xxe-analyser"
	AgentTypeRace      = "code-race-analyser"

	// Agent statuses
	AgentStatusPending    = "pending"
	AgentStatusRunning    = "running"
	AgentStatusCompleted  = "completed"
	AgentStatusFailed     = "failed"
	AgentStatusTerminated = "terminated"
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
