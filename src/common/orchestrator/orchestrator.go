package orchestrator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/asii-mov/codesucks-ai/common"
	"github.com/asii-mov/codesucks-ai/common/agent"
	"github.com/asii-mov/codesucks-ai/common/github"
	"github.com/google/uuid"
)

// SecurityOrchestrator implements the 7-phase security analysis workflow
type SecurityOrchestrator struct {
	SessionID    string
	SessionDir   string
	AgentsDir    string
	State        *common.OrchestratorState
	StateFile    string
	ClaudeSDK    *agent.ClaudeSDKClient
	GitHubClient *github.GitHubClient
	Options      *common.Options
	mu           sync.RWMutex
}

// NewSecurityOrchestrator creates a new orchestrator instance
func NewSecurityOrchestrator(sessionDir, agentsDir string, options *common.Options) (*SecurityOrchestrator, error) {
	sessionID := uuid.New().String()
	sessionPath := filepath.Join(sessionDir, sessionID)
	stateFile := filepath.Join(sessionPath, "orchestrator_state.json")

	// Create session directory
	if err := os.MkdirAll(sessionPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create session directory: %w", err)
	}

	// Create sub-directories
	for _, dir := range []string{"sub_agents", "vulnerable_code"} {
		if err := os.MkdirAll(filepath.Join(sessionPath, dir), 0755); err != nil {
			return nil, fmt.Errorf("failed to create %s directory: %w", dir, err)
		}
	}

	// Initialize Claude SDK client
	claudeSDK, err := agent.NewClaudeSDKClient(filepath.Join(sessionPath, "sub_agents"), agentsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Claude SDK client: %w", err)
	}

	// Initialize GitHub client
	githubClient, err := github.NewClient(options)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GitHub client: %w", err)
	}

	// Initialize orchestrator state
	state := &common.OrchestratorState{
		SessionID:       sessionID,
		CreatedAt:       time.Now(),
		CurrentPhase:    common.PhaseInitialization,
		CodebaseContext: common.CodebaseContext{},
		CodePatterns: common.CodePatterns{
			InputSources:     []common.InputSource{},
			DangerousSinks:   []common.DangerousSink{},
			SecurityControls: []common.SecurityControl{},
		},
		DecomposedAnalyses:    []common.DecomposedAnalysis{},
		AnalysisAgents:        []common.AnalysisAgent{},
		Vulnerabilities:       []common.EnhancedVulnerability{},
		VulnerabilityPatterns: []common.VulnerabilityPattern{},
		CodeMetrics: common.CodeMetrics{
			SeverityDistribution:     make(map[string]int),
			MostVulnerableComponents: []string{},
		},
	}

	orchestrator := &SecurityOrchestrator{
		SessionID:    sessionID,
		SessionDir:   sessionPath,
		AgentsDir:    agentsDir,
		State:        state,
		StateFile:    stateFile,
		ClaudeSDK:    claudeSDK,
		GitHubClient: githubClient,
		Options:      options,
	}

	// Save initial state
	if err := orchestrator.saveState(); err != nil {
		return nil, fmt.Errorf("failed to save initial state: %w", err)
	}

	return orchestrator, nil
}

// ExecuteSecurityAnalysis runs the complete 7-phase security analysis workflow
func (o *SecurityOrchestrator) ExecuteSecurityAnalysis(repoURL string) (*common.ScanResult, error) {
	fmt.Printf("🚀 Starting security analysis orchestration for %s\n", repoURL)
	fmt.Printf("📋 Session ID: %s\n", o.SessionID)

	// Phase 1: Initialize Code Analysis
	if err := o.phase1_InitializeCodeAnalysis(); err != nil {
		return nil, fmt.Errorf("phase 1 failed: %w", err)
	}

	// Phase 2: Analyze Codebase Structure
	repoContext, err := o.phase2_AnalyzeCodebaseStructure(repoURL)
	if err != nil {
		return nil, fmt.Errorf("phase 2 failed: %w", err)
	}

	// Phase 3: Map Entry Points and Data Flow
	if err := o.phase3_MapEntryPointsAndDataFlow(repoContext); err != nil {
		return nil, fmt.Errorf("phase 3 failed: %w", err)
	}

	// Phase 4: Decompose into Parallel Analyses
	if err := o.phase4_DecomposeIntoParallelAnalyses(); err != nil {
		return nil, fmt.Errorf("phase 4 failed: %w", err)
	}

	// Phase 5: Execute Parallel Code Analysis
	if err := o.phase5_ExecuteParallelCodeAnalysis(repoContext); err != nil {
		return nil, fmt.Errorf("phase 5 failed: %w", err)
	}

	// Phase 6: Synthesize and Validate Findings
	if err := o.phase6_SynthesizeAndValidateFindings(); err != nil {
		return nil, fmt.Errorf("phase 6 failed: %w", err)
	}

	// Phase 7: Generate Code Security Report
	reportPath, err := o.phase7_GenerateCodeSecurityReport()
	if err != nil {
		return nil, fmt.Errorf("phase 7 failed: %w", err)
	}

	// Create final scan result
	result := &common.ScanResult{
		RepoInfo: common.RepoInfo{
			URL:         repoURL,
			Language:    o.State.CodebaseContext.PrimaryLanguage,
			Description: fmt.Sprintf("AI-orchestrated security analysis with %d agents", len(o.State.AnalysisAgents)),
		},
		ValidatedResults: o.convertToValidatedResults(),
		ReportPath:       reportPath,
		FixesApplied:     len(o.State.Vulnerabilities),
		SecretsFound:     o.countSecrets(),
	}

	fmt.Printf("✅ Security analysis completed successfully\n")
	fmt.Printf("📊 Found %d vulnerabilities across %d files\n", len(o.State.Vulnerabilities), o.State.CodeMetrics.FilesAnalyzed)
	fmt.Printf("📄 Report generated: %s\n", reportPath)

	return result, nil
}

// Phase 1: Initialize Code Analysis
func (o *SecurityOrchestrator) phase1_InitializeCodeAnalysis() error {
	fmt.Println("🔄 Phase 1: Initialize Code Analysis")

	o.mu.Lock()
	o.State.CurrentPhase = common.PhaseInitialization
	o.mu.Unlock()

	// Verify directory structure
	requiredDirs := []string{
		filepath.Join(o.SessionDir, "sub_agents"),
		filepath.Join(o.SessionDir, "vulnerable_code"),
	}

	for _, dir := range requiredDirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	fmt.Println("✅ Directory structure verified")
	return o.updatePhase(common.PhaseCodebaseAnalysis)
}

// Phase 2: Analyze Codebase Structure
func (o *SecurityOrchestrator) phase2_AnalyzeCodebaseStructure(repoURL string) (*common.RepositoryContext, error) {
	fmt.Println("🔄 Phase 2: Analyze Codebase Structure")

	// Parse repository URL
	owner, repo, err := github.ParseRepositoryURL(repoURL)
	if err != nil {
		return nil, fmt.Errorf("invalid repository URL: %w", err)
	}

	// Get repository information
	repoInfo, err := o.GitHubClient.GetRepositoryInfo(owner, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository info: %w", err)
	}

	// Get repository contents
	files, err := o.GitHubClient.ListRepositoryFiles(owner, repo, repoInfo.DefaultBranch)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository contents: %w", err)
	}

	// Analyze project structure
	projectStructure := o.analyzeProjectStructure(files, repoInfo.Language)

	// Detect frameworks and libraries
	techStack := o.detectTechnologyStack(files, projectStructure.Language)

	// Update codebase context
	o.mu.Lock()
	o.State.CodebaseContext = common.CodebaseContext{
		PrimaryLanguage:       projectStructure.Language,
		Frameworks:            techStack.Libraries,
		EntryPoints:           projectStructure.MainEntryPoints,
		TotalFiles:            len(files),
		TotalLOC:              o.estimateLinesOfCode(files),
		SecurityRelevantFiles: o.identifySecurityRelevantFiles(files),
	}
	o.mu.Unlock()

	// Create repository context for agents
	repoContext := &common.RepositoryContext{
		ProjectStructure:      projectStructure,
		TechnologyStack:       techStack,
		SecurityPatterns:      []common.SecurityPattern{},
		FrameworkMitigations:  []common.FrameworkMitigation{},
		DocumentationInsights: []common.DocumentationInsight{},
	}

	fmt.Printf("✅ Detected language: %s, files: %d, LOC: ~%d\n",
		projectStructure.Language, len(files), o.State.CodebaseContext.TotalLOC)

	return repoContext, o.updatePhase(common.PhaseEntryPointMapping)
}

// Phase 3: Map Entry Points and Data Flow
func (o *SecurityOrchestrator) phase3_MapEntryPointsAndDataFlow(repoContext *common.RepositoryContext) error {
	fmt.Println("🔄 Phase 3: Map Entry Points and Data Flow")

	// Identify input sources based on language and framework
	inputSources := o.identifyInputSources(repoContext)

	// Locate dangerous operations
	dangerousSinks := o.identifyDangerousSinks(repoContext)

	// Map security controls
	securityControls := o.identifySecurityControls(repoContext)

	o.mu.Lock()
	o.State.CodePatterns = common.CodePatterns{
		InputSources:     inputSources,
		DangerousSinks:   dangerousSinks,
		SecurityControls: securityControls,
	}
	o.mu.Unlock()

	fmt.Printf("✅ Mapped %d input sources, %d dangerous sinks, %d security controls\n",
		len(inputSources), len(dangerousSinks), len(securityControls))

	return o.updatePhase(common.PhaseVulnerabilityDecomposition)
}

// Phase 4: Decompose into Parallel Analyses
func (o *SecurityOrchestrator) phase4_DecomposeIntoParallelAnalyses() error {
	fmt.Println("🔄 Phase 4: Decompose into Parallel Analyses")

	// Create specialized analysis tasks by vulnerability class
	analyses := []common.DecomposedAnalysis{
		{
			AnalysisID:     "analysis_injection",
			Focus:          "SQL, NoSQL, LDAP, OS Command, Expression Language injection",
			TargetPatterns: []string{"db.query", "execute", "system", "eval"},
			FileScope:      o.filterFilesByPatterns([]string{"*.sql", "*.py", "*.js", "*.java", "*.go"}),
			AssignedAgent:  common.AgentTypeInjection,
		},
		{
			AnalysisID:     "analysis_xss",
			Focus:          "Reflected, Stored, and DOM-based XSS",
			TargetPatterns: []string{"innerHTML", "document.write", "template", "render"},
			FileScope:      o.filterFilesByPatterns([]string{"*.html", "*.js", "*.jsx", "*.vue", "*.py", "*.php"}),
			AssignedAgent:  common.AgentTypeXSS,
		},
		{
			AnalysisID:     "analysis_path",
			Focus:          "Path traversal and file inclusion",
			TargetPatterns: []string{"open", "read", "include", "require"},
			FileScope:      o.filterFilesByPatterns([]string{"*.py", "*.js", "*.php", "*.java", "*.go"}),
			AssignedAgent:  common.AgentTypePath,
		},
		{
			AnalysisID:     "analysis_crypto",
			Focus:          "Cryptographic implementation flaws",
			TargetPatterns: []string{"md5", "sha1", "des", "random", "encrypt"},
			FileScope:      o.filterFilesByPatterns([]string{"*.py", "*.js", "*.java", "*.go", "*.c", "*.cpp"}),
			AssignedAgent:  common.AgentTypeCrypto,
		},
		{
			AnalysisID:     "analysis_auth",
			Focus:          "Authentication and authorization flaws",
			TargetPatterns: []string{"login", "auth", "session", "token", "password"},
			FileScope:      o.filterFilesByPatterns([]string{"*.py", "*.js", "*.java", "*.go", "*.php"}),
			AssignedAgent:  common.AgentTypeAuth,
		},
	}

	// Create agent assignments
	agents := make([]common.AnalysisAgent, len(analyses))
	for i, analysis := range analyses {
		agentID := fmt.Sprintf("agent_%s_%d", analysis.AssignedAgent, i+1)
		agents[i] = common.AnalysisAgent{
			AgentID:              agentID,
			AgentType:            analysis.AssignedAgent,
			AnalysisID:           analysis.AnalysisID,
			StateFile:            filepath.Join(o.SessionDir, "sub_agents", fmt.Sprintf("%s_state.json", agentID)),
			Status:               common.AgentStatusPending,
			FilesAnalyzed:        0,
			VulnerabilitiesFound: 0,
		}
	}

	o.mu.Lock()
	o.State.DecomposedAnalyses = analyses
	o.State.AnalysisAgents = agents
	o.mu.Unlock()

	fmt.Printf("✅ Created %d specialized analysis tasks with %d agents\n", len(analyses), len(agents))

	return o.updatePhase(common.PhaseParallelAnalysis)
}

// Phase 5: Execute Parallel Code Analysis
func (o *SecurityOrchestrator) phase5_ExecuteParallelCodeAnalysis(repoContext *common.RepositoryContext) error {
	fmt.Println("🔄 Phase 5: Execute Parallel Code Analysis")

	var wg sync.WaitGroup
	agentResults := make(chan *common.AgentResults, len(o.State.AnalysisAgents))
	errors := make(chan error, len(o.State.AnalysisAgents))

	// Spawn all analysis agents in parallel
	for _, analysisAgent := range o.State.AnalysisAgents {
		wg.Add(1)
		go func(agentInfo common.AnalysisAgent) {
			defer wg.Done()

			fmt.Printf("🤖 Starting agent: %s (%s)\n", agentInfo.AgentID, agentInfo.AgentType)

			// Find the corresponding analysis
			var analysis *common.DecomposedAnalysis
			for _, a := range o.State.DecomposedAnalyses {
				if a.AnalysisID == agentInfo.AnalysisID {
					analysis = &a
					break
				}
			}

			if analysis == nil {
				errors <- fmt.Errorf("analysis not found for agent %s", agentInfo.AgentID)
				return
			}

			// Create agent session
			agentProcess, err := o.ClaudeSDK.CreateAgentSession(agentInfo.AgentType, agentInfo.AnalysisID, analysis.FileScope)
			if err != nil {
				errors <- fmt.Errorf("failed to create agent session: %w", err)
				return
			}

			// Spawn the agent
			if err := o.ClaudeSDK.SpawnAgent(agentProcess, repoContext); err != nil {
				errors <- fmt.Errorf("failed to spawn agent: %w", err)
				return
			}

			// Monitor agent progress
			if err := o.monitorAgentProgress(agentProcess.ID); err != nil {
				errors <- fmt.Errorf("agent monitoring failed: %w", err)
				return
			}

			// Collect results
			results, err := o.ClaudeSDK.CollectResults(agentProcess.ID)
			if err != nil {
				errors <- fmt.Errorf("failed to collect results: %w", err)
				return
			}

			fmt.Printf("✅ Agent %s completed: %d vulnerabilities found\n",
				agentInfo.AgentID, len(results.Vulnerabilities))

			agentResults <- results

		}(analysisAgent)
	}

	// Wait for all agents to complete
	go func() {
		wg.Wait()
		close(agentResults)
		close(errors)
	}()

	// Collect all results and errors
	var allResults []*common.AgentResults
	var allErrors []error

	for {
		select {
		case result, ok := <-agentResults:
			if !ok {
				goto done
			}
			if result != nil {
				allResults = append(allResults, result)
			}
		case err, ok := <-errors:
			if !ok {
				goto done
			}
			if err != nil {
				allErrors = append(allErrors, err)
				fmt.Printf("⚠️ Agent error: %v\n", err)
			}
		}
	}

done:
	if len(allErrors) > 0 {
		return fmt.Errorf("some agents failed: %d errors occurred", len(allErrors))
	}

	fmt.Printf("✅ All %d agents completed successfully\n", len(allResults))

	return o.updatePhase(common.PhaseSynthesis)
}

// Helper methods for codebase analysis

func (o *SecurityOrchestrator) analyzeProjectStructure(files []common.RepositoryFile, primaryLang string) common.ProjectStructure {
	structure := common.ProjectStructure{
		Language:        primaryLang,
		MainEntryPoints: []string{},
		ConfigFiles:     []string{},
		TestDirectories: []string{},
		Documentation:   []string{},
		Dependencies:    make(map[string]string),
		Architecture:    "unknown",
	}

	for _, file := range files {
		name := strings.ToLower(file.Path)

		// Identify entry points
		if strings.Contains(name, "main.") || strings.Contains(name, "index.") ||
			strings.Contains(name, "app.") || strings.Contains(name, "server.") {
			structure.MainEntryPoints = append(structure.MainEntryPoints, file.Path)
		}

		// Identify config files
		if strings.Contains(name, "config") || strings.HasSuffix(name, ".conf") ||
			strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") ||
			strings.HasSuffix(name, ".json") && (strings.Contains(name, "package") || strings.Contains(name, "config")) {
			structure.ConfigFiles = append(structure.ConfigFiles, file.Path)
		}

		// Identify test directories
		if strings.Contains(name, "test") || strings.Contains(name, "spec") {
			structure.TestDirectories = append(structure.TestDirectories, file.Path)
		}

		// Identify documentation
		if strings.HasSuffix(name, ".md") || strings.HasSuffix(name, ".rst") ||
			strings.HasSuffix(name, ".txt") && strings.Contains(name, "readme") {
			structure.Documentation = append(structure.Documentation, file.Path)
		}
	}

	return structure
}

func (o *SecurityOrchestrator) detectTechnologyStack(files []common.RepositoryFile, language string) common.TechnologyStack {
	stack := common.TechnologyStack{
		Framework:         "unknown",
		Libraries:         []string{},
		DatabaseTech:      []string{},
		WebServer:         "unknown",
		SecurityLibraries: []string{},
		BuildTools:        []string{},
	}

	// Framework detection based on files and language
	frameworkIndicators := map[string]string{
		"package.json":     "Node.js",
		"requirements.txt": "Python",
		"pom.xml":          "Java/Maven",
		"go.mod":           "Go",
		"Gemfile":          "Ruby",
		"composer.json":    "PHP",
	}

	for _, file := range files {
		name := strings.ToLower(file.Path)

		if framework, exists := frameworkIndicators[name]; exists {
			stack.Framework = framework
		}

		// Detect build tools
		if strings.Contains(name, "makefile") || strings.Contains(name, "dockerfile") ||
			strings.Contains(name, "build.") || strings.Contains(name, "webpack") {
			stack.BuildTools = append(stack.BuildTools, file.Path)
		}
	}

	return stack
}

func (o *SecurityOrchestrator) estimateLinesOfCode(files []common.RepositoryFile) int {
	// Simple estimation: 50 lines per code file on average
	codeFiles := 0
	for _, file := range files {
		if o.isCodeFile(file.Path) {
			codeFiles++
		}
	}
	return codeFiles * 50
}

func (o *SecurityOrchestrator) identifySecurityRelevantFiles(files []common.RepositoryFile) []string {
	var securityFiles []string

	securityPatterns := []string{
		"auth", "login", "security", "crypto", "encrypt", "password",
		"session", "token", "secret", "key", "cert", "ssl", "tls",
	}

	for _, file := range files {
		name := strings.ToLower(file.Path)
		for _, pattern := range securityPatterns {
			if strings.Contains(name, pattern) {
				securityFiles = append(securityFiles, file.Path)
				break
			}
		}
	}

	return securityFiles
}

func (o *SecurityOrchestrator) isCodeFile(path string) bool {
	codeExtensions := []string{".py", ".js", ".java", ".go", ".php", ".rb", ".c", ".cpp", ".cs", ".jsx", ".ts", ".vue"}
	for _, ext := range codeExtensions {
		if strings.HasSuffix(strings.ToLower(path), ext) {
			return true
		}
	}
	return false
}

// Additional helper methods would be implemented here...
// (identifyInputSources, identifyDangerousSinks, etc.)

// Save state to JSON file
func (o *SecurityOrchestrator) saveState() error {
	o.mu.RLock()
	defer o.mu.RUnlock()

	data, err := json.MarshalIndent(o.State, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	return os.WriteFile(o.StateFile, data, 0644)
}

// Update current phase and save state
func (o *SecurityOrchestrator) updatePhase(phase string) error {
	o.mu.Lock()
	o.State.CurrentPhase = phase
	o.mu.Unlock()

	return o.saveState()
}

// Placeholder implementations for remaining phases and helper methods
func (o *SecurityOrchestrator) identifyInputSources(repoContext *common.RepositoryContext) []common.InputSource {
	return []common.InputSource{}
}

func (o *SecurityOrchestrator) identifyDangerousSinks(repoContext *common.RepositoryContext) []common.DangerousSink {
	return []common.DangerousSink{}
}

func (o *SecurityOrchestrator) identifySecurityControls(repoContext *common.RepositoryContext) []common.SecurityControl {
	return []common.SecurityControl{}
}

func (o *SecurityOrchestrator) filterFilesByPatterns(patterns []string) []string {
	return []string{}
}

func (o *SecurityOrchestrator) monitorAgentProgress(agentID string) error {
	return nil
}

func (o *SecurityOrchestrator) phase6_SynthesizeAndValidateFindings() error {
	fmt.Println("🔄 Phase 6: Synthesize and Validate Findings")
	return o.updatePhase(common.PhaseReporting)
}

func (o *SecurityOrchestrator) phase7_GenerateCodeSecurityReport() (string, error) {
	fmt.Println("🔄 Phase 7: Generate Code Security Report")
	reportPath := filepath.Join(o.SessionDir, "security_report.md")

	// Create basic report
	report := fmt.Sprintf("# Security Analysis Report\n\nSession: %s\nCompleted: %s\n",
		o.SessionID, time.Now().Format(time.RFC3339))

	if err := os.WriteFile(reportPath, []byte(report), 0644); err != nil {
		return "", fmt.Errorf("failed to write report: %w", err)
	}

	o.mu.Lock()
	o.State.CurrentPhase = common.PhaseCompleted
	o.State.FinalReportPath = &reportPath
	now := time.Now()
	o.State.CompletedAt = &now
	o.mu.Unlock()

	return reportPath, o.saveState()
}

func (o *SecurityOrchestrator) convertToValidatedResults() []common.ValidatedResult {
	return []common.ValidatedResult{}
}

func (o *SecurityOrchestrator) countSecrets() int {
	return 0
}
