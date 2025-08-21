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
	"github.com/asii-mov/codesucks-ai/common/report"
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

	// Clean up downloaded code (optional - keep for debugging)
	if !o.Options.Debug {
		vulnerableCodePath := filepath.Join(o.SessionDir, "vulnerable_code")
		if err := os.RemoveAll(vulnerableCodePath); err != nil {
			fmt.Printf("⚠️ Warning: Failed to clean up temp files: %v\n", err)
		}
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

	// Create temp directory for repository content
	tempDir := filepath.Join(o.SessionDir, "vulnerable_code")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create vulnerable_code directory: %w", err)
	}

	// Fetch actual repository content via GitHub API
	sourcePath, err := o.GitHubClient.FetchRepositoryContent(owner, repo, repoInfo.DefaultBranch, tempDir)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch repository content: %w", err)
	}

	// Get repository file metadata (for analysis)
	files, err := o.GitHubClient.ListRepositoryFiles(owner, repo, repoInfo.DefaultBranch)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository contents: %w", err)
	}

	// Store source path and default branch in orchestrator state for agents
	o.mu.Lock()
	o.State.SourcePath = sourcePath
	o.State.DefaultBranch = repoInfo.DefaultBranch
	o.State.FilesDownloaded = len(files)
	o.mu.Unlock()

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
		SourcePath:            sourcePath,
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

	// Get actual file paths from downloaded source
	actualFiles, err := o.getSourceFiles(repoContext.SourcePath)
	if err != nil {
		return fmt.Errorf("failed to get source files: %w", err)
	}

	// Distribute files to agents based on their specialization
	o.distributeFilesToAgents(actualFiles)

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

			// Create agent session with predefined ID
			agentProcess, err := o.ClaudeSDK.CreateAgentSessionWithID(agentInfo.AgentID, agentInfo.AgentType, agentInfo.AnalysisID, analysis.FileScope)
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

	// Collect all validated results from agents
	allValidatedResults := o.convertToValidatedResults()

	// Synthesize findings into enhanced vulnerabilities
	enhancedVulns := o.synthesizeVulnerabilities(allValidatedResults)

	// Identify vulnerability patterns across agents
	patterns := o.identifyVulnerabilityPatterns(allValidatedResults)

	// Update orchestrator state with synthesized data
	o.mu.Lock()
	o.State.Vulnerabilities = enhancedVulns
	o.State.VulnerabilityPatterns = patterns
	o.State.CodeMetrics = o.calculateCodeMetrics(allValidatedResults)
	o.mu.Unlock()

	fmt.Printf("📊 Synthesized %d vulnerabilities and %d patterns from agent findings\n",
		len(enhancedVulns), len(patterns))

	return o.updatePhase(common.PhaseReporting)
}

// synthesizeVulnerabilities converts ValidatedResults to EnhancedVulnerabilities
func (o *SecurityOrchestrator) synthesizeVulnerabilities(results []common.ValidatedResult) []common.EnhancedVulnerability {
	var enhanced []common.EnhancedVulnerability

	for i, result := range results {
		vuln := common.EnhancedVulnerability{
			VulnID:     fmt.Sprintf("VULN-%04d", i+1),
			Type:       o.extractVulnerabilityType(result.CheckID),
			CweID:      o.mapToCWE(result.CheckID),
			Severity:   result.Extra.Metadata.Impact,
			Confidence: fmt.Sprintf("%.2f", result.AgentValidation.Confidence),
			Location: common.VulnLocation{
				File:      result.Path,
				StartLine: result.Start.Line,
				EndLine:   result.End.Line,
				Function:  o.extractFunctionName(result.Extra.Lines),
			},
			DataFlow: common.DataFlow{
				Source:          "user_input",
				Transformations: []string{},
				Sink:            result.Extra.Message,
			},
			VulnerableCode: result.Extra.Lines,
			ExploitExample: o.generateExploitExample(result),
			SecureCode:     result.AgentValidation.RecommendedAction,
			FixExplanation: result.AgentValidation.Reasoning,
		}
		enhanced = append(enhanced, vuln)
	}

	return enhanced
}

// identifyVulnerabilityPatterns finds systemic issues across findings
func (o *SecurityOrchestrator) identifyVulnerabilityPatterns(results []common.ValidatedResult) []common.VulnerabilityPattern {
	var patterns []common.VulnerabilityPattern

	// Group vulnerabilities by type
	typeGroups := make(map[string][]common.ValidatedResult)
	for _, result := range results {
		vulnType := o.extractVulnerabilityType(result.CheckID)
		typeGroups[vulnType] = append(typeGroups[vulnType], result)
	}

	// Create patterns for types with multiple instances
	patternID := 1
	for vulnType, instances := range typeGroups {
		if len(instances) >= 2 { // Pattern if 2+ instances
			var locations []string
			for _, instance := range instances {
				locations = append(locations, fmt.Sprintf("%s:%d", instance.Path, instance.Start.Line))
			}

			pattern := common.VulnerabilityPattern{
				PatternID:   fmt.Sprintf("PATTERN-%03d", patternID),
				Description: fmt.Sprintf("Systemic %s vulnerabilities found across %d locations", vulnType, len(instances)),
				Instances:   locations,
				SystemicFix: o.generateSystemicFix(vulnType, instances),
			}
			patterns = append(patterns, pattern)
			patternID++
		}
	}

	return patterns
}

// calculateCodeMetrics computes metrics from synthesized findings
func (o *SecurityOrchestrator) calculateCodeMetrics(results []common.ValidatedResult) common.CodeMetrics {
	severityCount := make(map[string]int)
	fileSet := make(map[string]bool)

	for _, result := range results {
		severityCount[result.Extra.Metadata.Impact]++
		fileSet[result.Path] = true
	}

	var density float64
	if len(fileSet) > 0 {
		density = float64(len(results)) / float64(len(fileSet))
	}

	return common.CodeMetrics{
		FilesAnalyzed:            len(fileSet),
		FunctionsAnalyzed:        0, // TODO: Could be enhanced by analyzing function extraction
		TotalVulnerabilities:     len(results),
		SeverityDistribution:     severityCount,
		VulnerabilityDensity:     density,
		MostVulnerableComponents: o.findMostVulnerableComponents(results),
	}
}

// Helper functions for synthesis

func (o *SecurityOrchestrator) extractVulnerabilityType(checkID string) string {
	// Extract vulnerability type from agent type and check ID
	parts := strings.Split(checkID, "-")
	if len(parts) >= 2 {
		return parts[1] // e.g., "code-xss-analyser-stored_xss" -> "xss"
	}
	return "unknown"
}

func (o *SecurityOrchestrator) mapToCWE(checkID string) string {
	// Map common vulnerability types to CWE IDs
	cweMap := map[string]string{
		"xss":       "CWE-79",
		"sqli":      "CWE-89",
		"injection": "CWE-94",
		"path":      "CWE-22",
		"crypto":    "CWE-327",
		"auth":      "CWE-287",
	}

	for vulnType, cwe := range cweMap {
		if strings.Contains(strings.ToLower(checkID), vulnType) {
			return cwe
		}
	}

	return "CWE-1000" // Default: unknown
}

func (o *SecurityOrchestrator) extractFunctionName(codeLines string) string {
	// Simple function name extraction from code context
	lines := strings.Split(codeLines, "\n")
	for _, line := range lines {
		if strings.Contains(line, "function") || strings.Contains(line, "def ") {
			// Extract function name after "function" or "def"
			words := strings.Fields(line)
			for i, word := range words {
				if (word == "function" || word == "def") && i+1 < len(words) {
					return strings.TrimSuffix(words[i+1], "(")
				}
			}
		}
	}
	return "unknown"
}

func (o *SecurityOrchestrator) generateExploitExample(result common.ValidatedResult) string {
	vulnType := o.extractVulnerabilityType(result.CheckID)

	examples := map[string]string{
		"xss":       "<script>alert('XSS')</script>",
		"sqli":      "'; DROP TABLE users; --",
		"injection": "$(rm -rf /)",
		"path":      "../../../etc/passwd",
	}

	if example, exists := examples[vulnType]; exists {
		return example
	}

	return "Exploit depends on specific context"
}

func (o *SecurityOrchestrator) generateSystemicFix(vulnType string, instances []common.ValidatedResult) string {
	fixes := map[string]string{
		"xss":       "Implement global output encoding and CSP headers",
		"sqli":      "Use parameterized queries and input validation throughout",
		"injection": "Sanitize all user inputs and avoid dynamic code execution",
		"path":      "Implement proper path validation and sandboxing",
		"crypto":    "Update to secure cryptographic algorithms and proper key management",
		"auth":      "Implement proper authentication and authorization frameworks",
	}

	if fix, exists := fixes[vulnType]; exists {
		return fix
	}

	return "Review and standardize security practices for this vulnerability type"
}

func (o *SecurityOrchestrator) findMostVulnerableComponents(results []common.ValidatedResult) []string {
	fileCount := make(map[string]int)

	for _, result := range results {
		fileCount[result.Path]++
	}

	// Sort files by vulnerability count
	type fileStat struct {
		file  string
		count int
	}

	var stats []fileStat
	for file, count := range fileCount {
		stats = append(stats, fileStat{file, count})
	}

	// Simple bubble sort for top 5
	for i := 0; i < len(stats)-1; i++ {
		for j := 0; j < len(stats)-i-1; j++ {
			if stats[j].count < stats[j+1].count {
				stats[j], stats[j+1] = stats[j+1], stats[j]
			}
		}
	}

	// Return top 5 most vulnerable components
	var components []string
	for i := 0; i < len(stats) && i < 5; i++ {
		components = append(components, fmt.Sprintf("%s (%d vulns)", stats[i].file, stats[i].count))
	}

	return components
}

func (o *SecurityOrchestrator) phase7_GenerateCodeSecurityReport() (string, error) {
	fmt.Println("🔄 Phase 7: Generate Code Security Report")

	// Convert orchestrator findings to ValidatedResults format
	validatedResults := o.convertToValidatedResults()

	// Use the existing report conversion function to create proper ReportData
	reportData := report.ConvertValidatedResultsToReport(o.Options.Repo, o.State.DefaultBranch, validatedResults, nil, o.State.SourcePath)

	// Generate HTML report
	htmlReportPath, err := report.GenerateHTML(reportData, o.SessionDir)
	if err != nil {
		return "", fmt.Errorf("failed to generate HTML report: %w", err)
	}

	// Also create basic markdown report for compatibility
	mdReportPath := filepath.Join(o.SessionDir, "security_report.md")
	mdReport := fmt.Sprintf("# Security Analysis Report\n\nSession: %s\nCompleted: %s\nVulnerabilities Found: %d\nHTML Report: %s\n",
		o.SessionID, time.Now().Format(time.RFC3339), len(validatedResults), htmlReportPath)

	if err := os.WriteFile(mdReportPath, []byte(mdReport), 0644); err != nil {
		return "", fmt.Errorf("failed to write markdown report: %w", err)
	}

	o.mu.Lock()
	o.State.CurrentPhase = common.PhaseCompleted
	o.State.FinalReportPath = &htmlReportPath
	now := time.Now()
	o.State.CompletedAt = &now
	o.mu.Unlock()

	fmt.Printf("✅ HTML Report generated: %s\n", htmlReportPath)
	fmt.Printf("📋 Summary report: %s\n", mdReportPath)

	return htmlReportPath, o.saveState()
}

func (o *SecurityOrchestrator) convertToValidatedResults() []common.ValidatedResult {
	var allResults []common.ValidatedResult

	// Iterate through all agents to collect their results
	for _, analysisAgent := range o.State.AnalysisAgents {
		agentResults := o.parseAgentResults(analysisAgent)
		allResults = append(allResults, agentResults...)
	}

	// Deduplicate and sort results
	allResults = o.deduplicateResults(allResults)

	fmt.Printf("📊 Parsed %d vulnerabilities from %d agents\n", len(allResults), len(o.State.AnalysisAgents))

	return allResults
}

// parseAgentResults reads and parses results from a single agent
func (o *SecurityOrchestrator) parseAgentResults(agent common.AnalysisAgent) []common.ValidatedResult {
	// Construct path to agent results file
	agentDir := filepath.Join(o.SessionDir, "sub_agents", agent.AgentID)
	resultsFile := filepath.Join(agentDir, "results.json")

	// Check if results file exists
	if _, err := os.Stat(resultsFile); os.IsNotExist(err) {
		fmt.Printf("⚠️ No results file found for agent %s (%s)\n", agent.AgentID, agent.AgentType)
		return []common.ValidatedResult{}
	}

	// Read results file
	resultsData, err := os.ReadFile(resultsFile)
	if err != nil {
		fmt.Printf("⚠️ Failed to read results for agent %s: %v\n", agent.AgentID, err)
		return []common.ValidatedResult{}
	}

	// Parse Claude CLI response format
	actualContent := o.extractContentFromClaudeResponse(resultsData)

	// Try to extract JSON from the content
	agentResults := o.parseAgentVulnerabilities(actualContent, agent)

	// Convert to ValidatedResult format
	var validatedResults []common.ValidatedResult
	for _, vuln := range agentResults.Vulnerabilities {
		validatedResult := o.convertSecurityFindingToValidatedResult(vuln, agent)
		validatedResults = append(validatedResults, validatedResult)
	}

	if len(validatedResults) > 0 {
		fmt.Printf("✅ Agent %s (%s): parsed %d vulnerabilities\n", agent.AgentID, agent.AgentType, len(validatedResults))
	}

	return validatedResults
}

// extractContentFromClaudeResponse extracts actual content from Claude CLI response format
func (o *SecurityOrchestrator) extractContentFromClaudeResponse(data []byte) string {
	// First try to parse as Claude CLI response format
	var claudeResponse struct {
		Type     string `json:"type"`
		Content  string `json:"content,omitempty"`
		Result   string `json:"result,omitempty"`
		Messages []struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"messages,omitempty"`
	}

	if err := json.Unmarshal(data, &claudeResponse); err == nil {
		// Extract actual content from Claude CLI response
		if claudeResponse.Result != "" {
			return claudeResponse.Result
		} else if claudeResponse.Content != "" {
			return claudeResponse.Content
		} else if len(claudeResponse.Messages) > 0 && len(claudeResponse.Messages[0].Content) > 0 {
			return claudeResponse.Messages[0].Content[0].Text
		}
	}

	// Fallback to raw data as string
	return string(data)
}

// parseAgentVulnerabilities attempts to parse vulnerabilities from agent content
func (o *SecurityOrchestrator) parseAgentVulnerabilities(content string, agent common.AnalysisAgent) common.AgentResults {
	// Try to extract JSON from the content (Claude often puts JSON in code blocks)
	jsonStart := strings.Index(content, "{")
	jsonEnd := strings.LastIndex(content, "}")

	if jsonStart >= 0 && jsonEnd > jsonStart {
		jsonContent := content[jsonStart : jsonEnd+1]

		var results common.AgentResults
		if err := json.Unmarshal([]byte(jsonContent), &results); err == nil {
			return results
		}

		// Try alternative format where vulnerabilities are in a different structure
		var altResults struct {
			AgentID         string                   `json:"agent_id"`
			AnalysisType    string                   `json:"analysis_type"`
			FilesAnalyzed   []string                 `json:"files_analyzed"`
			Vulnerabilities []common.SecurityFinding `json:"vulnerabilities"`
		}

		if err := json.Unmarshal([]byte(jsonContent), &altResults); err == nil {
			return common.AgentResults{
				AgentID:         altResults.AgentID,
				Type:            altResults.AnalysisType,
				Status:          "completed",
				Vulnerabilities: altResults.Vulnerabilities,
			}
		}
	}

	// If no valid JSON found, create empty results
	return common.AgentResults{
		AgentID:         agent.AgentID,
		Type:            agent.AgentType,
		Status:          "no_results",
		Vulnerabilities: []common.SecurityFinding{},
	}
}

// convertSecurityFindingToValidatedResult converts a SecurityFinding to ValidatedResult format
func (o *SecurityOrchestrator) convertSecurityFindingToValidatedResult(finding common.SecurityFinding, agent common.AnalysisAgent) common.ValidatedResult {
	// Create base Result structure
	result := common.Result{
		CheckID: fmt.Sprintf("%s-%s", agent.AgentType, finding.Type),
		Path:    finding.File,
		Start: struct {
			Line int `json:"line"`
			Col  int `json:"col"`
		}{
			Line: finding.LineStart,
			Col:  1, // Default column
		},
		End: struct {
			Line int `json:"line"`
			Col  int `json:"col"`
		}{
			Line: finding.LineEnd,
			Col:  100, // Default column
		},
		Extra: struct {
			Message  string `json:"message"`
			Lines    string `json:"lines"`
			Metadata struct {
				Impact string `json:"impact"`
			} `json:"metadata"`
		}{
			Message: finding.Description,
			Lines:   finding.VulnerableCode,
			Metadata: struct {
				Impact string `json:"impact"`
			}{
				Impact: finding.Severity,
			},
		},
	}

	// Create agent validation
	agentValidation := &common.AgentValidation{
		IsLegitimate:        true,
		Confidence:          finding.Confidence,
		Reasoning:           finding.FixExplanation,
		ContextAnalysis:     finding.Description,
		RecommendedAction:   finding.SecureFix,
		FalsePositiveReason: "",
		ValidatedAt:         time.Now().Format(time.RFC3339),
	}

	return common.ValidatedResult{
		Result:          result,
		AgentValidation: agentValidation,
		IsFiltered:      false,
	}
}

// deduplicateResults removes duplicate vulnerabilities and sorts by severity
func (o *SecurityOrchestrator) deduplicateResults(results []common.ValidatedResult) []common.ValidatedResult {
	seen := make(map[string]bool)
	var deduped []common.ValidatedResult

	// Create a map to track seen vulnerabilities by file + line + type
	for _, result := range results {
		key := fmt.Sprintf("%s:%d:%s", result.Path, result.Start.Line, result.CheckID)
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, result)
		}
	}

	// Sort by severity (HIGH > MEDIUM > LOW)
	severityOrder := map[string]int{"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

	for i := 0; i < len(deduped)-1; i++ {
		for j := i + 1; j < len(deduped); j++ {
			severity1 := deduped[i].Extra.Metadata.Impact
			severity2 := deduped[j].Extra.Metadata.Impact

			if severityOrder[severity1] < severityOrder[severity2] {
				deduped[i], deduped[j] = deduped[j], deduped[i]
			}
		}
	}

	return deduped
}

func (o *SecurityOrchestrator) countSecrets() int {
	count := 0

	// Count secrets from agent results
	for _, agent := range o.State.AnalysisAgents {
		agentResults := o.parseAgentResults(agent)
		for _, result := range agentResults {
			// Check if this is a secret-related vulnerability
			if o.isSecretVulnerability(result) {
				count++
			}
		}
	}

	// Count from orchestrator state vulnerabilities (from synthesis)
	for _, vuln := range o.State.Vulnerabilities {
		if o.isSecretType(vuln.Type) {
			count++
		}
	}

	return count
}

// isSecretVulnerability checks if a validated result represents a secret vulnerability
func (o *SecurityOrchestrator) isSecretVulnerability(result common.ValidatedResult) bool {
	secretKeywords := []string{
		"secret", "password", "key", "token", "credential", "api_key",
		"auth", "private", "certificate", "ssl", "tls", "hardcoded",
	}

	checkID := strings.ToLower(result.CheckID)
	message := strings.ToLower(result.Extra.Message)

	for _, keyword := range secretKeywords {
		if strings.Contains(checkID, keyword) || strings.Contains(message, keyword) {
			return true
		}
	}

	return false
}

// isSecretType checks if a vulnerability type represents a secret
func (o *SecurityOrchestrator) isSecretType(vulnType string) bool {
	secretTypes := []string{
		"hardcoded_secret", "exposed_credential", "api_key_exposure",
		"password_in_code", "private_key_exposure", "token_leak",
		"credential_leak", "secret_in_config",
	}

	vulnTypeLower := strings.ToLower(vulnType)
	for _, secretType := range secretTypes {
		if strings.Contains(vulnTypeLower, secretType) {
			return true
		}
	}

	return false
}

// getSourceFiles walks the source directory and returns all source files
func (o *SecurityOrchestrator) getSourceFiles(sourcePath string) ([]string, error) {
	var sourceFiles []string

	err := filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-source files
		if info.IsDir() || !o.isSourceFile(path) {
			return nil
		}

		// Make path relative to source directory
		relPath, err := filepath.Rel(sourcePath, path)
		if err != nil {
			return err
		}

		sourceFiles = append(sourceFiles, relPath)
		return nil
	})

	return sourceFiles, err
}

// isSourceFile determines if a file should be analyzed for security issues
func (o *SecurityOrchestrator) isSourceFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))

	// Include common source file extensions
	sourceExtensions := map[string]bool{
		".js": true, ".jsx": true, ".ts": true, ".tsx": true,
		".py": true, ".rb": true, ".php": true, ".java": true,
		".c": true, ".cpp": true, ".cc": true, ".cxx": true, ".h": true, ".hpp": true,
		".cs": true, ".go": true, ".rs": true, ".swift": true, ".kt": true,
		".html": true, ".htm": true, ".xml": true, ".json": true, ".yaml": true, ".yml": true,
		".sql": true, ".sh": true, ".bash": true, ".dockerfile": true,
	}

	return sourceExtensions[ext]
}

// distributeFilesToAgents assigns files to agents based on their specialization
func (o *SecurityOrchestrator) distributeFilesToAgents(files []string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	for i := range o.State.AnalysisAgents {
		agent := &o.State.AnalysisAgents[i]
		agent.Files = o.filterFilesForAgent(files, agent.AgentType)
	}
}

// filterFilesForAgent returns files relevant to a specific agent type
func (o *SecurityOrchestrator) filterFilesForAgent(files []string, agentType string) []string {
	var relevantFiles []string

	for _, file := range files {
		if o.isFileRelevantForAgent(file, agentType) {
			relevantFiles = append(relevantFiles, file)
		}
	}

	// If no specific files, give all source files
	if len(relevantFiles) == 0 {
		return files
	}

	return relevantFiles
}

// isFileRelevantForAgent determines if a file is relevant for a specific agent type
func (o *SecurityOrchestrator) isFileRelevantForAgent(filePath, agentType string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	fileName := strings.ToLower(filepath.Base(filePath))

	switch agentType {
	case "code-injection-analyser":
		// Focus on server-side code and database interactions
		return ext == ".js" || ext == ".py" || ext == ".php" || ext == ".java" || ext == ".sql" ||
			strings.Contains(fileName, "db") || strings.Contains(fileName, "sql") ||
			strings.Contains(fileName, "query") || strings.Contains(fileName, "api")

	case "code-xss-analyser":
		// Focus on web frontend and template files
		return ext == ".html" || ext == ".htm" || ext == ".jsx" || ext == ".tsx" ||
			ext == ".js" || ext == ".ts" || strings.Contains(fileName, "template") ||
			strings.Contains(fileName, "view") || strings.Contains(fileName, "component")

	case "code-path-analyser":
		// Focus on file handling and path operations
		return ext == ".js" || ext == ".py" || ext == ".php" || ext == ".java" ||
			strings.Contains(fileName, "file") || strings.Contains(fileName, "path") ||
			strings.Contains(fileName, "upload") || strings.Contains(fileName, "download")

	case "code-crypto-analyser":
		// Focus on crypto and security-related files
		return strings.Contains(fileName, "crypto") || strings.Contains(fileName, "encrypt") ||
			strings.Contains(fileName, "auth") || strings.Contains(fileName, "security") ||
			strings.Contains(fileName, "password") || strings.Contains(fileName, "token")

	case "code-auth-analyser":
		// Focus on authentication and authorization
		return strings.Contains(fileName, "auth") || strings.Contains(fileName, "login") ||
			strings.Contains(fileName, "session") || strings.Contains(fileName, "user") ||
			strings.Contains(fileName, "permission") || strings.Contains(fileName, "role")

	default:
		return true // Default: analyze all files
	}
}
