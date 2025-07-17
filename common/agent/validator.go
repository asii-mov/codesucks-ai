package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/asii-mov/codesucks-ai/common"
	"github.com/asii-mov/codesucks-ai/common/github"
)

// AgentValidator provides repository-aware vulnerability validation
type AgentValidator struct {
	APIKey         string
	Model          string
	HTTPClient     *http.Client
	GitHubClient   *github.GitHubClient
	RepoContext    *common.RepositoryContext
	Debug          bool
}

// NewAgentValidator creates a new agent validator
func NewAgentValidator(apiKey string, githubClient *github.GitHubClient, debug bool) *AgentValidator {
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}

	return &AgentValidator{
		APIKey:       apiKey,
		Model:        common.DefaultModel,
		HTTPClient:   &http.Client{Timeout: 120 * time.Second},
		GitHubClient: githubClient,
		Debug:        debug,
	}
}

// FamiliarizeWithRepository analyzes the repository to build context
func (av *AgentValidator) FamiliarizeWithRepository(owner, repo, branch, tempDir string) (*common.RepositoryContext, error) {
	if av.Debug {
		fmt.Printf("🔍 Agent: Familiarizing with repository %s/%s\n", owner, repo)
	}

	context := &common.RepositoryContext{
		ProjectStructure:     common.ProjectStructure{},
		TechnologyStack:      common.TechnologyStack{},
		SecurityPatterns:     []common.SecurityPattern{},
		FrameworkMitigations: []common.FrameworkMitigation{},
		DocumentationInsights: []common.DocumentationInsight{},
	}

	// Analyze project structure
	if err := av.analyzeProjectStructure(owner, repo, branch, tempDir, context); err != nil {
		return nil, fmt.Errorf("failed to analyze project structure: %w", err)
	}

	// Analyze technology stack
	if err := av.analyzeTechnologyStack(owner, repo, branch, context); err != nil {
		return nil, fmt.Errorf("failed to analyze technology stack: %w", err)
	}

	// Analyze security patterns
	if err := av.analyzeSecurityPatterns(owner, repo, branch, context); err != nil {
		return nil, fmt.Errorf("failed to analyze security patterns: %w", err)
	}

	// Analyze documentation
	if err := av.analyzeDocumentation(owner, repo, branch, context); err != nil {
		return nil, fmt.Errorf("failed to analyze documentation: %w", err)
	}

	av.RepoContext = context
	return context, nil
}

// ValidateVulnerability validates a vulnerability using repository context
func (av *AgentValidator) ValidateVulnerability(result common.Result, sourcePath string) (*common.AgentValidation, error) {
	if av.RepoContext == nil {
		return nil, fmt.Errorf("repository context not initialized - call FamiliarizeWithRepository first")
	}

	if av.Debug {
		fmt.Printf("🤖 Agent: Validating vulnerability %s in %s\n", result.CheckID, result.Path)
	}

	// Get file content and context
	fileContent, err := av.getFileContent(sourcePath, result.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to get file content: %w", err)
	}

	// Extract vulnerable code with context
	vulnerableCode, contextCode, err := av.extractCodeContext(fileContent, result.Start.Line, result.End.Line)
	if err != nil {
		return nil, fmt.Errorf("failed to extract code context: %w", err)
	}

	// Build validation prompt
	prompt := av.buildValidationPrompt(result, vulnerableCode, contextCode)

	// Send to Claude for analysis
	response, err := av.sendRequest(prompt)
	if err != nil {
		return nil, fmt.Errorf("failed to get validation response: %w", err)
	}

	// Parse validation response
	validation, err := av.parseValidationResponse(response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse validation response: %w", err)
	}

	validation.ValidatedAt = time.Now().UTC().Format(time.RFC3339)
	return validation, nil
}

// analyzeProjectStructure analyzes the project structure
func (av *AgentValidator) analyzeProjectStructure(owner, repo, branch, tempDir string, context *common.RepositoryContext) error {
	// Walk through the temporary directory to understand structure
	mainFiles := []string{}
	configFiles := []string{}
	testDirs := []string{}
	docFiles := []string{}
	dependencies := make(map[string]string)

	err := filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, _ := filepath.Rel(tempDir, path)
		if relPath == "." || strings.HasPrefix(relPath, ".git") {
			return nil
		}

		if info.IsDir() {
			if strings.Contains(strings.ToLower(relPath), "test") {
				testDirs = append(testDirs, relPath)
			}
			return nil
		}

		filename := strings.ToLower(info.Name())
		
		// Identify main entry points
		if filename == "main.go" || filename == "index.js" || filename == "app.js" || 
		   filename == "server.js" || filename == "main.py" || filename == "__init__.py" {
			mainFiles = append(mainFiles, relPath)
		}

		// Identify config files
		if strings.Contains(filename, "config") || filename == "package.json" || 
		   filename == "go.mod" || filename == "requirements.txt" || filename == "pom.xml" ||
		   filename == "dockerfile" || strings.HasSuffix(filename, ".conf") ||
		   strings.HasSuffix(filename, ".yaml") || strings.HasSuffix(filename, ".yml") {
			configFiles = append(configFiles, relPath)
		}

		// Identify documentation
		if strings.Contains(filename, "readme") || strings.Contains(filename, "doc") ||
		   strings.HasSuffix(filename, ".md") {
			docFiles = append(docFiles, relPath)
		}

		return nil
	})

	if err != nil {
		return err
	}

	// Detect primary language
	language := av.detectLanguage(tempDir)

	// Parse dependencies from common files
	av.parseDependencies(tempDir, dependencies)

	context.ProjectStructure = common.ProjectStructure{
		Language:        language,
		MainEntryPoints: mainFiles,
		ConfigFiles:     configFiles,
		TestDirectories: testDirs,
		Documentation:   docFiles,
		Dependencies:    dependencies,
		Architecture:    av.detectArchitecture(tempDir, language),
	}

	return nil
}

// analyzeTechnologyStack analyzes the technology stack
func (av *AgentValidator) analyzeTechnologyStack(owner, repo, branch string, context *common.RepositoryContext) error {
	stack := common.TechnologyStack{
		Libraries:         []string{},
		DatabaseTech:      []string{},
		SecurityLibraries: []string{},
		BuildTools:        []string{},
	}

	// Analyze based on language and dependencies
	for depName, depVersion := range context.ProjectStructure.Dependencies {
		depLower := strings.ToLower(depName)
		
		// Security libraries
		if av.isSecurityLibrary(depLower) {
			stack.SecurityLibraries = append(stack.SecurityLibraries, fmt.Sprintf("%s@%s", depName, depVersion))
		}

		// Database technologies
		if av.isDatabaseTech(depLower) {
			stack.DatabaseTech = append(stack.DatabaseTech, depName)
		}

		// Web frameworks
		if av.isWebFramework(depLower) {
			stack.Framework = depName
		}

		// Build tools
		if av.isBuildTool(depLower) {
			stack.BuildTools = append(stack.BuildTools, depName)
		}

		stack.Libraries = append(stack.Libraries, depName)
	}

	context.TechnologyStack = stack
	return nil
}

// analyzeSecurityPatterns analyzes existing security patterns
func (av *AgentValidator) analyzeSecurityPatterns(owner, repo, branch string, context *common.RepositoryContext) error {
	patterns := []common.SecurityPattern{}

	// Look for common security patterns based on the tech stack
	if context.TechnologyStack.Framework != "" {
		patterns = append(patterns, av.getFrameworkSecurityPatterns(context.TechnologyStack.Framework)...)
	}

	for _, lib := range context.TechnologyStack.SecurityLibraries {
		patterns = append(patterns, av.getLibrarySecurityPatterns(lib)...)
	}

	context.SecurityPatterns = patterns
	return nil
}

// analyzeDocumentation analyzes documentation for security insights
func (av *AgentValidator) analyzeDocumentation(owner, repo, branch string, context *common.RepositoryContext) error {
	insights := []common.DocumentationInsight{}

	// Read README and other documentation
	for _, docFile := range context.ProjectStructure.Documentation {
		if strings.ToLower(filepath.Base(docFile)) == "readme.md" {
			content, err := av.GitHubClient.GetFileContent(owner, repo, branch, docFile)
			if err != nil {
				continue
			}

			insights = append(insights, common.DocumentationInsight{
				Source:    docFile,
				Content:   content,
				Relevance: 0.8,
			})
		}
	}

	context.DocumentationInsights = insights
	return nil
}

// buildValidationPrompt builds the prompt for vulnerability validation
func (av *AgentValidator) buildValidationPrompt(result common.Result, vulnerableCode, contextCode string) string {
	repoContextStr := av.formatRepositoryContext()
	
	prompt := fmt.Sprintf("You are a security expert with deep knowledge of software vulnerabilities and the ability to analyze code in context. Your task is to validate whether a reported vulnerability is a true positive or false positive by considering the full repository context.\n\n"+
		"REPOSITORY CONTEXT:\n%s\n\n"+
		"VULNERABILITY DETAILS:\n"+
		"- Rule ID: %s\n"+
		"- File: %s\n"+
		"- Lines: %d-%d\n"+
		"- Severity: %s\n"+
		"- Description: %s\n\n"+
		"VULNERABLE CODE:\n```\n%s\n```\n\n"+
		"SURROUNDING CONTEXT:\n```\n%s\n```\n\n"+
		"ANALYSIS INSTRUCTIONS:\n"+
		"1. First, understand the repository's architecture, framework, and security patterns\n"+
		"2. Analyze the vulnerability in the context of the entire codebase\n"+
		"3. Consider framework-specific mitigations and security patterns\n"+
		"4. Evaluate if the vulnerability is actually exploitable given the context\n"+
		"5. Check for existing security controls that might mitigate the issue\n\n"+
		"VALIDATION CRITERIA:\n"+
		"- Is this vulnerability actually exploitable in this specific context?\n"+
		"- Are there framework or library mitigations that prevent exploitation?\n"+
		"- Are there input validation or sanitization mechanisms in place?\n"+
		"- Is the vulnerable code in a test file or unreachable code path?\n"+
		"- Are there configuration or deployment factors that mitigate the risk?\n\n"+
		"Please respond in JSON format:\n"+
		"{\n"+
		"  \"is_legitimate\": true/false,\n"+
		"  \"confidence\": 0.0-1.0,\n"+
		"  \"reasoning\": \"Detailed explanation of your analysis\",\n"+
		"  \"context_analysis\": \"How the repository context affects this vulnerability\",\n"+
		"  \"recommended_action\": \"What should be done about this finding\",\n"+
		"  \"false_positive_reason\": \"If false positive, explain why (omit if legitimate)\"\n"+
		"}\n\n"+
		"Be thorough in your analysis and provide clear reasoning for your decision.",
		repoContextStr,
		result.CheckID,
		result.Path,
		result.Start.Line,
		result.End.Line,
		result.Extra.Metadata.Impact,
		result.Extra.Message,
		vulnerableCode,
		contextCode,
	)

	return prompt
}

// formatRepositoryContext formats the repository context for the prompt
func (av *AgentValidator) formatRepositoryContext() string {
	if av.RepoContext == nil {
		return "No repository context available"
	}

	var buf strings.Builder
	
	buf.WriteString("PROJECT STRUCTURE:\n")
	buf.WriteString(fmt.Sprintf("  Language: %s\n", av.RepoContext.ProjectStructure.Language))
	buf.WriteString(fmt.Sprintf("  Architecture: %s\n", av.RepoContext.ProjectStructure.Architecture))
	buf.WriteString(fmt.Sprintf("  Entry Points: %s\n", strings.Join(av.RepoContext.ProjectStructure.MainEntryPoints, ", ")))
	
	buf.WriteString("\nTECHNOLOGY STACK:\n")
	buf.WriteString(fmt.Sprintf("  Framework: %s\n", av.RepoContext.TechnologyStack.Framework))
	buf.WriteString(fmt.Sprintf("  Security Libraries: %s\n", strings.Join(av.RepoContext.TechnologyStack.SecurityLibraries, ", ")))
	buf.WriteString(fmt.Sprintf("  Database Tech: %s\n", strings.Join(av.RepoContext.TechnologyStack.DatabaseTech, ", ")))
	
	buf.WriteString("\nSECURITY PATTERNS:\n")
	for _, pattern := range av.RepoContext.SecurityPatterns {
		buf.WriteString(fmt.Sprintf("  - %s: %s (confidence: %.2f)\n", pattern.Pattern, pattern.Description, pattern.Confidence))
	}
	
	return buf.String()
}

// Helper functions for analysis
func (av *AgentValidator) detectLanguage(tempDir string) string {
	languages := make(map[string]int)
	
	filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		
		ext := strings.ToLower(filepath.Ext(info.Name()))
		switch ext {
		case ".go":
			languages["Go"]++
		case ".js", ".jsx":
			languages["JavaScript"]++
		case ".ts", ".tsx":
			languages["TypeScript"]++
		case ".py":
			languages["Python"]++
		case ".java":
			languages["Java"]++
		case ".php":
			languages["PHP"]++
		case ".rb":
			languages["Ruby"]++
		case ".rs":
			languages["Rust"]++
		case ".cpp", ".cc", ".cxx":
			languages["C++"]++
		case ".c":
			languages["C"]++
		}
		return nil
	})
	
	maxLang := "Unknown"
	maxCount := 0
	for lang, count := range languages {
		if count > maxCount {
			maxCount = count
			maxLang = lang
		}
	}
	
	return maxLang
}

func (av *AgentValidator) detectArchitecture(tempDir, language string) string {
	// Simple heuristics for architecture detection
	if language == "Go" {
		if av.fileExists(filepath.Join(tempDir, "cmd")) {
			return "CLI Application"
		}
		if av.fileExists(filepath.Join(tempDir, "main.go")) {
			return "Monolith"
		}
	}
	
	if language == "JavaScript" || language == "TypeScript" {
		if av.fileExists(filepath.Join(tempDir, "package.json")) {
			return "Node.js Application"
		}
	}
	
	return "Unknown"
}

func (av *AgentValidator) fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (av *AgentValidator) parseDependencies(tempDir string, dependencies map[string]string) {
	// Parse Go dependencies
	if goMod := filepath.Join(tempDir, "go.mod"); av.fileExists(goMod) {
		av.parseGoMod(goMod, dependencies)
	}
	
	// Parse Node.js dependencies
	if packageJson := filepath.Join(tempDir, "package.json"); av.fileExists(packageJson) {
		av.parsePackageJson(packageJson, dependencies)
	}
}

func (av *AgentValidator) parseGoMod(goModPath string, dependencies map[string]string) {
	// Simple parsing - in production, use proper go.mod parser
	content, err := os.ReadFile(goModPath)
	if err != nil {
		return
	}
	
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "require") || strings.Contains(line, "github.com/") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				dependencies[parts[0]] = parts[1]
			}
		}
	}
}

func (av *AgentValidator) parsePackageJson(packageJsonPath string, dependencies map[string]string) {
	content, err := os.ReadFile(packageJsonPath)
	if err != nil {
		return
	}
	
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	
	if err := json.Unmarshal(content, &pkg); err != nil {
		return
	}
	
	for name, version := range pkg.Dependencies {
		dependencies[name] = version
	}
	for name, version := range pkg.DevDependencies {
		dependencies[name] = version
	}
}

func (av *AgentValidator) isSecurityLibrary(name string) bool {
	securityLibs := []string{
		"helmet", "cors", "express-rate-limit", "bcrypt", "jsonwebtoken",
		"crypto", "argon2", "scrypt", "oauth2", "passport",
		"csrf", "csurf", "express-validator", "joi", "yup",
	}
	
	for _, lib := range securityLibs {
		if strings.Contains(name, lib) {
			return true
		}
	}
	return false
}

func (av *AgentValidator) isDatabaseTech(name string) bool {
	dbTech := []string{
		"mongodb", "mysql", "postgresql", "sqlite", "redis",
		"elasticsearch", "cassandra", "neo4j", "couchdb",
	}
	
	for _, tech := range dbTech {
		if strings.Contains(name, tech) {
			return true
		}
	}
	return false
}

func (av *AgentValidator) isWebFramework(name string) bool {
	frameworks := []string{
		"express", "koa", "fastify", "hapi", "nestjs",
		"react", "vue", "angular", "svelte",
		"gin", "echo", "fiber", "chi",
		"django", "flask", "fastapi",
	}
	
	for _, framework := range frameworks {
		if strings.Contains(name, framework) {
			return true
		}
	}
	return false
}

func (av *AgentValidator) isBuildTool(name string) bool {
	buildTools := []string{
		"webpack", "vite", "rollup", "parcel",
		"babel", "typescript", "eslint", "prettier",
		"jest", "mocha", "chai", "cypress",
	}
	
	for _, tool := range buildTools {
		if strings.Contains(name, tool) {
			return true
		}
	}
	return false
}

func (av *AgentValidator) getFrameworkSecurityPatterns(framework string) []common.SecurityPattern {
	patterns := []common.SecurityPattern{}
	
	switch strings.ToLower(framework) {
	case "express":
		patterns = append(patterns, common.SecurityPattern{
			Pattern:     "Express Helmet",
			Description: "Security headers middleware",
			Confidence:  0.8,
		})
	case "gin":
		patterns = append(patterns, common.SecurityPattern{
			Pattern:     "Gin CORS",
			Description: "CORS middleware for Gin",
			Confidence:  0.7,
		})
	}
	
	return patterns
}

func (av *AgentValidator) getLibrarySecurityPatterns(library string) []common.SecurityPattern {
	patterns := []common.SecurityPattern{}
	
	if strings.Contains(library, "helmet") {
		patterns = append(patterns, common.SecurityPattern{
			Pattern:     "Security Headers",
			Description: "Helmet provides security headers",
			Confidence:  0.9,
		})
	}
	
	return patterns
}

func (av *AgentValidator) getFileContent(sourcePath, filePath string) (string, error) {
	fullPath := filepath.Join(sourcePath, filePath)
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func (av *AgentValidator) extractCodeContext(content string, startLine, endLine int) (string, string, error) {
	lines := strings.Split(content, "\n")
	
	if startLine < 1 || endLine > len(lines) {
		return "", "", fmt.Errorf("invalid line range")
	}
	
	// Vulnerable code (0-indexed)
	vulnerableCode := strings.Join(lines[startLine-1:endLine], "\n")
	
	// Context (10 lines before and after)
	contextStart := max(0, startLine-10)
	contextEnd := min(len(lines), endLine+10)
	
	var contextLines []string
	for i := contextStart; i < contextEnd; i++ {
		lineNum := i + 1
		prefix := "    "
		if lineNum >= startLine && lineNum <= endLine {
			prefix = ">>> "
		}
		contextLines = append(contextLines, fmt.Sprintf("%s%4d: %s", prefix, lineNum, lines[i]))
	}
	
	contextCode := strings.Join(contextLines, "\n")
	
	return vulnerableCode, contextCode, nil
}

func (av *AgentValidator) sendRequest(prompt string) (string, error) {
	reqBody := common.ClaudeRequest{
		Model:     av.Model,
		MaxTokens: 2048,
		Messages: []common.Message{
			{
				Role:    "user",
				Content: prompt,
			},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", common.ClaudeAPIEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", av.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := av.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var claudeResp common.ClaudeResponse
	if err := json.Unmarshal(body, &claudeResp); err != nil {
		return "", err
	}

	if len(claudeResp.Content) == 0 {
		return "", fmt.Errorf("empty response from Claude API")
	}

	return claudeResp.Content[0].Text, nil
}

func (av *AgentValidator) parseValidationResponse(response string) (*common.AgentValidation, error) {
	// Try to extract JSON from response
	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")
	
	if jsonStart == -1 || jsonEnd == -1 {
		return nil, fmt.Errorf("no valid JSON found in response")
	}
	
	jsonStr := response[jsonStart : jsonEnd+1]
	
	var validation common.AgentValidation
	if err := json.Unmarshal([]byte(jsonStr), &validation); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}
	
	return &validation, nil
}

// Helper functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}