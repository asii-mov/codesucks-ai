package matrix

import (
	"fmt"
	"strings"

	"github.com/asii-mov/codesucks-ai/common"
	"github.com/asii-mov/codesucks-ai/common/detector"
)

// MatrixBuilder handles creation of matrix build configurations
type MatrixBuilder struct {
	languageDetector  *detector.LanguageDetector
	frameworkDetector *detector.FrameworkDetector
}

// NewMatrixBuilder creates a new matrix builder
func NewMatrixBuilder() *MatrixBuilder {
	return &MatrixBuilder{
		languageDetector:  detector.NewLanguageDetector(),
		frameworkDetector: detector.NewFrameworkDetector(),
	}
}

// BuildMatrixConfig creates a complete matrix configuration from detection results
func (mb *MatrixBuilder) BuildMatrixConfig(detection common.DetectionResult) common.MatrixConfig {
	// Get language-specific rulesets
	baseRulesets := mb.languageDetector.GetLanguageRulesets(detection.Languages)

	// Get framework-specific rulesets
	frameworkRulesets := mb.frameworkDetector.GetFrameworkRulesets(detection.Frameworks)

	// Get security rulesets based on application type
	securityRulesets := mb.getSecurityRulesets(detection.Frameworks, detection.Languages.Primary.Name)

	// Combine all rulesets without duplicates
	allRulesets := mb.combineRulesets(baseRulesets, frameworkRulesets, securityRulesets)

	// Generate configuration file path
	configPath := mb.GenerateConfigPath(detection.Languages.Primary.Name, detection.Frameworks.Primary)

	return common.MatrixConfig{
		Languages:     detection.Languages,
		Frameworks:    detection.Frameworks,
		Rulesets:      allRulesets,
		BaseRulesets:  baseRulesets,
		SecurityRules: securityRulesets,
		ConfigPath:    configPath,
		AutoDetected:  true,
	}
}

// GenerateConfigPath creates a configuration file path based on language and framework
func (mb *MatrixBuilder) GenerateConfigPath(primaryLanguage, primaryFramework string) string {
	// Normalize names for file paths
	lang := strings.ToLower(strings.ReplaceAll(primaryLanguage, " ", "-"))

	if primaryFramework == "None" || primaryFramework == "" {
		return fmt.Sprintf("configs/matrix/%s.yaml", lang)
	}

	framework := strings.ToLower(strings.ReplaceAll(primaryFramework, " ", "-"))
	return fmt.Sprintf("configs/matrix/%s-%s.yaml", lang, framework)
}

// getSecurityRulesets determines appropriate security rulesets based on application type
func (mb *MatrixBuilder) getSecurityRulesets(frameworks common.FrameworkDetection, primaryLanguage string) []string {
	var rules []string
	seen := make(map[string]bool)

	// Base security rules for all applications
	baseSecurityRules := []string{
		"p/secrets",
		"p/security-audit",
	}

	for _, rule := range baseSecurityRules {
		if !seen[rule] {
			rules = append(rules, rule)
			seen[rule] = true
		}
	}

	// Web application security rules
	if mb.isWebFramework(frameworks.Primary) || mb.hasWebFramework(frameworks.Secondary) {
		webRules := []string{
			"p/owasp-top-ten",
			"p/xss",
		}
		for _, rule := range webRules {
			if !seen[rule] {
				rules = append(rules, rule)
				seen[rule] = true
			}
		}
	}

	// API security rules
	if mb.isAPIFramework(frameworks.Primary) || mb.hasAPIFramework(frameworks.Secondary) {
		apiRules := []string{
			"p/jwt",
			"p/owasp-top-ten",
		}
		for _, rule := range apiRules {
			if !seen[rule] {
				rules = append(rules, rule)
				seen[rule] = true
			}
		}
	}

	// Language-specific security rules
	languageSecurityRules := mb.getLanguageSecurityRules(primaryLanguage)
	for _, rule := range languageSecurityRules {
		if !seen[rule] {
			rules = append(rules, rule)
			seen[rule] = true
		}
	}

	return rules
}

// getLanguageSecurityRules returns language-specific security rulesets
func (mb *MatrixBuilder) getLanguageSecurityRules(language string) []string {
	languageRules := map[string][]string{
		"Java": {
			"p/supply-chain",
			"p/cwe-top-25",
		},
		"JavaScript": {
			"p/supply-chain",
		},
		"TypeScript": {
			"p/supply-chain",
		},
		"Python": {
			"p/supply-chain",
		},
		"Go": {
			"p/cwe-top-25",
		},
		"C#": {
			"p/cwe-top-25",
		},
		"Ruby": {
			"p/supply-chain",
		},
		"PHP": {
			"p/owasp-top-ten",
		},
	}

	if rules, exists := languageRules[language]; exists {
		return rules
	}

	return []string{}
}

// combineRulesets combines multiple ruleset arrays without duplicates
func (mb *MatrixBuilder) combineRulesets(base, framework, security []string) []string {
	seen := make(map[string]bool)
	var combined []string

	// Add all rulesets from all sources
	allRulesets := append(append(base, framework...), security...)

	for _, ruleset := range allRulesets {
		if !seen[ruleset] {
			combined = append(combined, ruleset)
			seen[ruleset] = true
		}
	}

	return combined
}

// isWebFramework checks if a framework is primarily for web applications
func (mb *MatrixBuilder) isWebFramework(framework string) bool {
	webFrameworks := []string{
		"React",
		"Vue.js",
		"Angular",
		"Next.js",
		"Django",
		"Flask",
		"Laravel",
		"Ruby on Rails",
		"Symfony",
	}

	for _, web := range webFrameworks {
		if framework == web {
			return true
		}
	}

	return false
}

// hasWebFramework checks if any of the secondary frameworks are web frameworks
func (mb *MatrixBuilder) hasWebFramework(frameworks []string) bool {
	for _, framework := range frameworks {
		if mb.isWebFramework(framework) {
			return true
		}
	}
	return false
}

// isAPIFramework checks if a framework is primarily for API development
func (mb *MatrixBuilder) isAPIFramework(framework string) bool {
	apiFrameworks := []string{
		"Express",
		"FastAPI",
		"Spring Boot",
		"Gin",
		"Echo",
		"Koa",
		"Fastify",
		"Tornado",
	}

	for _, api := range apiFrameworks {
		if framework == api {
			return true
		}
	}

	return false
}

// hasAPIFramework checks if any of the secondary frameworks are API frameworks
func (mb *MatrixBuilder) hasAPIFramework(frameworks []string) bool {
	for _, framework := range frameworks {
		if mb.isAPIFramework(framework) {
			return true
		}
	}
	return false
}

// BuildFromGitHubAPI creates a matrix config using GitHub API for language detection
func (mb *MatrixBuilder) BuildFromGitHubAPI(languageStats common.LanguageStats, files []common.RepositoryFile, threshold float64) common.MatrixConfig {
	// Detect languages from GitHub API
	languages := mb.languageDetector.DetectFromGitHubStats(languageStats, threshold)

	// Detect frameworks from file analysis
	frameworks := mb.frameworkDetector.DetectFrameworks(files, languages.Primary.Name)

	// Create detection result
	detection := common.DetectionResult{
		Languages:  languages,
		Frameworks: frameworks,
		Confidence: 0.9, // High confidence for GitHub API data
		Source:     "github-api",
	}

	return mb.BuildMatrixConfig(detection)
}

// BuildFromFileAnalysis creates a matrix config using only file analysis
func (mb *MatrixBuilder) BuildFromFileAnalysis(files []common.RepositoryFile, threshold float64) common.MatrixConfig {
	// Detect languages from file extensions
	languages := mb.languageDetector.DetectFromFileList(files, threshold)

	// Detect frameworks from file analysis
	frameworks := mb.frameworkDetector.DetectFrameworks(files, languages.Primary.Name)

	// Create detection result
	detection := common.DetectionResult{
		Languages:  languages,
		Frameworks: frameworks,
		Confidence: 0.7, // Lower confidence for file-based analysis
		Source:     "file-analysis",
	}

	return mb.BuildMatrixConfig(detection)
}

// BuildHybrid creates a matrix config using both GitHub API and file analysis
func (mb *MatrixBuilder) BuildHybrid(languageStats common.LanguageStats, files []common.RepositoryFile, threshold float64) common.MatrixConfig {
	// Use GitHub API for languages (more accurate)
	languages := mb.languageDetector.DetectFromGitHubStats(languageStats, threshold)

	// Use file analysis for frameworks (more detailed)
	frameworks := mb.frameworkDetector.DetectFrameworks(files, languages.Primary.Name)

	// Create detection result
	detection := common.DetectionResult{
		Languages:  languages,
		Frameworks: frameworks,
		Confidence: 0.85, // Medium-high confidence for hybrid approach
		Source:     "mixed",
	}

	return mb.BuildMatrixConfig(detection)
}
