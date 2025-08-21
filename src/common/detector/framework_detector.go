package detector

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/asii-mov/codesucks-ai/common"
)

// FrameworkDetector handles detection of web frameworks and libraries
type FrameworkDetector struct {
	// Framework detection patterns
	filePatterns map[string][]string

	// Content-based detection
	contentPatterns map[string]map[string]string
}

// NewFrameworkDetector creates a new framework detector
func NewFrameworkDetector() *FrameworkDetector {
	return &FrameworkDetector{
		filePatterns: map[string][]string{
			"Django":        {"manage.py", "settings.py", "wsgi.py", "asgi.py"},
			"Flask":         {"app.py", "application.py"},
			"Ruby on Rails": {"config/application.rb", "Rakefile", "config/routes.rb"},
			"Next.js":       {"next.config.js", "pages/", "app/"},
			"Laravel":       {"artisan", "config/app.php", "routes/web.php"},
			"Spring Boot":   {"application.properties", "application.yml"},
			"Gin":           {"main.go"},
			"Express":       {"server.js", "app.js"},
		},
		contentPatterns: map[string]map[string]string{
			"package.json": {
				"react":         "React",
				"next":          "Next.js",
				"vue":           "Vue.js",
				"@angular/core": "Angular",
				"express":       "Express",
				"koa":           "Koa",
				"fastify":       "Fastify",
				"webpack":       "Webpack",
				"vite":          "Vite",
				"typescript":    "TypeScript",
				"@types/":       "TypeScript",
			},
			"requirements.txt": {
				"Django":           "Django",
				"Flask":            "Flask",
				"Flask-SQLAlchemy": "SQLAlchemy",
				"FastAPI":          "FastAPI",
				"Tornado":          "Tornado",
				"Pyramid":          "Pyramid",
				"psycopg2":         "PostgreSQL",
				"PyMySQL":          "MySQL",
				"redis":            "Redis",
				"celery":           "Celery",
				"gunicorn":         "Gunicorn",
			},
			"pom.xml": {
				"spring-boot":     "Spring Boot",
				"spring-security": "Spring Security",
				"spring-data":     "Spring Data",
				"hibernate":       "Hibernate",
				"junit":           "JUnit",
			},
			"go.mod": {
				"gin-gonic/gin": "Gin",
				"gorilla/mux":   "Gorilla Mux",
				"echo":          "Echo",
				"fiber":         "Fiber",
				"gorm":          "GORM",
			},
			"Gemfile": {
				"rails":   "Ruby on Rails",
				"sinatra": "Sinatra",
				"sidekiq": "Sidekiq",
				"devise":  "Devise",
				"rspec":   "RSpec",
			},
			"composer.json": {
				"laravel/framework": "Laravel",
				"symfony/":          "Symfony",
				"cakephp/":          "CakePHP",
				"codeigniter":       "CodeIgniter",
				"doctrine/":         "Doctrine",
			},
		},
	}
}

// DetectFrameworks analyzes files to detect web frameworks and libraries
func (fd *FrameworkDetector) DetectFrameworks(files []common.RepositoryFile, primaryLanguage string) common.FrameworkDetection {
	result := common.FrameworkDetection{
		Primary:    "None",
		Secondary:  []string{},
		BuildTools: []string{},
		WebServer:  "",
		Database:   []string{},
		Security:   []string{},
		Indicators: make(map[string]string),
	}

	frameworkCounts := make(map[string]int)

	// Analyze each file for framework indicators
	for _, file := range files {
		if file.Type != "file" {
			continue
		}

		fileName := filepath.Base(file.Path)

		// Check file-based patterns
		fd.checkFilePatterns(fileName, file.Path, frameworkCounts, result.Indicators)

		// Check content-based patterns
		if file.Content != "" {
			fd.checkContentPatterns(fileName, file.Content, frameworkCounts, result.Indicators, &result)
		}
	}

	// Determine primary and secondary frameworks
	fd.rankFrameworks(frameworkCounts, &result)

	return result
}

// checkFilePatterns looks for framework indicators based on file names and paths
func (fd *FrameworkDetector) checkFilePatterns(fileName, filePath string, counts map[string]int, indicators map[string]string) {
	for framework, patterns := range fd.filePatterns {
		for _, pattern := range patterns {
			if strings.Contains(filePath, pattern) || fileName == pattern {
				counts[framework]++
				if indicators[framework] == "" {
					indicators[framework] = fileName
				}
			}
		}
	}
}

// checkContentPatterns analyzes file content for framework dependencies
func (fd *FrameworkDetector) checkContentPatterns(fileName, content string, counts map[string]int, indicators map[string]string, result *common.FrameworkDetection) {
	if patterns, exists := fd.contentPatterns[fileName]; exists {
		switch fileName {
		case "package.json":
			frameworks, buildTools := fd.analyzePackageJSON(content)
			for _, framework := range frameworks {
				counts[framework]++
				if indicators[framework] == "" {
					indicators[framework] = fileName
				}
			}
			result.BuildTools = append(result.BuildTools, buildTools...)

		case "requirements.txt":
			frameworks, databases := fd.analyzeRequirementsTxt(content)
			for _, framework := range frameworks {
				counts[framework]++
				if indicators[framework] == "" {
					indicators[framework] = fileName
				}
			}
			result.Database = append(result.Database, databases...)

		case "pom.xml":
			frameworks, security := fd.analyzePomXML(content)
			for _, framework := range frameworks {
				counts[framework]++
				if indicators[framework] == "" {
					indicators[framework] = fileName
				}
			}
			result.Security = append(result.Security, security...)

		default:
			// Generic content analysis
			for pattern, framework := range patterns {
				if strings.Contains(strings.ToLower(content), strings.ToLower(pattern)) {
					counts[framework]++
					if indicators[framework] == "" {
						indicators[framework] = fileName
					}
				}
			}
		}
	}
}

// analyzePackageJSON parses package.json for JavaScript/Node.js frameworks
func (fd *FrameworkDetector) analyzePackageJSON(content string) ([]string, []string) {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	frameworks := []string{}
	buildTools := []string{}

	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		// If JSON parsing fails, fall back to simple string matching
		return fd.analyzePackageJSONString(content)
	}

	allDeps := make(map[string]string)
	for k, v := range pkg.Dependencies {
		allDeps[k] = v
	}
	for k, v := range pkg.DevDependencies {
		allDeps[k] = v
	}

	patterns := fd.contentPatterns["package.json"]
	for dep := range allDeps {
		for pattern, framework := range patterns {
			if strings.Contains(dep, pattern) {
				if fd.isBuildTool(framework) {
					buildTools = append(buildTools, framework)
				} else {
					frameworks = append(frameworks, framework)
				}
			}
		}
	}

	return frameworks, buildTools
}

// analyzePackageJSONString fallback string-based analysis
func (fd *FrameworkDetector) analyzePackageJSONString(content string) ([]string, []string) {
	frameworks := []string{}
	buildTools := []string{}

	patterns := fd.contentPatterns["package.json"]
	for pattern, framework := range patterns {
		if strings.Contains(content, `"`+pattern+`"`) {
			if fd.isBuildTool(framework) {
				buildTools = append(buildTools, framework)
			} else {
				frameworks = append(frameworks, framework)
			}
		}
	}

	return frameworks, buildTools
}

// analyzeRequirementsTxt parses Python requirements.txt
func (fd *FrameworkDetector) analyzeRequirementsTxt(content string) ([]string, []string) {
	frameworks := []string{}
	databases := []string{}

	lines := strings.Split(content, "\n")
	patterns := fd.contentPatterns["requirements.txt"]

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Extract package name (before == or >= etc.)
		packageName := strings.Split(line, "==")[0]
		packageName = strings.Split(packageName, ">=")[0]
		packageName = strings.Split(packageName, "<=")[0]
		packageName = strings.TrimSpace(packageName)

		for pattern, framework := range patterns {
			if strings.EqualFold(packageName, pattern) || strings.Contains(strings.ToLower(packageName), strings.ToLower(pattern)) {
				if fd.isDatabase(framework) {
					databases = append(databases, framework)
				} else {
					frameworks = append(frameworks, framework)
				}
			}
		}
	}

	return frameworks, databases
}

// analyzePomXML parses Java Maven pom.xml
func (fd *FrameworkDetector) analyzePomXML(content string) ([]string, []string) {
	frameworks := []string{}
	security := []string{}

	patterns := fd.contentPatterns["pom.xml"]
	for pattern, framework := range patterns {
		if strings.Contains(content, pattern) {
			if fd.isSecurityFramework(framework) {
				security = append(security, framework)
			} else {
				frameworks = append(frameworks, framework)
			}
		}
	}

	return frameworks, security
}

// rankFrameworks determines primary and secondary frameworks based on detection counts
func (fd *FrameworkDetector) rankFrameworks(counts map[string]int, result *common.FrameworkDetection) {
	if len(counts) == 0 {
		return
	}

	// Sort frameworks by count
	type frameworkCount struct {
		name  string
		count int
	}

	var sorted []frameworkCount
	for name, count := range counts {
		sorted = append(sorted, frameworkCount{name, count})
	}

	// Sort by count (descending)
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].count > sorted[i].count {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Set primary framework
	if len(sorted) > 0 {
		result.Primary = sorted[0].name
	}

	// Set secondary frameworks
	for i := 1; i < len(sorted) && i < 4; i++ { // Limit to top 3 secondary
		result.Secondary = append(result.Secondary, sorted[i].name)
	}
}

// GetFrameworkRulesets returns appropriate Semgrep rulesets for detected frameworks
func (fd *FrameworkDetector) GetFrameworkRulesets(frameworks common.FrameworkDetection) []string {
	var rulesets []string
	seenRulesets := make(map[string]bool)

	// Add ruleset for primary framework
	if frameworks.Primary != "None" && frameworks.Primary != "" {
		for _, ruleset := range fd.getFrameworkSpecificRulesets(frameworks.Primary) {
			if !seenRulesets[ruleset] {
				rulesets = append(rulesets, ruleset)
				seenRulesets[ruleset] = true
			}
		}
	}

	// Add rulesets for secondary frameworks
	for _, framework := range frameworks.Secondary {
		for _, ruleset := range fd.getFrameworkSpecificRulesets(framework) {
			if !seenRulesets[ruleset] {
				rulesets = append(rulesets, ruleset)
				seenRulesets[ruleset] = true
			}
		}
	}

	return rulesets
}

// getFrameworkSpecificRulesets returns Semgrep rulesets for a specific framework
func (fd *FrameworkDetector) getFrameworkSpecificRulesets(framework string) []string {
	frameworkRulesets := map[string][]string{
		"React":         {"p/react"},
		"Next.js":       {"p/react", "p/javascript"},
		"Vue.js":        {"p/vue"},
		"Angular":       {"p/typescript"},
		"Express":       {"p/javascript"},
		"Django":        {"p/django"},
		"Flask":         {"p/flask"},
		"FastAPI":       {"p/fastapi"},
		"Ruby on Rails": {"p/rails"},
		"Laravel":       {"p/laravel"},
		"Spring Boot":   {"p/spring"},
		"Gin":           {"p/gin"},
		"Echo":          {"p/echo"},
		"Symfony":       {"p/symfony"},
		"Koa":           {"p/koa"},
		"Fastify":       {"p/fastify"},
	}

	if rulesets, exists := frameworkRulesets[framework]; exists {
		return rulesets
	}

	return []string{}
}

// Helper functions to categorize frameworks
func (fd *FrameworkDetector) isBuildTool(name string) bool {
	buildTools := []string{"Webpack", "Vite", "TypeScript", "Rollup", "Parcel"}
	for _, tool := range buildTools {
		if name == tool {
			return true
		}
	}
	return false
}

func (fd *FrameworkDetector) isDatabase(name string) bool {
	databases := []string{"PostgreSQL", "MySQL", "Redis", "MongoDB", "SQLite"}
	for _, db := range databases {
		if name == db {
			return true
		}
	}
	return false
}

func (fd *FrameworkDetector) isSecurityFramework(name string) bool {
	security := []string{"Spring Security", "Devise", "Passport"}
	for _, sec := range security {
		if name == sec {
			return true
		}
	}
	return false
}
