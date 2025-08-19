package matrix

import (
	"testing"

	"github.com/asii-mov/codesucks-ai/common"
	"github.com/stretchr/testify/assert"
)

func TestBuildMatrixConfig_ReactApp(t *testing.T) {
	languages := common.LanguagePercentages{
		Primary: common.LanguageInfo{
			Name:       "JavaScript",
			Bytes:      85000,
			Percentage: 85.0,
		},
		Secondary: common.LanguageInfo{
			Name:       "TypeScript",
			Bytes:      12000,
			Percentage: 12.0,
		},
		All: []common.LanguageInfo{
			{Name: "JavaScript", Bytes: 85000, Percentage: 85.0},
			{Name: "TypeScript", Bytes: 12000, Percentage: 12.0},
			{Name: "CSS", Bytes: 3000, Percentage: 3.0},
		},
		Threshold: 10.0,
	}

	frameworks := common.FrameworkDetection{
		Primary:    "React",
		Secondary:  []string{"Webpack"},
		BuildTools: []string{"Webpack", "TypeScript"},
		Indicators: map[string]string{"React": "package.json", "Webpack": "package.json"},
	}

	detection := common.DetectionResult{
		Languages:  languages,
		Frameworks: frameworks,
		Confidence: 0.95,
		Source:     "github-api",
	}

	builder := NewMatrixBuilder()
	config := builder.BuildMatrixConfig(detection)

	assert.Equal(t, languages, config.Languages)
	assert.Equal(t, frameworks, config.Frameworks)
	assert.True(t, config.AutoDetected)

	// Should include language rulesets
	assert.Contains(t, config.BaseRulesets, "p/javascript")
	assert.Contains(t, config.BaseRulesets, "p/typescript")

	// Should include framework rulesets
	assert.Contains(t, config.Rulesets, "p/react")

	// Should include security rulesets for web apps
	assert.Contains(t, config.SecurityRules, "p/owasp-top-ten")
	assert.Contains(t, config.SecurityRules, "p/secrets")
}

func TestBuildMatrixConfig_DjangoApp(t *testing.T) {
	languages := common.LanguagePercentages{
		Primary: common.LanguageInfo{
			Name:       "Python",
			Bytes:      95000,
			Percentage: 95.0,
		},
		All: []common.LanguageInfo{
			{Name: "Python", Bytes: 95000, Percentage: 95.0},
			{Name: "HTML", Bytes: 5000, Percentage: 5.0},
		},
		Threshold: 10.0,
	}

	frameworks := common.FrameworkDetection{
		Primary:    "Django",
		Secondary:  []string{},
		Database:   []string{"PostgreSQL"},
		Indicators: map[string]string{"Django": "requirements.txt"},
	}

	detection := common.DetectionResult{
		Languages:  languages,
		Frameworks: frameworks,
		Confidence: 0.90,
		Source:     "file-analysis",
	}

	builder := NewMatrixBuilder()
	config := builder.BuildMatrixConfig(detection)

	assert.Equal(t, languages, config.Languages)
	assert.Equal(t, frameworks, config.Frameworks)
	assert.True(t, config.AutoDetected)

	// Should include Python rulesets
	assert.Contains(t, config.BaseRulesets, "p/python")

	// Should include Django rulesets
	assert.Contains(t, config.Rulesets, "p/django")

	// Should include security rulesets
	assert.Contains(t, config.SecurityRules, "p/owasp-top-ten")
	assert.Contains(t, config.SecurityRules, "p/secrets")
}

func TestBuildMatrixConfig_SpringBootApp(t *testing.T) {
	languages := common.LanguagePercentages{
		Primary: common.LanguageInfo{
			Name:       "Java",
			Bytes:      90000,
			Percentage: 90.0,
		},
		All: []common.LanguageInfo{
			{Name: "Java", Bytes: 90000, Percentage: 90.0},
			{Name: "XML", Bytes: 10000, Percentage: 10.0},
		},
		Threshold: 5.0,
	}

	frameworks := common.FrameworkDetection{
		Primary:    "Spring Boot",
		Secondary:  []string{"Spring Security"},
		Security:   []string{"Spring Security"},
		Indicators: map[string]string{"Spring Boot": "pom.xml"},
	}

	detection := common.DetectionResult{
		Languages:  languages,
		Frameworks: frameworks,
		Confidence: 0.88,
		Source:     "mixed",
	}

	builder := NewMatrixBuilder()
	config := builder.BuildMatrixConfig(detection)

	// Should include Java rulesets
	assert.Contains(t, config.BaseRulesets, "p/java")

	// Should include Spring rulesets
	assert.Contains(t, config.Rulesets, "p/spring")

	// Should include API security rules for Spring apps
	assert.Contains(t, config.SecurityRules, "p/jwt")
}

func TestBuildMatrixConfig_NoFramework(t *testing.T) {
	languages := common.LanguagePercentages{
		Primary: common.LanguageInfo{
			Name:       "Python",
			Bytes:      100000,
			Percentage: 100.0,
		},
		All: []common.LanguageInfo{
			{Name: "Python", Bytes: 100000, Percentage: 100.0},
		},
		Threshold: 10.0,
	}

	frameworks := common.FrameworkDetection{
		Primary:    "None",
		Secondary:  []string{},
		Indicators: map[string]string{},
	}

	detection := common.DetectionResult{
		Languages:  languages,
		Frameworks: frameworks,
		Confidence: 0.75,
		Source:     "file-analysis",
	}

	builder := NewMatrixBuilder()
	config := builder.BuildMatrixConfig(detection)

	// Should include Python rulesets
	assert.Contains(t, config.BaseRulesets, "p/python")

	// Should not include framework-specific rulesets, but overall Rulesets should include base + security
	assert.NotEmpty(t, config.Rulesets)             // Contains base + security rulesets
	assert.Contains(t, config.Rulesets, "p/python") // Base language ruleset

	// Should still include basic security rules
	assert.Contains(t, config.SecurityRules, "p/secrets")
	assert.Contains(t, config.SecurityRules, "p/security-audit")
}

func TestGenerateConfigPath(t *testing.T) {
	tests := []struct {
		name      string
		primary   string
		framework string
		expected  string
	}{
		{
			name:      "JavaScript React",
			primary:   "JavaScript",
			framework: "React",
			expected:  "configs/matrix/javascript-react.yaml",
		},
		{
			name:      "Python Django",
			primary:   "Python",
			framework: "Django",
			expected:  "configs/matrix/python-django.yaml",
		},
		{
			name:      "Java Spring Boot",
			primary:   "Java",
			framework: "Spring Boot",
			expected:  "configs/matrix/java-spring-boot.yaml",
		},
		{
			name:      "Go no framework",
			primary:   "Go",
			framework: "None",
			expected:  "configs/matrix/go.yaml",
		},
		{
			name:      "TypeScript Angular",
			primary:   "TypeScript",
			framework: "Angular",
			expected:  "configs/matrix/typescript-angular.yaml",
		},
	}

	builder := NewMatrixBuilder()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.GenerateConfigPath(tt.primary, tt.framework)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetSecurityRulesets_WebFramework(t *testing.T) {
	builder := NewMatrixBuilder()

	// Test web framework (React)
	frameworks := common.FrameworkDetection{
		Primary:   "React",
		Secondary: []string{"Express"},
	}

	rules := builder.getSecurityRulesets(frameworks, "JavaScript")

	assert.Contains(t, rules, "p/owasp-top-ten")
	assert.Contains(t, rules, "p/secrets")
	assert.Contains(t, rules, "p/security-audit")
}

func TestGetSecurityRulesets_APIFramework(t *testing.T) {
	builder := NewMatrixBuilder()

	// Test API framework (Express)
	frameworks := common.FrameworkDetection{
		Primary:   "Express",
		Secondary: []string{},
	}

	rules := builder.getSecurityRulesets(frameworks, "JavaScript")

	assert.Contains(t, rules, "p/jwt")
	assert.Contains(t, rules, "p/owasp-top-ten")
	assert.Contains(t, rules, "p/secrets")
}

func TestGetSecurityRulesets_JavaApp(t *testing.T) {
	builder := NewMatrixBuilder()

	// Test Java framework
	frameworks := common.FrameworkDetection{
		Primary:   "Spring Boot",
		Secondary: []string{},
	}

	rules := builder.getSecurityRulesets(frameworks, "Java")

	assert.Contains(t, rules, "p/jwt")
	assert.Contains(t, rules, "p/supply-chain")
	assert.Contains(t, rules, "p/secrets")
}

func TestCombineRulesets_NoDuplicates(t *testing.T) {
	builder := NewMatrixBuilder()

	base := []string{"p/javascript", "p/typescript"}
	framework := []string{"p/react", "p/javascript"} // Duplicate javascript
	security := []string{"p/secrets", "p/owasp-top-ten"}

	combined := builder.combineRulesets(base, framework, security)

	// Should contain all unique rulesets
	assert.Contains(t, combined, "p/javascript")
	assert.Contains(t, combined, "p/typescript")
	assert.Contains(t, combined, "p/react")
	assert.Contains(t, combined, "p/secrets")
	assert.Contains(t, combined, "p/owasp-top-ten")

	// Should not have duplicates
	jsCount := 0
	for _, ruleset := range combined {
		if ruleset == "p/javascript" {
			jsCount++
		}
	}
	assert.Equal(t, 1, jsCount, "Should not have duplicate p/javascript")
}

func TestIsWebFramework(t *testing.T) {
	tests := []struct {
		name      string
		framework string
		expected  bool
	}{
		{"React is web", "React", true},
		{"Django is web", "Django", true},
		{"Laravel is web", "Laravel", true},
		{"Rails is web", "Ruby on Rails", true},
		{"Express is API", "Express", false}, // Express is primarily API
		{"FastAPI is API", "FastAPI", false},
		{"None is not web", "None", false},
		{"Unknown is not web", "SomeFramework", false},
	}

	builder := NewMatrixBuilder()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.isWebFramework(tt.framework)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsAPIFramework(t *testing.T) {
	tests := []struct {
		name      string
		framework string
		expected  bool
	}{
		{"Express is API", "Express", true},
		{"FastAPI is API", "FastAPI", true},
		{"Spring Boot is API", "Spring Boot", true},
		{"Gin is API", "Gin", true},
		{"React is not API", "React", false},
		{"None is not API", "None", false},
	}

	builder := NewMatrixBuilder()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.isAPIFramework(tt.framework)
			assert.Equal(t, tt.expected, result)
		})
	}
}
