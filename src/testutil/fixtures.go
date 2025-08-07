package testutil

import (
	"time"

	"github.com/asii-mov/codesucks-ai/common"
)

// Sample vulnerability data for testing
var (
	SampleSQLInjection = common.Vulnerability{
		Type:        "SQL Injection",
		Severity:    "HIGH",
		Confidence:  0.95,
		Description: "SQL injection vulnerability in user query",
		File:        "src/controllers/user.go",
		Line:        42,
		Code:        `query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)`,
		CWE:         "CWE-89",
		OWASP:       "A03:2021",
	}

	SampleXSS = common.Vulnerability{
		Type:        "Cross-Site Scripting",
		Severity:    "MEDIUM",
		Confidence:  0.85,
		Description: "Reflected XSS in error message",
		File:        "src/handlers/error.go",
		Line:        78,
		Code:        `fmt.Fprintf(w, "<div>Error: %s</div>", errorMsg)`,
		CWE:         "CWE-79",
		OWASP:       "A03:2021",
	}

	SampleWeakCrypto = common.Vulnerability{
		Type:        "Weak Cryptography",
		Severity:    "MEDIUM",
		Confidence:  0.90,
		Description: "MD5 used for password hashing",
		File:        "src/auth/password.go",
		Line:        23,
		Code:        `hash := md5.Sum([]byte(password))`,
		CWE:         "CWE-327",
		OWASP:       "A02:2021",
	}
)

// CreateSampleVulnerabilities creates a list of sample vulnerabilities
func CreateSampleVulnerabilities() []common.Vulnerability {
	return []common.Vulnerability{
		SampleSQLInjection,
		SampleXSS,
		SampleWeakCrypto,
	}
}

// CreateSampleEnhancedVulnerability creates an enhanced vulnerability for orchestrator
func CreateSampleEnhancedVulnerability() common.EnhancedVulnerability {
	return common.EnhancedVulnerability{
		VulnID:     "VULN_001",
		Type:       "SQL Injection",
		CweID:      "CWE-89",
		Severity:   "CRITICAL",
		Confidence: "HIGH",
		Location: common.VulnLocation{
			File:      "src/controllers/user.go",
			StartLine: 42,
			EndLine:   45,
			Function:  "getUserByID",
		},
		DataFlow: common.DataFlow{
			Source:          "HTTP parameter 'id' at line 41",
			Transformations: []string{},
			Sink:            "SQL query at line 44",
		},
		VulnerableCode:   `query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)`,
		ExploitExample:   `curl -X GET 'http://app/user?id=1 OR 1=1--'`,
		SecureCode:       `query := "SELECT * FROM users WHERE id = ?" \n db.Query(query, userID)`,
		FixExplanation:   "Use parameterized queries to prevent SQL injection",
	}
}

// CreateSampleOrchestratorState creates a sample orchestrator state
func CreateSampleOrchestratorState() *common.OrchestratorState {
	return &common.OrchestratorState{
		SessionID:    "test-session-123",
		CreatedAt:    time.Now(),
		CurrentPhase: common.PhaseInitialization,
		CodebaseContext: common.CodebaseContext{
			PrimaryLanguage:      "go",
			Frameworks:           []string{"gin", "gorm"},
			EntryPoints:          []string{"main.go", "cmd/server/main.go"},
			TotalFiles:           150,
			TotalLOC:             25000,
			SecurityRelevantFiles: []string{"auth/", "controllers/", "middleware/"},
		},
		CodePatterns: common.CodePatterns{
			InputSources: []common.InputSource{
				{
					Type:     "http",
					Location: "controllers/user.go:41",
					DataType: "string",
				},
			},
			DangerousSinks: []common.DangerousSink{
				{
					Type:     "sql",
					Location: "models/user.go:88",
					Function: "db.Query()",
				},
			},
			SecurityControls: []common.SecurityControl{
				{
					Type:     "input_validation",
					Location: "middleware/validation.go:23",
				},
			},
		},
		Vulnerabilities: []common.EnhancedVulnerability{
			CreateSampleEnhancedVulnerability(),
		},
		CodeMetrics: common.CodeMetrics{
			FilesAnalyzed:      100,
			FunctionsAnalyzed:  500,
			TotalVulnerabilities: 15,
			SeverityDistribution: map[string]int{
				"CRITICAL": 3,
				"HIGH":     5,
				"MEDIUM":   4,
				"LOW":      3,
			},
			VulnerabilityDensity:     0.6,
			MostVulnerableComponents: []string{"controllers/", "auth/"},
		},
	}
}

// CreateSampleSecret creates a sample secret finding
func CreateSampleSecret() common.Secret {
	return common.Secret{
		Type:       "AWS Access Key",
		File:       "config/aws.go",
		Line:       15,
		Value:      "AKIA****************",
		Verified:   true,
		Confidence: 0.99,
	}
}

// CreateSampleAnalysisResult creates a sample analysis result
func CreateSampleAnalysisResult() *common.AnalysisResult {
	return &common.AnalysisResult{
		Repository:      "https://github.com/test/repo",
		Vulnerabilities: CreateSampleVulnerabilities(),
		Secrets: []common.Secret{
			CreateSampleSecret(),
		},
		Timestamp: time.Now(),
		Duration:  5 * time.Minute,
		Summary: common.Summary{
			TotalVulnerabilities: 3,
			CriticalCount:        1,
			HighCount:            1,
			MediumCount:          1,
			LowCount:             0,
			SecretsFound:         1,
		},
	}
}