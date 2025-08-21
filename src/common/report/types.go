package report

import (
	"github.com/asii-mov/codesucks-ai/common"
)

// ReportData contains all the data needed for report generation
type ReportData struct {
	// Basic Information
	ReportID   string
	Repository string
	Branch     string
	Commit     string
	ScanConfig string

	// Scan Configuration
	OrchestratorMode bool
	MatrixBuild      bool
	MCPMode          bool

	// Vulnerability Data
	Vulnerabilities      []common.ValidatedResult
	TotalVulnerabilities int
	SeverityDistribution map[string]int

	// Secret Data
	Secrets      []common.Secret
	TotalSecrets int

	// Pattern Data
	Patterns []common.VulnerabilityPattern

	// Metrics
	FilesAnalyzed        int
	LinesOfCode          int
	VulnerabilityDensity float64
	TopVulnerableFiles   []string
	LanguageBreakdown    map[string]int

	// Validation Metrics
	TruePositives    int
	FalsePositives   int
	FixedCount       int
	AutoFixableCount int

	// Agent Performance (if orchestrator mode)
	AgentMetrics []AgentPerformanceMetric

	// Additional Options
	Options *common.Options
}

// AgentPerformanceMetric tracks individual agent performance
type AgentPerformanceMetric struct {
	AgentID              string
	AgentType            string
	ExecutionTime        float64 // seconds
	FilesAnalyzed        int
	VulnerabilitiesFound int
	MemoryUsage          int64 // bytes
	Status               string
}

// OutputFormat represents the report output format
type OutputFormat string

const (
	FormatHTML  OutputFormat = "html"
	FormatJSON  OutputFormat = "json"
	FormatSARIF OutputFormat = "sarif"
	FormatAll   OutputFormat = "all"
)

// GenerateReport generates a report in the specified format(s)
func GenerateReport(data *ReportData, outputPath string, format OutputFormat) error {
	switch format {
	case FormatHTML:
		return GenerateHTMLReport(data, outputPath)
	case FormatJSON:
		return GenerateJSONReport(data, outputPath)
	case FormatSARIF:
		return GenerateSARIFReport(data, outputPath)
	case FormatAll:
		// Generate all formats
		if err := GenerateHTMLReport(data, replaceExtension(outputPath, ".html")); err != nil {
			return err
		}
		if err := GenerateJSONReport(data, replaceExtension(outputPath, ".json")); err != nil {
			return err
		}
		if err := GenerateSARIFReport(data, replaceExtension(outputPath, ".sarif")); err != nil {
			return err
		}
		return nil
	default:
		return GenerateHTMLReport(data, outputPath)
	}
}

// replaceExtension replaces the file extension
func replaceExtension(path, newExt string) string {
	// Find the last dot
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			return path[:i] + newExt
		}
		if path[i] == '/' || path[i] == '\\' {
			break
		}
	}
	return path + newExt
}
