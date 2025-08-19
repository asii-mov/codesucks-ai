package detector

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/asii-mov/codesucks-ai/common"
)

// LanguageDetector handles detection of programming languages in repositories
type LanguageDetector struct {
	// Language file extension mappings
	extensions map[string]string
}

// NewLanguageDetector creates a new language detector with default mappings
func NewLanguageDetector() *LanguageDetector {
	return &LanguageDetector{
		extensions: map[string]string{
			".js":    "JavaScript",
			".jsx":   "JavaScript",
			".ts":    "TypeScript",
			".tsx":   "TypeScript",
			".py":    "Python",
			".java":  "Java",
			".kt":    "Kotlin",
			".go":    "Go",
			".rb":    "Ruby",
			".php":   "PHP",
			".cs":    "C#",
			".cpp":   "C++",
			".c":     "C",
			".h":     "C",
			".hpp":   "C++",
			".m":     "Objective-C",
			".swift": "Swift",
			".rs":    "Rust",
			".scala": "Scala",
			".sh":    "Shell",
			".bash":  "Shell",
			".zsh":   "Shell",
			".ps1":   "PowerShell",
			".r":     "R",
			".R":     "R",
			".dart":  "Dart",
			".lua":   "Lua",
			".perl":  "Perl",
			".pl":    "Perl",
		},
	}
}

// DetectFromGitHubStats analyzes GitHub language statistics and returns language percentages
func (ld *LanguageDetector) DetectFromGitHubStats(stats common.LanguageStats, threshold float64) common.LanguagePercentages {
	if stats.Total == 0 || len(stats.Languages) == 0 {
		return common.LanguagePercentages{
			All:       []common.LanguageInfo{},
			Threshold: threshold,
		}
	}

	return ld.CalculateLanguagePercentages(stats, threshold)
}

// CalculateLanguagePercentages converts language byte counts to percentages
func (ld *LanguageDetector) CalculateLanguagePercentages(stats common.LanguageStats, threshold float64) common.LanguagePercentages {
	var languages []common.LanguageInfo

	// Calculate percentages for each language
	for name, bytes := range stats.Languages {
		percentage := float64(bytes) / float64(stats.Total) * 100.0
		languages = append(languages, common.LanguageInfo{
			Name:       ld.NormalizeLanguageName(name),
			Bytes:      bytes,
			Percentage: percentage,
		})
	}

	// Sort by percentage (descending)
	sort.Slice(languages, func(i, j int) bool {
		return languages[i].Percentage > languages[j].Percentage
	})

	result := common.LanguagePercentages{
		All:       languages,
		Threshold: threshold,
	}

	// Set primary language (highest percentage)
	if len(languages) > 0 {
		result.Primary = languages[0]
	}

	// Set secondary language (second highest, if above threshold)
	if len(languages) > 1 && ld.IsSignificantLanguage(languages[1].Percentage, threshold) {
		result.Secondary = languages[1]
	}

	return result
}

// DetectFromFileList analyzes file extensions to estimate language distribution
func (ld *LanguageDetector) DetectFromFileList(files []common.RepositoryFile, threshold float64) common.LanguagePercentages {
	languageCounts := make(map[string]int)
	totalFiles := 0

	// Count files by language based on extensions
	for _, file := range files {
		if file.Type != "file" {
			continue
		}

		ext := strings.ToLower(filepath.Ext(file.Path))
		if language, exists := ld.extensions[ext]; exists {
			languageCounts[language]++
			totalFiles++
		}
	}

	if totalFiles == 0 {
		return common.LanguagePercentages{
			All:       []common.LanguageInfo{},
			Threshold: threshold,
		}
	}

	// Convert counts to fake byte counts (estimate based on file count)
	// This is a simplified approach for file-based detection
	stats := common.LanguageStats{
		Languages: make(map[string]int),
		Total:     0,
	}

	for language, count := range languageCounts {
		// Estimate bytes per file (rough average)
		estimatedBytes := count * 1000 // 1KB per file average
		stats.Languages[language] = estimatedBytes
		stats.Total += estimatedBytes
	}

	return ld.CalculateLanguagePercentages(stats, threshold)
}

// IsSignificantLanguage determines if a language percentage is above the threshold
func (ld *LanguageDetector) IsSignificantLanguage(percentage, threshold float64) bool {
	return percentage >= threshold
}

// NormalizeLanguageName standardizes language names
func (ld *LanguageDetector) NormalizeLanguageName(name string) string {
	// For now, just return the name as-is
	// In the future, we could map aliases (e.g., "js" -> "JavaScript")
	return strings.TrimSpace(name)
}

// GetLanguageRulesets returns appropriate Semgrep rulesets for detected languages
func (ld *LanguageDetector) GetLanguageRulesets(languages common.LanguagePercentages) []string {
	var rulesets []string
	seenRulesets := make(map[string]bool)

	// Add rulesets for primary language
	if languages.Primary.Name != "" {
		for _, ruleset := range ld.getLanguageSpecificRulesets(languages.Primary.Name) {
			if !seenRulesets[ruleset] {
				rulesets = append(rulesets, ruleset)
				seenRulesets[ruleset] = true
			}
		}
	}

	// Add rulesets for secondary language
	if languages.Secondary.Name != "" {
		for _, ruleset := range ld.getLanguageSpecificRulesets(languages.Secondary.Name) {
			if !seenRulesets[ruleset] {
				rulesets = append(rulesets, ruleset)
				seenRulesets[ruleset] = true
			}
		}
	}

	// Add additional rulesets for other significant languages
	for _, lang := range languages.All {
		if lang.Name != languages.Primary.Name && lang.Name != languages.Secondary.Name {
			if ld.IsSignificantLanguage(lang.Percentage, languages.Threshold) {
				for _, ruleset := range ld.getLanguageSpecificRulesets(lang.Name) {
					if !seenRulesets[ruleset] {
						rulesets = append(rulesets, ruleset)
						seenRulesets[ruleset] = true
					}
				}
			}
		}
	}

	return rulesets
}

// getLanguageSpecificRulesets returns Semgrep rulesets for a specific language
func (ld *LanguageDetector) getLanguageSpecificRulesets(language string) []string {
	languageRulesets := map[string][]string{
		"JavaScript": {"p/javascript", "p/nodejs"},
		"TypeScript": {"p/typescript", "p/javascript"},
		"Python":     {"p/python"},
		"Java":       {"p/java"},
		"Go":         {"p/go"},
		"Ruby":       {"p/ruby"},
		"PHP":        {"p/php"},
		"C#":         {"p/csharp"},
		"C++":        {"p/cpp"},
		"C":          {"p/c"},
		"Kotlin":     {"p/kotlin"},
		"Swift":      {"p/swift"},
		"Rust":       {"p/rust"},
		"Scala":      {"p/scala"},
		"Shell":      {"p/bash"},
		"PowerShell": {"p/powershell"},
	}

	if rulesets, exists := languageRulesets[language]; exists {
		return rulesets
	}

	return []string{}
}
