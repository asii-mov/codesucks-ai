package detector

import (
	"testing"

	"github.com/asii-mov/codesucks-ai/common"
	"github.com/stretchr/testify/assert"
)

func TestCalculateLanguagePercentages(t *testing.T) {
	tests := []struct {
		name      string
		stats     common.LanguageStats
		threshold float64
		expected  common.LanguagePercentages
	}{
		{
			name: "JavaScript dominant with TypeScript secondary",
			stats: common.LanguageStats{
				Languages: map[string]int{
					"JavaScript": 85000,
					"TypeScript": 12000,
					"CSS":        3000,
				},
				Total: 100000,
			},
			threshold: 10.0,
			expected: common.LanguagePercentages{
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
			},
		},
		{
			name: "Python only with no secondary",
			stats: common.LanguageStats{
				Languages: map[string]int{
					"Python": 95000,
					"HTML":   5000,
				},
				Total: 100000,
			},
			threshold: 10.0,
			expected: common.LanguagePercentages{
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
			},
		},
		{
			name: "Equal distribution Java and Kotlin",
			stats: common.LanguageStats{
				Languages: map[string]int{
					"Java":   45000,
					"Kotlin": 40000,
					"XML":    15000,
				},
				Total: 100000,
			},
			threshold: 20.0,
			expected: common.LanguagePercentages{
				Primary: common.LanguageInfo{
					Name:       "Java",
					Bytes:      45000,
					Percentage: 45.0,
				},
				Secondary: common.LanguageInfo{
					Name:       "Kotlin",
					Bytes:      40000,
					Percentage: 40.0,
				},
				All: []common.LanguageInfo{
					{Name: "Java", Bytes: 45000, Percentage: 45.0},
					{Name: "Kotlin", Bytes: 40000, Percentage: 40.0},
					{Name: "XML", Bytes: 15000, Percentage: 15.0},
				},
				Threshold: 20.0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := NewLanguageDetector()
			result := detector.CalculateLanguagePercentages(tt.stats, tt.threshold)

			assert.Equal(t, tt.expected.Primary, result.Primary)
			assert.Equal(t, tt.expected.Secondary, result.Secondary)
			assert.Equal(t, tt.expected.All, result.All)
			assert.Equal(t, tt.expected.Threshold, result.Threshold)
		})
	}
}

func TestIsSignificantLanguage(t *testing.T) {
	tests := []struct {
		name       string
		percentage float64
		threshold  float64
		expected   bool
	}{
		{"Above threshold", 15.0, 10.0, true},
		{"Equal to threshold", 10.0, 10.0, true},
		{"Below threshold", 5.0, 10.0, false},
		{"Zero percentage", 0.0, 10.0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := NewLanguageDetector()
			result := detector.IsSignificantLanguage(tt.percentage, tt.threshold)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeLanguageName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"JavaScript", "JavaScript", "JavaScript"},
		{"TypeScript", "TypeScript", "TypeScript"},
		{"Go", "Go", "Go"},
		{"C++", "C++", "C++"},
		{"C#", "C#", "C#"},
		{"Objective-C", "Objective-C", "Objective-C"},
		{"Shell", "Shell", "Shell"},
		{"Empty string", "", ""},
		{"Unknown", "SomeUnknown", "SomeUnknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := NewLanguageDetector()
			result := detector.NormalizeLanguageName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectFromGitHubStats_EmptyStats(t *testing.T) {
	detector := NewLanguageDetector()
	stats := common.LanguageStats{
		Languages: map[string]int{},
		Total:     0,
	}

	result := detector.DetectFromGitHubStats(stats, 10.0)

	assert.Empty(t, result.All)
	assert.Equal(t, "", result.Primary.Name)
	assert.Equal(t, "", result.Secondary.Name)
}

func TestDetectFromGitHubStats_SingleLanguage(t *testing.T) {
	detector := NewLanguageDetector()
	stats := common.LanguageStats{
		Languages: map[string]int{
			"Python": 100000,
		},
		Total: 100000,
	}

	result := detector.DetectFromGitHubStats(stats, 10.0)

	assert.Len(t, result.All, 1)
	assert.Equal(t, "Python", result.Primary.Name)
	assert.Equal(t, 100.0, result.Primary.Percentage)
	assert.Equal(t, "", result.Secondary.Name)
}

func TestDetectFromFileList_WebApp(t *testing.T) {
	files := []common.RepositoryFile{
		{Path: "package.json", Type: "file"},
		{Path: "src/components/App.jsx", Type: "file"},
		{Path: "src/utils/api.js", Type: "file"},
		{Path: "public/index.html", Type: "file"},
		{Path: "src/styles/main.css", Type: "file"},
		{Path: "webpack.config.js", Type: "file"},
	}

	detector := NewLanguageDetector()
	result := detector.DetectFromFileList(files, 5.0)

	// Should detect JavaScript as primary due to .js and .jsx files
	assert.Equal(t, "JavaScript", result.Primary.Name)
	assert.True(t, result.Primary.Percentage > 0)
}

func TestDetectFromFileList_PythonApp(t *testing.T) {
	files := []common.RepositoryFile{
		{Path: "requirements.txt", Type: "file"},
		{Path: "app.py", Type: "file"},
		{Path: "models/user.py", Type: "file"},
		{Path: "views/auth.py", Type: "file"},
		{Path: "static/css/style.css", Type: "file"},
		{Path: "templates/index.html", Type: "file"},
	}

	detector := NewLanguageDetector()
	result := detector.DetectFromFileList(files, 5.0)

	// Should detect Python as primary due to .py files
	assert.Equal(t, "Python", result.Primary.Name)
	assert.True(t, result.Primary.Percentage > 0)
}

func TestDetectFromFileList_JavaApp(t *testing.T) {
	files := []common.RepositoryFile{
		{Path: "pom.xml", Type: "file"},
		{Path: "src/main/java/com/example/App.java", Type: "file"},
		{Path: "src/main/java/com/example/controller/UserController.java", Type: "file"},
		{Path: "src/main/java/com/example/model/User.java", Type: "file"},
		{Path: "src/main/resources/application.properties", Type: "file"},
	}

	detector := NewLanguageDetector()
	result := detector.DetectFromFileList(files, 5.0)

	// Should detect Java as primary due to .java files
	assert.Equal(t, "Java", result.Primary.Name)
	assert.True(t, result.Primary.Percentage > 0)
}
