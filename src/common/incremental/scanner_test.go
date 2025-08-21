package incremental

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/asii-mov/codesucks-ai/common"
)

func TestNewIncrementalScanner(t *testing.T) {
	options := &common.Options{
		Repo:   "https://github.com/test/repo",
		OutDir: "/tmp/test-incremental",
	}

	scanner := NewIncrementalScanner(options)
	if scanner == nil {
		t.Fatal("Failed to create incremental scanner")
	}

	if scanner.options != options {
		t.Error("Options not properly set")
	}

	expectedCacheFile := filepath.Join("/tmp/test-incremental", ".scan-cache", "last-scan.json")
	if scanner.cacheFile != expectedCacheFile {
		t.Errorf("Expected cache file %s, got %s", expectedCacheFile, scanner.cacheFile)
	}
}

func TestIsSourceFile(t *testing.T) {
	scanner := &IncrementalScanner{}

	testCases := []struct {
		path     string
		expected bool
	}{
		{"main.go", true},
		{"test.java", true},
		{"app.py", true},
		{"script.js", true},
		{"component.tsx", true},
		{"style.css", false},
		{"image.png", false},
		{"README.md", false},
		{"data.json", false},
	}

	for _, tc := range testCases {
		result := scanner.isSourceFile(tc.path)
		if result != tc.expected {
			t.Errorf("isSourceFile(%s) = %v, expected %v", tc.path, result, tc.expected)
		}
	}
}

func TestScanCache(t *testing.T) {
	// Create temp directory for testing
	tmpDir, err := os.MkdirTemp("", "scan-cache-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	options := &common.Options{
		Repo:   "https://github.com/test/repo",
		OutDir: tmpDir,
	}

	scanner := NewIncrementalScanner(options)

	// Test saving cache
	vulnerabilities := []common.Vulnerability{
		{
			Type:     "SQL Injection",
			File:     "app.py",
			Line:     10,
			Severity: "HIGH",
		},
		{
			Type:     "XSS",
			File:     "index.js",
			Line:     25,
			Severity: "MEDIUM",
		},
	}

	err = scanner.SaveCache(tmpDir, vulnerabilities)
	if err != nil {
		t.Fatalf("Failed to save cache: %v", err)
	}

	// Test loading cache
	err = scanner.loadCache()
	if err != nil {
		t.Fatalf("Failed to load cache: %v", err)
	}

	if scanner.lastScanCache == nil {
		t.Fatal("Cache not loaded properly")
	}

	if scanner.lastScanCache.Repository != "https://github.com/test/repo" {
		t.Errorf("Repository not saved correctly in cache")
	}

	if len(scanner.lastScanCache.Vulnerabilities) != 2 {
		t.Errorf("Expected 2 vulnerability groups in cache, got %d", len(scanner.lastScanCache.Vulnerabilities))
	}
}

func TestMergeWithCachedResults(t *testing.T) {
	scanner := &IncrementalScanner{
		lastScanCache: &ScanCache{
			LastScanTime: time.Now().Add(-1 * time.Hour),
			Vulnerabilities: map[string][]common.Vulnerability{
				"unchanged.py": {
					{Type: "SQL Injection", File: "unchanged.py", Line: 10},
				},
				"changed.js": {
					{Type: "XSS", File: "changed.js", Line: 20},
				},
			},
		},
	}

	newVulnerabilities := []common.Vulnerability{
		{Type: "Path Traversal", File: "changed.js", Line: 30},
	}

	changedFiles := []string{"changed.js"}

	merged := scanner.MergeWithCachedResults(newVulnerabilities, changedFiles)

	// Should have 1 from unchanged.py (cached) + 1 new from changed.js
	if len(merged) != 2 {
		t.Errorf("Expected 2 vulnerabilities after merge, got %d", len(merged))
	}

	// Check that unchanged.py vulnerability is preserved
	foundUnchanged := false
	foundNew := false
	for _, vuln := range merged {
		if vuln.File == "unchanged.py" && vuln.Type == "SQL Injection" {
			foundUnchanged = true
		}
		if vuln.File == "changed.js" && vuln.Type == "Path Traversal" {
			foundNew = true
		}
	}

	if !foundUnchanged {
		t.Error("Cached vulnerability from unchanged file not preserved")
	}
	if !foundNew {
		t.Error("New vulnerability not included in merged results")
	}
}

func TestGetScanStatistics(t *testing.T) {
	scanner := &IncrementalScanner{}

	// Test initial scan
	stats := scanner.GetScanStatistics(100, 100)
	if stats != "Initial scan: 100 files analyzed" {
		t.Errorf("Unexpected initial scan statistics: %s", stats)
	}

	// Test incremental scan
	scanner.lastScanCache = &ScanCache{}
	stats = scanner.GetScanStatistics(100, 25)
	expected := "Incremental scan: 25 of 100 files changed (25.0%), estimated 75% time saved"
	if stats != expected {
		t.Errorf("Expected '%s', got '%s'", expected, stats)
	}
}