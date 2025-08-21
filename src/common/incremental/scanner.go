package incremental

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/asii-mov/codesucks-ai/common"
)

// IncrementalScanner implements incremental scanning capabilities
type IncrementalScanner struct {
	options        *common.Options
	lastScanCache  *ScanCache
	cacheFile      string
}

// ScanCache stores information about the last scan
type ScanCache struct {
	LastScanTime   time.Time               `json:"last_scan_time"`
	FileHashes     map[string]string       `json:"file_hashes"`
	Vulnerabilities map[string][]common.Vulnerability `json:"vulnerabilities"`
	Repository     string                  `json:"repository"`
	Branch         string                  `json:"branch"`
	Commit         string                  `json:"commit"`
}

// NewIncrementalScanner creates a new incremental scanner
func NewIncrementalScanner(options *common.Options) *IncrementalScanner {
	cacheDir := filepath.Join(options.OutDir, ".scan-cache")
	os.MkdirAll(cacheDir, 0755)
	
	return &IncrementalScanner{
		options:   options,
		cacheFile: filepath.Join(cacheDir, "last-scan.json"),
	}
}

// GetChangedFiles returns files that have changed since the last scan
func (s *IncrementalScanner) GetChangedFiles(repoPath string) ([]string, error) {
	// Load cache
	if err := s.loadCache(); err != nil {
		// No cache means first scan - return all files
		return s.getAllSourceFiles(repoPath)
	}
	
	// Get current commit
	currentCommit, err := s.getCurrentCommit(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get current commit: %w", err)
	}
	
	// If on different commit, use git diff
	if s.lastScanCache.Commit != "" && s.lastScanCache.Commit != currentCommit {
		return s.getGitChangedFiles(repoPath, s.lastScanCache.Commit, currentCommit)
	}
	
	// Otherwise, use file modification times
	return s.getModifiedFiles(repoPath)
}

// loadCache loads the scan cache from disk
func (s *IncrementalScanner) loadCache() error {
	data, err := os.ReadFile(s.cacheFile)
	if err != nil {
		return err
	}
	
	cache := &ScanCache{}
	if err := json.Unmarshal(data, cache); err != nil {
		return err
	}
	s.lastScanCache = cache
	return nil
}

// SaveCache saves the scan cache to disk  
func (s *IncrementalScanner) SaveCache(repoPath string, vulnerabilities []common.Vulnerability) error {
	commit, _ := s.getCurrentCommit(repoPath)
	cache := &ScanCache{
		LastScanTime:    time.Now(),
		FileHashes:      s.calculateFileHashes(repoPath),
		Vulnerabilities: s.groupVulnerabilitiesByFile(vulnerabilities),
		Repository:      s.options.Repo,
		Branch:          s.getCurrentBranch(repoPath),
		Commit:          commit,
	}
	
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(s.cacheFile, data, 0644)
}

// getCurrentCommit gets the current git commit hash
func (s *IncrementalScanner) getCurrentCommit(repoPath string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// getCurrentBranch gets the current git branch
func (s *IncrementalScanner) getCurrentBranch(repoPath string) string {
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

// getGitChangedFiles gets files changed between two commits
func (s *IncrementalScanner) getGitChangedFiles(repoPath, fromCommit, toCommit string) ([]string, error) {
	cmd := exec.Command("git", "diff", "--name-only", fromCommit, toCommit)
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get git diff: %w", err)
	}
	
	var files []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		file := scanner.Text()
		if s.isSourceFile(file) {
			files = append(files, file)
		}
	}
	
	return files, nil
}

// getModifiedFiles gets files modified since last scan time
func (s *IncrementalScanner) getModifiedFiles(repoPath string) ([]string, error) {
	var modifiedFiles []string
	lastScanTime := s.lastScanCache.LastScanTime
	
	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		
		if info.IsDir() || !s.isSourceFile(path) {
			return nil
		}
		
		// Check if modified since last scan
		if info.ModTime().After(lastScanTime) {
			relPath, _ := filepath.Rel(repoPath, path)
			modifiedFiles = append(modifiedFiles, relPath)
		}
		
		return nil
	})
	
	return modifiedFiles, err
}

// getAllSourceFiles returns all source files in the repository
func (s *IncrementalScanner) getAllSourceFiles(repoPath string) ([]string, error) {
	var sourceFiles []string
	
	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		
		if info.IsDir() || !s.isSourceFile(path) {
			return nil
		}
		
		relPath, _ := filepath.Rel(repoPath, path)
		sourceFiles = append(sourceFiles, relPath)
		return nil
	})
	
	return sourceFiles, err
}

// isSourceFile checks if a file should be scanned
func (s *IncrementalScanner) isSourceFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	sourceExts := map[string]bool{
		".go": true, ".java": true, ".py": true, ".js": true,
		".ts": true, ".jsx": true, ".tsx": true, ".php": true,
		".rb": true, ".cs": true, ".cpp": true, ".c": true,
		".rs": true, ".kt": true, ".swift": true, ".scala": true,
	}
	return sourceExts[ext]
}

// calculateFileHashes calculates hashes for all source files
func (s *IncrementalScanner) calculateFileHashes(repoPath string) map[string]string {
	hashes := make(map[string]string)
	// Implementation would calculate actual file hashes
	// For now, using modification time as a simple check
	return hashes
}

// groupVulnerabilitiesByFile groups vulnerabilities by file path
func (s *IncrementalScanner) groupVulnerabilitiesByFile(vulnerabilities []common.Vulnerability) map[string][]common.Vulnerability {
	grouped := make(map[string][]common.Vulnerability)
	for _, vuln := range vulnerabilities {
		grouped[vuln.File] = append(grouped[vuln.File], vuln)
	}
	return grouped
}

// MergeWithCachedResults merges new scan results with cached results for unchanged files
func (s *IncrementalScanner) MergeWithCachedResults(newVulnerabilities []common.Vulnerability, changedFiles []string) []common.Vulnerability {
	if s.lastScanCache == nil {
		return newVulnerabilities
	}
	
	// Create a set of changed files for quick lookup
	changedSet := make(map[string]bool)
	for _, file := range changedFiles {
		changedSet[file] = true
	}
	
	// Add cached vulnerabilities for unchanged files
	var mergedResults []common.Vulnerability
	for file, vulns := range s.lastScanCache.Vulnerabilities {
		if !changedSet[file] {
			mergedResults = append(mergedResults, vulns...)
		}
	}
	
	// Add new vulnerabilities
	mergedResults = append(mergedResults, newVulnerabilities...)
	
	return mergedResults
}

// GetScanStatistics returns statistics about the incremental scan
func (s *IncrementalScanner) GetScanStatistics(totalFiles, changedFiles int) string {
	if s.lastScanCache == nil {
		return fmt.Sprintf("Initial scan: %d files analyzed", totalFiles)
	}
	
	percentage := float64(changedFiles) / float64(totalFiles) * 100
	timeSaved := (1.0 - float64(changedFiles)/float64(totalFiles)) * 100
	
	return fmt.Sprintf(
		"Incremental scan: %d of %d files changed (%.1f%%), estimated %.0f%% time saved",
		changedFiles, totalFiles, percentage, timeSaved,
	)
}