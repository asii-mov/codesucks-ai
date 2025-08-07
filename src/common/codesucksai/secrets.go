package codesucksai

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/asii-mov/codesucks-ai/common"
)

// RunTruffleHog executes TruffleHog analysis on the target directory
func RunTruffleHog(sourcePath, outDir, trufflehogPath string, verifySecrets bool) (*common.TruffleHogJson, error) {
	// Create results directory
	resultsDir := filepath.Join(outDir, "trufflehog")
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create results directory: %v", err)
	}

	// Generate output file path
	outputFile := filepath.Join(resultsDir, "results.json")

	// Build TruffleHog command args
	args := buildTruffleHogArgs(sourcePath, verifySecrets)

	// Execute TruffleHog
	cmd := exec.Command(trufflehogPath, args...)
	cmd.Dir = sourcePath

	// Capture output for debugging
	output, err := cmd.CombinedOutput()

	var jsonOutput []byte
	exitCode := 0

	if err != nil {
		// Extract exit code from error
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()

			// TruffleHog exit codes:
			// - Exit code 0: No secrets found
			// - Exit code 1: Secrets detected
			// - Exit code 2+: Errors occurred

			if exitCode <= 1 {
				// Exit codes 0, 1 are acceptable - scan completed
				fmt.Printf("✅ TruffleHog completed (exit code %d)\n", exitCode)
				jsonOutput = output
			} else {
				// Exit codes 2+ indicate errors
				return nil, fmt.Errorf("trufflehog execution failed with exit code %d: %v\nOutput: %s", exitCode, err, string(output))
			}
		} else {
			// Non-exit error (e.g., command not found)
			return nil, fmt.Errorf("trufflehog execution failed: %v\nOutput: %s", err, string(output))
		}
	} else {
		// Success case
		jsonOutput = output
	}

	// Clean up output - TruffleHog may output multiple JSON objects, one per line
	// We need to combine them into a single JSON array
	jsonOutput = cleanTruffleHogOutput(jsonOutput)

	// Write JSON output to file
	if writeErr := os.WriteFile(outputFile, jsonOutput, 0644); writeErr != nil {
		return nil, fmt.Errorf("failed to write trufflehog output to file: %v", writeErr)
	}

	// Parse TruffleHog JSON output
	trufflehogJson, err := parseTruffleHogOutput(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TruffleHog output: %v", err)
	}

	return trufflehogJson, nil
}

// buildTruffleHogArgs constructs the command line arguments for TruffleHog
func buildTruffleHogArgs(sourcePath string, verifySecrets bool) []string {
	args := []string{
		"filesystem",
		"--json",
		"--no-update",
	}

	// Add verification if enabled
	if verifySecrets {
		args = append(args, "--only-verified")
	}

	// Add target path
	args = append(args, ".")

	return args
}

// cleanTruffleHogOutput processes TruffleHog NDJSON output and converts to results array
func cleanTruffleHogOutput(output []byte) []byte {
	if len(output) == 0 {
		return []byte(`{"results":[]}`)
	}

	outputStr := string(output)
	lines := strings.Split(strings.TrimSpace(outputStr), "\n")

	var results []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && strings.HasPrefix(line, "{") {
			results = append(results, line)
		}
	}

	if len(results) == 0 {
		return []byte(`{"results":[]}`)
	}

	// Combine all results into a single JSON structure
	combinedJSON := fmt.Sprintf(`{"results":[%s]}`, strings.Join(results, ","))
	return []byte(combinedJSON)
}

// parseTruffleHogOutput parses the TruffleHog JSON output file
func parseTruffleHogOutput(outputFile string) (*common.TruffleHogJson, error) {
	data, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read output file: %v", err)
	}

	var trufflehogJson common.TruffleHogJson
	if err := json.Unmarshal(data, &trufflehogJson); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	return &trufflehogJson, nil
}
