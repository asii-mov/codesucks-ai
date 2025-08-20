package envloader

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
)

// LoadEnvFile loads environment variables from .env file if it exists
func LoadEnvFile() error {
	// Try to find .env file in multiple locations
	envPaths := []string{
		".env",
		"../.env",
		"../../.env",
	}

	// Also check if running from src directory
	if cwd, err := os.Getwd(); err == nil {
		if strings.Contains(cwd, "/src") {
			envPaths = append(envPaths, filepath.Join(cwd, "../.env"))
		}
	}

	var loaded bool
	for _, path := range envPaths {
		if _, err := os.Stat(path); err == nil {
			if err := godotenv.Load(path); err != nil {
				return fmt.Errorf("failed to load .env file from %s: %w", path, err)
			}
			loaded = true
			break
		}
	}

	// It's OK if no .env file exists - environment variables might be set directly
	if !loaded && os.Getenv("CODESUCKS_ENV_REQUIRED") == "true" {
		return fmt.Errorf("no .env file found and CODESUCKS_ENV_REQUIRED is set")
	}

	return nil
}

// ValidateRequiredEnvVars checks if required environment variables are set
func ValidateRequiredEnvVars(required []string) error {
	var missing []string

	for _, envVar := range required {
		if os.Getenv(envVar) == "" {
			missing = append(missing, envVar)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	return nil
}

// GetEnvWithDefault returns environment variable value or default if not set
func GetEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// LoadEnvForTesting loads a test-specific .env file
func LoadEnvForTesting() error {
	testEnvPaths := []string{
		".env.test",
		"../.env.test",
		"../../.env.test",
		".env",
		"../.env",
		"../../.env",
	}

	for _, path := range testEnvPaths {
		if _, err := os.Stat(path); err == nil {
			// Clear existing env vars first for consistent testing
			_ = godotenv.Overload(path)
			return nil
		}
	}

	// For testing, we don't require .env files
	return nil
}
