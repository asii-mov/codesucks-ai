package envloader

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetEnvWithDefault(t *testing.T) {
	tests := []struct {
		name         string
		envKey       string
		envValue     string
		defaultValue string
		expected     string
	}{
		{
			name:         "returns environment variable when set",
			envKey:       "TEST_VAR",
			envValue:     "test_value",
			defaultValue: "default",
			expected:     "test_value",
		},
		{
			name:         "returns default when environment variable not set",
			envKey:       "UNSET_VAR",
			envValue:     "",
			defaultValue: "default",
			expected:     "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			if tt.envValue != "" {
				os.Setenv(tt.envKey, tt.envValue)
				defer os.Unsetenv(tt.envKey)
			}

			// Test
			result := GetEnvWithDefault(tt.envKey, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateRequiredEnvVars(t *testing.T) {
	tests := []struct {
		name        string
		required    []string
		setVars     map[string]string
		expectError bool
	}{
		{
			name:     "all required variables set",
			required: []string{"VAR1", "VAR2"},
			setVars: map[string]string{
				"VAR1": "value1",
				"VAR2": "value2",
			},
			expectError: false,
		},
		{
			name:     "missing required variable",
			required: []string{"VAR1", "VAR2"},
			setVars: map[string]string{
				"VAR1": "value1",
			},
			expectError: true,
		},
		{
			name:        "no required variables",
			required:    []string{},
			setVars:     map[string]string{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			for key, value := range tt.setVars {
				os.Setenv(key, value)
				defer os.Unsetenv(key)
			}

			// Test
			err := ValidateRequiredEnvVars(tt.required)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLoadEnvFile(t *testing.T) {
	// Create a temporary .env file for testing
	tempDir := t.TempDir()
	envFile := filepath.Join(tempDir, ".env")

	content := `TEST_ENV_VAR=test_value
TEST_ANOTHER_VAR=another_value`

	err := os.WriteFile(envFile, []byte(content), 0644)
	require.NoError(t, err)

	// Change to temp directory
	originalDir, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(originalDir)

	// Test loading
	err = LoadEnvFile()
	assert.NoError(t, err)

	// Verify variables were loaded
	assert.Equal(t, "test_value", os.Getenv("TEST_ENV_VAR"))
	assert.Equal(t, "another_value", os.Getenv("TEST_ANOTHER_VAR"))

	// Cleanup
	os.Unsetenv("TEST_ENV_VAR")
	os.Unsetenv("TEST_ANOTHER_VAR")
}

func TestLoadEnvForTesting(t *testing.T) {
	// This should not fail even without .env files
	err := LoadEnvForTesting()
	assert.NoError(t, err)
}
