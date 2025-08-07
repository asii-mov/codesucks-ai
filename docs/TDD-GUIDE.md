# Test-Driven Development Guide

## Overview

This project follows Test-Driven Development (TDD) principles to ensure code quality, maintainability, and reliability. Every feature has comprehensive tests to prevent regressions and enable confident refactoring.

## Environment Setup

### 1. Environment Variables (.env)

The project uses `.env` files for managing secrets and configuration:

```bash
# Copy the example file
cp .env.example .env

# Edit .env and add your credentials
nano .env
```

Required environment variables:
- `GITHUB_TOKEN` - GitHub Personal Access Token
- `ANTHROPIC_API_KEY` - Claude AI API key

### 2. Running Tests

#### Quick Start
```bash
cd src
make test           # Run all tests
make test-unit      # Run unit tests only
make test-coverage  # Generate coverage report
```

#### Advanced Testing
```bash
make test-race      # Run with race detector
make test-bench     # Run benchmarks
make test-verbose   # Verbose output
make test-watch     # Watch mode (requires entr)
make test-specific TEST=TestName  # Run specific test
```

## Project Test Structure

```
src/
├── common/
│   ├── config_test.go           # Configuration tests
│   ├── envloader/
│   │   └── envloader_test.go    # Environment loader tests
│   └── github/
│       └── client_test.go       # GitHub client tests
├── testutil/
│   ├── helpers.go               # Test helper functions
│   └── fixtures.go              # Test data fixtures
└── Makefile                     # Test targets
```

## Writing Tests

### 1. Basic Test Structure

```go
func TestFeatureName(t *testing.T) {
    // Arrange - Set up test data
    testutil.SetupTestEnvironment(t)
    config := testutil.CreateTestConfig()
    
    // Act - Execute the feature
    result, err := FeatureUnderTest(config)
    
    // Assert - Verify results
    assert.NoError(t, err)
    assert.Equal(t, expected, result)
}
```

### 2. Table-Driven Tests

```go
func TestValidation(t *testing.T) {
    tests := []struct {
        name        string
        input       string
        expected    bool
        expectError bool
    }{
        {
            name:        "valid input",
            input:       "valid",
            expected:    true,
            expectError: false,
        },
        {
            name:        "invalid input",
            input:       "",
            expected:    false,
            expectError: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := Validate(tt.input)
            
            if tt.expectError {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tt.expected, result)
            }
        })
    }
}
```

### 3. Using Test Helpers

```go
func TestWithMockEnvironment(t *testing.T) {
    // Mock environment variables
    cleanup := testutil.MockEnvVars(t, map[string]string{
        "GITHUB_TOKEN": "test-token",
        "DEBUG": "true",
    })
    defer cleanup()
    
    // Create temp config file
    configPath := testutil.CreateTempYAMLConfig(t)
    
    // Test with mocked environment
    result := ProcessWithEnv(configPath)
    assert.NotNil(t, result)
}
```

## Test Utilities

### testutil/helpers.go

- `SetupTestEnvironment(t)` - Initialize test environment
- `CreateTestConfig()` - Generate test configuration
- `CreateTestOptions()` - Generate test options
- `CreateTempFile(t, name, content)` - Create temporary test files
- `MockEnvVars(t, vars)` - Mock environment variables
- `AssertFileExists(t, path)` - Verify file existence
- `AssertFileContains(t, path, content)` - Verify file content

### testutil/fixtures.go

- `CreateSampleVulnerabilities()` - Generate test vulnerability data
- `CreateSampleEnhancedVulnerability()` - Generate enhanced vulnerability
- `CreateSampleOrchestratorState()` - Generate orchestrator state
- `CreateSampleSecret()` - Generate test secret data
- `CreateSampleAnalysisResult()` - Generate analysis result

## Coverage Requirements

- Aim for **80% or higher** code coverage
- Critical security components require **90% or higher** coverage
- View coverage reports: `make test-coverage` then open `coverage/coverage.html`

## Continuous Integration

GitHub Actions runs tests automatically on:
- Every push to main/develop branches
- All pull requests
- Manual workflow dispatch

CI pipeline includes:
- Unit tests
- Integration tests
- Race condition detection
- Benchmark tests
- Coverage reporting
- Multi-platform builds

## TDD Workflow

1. **Write a failing test** - Define expected behavior
2. **Write minimal code** - Make the test pass
3. **Refactor** - Improve code quality
4. **Repeat** - Continue the cycle

### Example TDD Session

```bash
# 1. Write a new test
echo 'func TestNewFeature(t *testing.T) {
    result := NewFeature()
    assert.Equal(t, "expected", result)
}' >> feature_test.go

# 2. Run test (should fail)
go test ./... -run TestNewFeature

# 3. Implement feature
echo 'func NewFeature() string {
    return "expected"
}' >> feature.go

# 4. Run test again (should pass)
go test ./... -run TestNewFeature

# 5. Refactor and ensure tests still pass
make test
```

## Best Practices

1. **Test First** - Write tests before implementation
2. **One Test, One Assertion** - Keep tests focused
3. **Descriptive Names** - Use clear test names that describe behavior
4. **Fast Tests** - Keep unit tests under 100ms
5. **Isolated Tests** - Tests should not depend on each other
6. **Mock External Dependencies** - Use mocks for APIs, databases, etc.
7. **Clean Up** - Always clean up test artifacts
8. **Parallel Testing** - Use `t.Parallel()` for independent tests

## Debugging Tests

```bash
# Run with verbose output
go test -v ./...

# Run with specific test filter
go test -run TestName ./...

# Debug with delve
dlv test ./package

# Check for race conditions
go test -race ./...

# Profile tests
go test -cpuprofile=cpu.prof -memprofile=mem.prof ./...
```

## Common Testing Patterns

### Testing with .env Files

```go
func TestWithEnvFile(t *testing.T) {
    // Load test environment
    _ = envloader.LoadEnvForTesting()
    
    // Verify env vars are loaded
    token := os.Getenv("GITHUB_TOKEN")
    assert.NotEmpty(t, token)
}
```

### Testing Configuration

```go
func TestConfigLoading(t *testing.T) {
    configPath := testutil.CreateTempYAMLConfig(t)
    
    config, err := LoadConfig(configPath)
    assert.NoError(t, err)
    assert.NotNil(t, config)
    assert.Equal(t, "expected", config.Field)
}
```

### Testing with HTTP Mocks

```go
func TestAPIClient(t *testing.T) {
    httpmock.Activate()
    defer httpmock.DeactivateAndReset()
    
    httpmock.RegisterResponder("GET", "https://api.example.com/data",
        httpmock.NewStringResponder(200, `{"status": "ok"}`))
    
    client := NewAPIClient()
    result, err := client.GetData()
    
    assert.NoError(t, err)
    assert.Equal(t, "ok", result.Status)
}
```

## Troubleshooting

### Import Cycles
- Keep test utilities in separate `testutil` package
- Use interfaces to break circular dependencies

### Flaky Tests
- Use `testutil.SetupTestEnvironment(t)` for consistent setup
- Avoid time-dependent assertions
- Use deterministic test data

### Slow Tests
- Mark integration tests with build tags
- Use `t.Parallel()` for independent tests
- Mock expensive operations

## Resources

- [Go Testing Documentation](https://golang.org/pkg/testing/)
- [Testify Assertions](https://github.com/stretchr/testify)
- [HTTP Mocking](https://github.com/jarcoal/httpmock)
- [Table-Driven Tests](https://dave.cheney.net/2019/05/07/prefer-table-driven-tests)