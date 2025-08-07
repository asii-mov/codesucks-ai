# codesucks-ai Makefile

.PHONY: help build clean test lint install deps check presets run-example

# Variables
BINARY_NAME=codesucks-ai
BUILD_DIR=../build
GO_VERSION=1.21
SEMGREP_VERSION=latest

# Colors for output
GREEN=\033[0;32m
YELLOW=\033[1;33m
RED=\033[0;31m
NC=\033[0m # No Color

help: ## Show this help message
	@echo "$(GREEN)codesucks-ai - AI-Powered Security Analysis Tool$(NC)"
	@echo ""
	@echo "$(YELLOW)Available targets:$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the binary
	@echo "$(YELLOW)Building $(BINARY_NAME)...$(NC)"
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/codesucks-ai
	@echo "$(GREEN)✅ Build complete: $(BUILD_DIR)/$(BINARY_NAME)$(NC)"

clean: ## Clean build artifacts and temporary files
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	rm -rf $(BUILD_DIR)
	rm -rf results/ findings/ *-results/ *-findings/ reports/ scans/
	rm -rf temp/ tmp/ *.tmp *.temp
	rm -f *.log debug.log error.log
	go clean -cache
	@echo "$(GREEN)✅ Clean complete$(NC)"

test: ## Run all tests
	@echo "$(YELLOW)Running all tests...$(NC)"
	go test -v ./...
	@echo "$(GREEN)✅ Tests complete$(NC)"

test-unit: ## Run unit tests only
	@echo "$(YELLOW)Running unit tests...$(NC)"
	go test -v -short ./...
	@echo "$(GREEN)✅ Unit tests complete$(NC)"

test-integration: ## Run integration tests only
	@echo "$(YELLOW)Running integration tests...$(NC)"
	go test -v -run Integration ./...
	@echo "$(GREEN)✅ Integration tests complete$(NC)"

test-coverage: ## Generate test coverage report
	@echo "$(YELLOW)Generating coverage report...$(NC)"
	@mkdir -p coverage
	go test -v -coverprofile=coverage/coverage.out ./...
	go tool cover -html=coverage/coverage.out -o coverage/coverage.html
	@echo "$(GREEN)✅ Coverage report generated: coverage/coverage.html$(NC)"
	@echo "Coverage summary:"
	@go tool cover -func=coverage/coverage.out | grep total | awk '{print "Total coverage: " $$3}'

test-watch: ## Run tests in watch mode (requires entr)
	@if command -v entr >/dev/null 2>&1; then \
		echo "$(YELLOW)Running tests in watch mode...$(NC)"; \
		find . -name '*.go' | entr -c go test -v ./...; \
	else \
		echo "$(RED)❌ entr not found. Install with: brew install entr (macOS) or apt-get install entr (Linux)$(NC)"; \
		exit 1; \
	fi

test-verbose: ## Run tests with verbose output
	@echo "$(YELLOW)Running tests with verbose output...$(NC)"
	go test -v -count=1 ./...
	@echo "$(GREEN)✅ Verbose tests complete$(NC)"

test-race: ## Run tests with race detector
	@echo "$(YELLOW)Running tests with race detector...$(NC)"
	go test -v -race ./...
	@echo "$(GREEN)✅ Race condition tests complete$(NC)"

test-bench: ## Run benchmark tests
	@echo "$(YELLOW)Running benchmark tests...$(NC)"
	go test -v -bench=. -benchmem ./...
	@echo "$(GREEN)✅ Benchmark tests complete$(NC)"

test-specific: ## Run specific test (use TEST=TestName)
	@if [ -z "$(TEST)" ]; then \
		echo "$(RED)❌ Please specify a test name: make test-specific TEST=TestName$(NC)"; \
		exit 1; \
	fi
	@echo "$(YELLOW)Running test: $(TEST)...$(NC)"
	go test -v -run $(TEST) ./...
	@echo "$(GREEN)✅ Test $(TEST) complete$(NC)"

lint: ## Run linters
	@echo "$(YELLOW)Running linters...$(NC)"
	go fmt ./...
	go vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "$(YELLOW)⚠️  golangci-lint not installed, skipping$(NC)"; \
	fi
	@echo "$(GREEN)✅ Linting complete$(NC)"

deps: ## Install dependencies
	@echo "$(YELLOW)Installing dependencies...$(NC)"
	go mod tidy
	go mod download
	@echo "$(YELLOW)Installing Semgrep...$(NC)"
	@if command -v python3 >/dev/null 2>&1; then \
		python3 -m pip install --user semgrep; \
	elif command -v pip3 >/dev/null 2>&1; then \
		pip3 install --user semgrep; \
	else \
		echo "$(RED)❌ Python3/pip3 not found - please install Semgrep manually$(NC)"; \
		exit 1; \
	fi
	@echo "$(GREEN)✅ Dependencies installed$(NC)"

install: build ## Install the binary to /usr/local/bin
	@echo "$(YELLOW)Installing $(BINARY_NAME) to /usr/local/bin...$(NC)"
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "$(GREEN)✅ Installation complete$(NC)"

check: ## Verify installation and configuration
	@echo "$(YELLOW)Checking installation...$(NC)"
	@echo "Go version:"
	@go version
	@echo ""
	@echo "Semgrep version:"
	@if command -v semgrep >/dev/null 2>&1; then \
		semgrep --version; \
	else \
		echo "$(RED)❌ Semgrep not found$(NC)"; \
	fi
	@echo ""
	@echo "Binary check:"
	@if [ -f "$(BUILD_DIR)/$(BINARY_NAME)" ]; then \
		echo "$(GREEN)✅ $(BUILD_DIR)/$(BINARY_NAME) exists$(NC)"; \
		ls -la $(BUILD_DIR)/$(BINARY_NAME); \
	else \
		echo "$(RED)❌ $(BUILD_DIR)/$(BINARY_NAME) not found - run 'make build'$(NC)"; \
	fi
	@echo ""
	@echo "Configuration presets:"
	@ls -la ../configs/

presets: ## List available configuration presets
	@echo "$(GREEN)Available Configuration Presets:$(NC)"
	@echo ""
	@echo "$(YELLOW)📋 PRESET NAME       DESCRIPTION$(NC)"
	@echo "├─ basic             Minimal ruleset for fast scanning"
	@echo "├─ codesucks-ai      Default balanced configuration (recommended)"
	@echo "├─ security-focused  Security vulnerabilities and secrets"
	@echo "├─ comprehensive     All available rulesets for maximum coverage"
	@echo "└─ compliance        Enterprise compliance focused"
	@echo ""
	@echo "$(YELLOW)Usage:$(NC)"
	@echo "  ./$(BINARY_NAME) -config <preset-name> [options]"
	@echo "  ./run-codesucks-ai.sh -c <preset-name> [options]"

run-example: build ## Run example scan on a public repository
	@echo "$(YELLOW)Running example scan...$(NC)"
	@if [ -z "$$GITHUB_TOKEN" ]; then \
		echo "$(RED)❌ GITHUB_TOKEN environment variable required$(NC)"; \
		echo "$(YELLOW)Set it with: export GITHUB_TOKEN=your_token_here$(NC)"; \
		exit 1; \
	fi
	@mkdir -p example-results
	$(BUILD_DIR)/$(BINARY_NAME) \
		-repo https://github.com/octocat/Hello-World \
		-github-token $$GITHUB_TOKEN \
		-config basic \
		-out ./example-results
	@echo "$(GREEN)✅ Example scan complete - check ./example-results/$(NC)"

docker-build: ## Build Docker image
	@echo "$(YELLOW)Building Docker image...$(NC)"
	docker build -f ../docker/Dockerfile -t codesucks-ai ..
	@echo "$(GREEN)✅ Docker image built: codesucks-ai$(NC)"

docker-run: ## Run in Docker container
	@echo "$(YELLOW)Running in Docker...$(NC)"
	@if [ -z "$$GITHUB_TOKEN" ]; then \
		echo "$(RED)❌ GITHUB_TOKEN environment variable required$(NC)"; \
		exit 1; \
	fi
	docker run --rm \
		-e GITHUB_TOKEN=$$GITHUB_TOKEN \
		-v $$(pwd)/docker-results:/app/results \
		codesucks-ai \
		-repo https://github.com/octocat/Hello-World \
		-github-token $$GITHUB_TOKEN \
		-config basic

release: clean lint test build ## Prepare release (clean, lint, test, build)
	@echo "$(GREEN)✅ Release preparation complete$(NC)"
	@echo "$(YELLOW)Next steps:$(NC)"
	@echo "  1. Tag release: git tag v1.0.0"
	@echo "  2. Push tag: git push origin v1.0.0"
	@echo "  3. Create GitHub release with binary"

dev-setup: deps ## Set up development environment
	@echo "$(YELLOW)Setting up development environment...$(NC)"
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "$(YELLOW)Installing golangci-lint...$(NC)"; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin; \
	fi
	@echo "$(GREEN)✅ Development environment ready$(NC)"

benchmark: build ## Run performance benchmark
	@echo "$(YELLOW)Running performance benchmark...$(NC)"
	@mkdir -p benchmark-results
	@echo "Testing basic configuration..."
	time $(BUILD_DIR)/$(BINARY_NAME) -repo https://github.com/octocat/Hello-World -github-token $$GITHUB_TOKEN -config basic -out benchmark-results/basic
	@echo "Testing comprehensive configuration..."
	time $(BUILD_DIR)/$(BINARY_NAME) -repo https://github.com/octocat/Hello-World -github-token $$GITHUB_TOKEN -config comprehensive -out benchmark-results/comprehensive
	@echo "$(GREEN)✅ Benchmark complete - check benchmark-results/$(NC)"

# Default target
all: clean deps lint test build ## Run full build pipeline

.DEFAULT_GOAL := help