#!/bin/bash

# Demo script to show Test-Driven Development infrastructure

echo "===========================================" 
echo "  Test-Driven Development Demo"
echo "==========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}1. Setting up environment from .env file...${NC}"
if [ -f .env.example ]; then
    echo "   Found .env.example - copy it to .env and add your credentials"
    echo ""
fi

echo -e "${YELLOW}2. Running test suite...${NC}"
cd src

echo ""
echo -e "${GREEN}Running unit tests:${NC}"
go test -v -short ./common/envloader 2>&1 | head -20

echo ""
echo -e "${GREEN}Available test commands:${NC}"
echo "   make test           - Run all tests"
echo "   make test-unit      - Run unit tests only"
echo "   make test-coverage  - Generate coverage report"
echo "   make test-race      - Run with race detector"
echo "   make test-bench     - Run benchmarks"
echo "   make test-watch     - Watch mode (requires entr)"
echo ""

echo -e "${GREEN}Test utilities available:${NC}"
echo "   - testutil/helpers.go   - Test helper functions"
echo "   - testutil/fixtures.go  - Test data fixtures"
echo "   - common/envloader      - .env file support"
echo ""

echo -e "${GREEN}GitHub Actions CI/CD:${NC}"
echo "   - .github/workflows/test.yml configured"
echo "   - Runs on push and pull requests"
echo "   - Includes coverage reporting"
echo ""

echo -e "${YELLOW}3. Example: Running specific test${NC}"
echo "   make test-specific TEST=TestLoadEnvFile"
make test-specific TEST=TestLoadEnvFile 2>&1 | tail -5

echo ""
echo -e "${GREEN}✅ Test infrastructure ready!${NC}"
echo ""
echo "To get started with TDD:"
echo "1. Copy .env.example to .env"
echo "2. Write your test first"
echo "3. Run the test (it should fail)"
echo "4. Write code to make the test pass"
echo "5. Refactor and repeat"