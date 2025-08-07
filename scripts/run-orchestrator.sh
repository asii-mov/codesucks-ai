#!/bin/bash

# codesucks-ai Enhanced Comprehensive Analysis Runner Script
# This script runs comprehensive scanning with deep AI analysis (SAST + Secrets + AI Orchestrator)

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
REPO_URL=""
CONFIG_FILE="../configs/orchestrator.yaml"
SESSION_DIR="./sessions"
AGENTS_DIR="../agents"
OUTPUT_DIR="./results"
DOCKER_MODE=false
DEBUG=false

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "codesucks-ai Enhanced Comprehensive Analysis Runner"
    echo ""
    echo "USAGE:"
    echo "  $0 [OPTIONS] -r <repository-url>"
    echo ""
    echo "OPTIONS:"
    echo "  -r, --repo <url>        Repository URL to analyze (required)"
    echo "  -c, --config <file>     Configuration file (default: configs/orchestrator.yaml)"
    echo "  -s, --session-dir <dir> Session directory (default: ./sessions)"
    echo "  -a, --agents-dir <dir>  Agents directory (default: ./agents)"
    echo "  -o, --output-dir <dir>  Output directory (default: ./results)"
    echo "  -d, --docker            Run in Docker mode"
    echo "  --debug                 Enable debug logging"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "EXAMPLES:"
    echo "  # Run orchestrator on a public repository"
    echo "  $0 -r https://github.com/owner/repo"
    echo ""
    echo "  # Run with custom configuration"
    echo "  $0 -r https://github.com/owner/repo -c my-config.yaml"
    echo ""
    echo "  # Run in Docker mode"
    echo "  $0 -r https://github.com/owner/repo --docker"
    echo ""
    echo "ENVIRONMENT VARIABLES:"
    echo "  ANTHROPIC_API_KEY    - Required: Your Anthropic API key"
    echo "  GITHUB_TOKEN         - Required: Your GitHub personal access token"
    echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--repo)
            REPO_URL="$2"
            shift 2
            ;;
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -s|--session-dir)
            SESSION_DIR="$2"
            shift 2
            ;;
        -a|--agents-dir)
            AGENTS_DIR="$2"
            shift 2
            ;;
        -o|--output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -d|--docker)
            DOCKER_MODE=true
            shift
            ;;
        --debug)
            DEBUG=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate required parameters
if [[ -z "$REPO_URL" ]]; then
    print_error "Repository URL is required"
    show_usage
    exit 1
fi

# Check environment variables
if [[ -z "$ANTHROPIC_API_KEY" ]]; then
    print_error "ANTHROPIC_API_KEY environment variable is required"
    exit 1
fi

if [[ -z "$GITHUB_TOKEN" ]]; then
    print_error "GITHUB_TOKEN environment variable is required"
    exit 1
fi

# Create directories if they don't exist
print_info "Setting up orchestrator environment..."
mkdir -p "$SESSION_DIR" "$OUTPUT_DIR"

# Copy agents if they don't exist
if [[ ! -d "$AGENTS_DIR" ]]; then
    print_info "Creating agents directory and copying default agents..."
    mkdir -p "$AGENTS_DIR"
    if [[ -d "../agents" ]]; then
        cp -r ../agents/* "$AGENTS_DIR/"
        print_success "Agent configurations copied to $AGENTS_DIR"
    else
        print_warning "No default agents found. Please ensure agent configurations are in $AGENTS_DIR"
    fi
fi

# Verify configuration file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    print_error "Configuration file not found: $CONFIG_FILE"
    exit 1
fi

print_info "Starting Enhanced Comprehensive Analysis (SAST + Secrets + AI)"
print_info "Repository: $REPO_URL"
print_info "Configuration: $CONFIG_FILE"
print_info "Session Directory: $SESSION_DIR"
print_info "Agents Directory: $AGENTS_DIR"
print_info "Output Directory: $OUTPUT_DIR"

if [[ "$DOCKER_MODE" == true ]]; then
    print_info "Running in Docker mode..."
    
    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not available in PATH"
        exit 1
    fi
    
    # Check if Docker Compose is available
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed or not available in PATH"
        exit 1
    fi
    
    # Build and run with Docker Compose
    print_info "Building Docker image..."
    docker-compose -f ../docker/docker-compose.orchestrator.yml build
    
    print_info "Starting orchestrator container..."
    docker-compose -f ../docker/docker-compose.orchestrator.yml run --rm codesucks-ai-orchestrator \
        -orchestrator-mode \
        -repo "$REPO_URL" \
        -config-file "/app/$CONFIG_FILE" \
        -session-dir "/app/$SESSION_DIR" \
        -agents-dir "/app/$AGENTS_DIR" \
        -out "/app/$OUTPUT_DIR" \
        $([ "$DEBUG" == true ] && echo "-debug")
        
else
    print_info "Running in native mode..."
    
    # Check if binary exists
    if [[ ! -f "../build/codesucks-ai" ]]; then
        print_info "Binary not found. Attempting to build..."
        if command -v go &> /dev/null; then
            cd ../src && make build && cd ../scripts
            print_success "Binary built successfully"
        else
            print_error "Go is not installed and binary not found. Please install Go or use Docker mode."
            exit 1
        fi
    fi
    
    # Run the orchestrator
    print_info "Executing security analysis orchestrator..."
    ../build/codesucks-ai \
        -orchestrator-mode \
        -repo "$REPO_URL" \
        -config-file "$CONFIG_FILE" \
        -session-dir "$SESSION_DIR" \
        -agents-dir "$AGENTS_DIR" \
        -out "$OUTPUT_DIR" \
        $([ "$DEBUG" == true ] && echo "-debug")
fi

# Check if analysis completed successfully
if [[ $? -eq 0 ]]; then
    print_success "🎉 Orchestrator analysis completed successfully!"
    print_info "📊 Results available in: $OUTPUT_DIR"
    print_info "📋 Session data saved in: $SESSION_DIR"
    
    # List generated reports
    if [[ -d "$OUTPUT_DIR" ]]; then
        print_info "📄 Generated reports:"
        find "$OUTPUT_DIR" -name "*.html" -o -name "*.json" -o -name "*.md" | head -10
    fi
else
    print_error "❌ Orchestrator analysis failed"
    exit 1
fi