#!/bin/bash

# Enhanced Orchestrator Runner for codesucks-ai
# Handles environment setup, MCP server, and orchestrator execution

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
REPO_URL=""
USE_MCP=false
SETUP_ONLY=false
DEBUG=false
CONFIG_FILE=""
OUTPUT_DIR="./scans"

# Function to print colored output
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    cat << EOF
Enhanced Orchestrator Runner for codesucks-ai

USAGE:
    ./run-orchestrator.sh [OPTIONS] -r <repository-url>

OPTIONS:
    -r, --repo <url>        Repository URL to scan (required)
    -m, --mcp               Enable MCP integration
    -s, --setup-only        Only setup environment, don't run scan
    -c, --config <file>     Use custom configuration file
    -o, --output <dir>      Output directory (default: ./results)
    -d, --debug             Enable debug output
    -h, --help              Show this help message

EXAMPLES:
    # Basic orchestrator scan
    ./run-orchestrator.sh -r https://github.com/owner/repo

    # With MCP integration
    ./run-orchestrator.sh -r https://github.com/owner/repo --mcp

    # Setup environment only
    ./run-orchestrator.sh --setup-only

    # Custom configuration
    ./run-orchestrator.sh -r https://github.com/owner/repo -c configs/orchestrator.yaml

REQUIREMENTS:
    - ANTHROPIC_API_KEY environment variable
    - GITHUB_TOKEN environment variable  
    - Claude Code CLI (for orchestrator subagents)
    - uv (for MCP virtual environment)

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--repo)
            REPO_URL="$2"
            shift 2
            ;;
        -m|--mcp)
            USE_MCP=true
            shift
            ;;
        -s|--setup-only)
            SETUP_ONLY=true
            shift
            ;;
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -d|--debug)
            DEBUG=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Enable debug mode if requested
if [ "$DEBUG" = true ]; then
    set -x
fi

log_info "Starting Enhanced Orchestrator Setup and Execution"

# Check if we're in the right directory
if [ ! -f "src/Makefile" ] && [ ! -f "build/codesucks-ai" ]; then
    log_error "Please run this script from the codesucks-ai root directory"
    exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check and setup environment variables
setup_environment() {
    log_info "Setting up environment variables..."
    
    # Check for .env file and source it
    if [ -f ".env" ]; then
        log_info "Loading environment from .env file"
        set -a
        source .env
        set +a
        log_success "Environment variables loaded"
    else
        log_warning ".env file not found"
    fi
    
    # Validate required environment variables
    if [ -z "$ANTHROPIC_API_KEY" ]; then
        log_error "ANTHROPIC_API_KEY environment variable is required"
        log_info "Please set it in .env file or export it: export ANTHROPIC_API_KEY='your-key'"
        exit 1
    fi
    
    if [ -z "$GITHUB_TOKEN" ]; then
        log_error "GITHUB_TOKEN environment variable is required"
        log_info "Please set it in .env file or export it: export GITHUB_TOKEN='your-token'"
        exit 1
    fi
    
    log_success "Environment variables validated"
}

# Function to check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check for Claude CLI
    if ! command_exists claude; then
        log_error "Claude Code CLI not found in PATH"
        log_info "Please install Claude Code CLI from: https://docs.anthropic.com/en/docs/claude-code"
        exit 1
    fi
    log_success "Claude Code CLI found: $(claude --version 2>/dev/null || echo 'installed')"
    
    # Check for uv (required for MCP)
    if [ "$USE_MCP" = true ] && ! command_exists uv; then
        log_error "uv not found in PATH (required for MCP setup)"
        log_info "Please install uv: curl -LsSf https://astral.sh/uv/install.sh | sh"
        exit 1
    fi
    
    # Check for Go (if binary doesn't exist)
    if [ ! -f "build/codesucks-ai" ] && ! command_exists go; then
        log_error "Go not found in PATH and binary doesn't exist"
        log_info "Please install Go 1.21+ or run: cd src && make build"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Function to build the application if needed
build_application() {
    if [ ! -f "build/codesucks-ai" ]; then
        log_info "Building application..."
        cd src
        if [ -f "Makefile" ]; then
            make build
        else
            go build -o ../build/codesucks-ai ./cmd/codesucks-ai
        fi
        cd ..
        log_success "Application built successfully"
    else
        log_success "Application binary already exists"
    fi
}

# Function to setup MCP environment
setup_mcp() {
    log_info "Setting up Semgrep MCP environment..."
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "mcp-env" ]; then
        log_info "Creating Python virtual environment with uv..."
        uv venv mcp-env
        log_success "Virtual environment created"
    fi
    
    # Activate virtual environment and install dependencies
    log_info "Installing MCP dependencies..."
    source mcp-env/bin/activate
    
    # Install semgrep-mcp and semgrep
    uv pip install semgrep-mcp semgrep
    
    log_success "MCP environment setup complete"
    
    # Test MCP server
    log_info "Testing MCP server startup..."
    python -c "import semgrep_mcp; print('MCP module available')" || {
        log_error "MCP module installation failed"
        exit 1
    }
    
    log_success "MCP environment validated"
}

# Function to start MCP server
start_mcp_server() {
    if [ "$USE_MCP" = true ]; then
        log_info "Starting Semgrep MCP server..."
        
        # Check if MCP server is already running
        if curl -s http://localhost:3000/health >/dev/null 2>&1; then
            log_success "MCP server already running"
            return 0
        fi
        
        # Activate virtual environment
        source mcp-env/bin/activate
        
        # Start MCP server in background
        python -m semgrep_mcp.server &
        MCP_PID=$!
        
        # Wait for server to start
        log_info "Waiting for MCP server to start..."
        for i in {1..10}; do
            if curl -s http://localhost:3000/health >/dev/null 2>&1; then
                log_success "MCP server started successfully (PID: $MCP_PID)"
                echo $MCP_PID > mcp-server.pid
                return 0
            fi
            sleep 2
        done
        
        log_error "MCP server failed to start"
        kill $MCP_PID 2>/dev/null || true
        exit 1
    fi
}

# Function to stop MCP server
stop_mcp_server() {
    if [ -f "mcp-server.pid" ]; then
        MCP_PID=$(cat mcp-server.pid)
        log_info "Stopping MCP server (PID: $MCP_PID)..."
        kill $MCP_PID 2>/dev/null || true
        rm -f mcp-server.pid
        log_success "MCP server stopped"
    fi
}

# Function to run the orchestrator
run_orchestrator() {
    log_info "Running orchestrator analysis..."
    
    # Build command arguments
    ARGS=("-orchestrator-mode" "-repo" "$REPO_URL")
    
    if [ "$USE_MCP" = true ]; then
        ARGS+=("-use-mcp-semgrep")
    fi
    
    if [ -n "$CONFIG_FILE" ]; then
        ARGS+=("-config-file" "$CONFIG_FILE")
    fi
    
    if [ -n "$OUTPUT_DIR" ]; then
        ARGS+=("-out" "$OUTPUT_DIR")
    fi
    
    if [ "$DEBUG" = true ]; then
        ARGS+=("-debug")
    fi
    
    log_info "Executing: ./build/codesucks-ai ${ARGS[*]}"
    
    # Run the analysis
    ./build/codesucks-ai "${ARGS[@]}"
    
    log_success "Orchestrator analysis completed"
}

# Function to cleanup on exit
cleanup() {
    if [ "$USE_MCP" = true ]; then
        stop_mcp_server
    fi
}

# Set trap for cleanup
trap cleanup EXIT

# Main execution flow
main() {
    # Always setup environment and check prerequisites
    setup_environment
    check_prerequisites
    build_application
    
    # Setup MCP if requested
    if [ "$USE_MCP" = true ]; then
        setup_mcp
        start_mcp_server
    fi
    
    # If setup-only mode, exit here
    if [ "$SETUP_ONLY" = true ]; then
        log_success "Setup completed successfully"
        if [ "$USE_MCP" = true ]; then
            log_info "MCP server running at http://localhost:3000"
            log_info "To stop: kill \$(cat mcp-server.pid)"
        fi
        exit 0
    fi
    
    # Validate repository URL
    if [ -z "$REPO_URL" ]; then
        log_error "Repository URL is required"
        show_usage
        exit 1
    fi
    
    # Run the orchestrator
    run_orchestrator
    
    log_success "All operations completed successfully!"
}

# Execute main function
main "$@"