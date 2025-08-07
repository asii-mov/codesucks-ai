#!/bin/bash

# codesucks-ai - AI-Powered Security Analysis Tool
# This script sets up the environment and runs the security scanner

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
GITHUB_TOKEN=""
ANTHROPIC_KEY=""
REPO_URL=""
OUTPUT_DIR="./findings"
SEMGREP_PATH="/home/asiimov/.local/bin/semgrep"
CONFIG_PRESET="codesucks-ai"
AUTO_FIX=false
CREATE_PR=false
CREATE_ISSUE=false
DEBUG=false
LIST_PRESETS=false

# Function to display usage
usage() {
    echo "Usage: $0 -g <github_token> -a <anthropic_key> -r <repo_url> [options]"
    echo ""
    echo "Required arguments:"
    echo "  -g, --github-token    GitHub personal access token"
    echo "  -a, --anthropic-key   Anthropic API key for Claude AI"
    echo "  -r, --repo           Repository URL to scan"
    echo ""
    echo "Optional arguments:"
    echo "  -o, --output         Output directory (default: ./findings)"
    echo "  -s, --semgrep-path   Path to semgrep binary (default: /home/asiimov/.local/bin/semgrep)"
    echo "  -c, --config         Configuration preset (default: codesucks-ai)"
    echo "  --list-presets       List available configuration presets"
    echo "  --auto-fix           Enable AI-powered vulnerability fixes"
    echo "  --create-pr          Create pull request with fixes"
    echo "  --create-issue       Create GitHub issue for vulnerabilities"
    echo "  --debug              Enable debug logging"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -g github_pat_xxx -a sk-ant-api03-xxx -r https://github.com/user/repo"
    echo "  $0 -g \$GITHUB_TOKEN -a \$ANTHROPIC_API_KEY -r https://github.com/user/repo --auto-fix --create-pr"
    echo "  $0 -g \$GITHUB_TOKEN -r https://github.com/user/repo -c comprehensive"
    echo "  $0 --list-presets"
}

# Function to list available presets
list_presets() {
    echo -e "${BLUE}Available Configuration Presets:${NC}"
    echo ""
    echo -e "${GREEN}📋 PRESET NAME       DESCRIPTION${NC}"
    echo -e "├─ basic             Minimal ruleset for fast scanning (p/trailofbits)"
    echo -e "├─ codesucks-ai      Default balanced configuration (recommended)"
    echo -e "├─ security-focused  Security vulnerabilities and secrets"
    echo -e "├─ comprehensive     All available rulesets for maximum coverage"
    echo -e "└─ compliance        Enterprise compliance focused (CWE, supply chain)"
    echo ""
    echo -e "${YELLOW}USAGE:${NC}"
    echo "  $0 -c <preset-name> [other options...]"
    echo ""
    echo -e "${YELLOW}EXAMPLES:${NC}"
    echo "  $0 -c basic -g \$GITHUB_TOKEN -r https://github.com/owner/repo"
    echo "  $0 -c comprehensive -g \$GITHUB_TOKEN -r https://github.com/owner/repo"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -g|--github-token)
            GITHUB_TOKEN="$2"
            shift 2
            ;;
        -a|--anthropic-key)
            ANTHROPIC_KEY="$2"
            shift 2
            ;;
        -r|--repo)
            REPO_URL="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -s|--semgrep-path)
            SEMGREP_PATH="$2"
            shift 2
            ;;
        -c|--config)
            CONFIG_PRESET="$2"
            shift 2
            ;;
        --list-presets)
            LIST_PRESETS=true
            shift
            ;;
        --auto-fix)
            AUTO_FIX=true
            shift
            ;;
        --create-pr)
            CREATE_PR=true
            shift
            ;;
        --create-issue)
            CREATE_ISSUE=true
            shift
            ;;
        --debug)
            DEBUG=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}"
            usage
            exit 1
            ;;
    esac
done

# Handle list presets option
if [[ "$LIST_PRESETS" == "true" ]]; then
    list_presets
    exit 0
fi

# Validate required arguments
if [[ -z "$GITHUB_TOKEN" ]]; then
    echo -e "${RED}Error: GitHub token is required${NC}"
    usage
    exit 1
fi

if [[ -z "$ANTHROPIC_KEY" ]]; then
    echo -e "${RED}Error: Anthropic API key is required${NC}"
    usage
    exit 1
fi

if [[ -z "$REPO_URL" ]]; then
    echo -e "${RED}Error: Repository URL is required${NC}"
    usage
    exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${BLUE}🔒 codesucks-ai - AI-Powered Security Analysis Tool${NC}"
echo -e "${BLUE}=================================================${NC}"
echo ""

# Check if binary exists
if [[ ! -f "./codesucks-ai" ]]; then
    echo -e "${YELLOW}⚠️  Binary not found. Building codesucks-ai...${NC}"
    if ! go build -o codesucks-ai ./cmd/codesucks-ai; then
        echo -e "${RED}❌ Failed to build codesucks-ai${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Build completed successfully${NC}"
fi

# Setup semgrep environment
echo -e "${YELLOW}🔧 Setting up Semgrep environment...${NC}"

# Check if semgrep is available
if [[ ! -f "$SEMGREP_PATH" ]]; then
    echo -e "${YELLOW}⚠️  Semgrep not found at $SEMGREP_PATH${NC}"
    echo -e "${YELLOW}🔧 Installing Semgrep...${NC}"
    
    # Try to install semgrep using pip with --break-system-packages
    if python3 -m pip install --user --break-system-packages semgrep; then
        echo -e "${GREEN}✅ Semgrep installed successfully${NC}"
        SEMGREP_PATH="/home/asiimov/.local/bin/semgrep"
    else
        echo -e "${RED}❌ Failed to install Semgrep${NC}"
        echo -e "${YELLOW}💡 Please install Semgrep manually:${NC}"
        echo "   python3 -m pip install --user --break-system-packages semgrep"
        exit 1
    fi
fi

# Verify semgrep installation
echo -e "${YELLOW}🔍 Verifying Semgrep installation...${NC}"
if PATH="/home/asiimov/.local/bin:$PATH" "$SEMGREP_PATH" --version > /dev/null 2>&1; then
    SEMGREP_VERSION=$(PATH="/home/asiimov/.local/bin:$PATH" "$SEMGREP_PATH" --version)
    echo -e "${GREEN}✅ Semgrep verified: $SEMGREP_VERSION${NC}"
else
    echo -e "${RED}❌ Semgrep verification failed${NC}"
    exit 1
fi

# Create output directory
echo -e "${YELLOW}📁 Creating output directory: $OUTPUT_DIR${NC}"
mkdir -p "$OUTPUT_DIR"

# Build command arguments
CMD_ARGS=(
    "-github-token" "$GITHUB_TOKEN"
    "-anthropic-key" "$ANTHROPIC_KEY" 
    "-repo" "$REPO_URL"
    "-out" "$(realpath "$OUTPUT_DIR")"
    "-semgrep-path" "$SEMGREP_PATH"
    "-config" "$CONFIG_PRESET"
)

# Add optional flags
if [[ "$AUTO_FIX" == "true" ]]; then
    CMD_ARGS+=("-auto-fix")
    echo -e "${GREEN}🤖 AI auto-fix enabled${NC}"
fi

if [[ "$CREATE_PR" == "true" ]]; then
    CMD_ARGS+=("-create-pr")
    echo -e "${GREEN}🔄 Pull request creation enabled${NC}"
fi

if [[ "$CREATE_ISSUE" == "true" ]]; then
    CMD_ARGS+=("-create-issue")
    echo -e "${GREEN}📝 Issue creation enabled${NC}"
fi

if [[ "$DEBUG" == "true" ]]; then
    CMD_ARGS+=("-debug")
    echo -e "${YELLOW}🐛 Debug mode enabled${NC}"
fi

echo ""
echo -e "${BLUE}🚀 Starting security scan...${NC}"
echo -e "${BLUE}Repository: $REPO_URL${NC}"
echo -e "${BLUE}Output: $OUTPUT_DIR${NC}"
echo -e "${BLUE}Configuration: $CONFIG_PRESET${NC}"
echo ""

# Run the security scan with proper PATH
if PATH="/home/asiimov/.local/bin:$PATH" ./codesucks-ai "${CMD_ARGS[@]}"; then
    echo ""
    echo -e "${GREEN}🎉 Scan completed successfully!${NC}"
    echo ""
    echo -e "${BLUE}📊 Results are available in: $OUTPUT_DIR${NC}"
    
    # Find and display report path
    REPORT_FILE=$(find "$OUTPUT_DIR" -name "security-report-*.html" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)
    if [[ -n "$REPORT_FILE" ]]; then
        echo -e "${GREEN}📋 HTML Report: $REPORT_FILE${NC}"
    fi
    
    echo ""
    echo -e "${YELLOW}💡 To view the report, open the HTML file in your browser:${NC}"
    echo -e "${YELLOW}   firefox \"$REPORT_FILE\" || xdg-open \"$REPORT_FILE\"${NC}"
    
else
    echo ""
    echo -e "${RED}❌ Scan failed. Check the output above for details.${NC}"
    exit 1
fi