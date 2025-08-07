#!/bin/bash

# Semgrep MCP Server Setup Script
# This script installs and configures the Semgrep MCP server

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Semgrep MCP Server Setup${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check Python version
echo -e "${YELLOW}Checking Python installation...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo -e "${GREEN}✓ Python $PYTHON_VERSION found${NC}"
else
    echo -e "${RED}✗ Python 3 is required but not installed${NC}"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

# Check pip
echo -e "${YELLOW}Checking pip installation...${NC}"
if command -v pip3 &> /dev/null; then
    echo -e "${GREEN}✓ pip3 found${NC}"
else
    echo -e "${RED}✗ pip3 not found${NC}"
    echo "Installing pip..."
    python3 -m ensurepip --default-pip || {
        echo -e "${RED}Failed to install pip${NC}"
        exit 1
    }
fi

# Install semgrep-mcp
echo ""
echo -e "${YELLOW}Installing semgrep-mcp...${NC}"
pip3 install --user semgrep-mcp || {
    echo -e "${RED}Failed to install semgrep-mcp${NC}"
    echo "Trying with --break-system-packages flag..."
    pip3 install --user --break-system-packages semgrep-mcp || {
        echo -e "${RED}Installation failed${NC}"
        exit 1
    }
}

# Install semgrep if not present
echo ""
echo -e "${YELLOW}Checking Semgrep installation...${NC}"
if command -v semgrep &> /dev/null; then
    SEMGREP_VERSION=$(semgrep --version 2>&1 | head -n1)
    echo -e "${GREEN}✓ Semgrep found: $SEMGREP_VERSION${NC}"
else
    echo -e "${YELLOW}Installing Semgrep...${NC}"
    pip3 install --user semgrep || {
        echo -e "${RED}Failed to install Semgrep${NC}"
        exit 1
    }
fi

# Create MCP configuration directory
MCP_CONFIG_DIR="$HOME/.config/mcp"
echo ""
echo -e "${YELLOW}Creating MCP configuration directory...${NC}"
mkdir -p "$MCP_CONFIG_DIR"
echo -e "${GREEN}✓ Created $MCP_CONFIG_DIR${NC}"

# Create MCP server configuration
CONFIG_FILE="$MCP_CONFIG_DIR/semgrep-config.json"
echo ""
echo -e "${YELLOW}Creating MCP server configuration...${NC}"
cat > "$CONFIG_FILE" << 'EOF'
{
  "server": {
    "host": "localhost",
    "port": 3000,
    "timeout": 30
  },
  "semgrep": {
    "default_config": "auto",
    "max_file_size": 1048576,
    "timeout": 60,
    "metrics": true
  },
  "features": {
    "security_check": true,
    "semgrep_scan": true,
    "custom_rules": true,
    "ast_analysis": true,
    "platform_api": false
  },
  "logging": {
    "level": "INFO",
    "file": "/tmp/semgrep-mcp.log"
  }
}
EOF
echo -e "${GREEN}✓ Created configuration at $CONFIG_FILE${NC}"

# Create systemd service file (optional)
if command -v systemctl &> /dev/null; then
    echo ""
    echo -e "${YELLOW}Creating systemd service file...${NC}"
    SERVICE_FILE="$HOME/.config/systemd/user/semgrep-mcp.service"
    mkdir -p "$HOME/.config/systemd/user"
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Semgrep MCP Server
After=network.target

[Service]
Type=simple
ExecStart=$(which python3) -m semgrep_mcp.server --config $CONFIG_FILE
Restart=on-failure
RestartSec=10
StandardOutput=append:/tmp/semgrep-mcp.log
StandardError=append:/tmp/semgrep-mcp.error.log

[Install]
WantedBy=default.target
EOF
    
    echo -e "${GREEN}✓ Created systemd service file${NC}"
    echo ""
    echo "To enable the service, run:"
    echo "  systemctl --user daemon-reload"
    echo "  systemctl --user enable semgrep-mcp"
    echo "  systemctl --user start semgrep-mcp"
fi

# Create start script
START_SCRIPT="$HOME/.local/bin/start-semgrep-mcp"
mkdir -p "$HOME/.local/bin"
echo ""
echo -e "${YELLOW}Creating start script...${NC}"
cat > "$START_SCRIPT" << 'EOF'
#!/bin/bash
# Start Semgrep MCP Server

CONFIG_FILE="$HOME/.config/mcp/semgrep-config.json"
LOG_FILE="/tmp/semgrep-mcp.log"

echo "Starting Semgrep MCP Server..."
echo "Configuration: $CONFIG_FILE"
echo "Log file: $LOG_FILE"
echo ""

# Check if already running
if pgrep -f "semgrep_mcp.server" > /dev/null; then
    echo "Semgrep MCP Server is already running"
    echo "To stop it, run: pkill -f semgrep_mcp.server"
    exit 1
fi

# Start the server
python3 -m semgrep_mcp.server --config "$CONFIG_FILE" >> "$LOG_FILE" 2>&1 &
SERVER_PID=$!

echo "Server started with PID: $SERVER_PID"
echo ""
echo "To check status: tail -f $LOG_FILE"
echo "To stop server: kill $SERVER_PID"

# Wait a moment and check if it's running
sleep 2
if ps -p $SERVER_PID > /dev/null; then
    echo ""
    echo "✓ Server is running on http://localhost:3000"
else
    echo ""
    echo "✗ Server failed to start. Check $LOG_FILE for errors"
    exit 1
fi
EOF

chmod +x "$START_SCRIPT"
echo -e "${GREEN}✓ Created start script at $START_SCRIPT${NC}"

# Add to PATH if not already there
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo ""
    echo -e "${YELLOW}Adding ~/.local/bin to PATH...${NC}"
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
    echo -e "${GREEN}✓ Added to .bashrc (restart shell or run: source ~/.bashrc)${NC}"
fi

# Create test script
TEST_SCRIPT="$HOME/.local/bin/test-semgrep-mcp"
echo ""
echo -e "${YELLOW}Creating test script...${NC}"
cat > "$TEST_SCRIPT" << 'EOF'
#!/bin/bash
# Test Semgrep MCP Server

echo "Testing Semgrep MCP Server..."
echo ""

# Test with curl
echo "Sending ping request..."
curl -X POST http://localhost:3000 \
  -H "Content-Type: application/json" \
  -d '{"id":"test-1","type":"request","method":"ping","version":"1.0.0"}' \
  2>/dev/null | python3 -m json.tool

echo ""
echo "Testing security_check tool..."
curl -X POST http://localhost:3000 \
  -H "Content-Type: application/json" \
  -d '{
    "id":"test-2",
    "type":"request",
    "method":"tools/call",
    "params":{
      "name":"security_check",
      "arguments":{
        "code":"import os\nos.system(user_input)"
      }
    },
    "version":"1.0.0"
  }' 2>/dev/null | python3 -m json.tool
EOF

chmod +x "$TEST_SCRIPT"
echo -e "${GREEN}✓ Created test script at $TEST_SCRIPT${NC}"

# Final instructions
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "To start the MCP server:"
echo -e "  ${YELLOW}start-semgrep-mcp${NC}"
echo ""
echo "To test the server:"
echo -e "  ${YELLOW}test-semgrep-mcp${NC}"
echo ""
echo "To use with codesucks-ai:"
echo -e "  ${YELLOW}./build/codesucks-ai -use-mcp-semgrep -repo https://github.com/owner/repo${NC}"
echo ""
echo "Environment variable (optional):"
echo -e "  ${YELLOW}export SEMGREP_MCP_SERVER=http://localhost:3000${NC}"
echo ""

# Offer to start the server now
echo -e "${YELLOW}Would you like to start the server now? (y/n)${NC}"
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    echo ""
    $START_SCRIPT
fi