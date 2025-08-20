#!/bin/bash

# Simple wrapper script for codesucks-ai
# Loads .env file and passes all arguments to the binary

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Check if binary exists
BINARY="./build/codesucks-ai"
if [ ! -f "$BINARY" ]; then
    echo -e "${RED}Error: $BINARY not found${NC}"
    echo "Please build the application first:"
    echo "  cd src && make build && cd .."
    exit 1
fi

# Load .env file if it exists
if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
    echo -e "${GREEN}Loaded environment from .env${NC}"
fi

# Execute the binary with all passed arguments
exec "$BINARY" "$@"