#!/bin/bash

# VPN Security Project - Start Script
# This script starts either the VPN server or client

set -e

# Default values
MODE=""
CONFIG_FILE="config/vpn_config.json"
LOG_LEVEL="INFO"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print usage information
function show_usage() {
    echo "Usage: $0 [server|client] [options]"
    echo ""
    echo "Options:"
    echo "  -c, --config FILE    Configuration file (default: config/vpn_config.json)"
    echo "  -l, --log LEVEL      Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)"
    echo "  -h, --help           Show this help message and exit"
    echo ""
    echo "Examples:"
    echo "  $0 server -c config/server_config.json"
    echo "  $0 client -l DEBUG"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        server|client)
            MODE="$1"
            shift
            ;;
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -l|--log)
            LOG_LEVEL="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            ;;
        *)
            echo "Error: Unknown option $1"
            show_usage
            ;;
    escaped

# Check if mode is specified
if [ -z "$MODE" ]; then
    echo "Error: Mode (server|client) must be specified"
    show_usage
fi

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file $CONFIG_FILE not found"
    exit 1
fi

# Activate virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
else
    echo "${YELLOW}Warning: Virtual environment not found. Running without activation.${NC}"
fi

# Set log level
export PYTHONUNBUFFERED=1
export LOG_LEVEL="$LOG_LEVEL"

# Start the appropriate service
case $MODE in
    server)
        echo "${GREEN}🚀 Starting VPN Server...${NC}"
        echo "📋 Config: $CONFIG_FILE"
        echo "📝 Log Level: $LOG_LEVEL"
        echo ""
        python src/main.py server --config "$CONFIG_FILE"
        ;;
    client)
        echo "${GREEN}🚀 Starting VPN Client...${NC}"
        echo "📋 Config: $CONFIG_FILE"
        echo "📝 Log Level: $LOG_LEVEL"
        echo ""
        python src/main.py client --config "$CONFIG_FILE"
        ;;
    *)
        echo "Error: Invalid mode '$MODE'. Use 'server' or 'client'."
        show_usage
        ;;
esac

echo "${GREEN}✅ VPN $MODE stopped.${NC}"
