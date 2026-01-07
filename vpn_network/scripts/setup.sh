#!/bin/bash

# VPN Security Project Setup Script
# This script sets up the development environment and installs required dependencies

set -e

echo "🚀 Starting VPN Security Project Setup..."
echo "=================================="

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "❌ This script must be run as root"
    exit 1
fi

# Update package lists
echo "🔄 Updating package lists..."
apt-get update

# Install required system packages
echo "📦 Installing system dependencies..."
apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    net-tools \
    iptables \
    iproute2 \
    openvpn \
    tcpdump \
    netcat \
    wget \
    curl \
    git

# Create and activate Python virtual environment
echo "🐍 Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt

# Set up TUN/TAP device
echo "🔧 Setting up TUN/TAP device..."
if [ ! -e "/dev/net/tun" ]; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 600 /dev/net/tun
fi

# Enable IP forwarding
echo "🔁 Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

# Make scripts executable
echo "🔧 Making scripts executable..."
chmod +x scripts/*.sh

# Create necessary directories
echo "📂 Creating directories..."
mkdir -p logs certificates config

# Generate default configuration if it doesn't exist
if [ ! -f "config/vpn_config.json" ]; then
    echo "⚙️  Generating default configuration..."
    cp config/vpn_config.example.json config/vpn_config.json
fi

echo "✅ Setup completed successfully!"
echo "=================================="
echo "To start the VPN server:"
echo "  source venv/bin/activate"
echo "  ./scripts/start_vpn.sh server"
echo ""
echo "To start the VPN client:"
echo "  source venv/bin/activate"
echo "  ./scripts/start_vpn.sh client"
