#!/bin/bash
# NetWatch — Setup Script
# Installs system dependencies and Python packages
# DISCLAIMER: For use on your own network/devices only.

set -e
echo "=== NetWatch Setup ==="
echo ""
echo "DISCLAIMER: This tool is for authorized use on your own network only."
echo ""

# Install system packages
if command -v apt-get &>/dev/null; then
    sudo apt-get update -q
    sudo apt-get install -y nmap tshark arp-scan python3 python3-pip
    echo "System packages installed."
elif command -v brew &>/dev/null; then
    brew install nmap wireshark python
    echo "Homebrew packages installed."
else
    echo "WARNING: Could not detect package manager. Install nmap, tshark, arp-scan manually."
fi

# Python packages
pip3 install -r requirements.txt

# Create config if not exists
if [ ! -f configs/config.yaml ]; then
    cp configs/config.example.yaml configs/config.yaml
    echo ""
    echo "Created configs/config.yaml — EDIT IT before running!"
    echo "  Set network.interface (e.g. wlan0)"
    echo "  Set network.subnet (e.g. 192.168.1.0/24)"
fi

echo ""
echo "=== Setup complete ==="
echo "Run: python3 netwatch.py --check"
echo "Run: sudo python3 netwatch.py"
