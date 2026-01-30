#!/bin/bash

# VPN Bot Deployment Script
# Run this script on your VPS

echo "🚀 VPN Bot Deployment Starting..."

# Update system
apt update && apt upgrade -y

# Install Python
apt install python3 python3-pip -y

# Create bot directory
mkdir -p /root/vpn-bot
cd /root/vpn-bot

# Install dependencies
pip3 install -r requirements.txt

# Copy service file
cp vpn-bot.service /etc/systemd/system/

# Reload systemd
systemctl daemon-reload

# Enable and start service
systemctl enable vpn-bot
systemctl start vpn-bot

echo "✅ Bot deployed successfully!"
echo ""
echo "📋 Useful commands:"
echo "  - Check status: systemctl status vpn-bot"
echo "  - View logs: journalctl -u vpn-bot -f"
echo "  - Restart bot: systemctl restart vpn-bot"
echo "  - Stop bot: systemctl stop vpn-bot"
