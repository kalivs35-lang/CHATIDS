#!/bin/bash
echo "🚀 Setting up ChatIDS on new system..."

# Install system dependencies
sudo apt update
sudo apt install -y python3 python3-pip suricata

# Install Python packages
pip3 install -r requirements.txt

# Configure Suricata
sudo suricata-update
sudo mkdir -p /var/log/suricata
sudo chmod 755 /var/log/suricata

echo "✅ Setup complete! Edit .env with your Gemini API key and run: python run_chatids.py --real"

