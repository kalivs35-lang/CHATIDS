ChatIDS - AI-Powered Intrusion Detection System

ChatIDS transforms complex cybersecurity alerts into simple, actionable explanations using Google's Gemini AI. Designed for home users and non-experts, it makes enterprise-level security monitoring accessible to everyone.

🚀 Quick Deployment
One-Command Setup on New System
bash
# Clone the repository
git clone https://github.com/kalivs35-lang/CHATIDS.git
cd CHATIDS

# Make setup scripts executable
chmod +x setup_chatids.sh configure_suricata.sh

# Run automated setup
./setup_chatids.sh
./configure_suricate.sh

# Configure environment
cp .env.template .env
nano .env  # Add your Gemini API key

# Launch ChatIDS with real monitoring
python run_chatids.py --real
What the setup scripts do:
setup_chatids.sh - Installs all dependencies:

System packages (Python, Suricata)

Python dependencies from requirements.txt

Creates necessary directories

Sets up log file permissions

configure_suricata.sh - Auto-configures Suricata:

Detects your network interface automatically

Identifies your local IP range

Creates optimized Suricata configuration

Downloads latest rule sets

🛠️ Manual Installation (Alternative)
Prerequisites
Python 3.8+

Suricata IDS

Google Gemini API key

Step-by-Step Setup
Clone and setup:

bash
git clone https://github.com/kalivs35-lang/CHATIDS.git
cd CHATIDS
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
Configure environment:

bash
cp .env.template .env
# Edit .env with your Gemini API key and settings
Install and configure Suricata:

bash
sudo apt update
sudo apt install suricata suricata-update
sudo suricata-update
Run ChatIDS:

bash
python run_chatids.py --real
📁 Project Structure
text
chatids/
.
├── alerts.db
├── commands.txt
├── configure_suricata.sh
├── generate_sample_data.py
├── live_eve.json
├── README.md
├── requirements.txt
├── run_chatids.py
├── sample_eve.json
├── sec_v17_n12_2024_6.pdf
├── setup_chatids.sh
├── templates
│   ├── alert_detail.html
│   ├── base.html
│   └── dashboard.html
├── test.py
├── watcher.py
└── webapp.py

⚙️ Configuration
Environment Variables (.env)
bash
# Required: Gemini API Configuration
GEMINI_API_KEY=your_gemini_api_key_here

# Suricata Log File
SURICATA_LOG_FILE=/var/log/suricata/eve.json

# Database
DATABASE_PATH=alerts.db

# Web Server
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
DEBUG_MODE=False

# Optional: Customization
CUSTOM_PROMPT_FILE=custom_prompt.txt
Auto-Detected Settings
The setup scripts automatically detect:

Network Interface (eth0, wlan0, ens33, etc.)

IP Address Range based on your current network

Suricata Configuration optimized for your system

🎯 Usage
Starting the System
Method 1: Using the launcher (recommended)

bash
python3 run_chatids.py 
Method 2: Manual component startup

bash
# Terminal 1 - Suricata
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Terminal 2 - Watcher
python3 watcher.py

# Terminal 3 - Web Dashboard
python3 webapp.py 
Method 3: Test mode (no Suricata required)

bash
python run_chatids.py --test-mode
Accessing the Dashboard
Open your browser to: http://localhost:5000 (or your configured port)

🚀 Deployment Scripts Details
setup_chatids.sh
bash
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

echo "✅ Setup complete! Edit .env with your Gemini API key and run: python run_chatids.py "
configure_suricata.sh
bash
#!/bin/bash
echo "🔧 Auto-configuring Suricata for this system..."

# Find network interface
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
echo "Detected network interface: $INTERFACE"

# Find local network
NETWORK=$(ip addr show $INTERFACE | grep "inet " | awk '{print $2}' | cut -d'/' -f1 | sed 's/\.[0-9]*$/\.0\/24/')
echo "Detected network: $NETWORK"

# Backup original config and create optimized one
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.backup

# Create optimized config for detected network
sudo tee /etc/suricata/suricata.yaml > /dev/null << EOF
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[$NETWORK, 10.0.0.0/8, 172.16.0.0/12]"
    EXTERNAL_NET: "any"

af-packet:
  - interface: $INTERFACE
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

eve-log:
  enabled: yes
  filetype: regular
  filename: /var/log/suricata/eve.json
  types:
    - alert

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
EOF

echo "✅ Suricata configured for interface: $INTERFACE, network: $NETWORK"
🔧 Components
1. Watcher (watcher.py)
Monitors Suricata's eve.json log file

Processes new alerts in real-time

Sends alerts to Gemini AI for explanation

Stores alerts and explanations in SQLite database

Implements privacy protection through data anonymization

2. Web Dashboard (webapp.py)
Flask-based web interface

Displays alerts with AI explanations

Service control (start/stop Suricata and Watcher)

Filtering and search capabilities

Database management tools

3. Sample Data Generator (generate_sample_data.py)
Creates realistic test alerts

Useful for development and demonstration

Supports live simulation mode

🤖 AI Explanation System
ChatIDS uses a structured prompt to generate user-friendly explanations:

text
WHAT HAPPENED:
[Simple 1-2 sentence explanation]

WHY IT MATTERS:
[2-3 sentences about potential risks]

WHAT TO DO:
[3-5 actionable steps for home users]
Example Alert Transformation:

Technical Alert: ET SCAN Potential SSH Scan
AI Explanation: "Someone is checking your network for vulnerable devices. This could be a hacker looking for ways to break in. Change your WiFi password and make sure your devices are updated."

🗄️ Database Schema
sql
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    alert_signature TEXT,
    alert_category TEXT,
    severity INTEGER,
    src_ip TEXT,
    dest_ip TEXT,
    src_port INTEGER,
    dest_port INTEGER,
    protocol TEXT,
    raw_alert TEXT,
    explanation TEXT,
    explanation_cached BOOLEAN DEFAULT 0
);
🔒 Privacy & Security
IP Anonymization: Real IPs are replaced with private IP ranges

Device Obfuscation: Device identifiers are masked

Local Processing: Raw alerts stay on your system

Cached Explanations: Reduces API calls and costs

🚨 Common Alerts Explained
ChatIDS can explain various security events:

Port Scans: "Someone is checking your network for open doors"

Malware Communication: "A device might be talking to a dangerous server"

Brute Force Attacks: "Someone is trying to guess passwords"

Suspicious Protocols: "Unusual network activity detected"

🛠️ Development
Adding New Features
Alert processing logic: watcher.py

Web interface: webapp.py and templates/

Database schema: Update AlertManager class

Testing
bash
# Generate sample data
python generate_sample_data.py --count 20

# Test with sample data
python run_chatids.py --test-mode

# Live simulation
python generate_sample_data.py --live --duration 60
📊 API Endpoints
Web Dashboard
GET / - Main dashboard

GET /alert/<id> - Alert details

GET /api/alerts - JSON alerts API

GET /api/stats - Statistics

Service Control
GET /api/start_suricata - Start Suricata

GET /api/stop_suricata - Stop Suricata

GET /api/start_watcher - Start AI watcher

GET /api/stop_watcher - Stop AI watcher

Database Management
GET /api/db/stats - Database statistics

GET /api/db/cleanup - Remove old alerts

GET /api/db/export - Export as JSON

GET /api/db/optimize - Optimize database

🔍 Troubleshooting
Common Issues
Permission denied for Suricata logs

bash
sudo chmod 644 /var/log/suricata/eve.json
Gemini API errors

Verify API key in .env

Check billing status in Google AI Studio

Ensure google-generativeai package is installed

No alerts appearing

Verify Suricata is running: sudo systemctl status suricata

Check interface configuration in suricata.yaml

Generate test traffic: curl http://testmyids.com

Watcher not starting from web interface

Start manually: python watcher.py

Check process: ps aux | grep watcher.py

🌐 Deployment
Production Considerations
Use production WSGI server (Gunicorn, uWSGI)

Configure reverse proxy (Nginx, Apache)

Set up SSL/TLS certificates

Implement proper firewall rules

Regular database backups

Systemd Services
Create /etc/systemd/system/chatids-watcher.service:

ini
[Unit]
Description=ChatIDS AI Alert Watcher
After=network.target

[Service]
Type=simple
User=chatids
WorkingDirectory=/opt/chatids
ExecStart=/usr/bin/python3 watcher.py
Restart=always

[Install]
WantedBy=multi-user.target
📈 Monitoring & Maintenance
Regular Tasks
Monitor disk usage of database

Update Suricata rules regularly

Review AI explanation quality

Backup important data

Log Files
Application logs: Console output

Suricata logs: /var/log/suricata/

Database: alerts.db

🤝 Contributing
Fork the repository

Create a feature branch

Make your changes

Test thoroughly

Submit a pull request

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

🙏 Acknowledgments
Based on research: "ChatIDS: Advancing Explainable Cybersecurity Using Generative AI"

Suricata IDS for network monitoring

Google Gemini for AI explanations

Flask framework for web interface

🆘 Support
For issues and questions:

Check troubleshooting section above

Review Suricata documentation

Verify Gemini API configuration

Check system logs for errors