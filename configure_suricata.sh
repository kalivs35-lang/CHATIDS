#!/bin/bash
echo "🔧 Auto-configuring Suricata for this system..."

# Find network interface
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
echo "Detected network interface: $INTERFACE"

# Find local network
NETWORK=$(ip addr show $INTERFACE | grep "inet " | awk '{print $2}' | cut -d'/' -f1 | sed 's/\.[0-9]*$/\.0\/24/')
echo "Detected network: $NETWORK"

# Backup original config
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.backup

# Create optimized config
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
