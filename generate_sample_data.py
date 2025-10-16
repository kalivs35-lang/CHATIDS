#!/usr/bin/env python3
"""
Generate sample Suricata alerts for testing ChatIDS
This script creates realistic-looking alert data for demonstration purposes
"""

import json
import time
import random
from datetime import datetime, timedelta

# Sample alert signatures from the research paper
SAMPLE_SIGNATURES = [
    "MALWARE-CNC Harakit botnet traffic",
    "SERVER-WEBAPP NetGear router default password login attempt admin/password",
    "PROTOCOL-ICMP TFN Probe",
    "PROTOCOL-FTP Bad login",
    "SERVER-OTHER SSH server banner overflow",
    "SURICATA MQTT unassigned message type (0 or >15)",
    "SURICATA HTTP Response abnormal chunked for transfer-encoding",
    "SURICATA SSH too long banner",
    "SURICATA FTP Request command too long",
    "SURICATA HTTP invalid content length field in request",
    "Mirai Botnet TR-069 Worm - Generic Architecture",
    "Linux.IotReaper",
    "BleedingLife2 Exploit Kit Detection",
    "Weevely Webshell - Generic Rule - heavily scrambled tiny web shell",
    "Mirage Identifying Strings"
]

SAMPLE_CATEGORIES = [
    "Potentially Bad Traffic",
    "Malware Command and Control Activity Detected",
    "Web Application Attack",
    "Protocol Command Decode",
    "A Network Trojan was detected",
    "Attempted Information Leak",
    "Unknown Traffic"
]

SAMPLE_IPS = [
    "192.168.1.100", "192.168.1.101", "192.168.1.102", "192.168.1.103",
    "10.0.0.1", "10.0.0.2", "172.16.1.100", "172.16.1.101",
    "203.0.113.1", "198.51.100.1", "203.0.113.100"
]

SAMPLE_PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS"]

def generate_sample_alert():
    """Generate a single sample alert in Suricata eve.json format"""
    now = datetime.now()
    # Generate alerts from the last 24 hours
    alert_time = now - timedelta(seconds=random.randint(0, 86400))
    
    # Select random components
    signature = random.choice(SAMPLE_SIGNATURES)
    category = random.choice(SAMPLE_CATEGORIES)
    protocol = random.choice(SAMPLE_PROTOCOLS)
    
    # Generate network details
    src_ip = random.choice(SAMPLE_IPS)
    dest_ip = random.choice(SAMPLE_IPS)
    while dest_ip == src_ip:
        dest_ip = random.choice(SAMPLE_IPS)
    
    src_port = random.randint(1024, 65535)
    dest_port = random.choice([22, 23, 80, 443, 8080, 3389, 21, 25])
    
    # Generate severity (1=high, 2=medium, 3=low)
    severity = random.choices([1, 2, 3], weights=[20, 30, 50])[0]
    
    # Create alert structure
    alert = {
        "timestamp": alert_time.isoformat() + "Z",
        "flow_id": random.randint(100000, 999999),
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": protocol,
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": random.randint(1000000, 9999999),
            "rev": 1,
            "signature": signature,
            "category": category,
            "severity": severity
        },
        "flow": {
            "pkts_toserver": random.randint(1, 10),
            "pkts_toclient": random.randint(1, 10),
            "bytes_toserver": random.randint(100, 5000),
            "bytes_toclient": random.randint(100, 5000),
            "start": alert_time.isoformat() + "Z"
        }
    }
    
    return alert

def generate_sample_eve_file(filename, num_alerts=50):
    """Generate a sample eve.json file with multiple alerts"""
    with open(filename, 'w') as f:
        for _ in range(num_alerts):
            alert = generate_sample_alert()
            f.write(json.dumps(alert) + '\n')
            
            # Add some non-alert events to make it realistic
            if random.random() < 0.3:  # 30% chance of non-alert event
                non_alert = {
                    "timestamp": datetime.now().isoformat() + "Z",
                    "event_type": random.choice(["flow", "stats", "drop"]),
                    "src_ip": random.choice(SAMPLE_IPS),
                    "dest_ip": random.choice(SAMPLE_IPS)
                }
                f.write(json.dumps(non_alert) + '\n')
    
    print(f"Generated {num_alerts} sample alerts in {filename}")

def create_live_simulation_file(filename, duration_minutes=60):
    """Create a file that simulates live alerts being generated"""
    print(f"Simulating live alerts for {duration_minutes} minutes...")
    print(f"Writing to {filename}")
    print("Press Ctrl+C to stop early")
    
    try:
        with open(filename, 'a') as f:  # Append mode
            start_time = time.time()
            end_time = start_time + (duration_minutes * 60)
            
            while time.time() < end_time:
                # Generate an alert every 30-120 seconds
                delay = random.randint(30, 120)
                time.sleep(delay)
                
                alert = generate_sample_alert()
                f.write(json.dumps(alert) + '\n')
                f.flush()  # Force write to disk
                
                print(f"Generated alert: {alert['alert']['signature']}")
                
    except KeyboardInterrupt:
        print("\nSimulation stopped by user")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate sample Suricata alerts for ChatIDS testing')
    parser.add_argument('--output', '-o', default='sample_eve.json',
                        help='Output filename (default: sample_eve.json)')
    parser.add_argument('--count', '-c', type=int, default=50,
                        help='Number of alerts to generate (default: 50)')
    parser.add_argument('--live', action='store_true',
                        help='Generate alerts continuously for testing')
    parser.add_argument('--duration', type=int, default=60,
                        help='Duration for live simulation in minutes (default: 60)')
    
    args = parser.parse_args()
    
    if args.live:
        create_live_simulation_file(args.output, args.duration)
    else:
        generate_sample_eve_file(args.output, args.count)

if __name__ == "__main__":
    main()
