#!/usr/bin/env python3
"""
ChatIDS Watcher - Monitors Suricata eve.json logs and generates user-friendly explanations
"""

import json
import time
import os
import re
import hashlib
import sqlite3
from datetime import datetime
from typing import Dict, Any, Optional
import google.generativeai as genai
import logging
import argparse
from dotenv import load_dotenv  # Add this


# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AlertAnonymizer:
    """Anonymizes IP addresses and device identifiers in alerts"""
    
    def __init__(self):
        self.ip_mapping = {}
        self.device_mapping = {}
        
    def anonymize_ip(self, ip: str) -> str:
        """Replace IP with anonymized version"""
        if ip not in self.ip_mapping:
            # Create a consistent hash-based anonymization
            hash_obj = hashlib.md5(ip.encode())
            hash_hex = hash_obj.hexdigest()[:8]
            self.ip_mapping[ip] = f"192.168.{int(hash_hex[:2], 16) % 256}.{int(hash_hex[2:4], 16) % 256}"
        return self.ip_mapping[ip]
    
    def anonymize_device(self, device: str) -> str:
        """Replace device identifiers with anonymized versions"""
        if device not in self.device_mapping:
            hash_obj = hashlib.md5(device.encode())
            device_types = ["Smart-TV", "IoT-Device", "Smart-Light", "Security-Cam", "Router", "Phone"]
            device_idx = int(hash_obj.hexdigest()[:2], 16) % len(device_types)
            self.device_mapping[device] = f"{device_types[device_idx]}-{hash_obj.hexdigest()[:4]}"
        return self.device_mapping[device]
    
    def anonymize_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Anonymize sensitive information in alert"""
        anonymized = alert_data.copy()
        
        # Anonymize IP addresses
        if 'src_ip' in anonymized:
            anonymized['src_ip'] = self.anonymize_ip(anonymized['src_ip'])
        if 'dest_ip' in anonymized:
            anonymized['dest_ip'] = self.anonymize_ip(anonymized['dest_ip'])
        
        # Anonymize in nested structures
        if 'flow' in anonymized:
            if 'src_ip' in anonymized['flow']:
                anonymized['flow']['src_ip'] = self.anonymize_ip(anonymized['flow']['src_ip'])
            if 'dest_ip' in anonymized['flow']:
                anonymized['flow']['dest_ip'] = self.anonymize_ip(anonymized['flow']['dest_ip'])
        
        # Remove or anonymize MAC addresses
        if 'src_mac' in anonymized:
            anonymized['src_mac'] = "XX:XX:XX:XX:XX:XX"
        if 'dest_mac' in anonymized:
            anonymized['dest_mac'] = "XX:XX:XX:XX:XX:XX"
            
        return anonymized

class GeminiExplainer:
    """Handles communication with Gemini API to explain alerts"""
    
    def __init__(self, api_key: str):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-2.0-flash')
        self.prompt_template = """You are a cybersecurity expert explaining network alerts to non-technical home users.

Alert Details:
{alert_json}

Please explain this security alert in simple, non-technical language following this structure:

1. WHAT HAPPENED:
Explain what the alert detected in 1-2 sentences using everyday language. Avoid technical jargon.

2. WHY IT MATTERS:
Explain the potential risks or consequences if this is a real threat (2-3 sentences).

3. WHAT TO DO:
Provide 3-5 specific, actionable steps a home user can take. Use simple language and avoid technical terms like "SSH", "firewall rules", etc.

Keep the tone calm but informative. Don't use fear tactics. Focus on practical advice."""

    def explain_alert(self, alert_data: Dict[str, Any]) -> Optional[str]:
        """Send alert to Gemini and get explanation"""
        try:
            prompt = self.prompt_template.format(alert_json=json.dumps(alert_data, indent=2))
            
            response = self.model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    max_output_tokens=800,
                    temperature=0.3,
                )
            )
            
            return response.text.strip() if response.text else None
            
        except Exception as e:
            logger.error(f"Error getting explanation from Gemini: {e}")
            return None

class AlertDatabase:
    """SQLite database to store alerts and explanations"""
    
    def __init__(self, db_path: str = "alerts.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
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
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_signature ON alerts(alert_signature)
            """)
    
    def store_alert(self, alert_data: Dict[str, Any], explanation: str = None):
        """Store alert and explanation in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO alerts (
                    alert_signature, alert_category, severity,
                    src_ip, dest_ip, src_port, dest_port, protocol,
                    raw_alert, explanation, explanation_cached
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_data.get('alert', {}).get('signature', 'Unknown'),
                alert_data.get('alert', {}).get('category', 'Unknown'),
                alert_data.get('alert', {}).get('severity', 3),
                alert_data.get('src_ip', ''),
                alert_data.get('dest_ip', ''),
                alert_data.get('src_port', 0),
                alert_data.get('dest_port', 0),
                alert_data.get('proto', ''),
                json.dumps(alert_data),
                explanation,
                1 if explanation else 0
            ))
    
    def get_cached_explanation(self, signature: str) -> Optional[str]:
        """Check if we have a cached explanation for this alert signature"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT explanation FROM alerts WHERE alert_signature = ? AND explanation IS NOT NULL LIMIT 1",
                (signature,)
            )
            row = cursor.fetchone()
            return row[0] if row else None

class SuricataWatcher:
    """Main class that watches Suricata logs and processes alerts"""
    
    def __init__(self, log_file: str, gemini_api_key: str, db_path: str = "alerts.db"):
        self.log_file = log_file
        self.anonymizer = AlertAnonymizer()
        self.explainer = GeminiExplainer(gemini_api_key)
        self.database = AlertDatabase(db_path)
        self.processed_lines = 0
        
    def tail_file(self):
        """Tail the log file and yield new lines"""
        try:
            with open(self.log_file, 'r') as f:
                # Go to end of file
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    yield line.strip()
        except FileNotFoundError:
            logger.error(f"Log file not found: {self.log_file}")
            raise
        except PermissionError:
            logger.error(f"Permission denied reading log file: {self.log_file}")
            raise
    
    def process_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Process a single log line and extract alert if present"""
        try:
            data = json.loads(line)
            
            # Only process alert events
            if data.get('event_type') == 'alert':
                return data
                
        except json.JSONDecodeError:
            logger.debug(f"Skipping invalid JSON line")
        except Exception as e:
            logger.error(f"Error processing line: {e}")
        
        return None
    
    def run(self):
        """Main execution loop"""
        logger.info(f"Starting ChatIDS watcher on {self.log_file}")
        
        try:
            for line in self.tail_file():
                alert_data = self.process_log_line(line)
                if not alert_data:
                    continue
                
                self.processed_lines += 1
                signature = alert_data.get('alert', {}).get('signature', 'Unknown')
                
                logger.info(f"Processing alert: {signature}")
                
                # Anonymize the alert
                anonymized_alert = self.anonymizer.anonymize_alert(alert_data)
                
                # Check for cached explanation
                cached_explanation = self.database.get_cached_explanation(signature)
                
                if cached_explanation:
                    logger.info("Using cached explanation")
                    explanation = cached_explanation
                else:
                    # Get explanation from Gemini
                    logger.info("Getting new explanation from Gemini")
                    explanation = self.explainer.explain_alert(anonymized_alert)
                
                # Store in database
                self.database.store_alert(anonymized_alert, explanation)
                
                logger.info(f"Processed {self.processed_lines} alerts")
                
        except KeyboardInterrupt:
            logger.info("Shutting down watcher...")
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            raise

def main():
        parser = argparse.ArgumentParser(description='ChatIDS Alert Watcher')
        parser.add_argument('--log-file', default=os.getenv('LOG_FILE', '/var/log/suricata/eve.json'),help='Path to Suricata eve.json log file')
        parser.add_argument('--gemini-key', default=os.getenv('GEMINI_API_KEY'),help='Gemini API key (or set GEMINI_API_KEY environment variable)')
        parser.add_argument('--db-path', default=os.getenv('DATABASE_PATH', 'alerts.db'),help='SQLite database path')
        parser.add_argument('--test-mode', action='store_true',help='Use sample data for testing')
        
        args = parser.parse_args()

        # Check if API key is provided
        if not args.gemini_key:
            logger.error("Gemini API key is required. Set GEMINI_API_KEY environment variable or use --gemini-key")
            return
        
        if args.test_mode:
            # Create sample alert for testing
            sample_alert = {
                "timestamp": datetime.now().isoformat(),
                "event_type": "alert",
                "src_ip": "192.168.1.100",
                "dest_ip": "10.0.0.1",
                "src_port": 12345,
                "dest_port": 22,
                "proto": "TCP",
                "alert": {
                    "signature": "SURICATA SSH too long banner",
                    "category": "Potentially Bad Traffic",
                    "severity": 2
                }
            }
            
            watcher = SuricataWatcher("dummy", args.gemini_key, args.db_path)
            anonymized = watcher.anonymizer.anonymize_alert(sample_alert)
            explanation = watcher.explainer.explain_alert(anonymized)
            watcher.database.store_alert(anonymized, explanation)
            
            print("Sample alert processed and stored!")
            return
        
        if not os.path.exists(args.log_file):
            logger.error(f"Log file does not exist: {args.log_file}")
            return
        
        watcher = SuricataWatcher(args.log_file, args.gemini_key, args.db_path)
        watcher.run()

if __name__ == "__main__":
    main()
