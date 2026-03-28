#!/usr/bin/env python3
"""
ChatIDS Web Application - Flask dashboard for displaying explained security alerts
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for
import sqlite3
import json
from datetime import datetime, timedelta
import os
import argparse
import subprocess
import sys
import psutil
import logging
from dotenv import load_dotenv
import google.generativeai as genai

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AlertManager:
    """Manages alert data from SQLite database"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
    
    def is_valid(self) -> bool:
        """Validate the SQLite database integrity."""
        if not os.path.exists(self.db_path):
            return False
        try:
            with sqlite3.connect(self.db_path) as conn:
                integrity = conn.execute("PRAGMA integrity_check").fetchone()
                return integrity is not None and integrity[0] == 'ok'
        except sqlite3.DatabaseError as exc:
            logger.error(f"Database integrity check failed: {exc}")
            return False
        except Exception as exc:
            logger.error(f"Unexpected error validating database: {exc}")
            return False
    
    def get_alerts(self, limit: int = 50, severity: int = None, hours: int = None):
        """Get alerts from database with optional filtering"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row  # This enables column access by name
            
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []
            
            if severity is not None:
                query += " AND severity = ?"
                params.append(severity)
            
            if hours is not None:
                cutoff_time = datetime.now() - timedelta(hours=hours)
                query += " AND timestamp > ?"
                params.append(cutoff_time.isoformat())
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_alert_stats(self):
        """Get summary statistics about alerts"""
        with sqlite3.connect(self.db_path) as conn:
            stats = {}
            
            # Total alerts
            cursor = conn.execute("SELECT COUNT(*) as total FROM alerts")
            stats['total_alerts'] = cursor.fetchone()[0]
            
            # Alerts in last 24 hours
            cutoff_24h = datetime.now() - timedelta(hours=24)
            cursor = conn.execute("SELECT COUNT(*) as count FROM alerts WHERE timestamp > ?", (cutoff_24h.isoformat(),))
            stats['alerts_24h'] = cursor.fetchone()[0]
            
            # Severity breakdown
            cursor = conn.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
            severity_counts = {row[0]: row[1] for row in cursor.fetchall()}
            stats['severity_breakdown'] = severity_counts
            
            # Top alert types
            cursor = conn.execute("""
                SELECT alert_signature, COUNT(*) as count 
                FROM alerts 
                GROUP BY alert_signature 
                ORDER BY count DESC 
                LIMIT 10
            """)
            stats['top_alerts'] = [{'signature': row[0], 'count': row[1]} for row in cursor.fetchall()]
            
            return stats
        
    def get_detailed_stats(self):
        """Get detailed database statistics"""
        with sqlite3.connect(self.db_path) as conn:
            stats = {}
            
            # Basic counts
            cursor = conn.execute("SELECT COUNT(*) as total FROM alerts")
            stats['total_alerts'] = cursor.fetchone()[0]
            
            # Severity breakdown
            cursor = conn.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
            stats['severity_breakdown'] = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Explanation stats
            cursor = conn.execute("SELECT COUNT(*) as explained FROM alerts WHERE explanation IS NOT NULL")
            stats['explained_alerts'] = cursor.fetchone()[0]
            
            # Time range
            cursor = conn.execute("SELECT MIN(timestamp), MAX(timestamp) FROM alerts")
            min_max = cursor.fetchone()
            stats['oldest_alert'] = min_max[0]
            stats['newest_alert'] = min_max[1]
            
            # Unique signatures
            cursor = conn.execute("SELECT COUNT(DISTINCT alert_signature) FROM alerts")
            stats['unique_signatures'] = cursor.fetchone()[0]
            
            return stats
    
    def get_alert_details(self, alert_id: int):
        """Get detailed information about a specific alert"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
            alert = cursor.fetchone()
            
            if alert:
                alert_dict = dict(alert)
                # Parse raw_alert JSON if it exists
                if alert_dict['raw_alert']:
                    try:
                        alert_dict['raw_alert_parsed'] = json.loads(alert_dict['raw_alert'])
                    except json.JSONDecodeError:
                        alert_dict['raw_alert_parsed'] = None
                return alert_dict
            return None

def is_process_running(process_name):
    """Check if a process is running"""
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if process_name in ' '.join(proc.info['cmdline'] or []):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return False

def get_process_status():
    """Get status of all ChatIDS components"""
    return {
        'suricata': is_process_running('suricata'),
        'watcher': is_process_running('watcher.py'),
        'webapp': True  # We're running this!
    }

@app.route('/api/status')
def api_status():
    """Get status of all services"""
    status = get_process_status()
    return jsonify(status)

@app.route('/api/start_suricata')
def api_start_suricata():
    """Start Suricata service"""
    try:
        # Start Suricata
        cmd = ['sudo', 'suricata', '-c', '/etc/suricata/suricata.yaml', '-i', 'eth0']
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Wait a moment for it to start
        import time
        time.sleep(2)
        
        status = get_process_status()
        return jsonify({
            'success': True,
            'message': 'Suricata started successfully',
            'status': status
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Failed to start Suricata: {str(e)}'
        }), 500

@app.route('/api/stop_suricata')
def api_stop_suricata():
    """Stop Suricata service"""
    try:
        # Stop Suricata processes
        subprocess.run(['sudo', 'pkill', '-f', 'suricata'], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        status = get_process_status()
        return jsonify({
            'success': True,
            'message': 'Suricata stopped successfully',
            'status': status
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Failed to stop Suricata: {str(e)}'
        }), 500

@app.route('/api/start_watcher')
def api_start_watcher():
    """Start ChatIDS watcher"""
    try:
        # Get project directory
        project_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Start watcher
        cmd = [sys.executable, os.path.join(project_dir, 'watcher.py')]
        subprocess.Popen(cmd, cwd=project_dir, 
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        status = get_process_status()
        return jsonify({
            'success': True,
            'message': 'Watcher started successfully',
            'status': status
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Failed to start watcher: {str(e)}'
        }), 500

@app.route('/api/stop_watcher')
def api_stop_watcher():
    """Stop ChatIDS watcher"""
    try:
        # Stop watcher processes
        subprocess.run(['pkill', '-f', 'watcher.py'], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        status = get_process_status()
        return jsonify({
            'success': True,
            'message': 'Watcher stopped successfully',
            'status': status
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Failed to stop watcher: {str(e)}'
        }), 500

@app.route('/')
def dashboard():
    """Main dashboard showing recent alerts"""
    if not alert_manager:
        return "Database not initialized", 500
    
    # Get filters from request
    severity_filter = request.args.get('severity', type=int)
    hours_filter = request.args.get('hours', type=int)
    
    alerts = alert_manager.get_alerts(limit=50, severity=severity_filter, hours=hours_filter)
    stats = alert_manager.get_alert_stats()
    status = get_process_status()
    
    return render_template('dashboard.html', alerts=alerts, stats=stats, 
                         current_severity=severity_filter, current_hours=hours_filter,
                         status=status)

@app.route('/alert/<int:alert_id>')
def alert_detail(alert_id):
    """Detailed view of a specific alert"""
    if not alert_manager:
        return "Database not initialized", 500
    
    alert = alert_manager.get_alert_details(alert_id)
    if not alert:
        return "Alert not found", 404
    
    return render_template('alert_detail.html', alert=alert)

@app.route('/api/alerts')
def api_alerts():
    """JSON API endpoint for alerts"""
    if not alert_manager:
        return jsonify({'error': 'Database not initialized'}), 500
    
    severity = request.args.get('severity', type=int)
    hours = request.args.get('hours', type=int)
    limit = request.args.get('limit', type=int, default=50)
    
    alerts = alert_manager.get_alerts(limit=limit, severity=severity, hours=hours)
    return jsonify(alerts)

@app.route('/api/stats')
def api_stats():
    """JSON API endpoint for statistics"""
    if not alert_manager:
        return jsonify({'error': 'Database not initialized'}), 500
    
    stats = alert_manager.get_alert_stats()
    return jsonify(stats)

@app.route('/api/db/stats')
def api_db_stats():
    """Get database statistics"""
    try:
        with sqlite3.connect(alert_manager.db_path) as conn:
            # Get table info
            cursor = conn.execute("""
                SELECT 
                    COUNT(*) as total_alerts,
                    COUNT(DISTINCT alert_signature) as unique_signatures,
                    COUNT(CASE WHEN explanation IS NOT NULL THEN 1 END) as explained_alerts,
                    COUNT(CASE WHEN explanation_cached = 1 THEN 1 END) as cached_explanations,
                    MAX(timestamp) as latest_alert,
                    MIN(timestamp) as oldest_alert
                FROM alerts
            """)
            db_stats = dict(zip([col[0] for col in cursor.description], cursor.fetchone()))
            
            # Get database file size
            if os.path.exists(alert_manager.db_path):
                db_stats['file_size_mb'] = round(os.path.getsize(alert_manager.db_path) / (1024 * 1024), 2)
            else:
                db_stats['file_size_mb'] = 0
            
            return jsonify({'success': True, 'stats': db_stats})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/db/cleanup')
def api_db_cleanup():
    """Clean up old alerts"""
    try:
        days_to_keep = request.args.get('days', 30, type=int)
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        
        with sqlite3.connect(alert_manager.db_path) as conn:
            cursor = conn.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff_date.isoformat(),))
            deleted_count = cursor.rowcount
            conn.commit()
            
        return jsonify({
            'success': True, 
            'message': f'Deleted {deleted_count} alerts older than {days_to_keep} days',
            'deleted_count': deleted_count
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/db/export')
def api_db_export():
    """Export database as JSON"""
    try:
        with sqlite3.connect(alert_manager.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
            alerts = [dict(row) for row in cursor.fetchall()]
            
            export_data = {
                'export_time': datetime.now().isoformat(),
                'total_alerts': len(alerts),
                'alerts': alerts
            }
            
            return jsonify({'success': True, 'data': export_data})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/db/clear_all')
def api_db_clear_all():
    """Clear all alerts from database (DANGEROUS - use with caution)"""
    try:
        confirm = request.args.get('confirm', 'false')
        
        if confirm != 'true':
            return jsonify({
                'success': False, 
                'message': 'Safety check failed. Pass confirm=true to clear database.'
            }), 400
        
        with sqlite3.connect(alert_manager.db_path) as conn:
            cursor = conn.execute("DELETE FROM alerts")
            deleted_count = cursor.rowcount
            conn.execute("VACUUM")  # Reclaim disk space
            conn.commit()
            
        return jsonify({
            'success': True, 
            'message': f'Cleared all {deleted_count} alerts from database',
            'deleted_count': deleted_count
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/db/optimize')
def api_db_optimize():
    """Optimize database performance"""
    try:
        with sqlite3.connect(alert_manager.db_path) as conn:
            # Run VACUUM to optimize database
            conn.execute("VACUUM")
            conn.commit()
            
            # Get new file size
            new_size = round(os.path.getsize(alert_manager.db_path) / (1024 * 1024), 2)
            
        return jsonify({
            'success': True, 
            'message': 'Database optimized successfully',
            'new_size_mb': new_size
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/chat/ask', methods=['POST'])
def api_chat_ask():
    """Handle chat questions about alerts"""
    try:
        data = request.get_json()
        alert_id = data.get('alert_id')
        user_message = data.get('message')
        chat_history = data.get('history', [])
        
        if not alert_id or not user_message:
            return jsonify({'success': False, 'error': 'Missing alert_id or message'}), 400
        
        # Get alert details
        alert = alert_manager.get_alert_details(alert_id)
        if not alert:
            return jsonify({'success': False, 'error': 'Alert not found'}), 404
        
        # Configure Gemini
        genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
        model = genai.GenerativeModel('gemini-2.0-flash')
        
        # Build context from alert and chat history
        context = build_chat_context(alert, chat_history, user_message)
        
        # Get response from Gemini
        response = model.generate_content(
            context,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=1000,
                temperature=0.3,
            )
        )
        
        return jsonify({
            'success': True,
            'response': response.text.strip() if response.text else "I couldn't generate a response. Please try again."
        })
        
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

def build_chat_context(alert, chat_history, current_question):
    """Build the context for the chat conversation"""
    
    # Base alert information
    alert_context = f"""
ALERT INFORMATION:
- ID: {alert['id']}
- Signature: {alert['alert_signature']}
- Category: {alert['alert_category']}
- Severity: {alert['severity']}
- Timestamp: {alert['timestamp']}
- Source: {alert['src_ip']}:{alert['src_port']}
- Destination: {alert['dest_ip']}:{alert['dest_port']}
- Protocol: {alert['protocol']}
- Original Explanation: {alert.get('explanation', 'No explanation available')}
"""
    
    # Build conversation history
    conversation_history = ""
    for msg in chat_history[-6:]:  # Last 6 messages for context
        role = "USER" if msg['role'] == 'user' else "ASSISTANT"
        conversation_history += f"{role}: {msg['content']}\n"
    
    prompt = f"""
You are a helpful cybersecurity assistant explaining security alerts to non-technical home users.

CONTEXT:
{alert_context}

CONVERSATION HISTORY:
{conversation_history}

CURRENT QUESTION:
USER: {current_question}

INSTRUCTIONS:
1. Answer the user's question specifically about this security alert
2. Use simple, non-technical language that a home user would understand
3. Be helpful, calm, and reassuring - don't cause unnecessary panic
4. If the user asks about technical details, explain them in simple terms
5. Focus on practical advice and next steps
6. Keep your response concise but thorough
7. If you're not sure about something, say so and suggest where they can find more information

Please provide a helpful response to the user's question:
"""
    
    return prompt

@app.route('/api/chat/suggested_questions')
def api_suggested_questions():
    """Get suggested questions for an alert"""
    alert_id = request.args.get('alert_id', type=int)
    
    if not alert_id:
        return jsonify({'success': False, 'error': 'Missing alert_id'}), 400
    
    alert = alert_manager.get_alert_details(alert_id)
    if not alert:
        return jsonify({'success': False, 'error': 'Alert not found'}), 404
    
    # Generate context-aware suggested questions
    questions = [
        "What does this alert mean in simple terms?",
        "How serious is this?",
        "What should I do right now?",
        "Could this be a false alarm?",
        "How can I prevent this in the future?",
        "Does this affect my specific devices?",
        "Should I be worried about my personal data?"
    ]
    
    # Add severity-specific questions
    if alert['severity'] == 1:
        questions.insert(0, "Is this an emergency?")
        questions.insert(1, "What's the immediate danger?")
    
    # Add signature-specific questions
    signature_lower = alert['alert_signature'].lower()
    if 'botnet' in signature_lower:
        questions.extend([
            "What is a botnet and why is it dangerous?",
            "How do I know if my device is part of a botnet?"
        ])
    elif 'ssh' in signature_lower or 'login' in signature_lower:
        questions.extend([
            "Should I change my passwords?",
            "How to secure my remote access?"
        ])
    elif 'malware' in signature_lower:
        questions.extend([
            "How to scan for malware?",
            "What antivirus should I use?"
        ])
    
    return jsonify({'success': True, 'questions': questions})

@app.route('/api/chat/regenerate_explanation', methods=['POST'])
def api_regenerate_explanation():
    """Regenerate AI explanation for an alert"""
    try:
        data = request.get_json()
        alert_id = data.get('alert_id')
        
        if not alert_id:
            return jsonify({'success': False, 'error': 'Missing alert_id'}), 400
        
        # Get alert details
        alert = alert_manager.get_alert_details(alert_id)
        if not alert:
            return jsonify({'success': False, 'error': 'Alert not found'}), 404
        
        # Configure Gemini
        genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
        model = genai.GenerativeModel('gemini-2.0-flash')
        
        # Create enhanced prompt for regeneration
        prompt = f"""
You are a cybersecurity expert explaining a network security alert to a non-technical home user.

ALERT DETAILS:
- Signature: {alert['alert_signature']}
- Category: {alert['alert_category']}
- Severity: {alert['severity']}
- Source: {alert['src_ip']}:{alert['src_port']}
- Destination: {alert['dest_ip']}:{alert['dest_port']}
- Protocol: {alert['protocol']}
- Timestamp: {alert['timestamp']}

Please provide a fresh, clear explanation with this structure:

🚨 **What Happened**: Briefly explain what was detected

⚠️ **Why It Matters**: Explain the potential impact

🔧 **What To Do**: Provide 3-5 specific, actionable steps

🎯 **Key Takeaway**: One sentence summary

Use simple, everyday language. Avoid technical jargon. Be reassuring but honest about risks.
"""
        
        # Get new explanation from Gemini
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=800,
                temperature=0.4,  # Slightly higher temperature for variety
            )
        )
        
        new_explanation = response.text.strip() if response.text else None
        
        if new_explanation:
            # Update the alert in database
            with sqlite3.connect(alert_manager.db_path) as conn:
                conn.execute(
                    "UPDATE alerts SET explanation = ? WHERE id = ?",
                    (new_explanation, alert_id)
                )
            
            return jsonify({
                'success': True,
                'new_explanation': new_explanation
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to generate new explanation'}), 500
        
    except Exception as e:
        logger.error(f"Explanation regeneration error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

def save_chat_message(alert_id: int, role: str, content: str):
    """Save chat message to database"""
    with sqlite3.connect(alert_manager.db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER,
                role TEXT,
                content TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (alert_id) REFERENCES alerts (id)
            )
        """)
        
        conn.execute(
            "INSERT INTO chat_messages (alert_id, role, content) VALUES (?, ?, ?)",
            (alert_id, role, content)
        )

def get_chat_history(alert_id: int, limit: int = 20):
    """Get chat history for an alert"""
    with sqlite3.connect(alert_manager.db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT role, content, timestamp FROM chat_messages WHERE alert_id = ? ORDER BY timestamp ASC LIMIT ?",
            (alert_id, limit)
        )
        return [dict(row) for row in cursor.fetchall()]

def create_templates():
    """Create HTML templates if they don't exist"""
    templates_dir = "templates"
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)
    
    # Base template (simplified - you already have the full version)
    base_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}ChatIDS Dashboard{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css">
    <style>
        .severity-1 { border-left: 4px solid #dc3545; }
        .severity-2 { border-left: 4px solid #fd7e14; }
        .severity-3 { border-left: 4px solid #ffc107; }
        .alert-card { transition: transform 0.2s; }
        .alert-card:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        .explanation-box { background-color: #f8f9fa; border-radius: 8px; padding: 1rem; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('dashboard') }}">
                <i class="bi bi-shield-check"></i> ChatIDS
            </a>
            <div class="navbar-nav">
                <a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a>
            </div>
        </div>
    </nav>
    
    <div class="container mt-4">
        {% block content %}{% endblock %}
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>'''
    
    # Write base template only if it doesn't exist
    base_template_path = os.path.join(templates_dir, "base.html")
    if not os.path.exists(base_template_path):
        with open(base_template_path, "w") as f:
            f.write(base_template)
        print(f"Created {base_template_path}")

def tojsonpretty(value):
    """Custom Jinja2 filter for pretty JSON formatting"""
    return json.dumps(value, indent=2, default=str)

# Initialize alert manager (will be set in main())
alert_manager = None

def main():
    global alert_manager
    
    parser = argparse.ArgumentParser(description='ChatIDS Web Dashboard')
    parser.add_argument('--db-path', default=os.getenv('DATABASE_PATH', 'alerts.db'),
                        help='SQLite database path')
    parser.add_argument('--host', default=os.getenv('FLASK_HOST', '127.0.0.1'),
                        help='Host to bind to')
    parser.add_argument('--port', type=int, default=int(os.getenv('FLASK_PORT', 5000)),
                        help='Port to listen on')
    parser.add_argument('--debug', action='store_true', default=os.getenv('DEBUG_MODE', 'False').lower() == 'true',
                        help='Run in debug mode')
    
    args = parser.parse_args()
    
    # Check if database exists
    if not os.path.exists(args.db_path):
        print(f"Warning: Database file {args.db_path} does not exist.")
        print("Run the watcher.py script first to create the database and populate it with alerts.")
    
    # Initialize alert manager
    alert_manager = AlertManager(args.db_path)
    if args.db_path and not alert_manager.is_valid():
        logger.warning(f"Database file '{args.db_path}' is missing or corrupted. The dashboard will start, but data access will be disabled until the watcher recreates the database.")
        alert_manager = None
    
    # Create templates if they don't exist
    create_templates()
    
    # Add custom filter
    app.jinja_env.filters['tojsonpretty'] = tojsonpretty
    
    print(f"Starting ChatIDS web dashboard on http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop the server")
    
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == "__main__":
    main()