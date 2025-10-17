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
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')

class AlertManager:
    """Manages alert data from SQLite database"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
    
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
    
    return jsonify({'success': True, 'questions': questions})


def create_templates():
    """Create HTML templates if they don't exist"""
    templates_dir = "templates"
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)


    
    # Base template
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
    
    # Dashboard template
    dashboard_template = '''{% extends "base.html" %}

{% block content %}
<div class="row mb-4">
    <div class="col">
        <h1>Security Alert Dashboard</h1>
        <p class="text-muted">AI-powered explanations of network security alerts</p>
    </div>
</div>

<!-- Service Status -->
<div class="row mb-4">
    <div class="col">
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0"><i class="bi bi-activity"></i> Service Status</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-4">
                        <div class="d-flex align-items-center">
                            <span class="badge bg-{% if status.suricata %}success{% else %}danger{% endif %} me-2">
                                {% if status.suricata %}Running{% else %}Stopped{% endif %}
                            </span>
                            <strong>Suricata IDS</strong>
                        </div>
                        <div class="mt-2">
                            {% if status.suricata %}
                            <button class="btn btn-warning btn-sm" onclick="stopSuricata()">
                                <i class="bi bi-stop-circle"></i> Stop
                            </button>
                            {% else %}
                            <button class="btn btn-success btn-sm" onclick="startSuricata()">
                                <i class="bi bi-play-circle"></i> Start
                            </button>
                            {% endif %}
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="d-flex align-items-center">
                            <span class="badge bg-{% if status.watcher %}success{% else %}danger{% endif %} me-2">
                                {% if status.watcher %}Running{% else %}Stopped{% endif %}
                            </span>
                            <strong>ChatIDS Watcher</strong>
                        </div>
                        <div class="mt-2">
                            {% if status.watcher %}
                            <button class="btn btn-warning btn-sm" onclick="stopWatcher()">
                                <i class="bi bi-stop-circle"></i> Stop
                            </button>
                            {% else %}
                            <button class="btn btn-success btn-sm" onclick="startWatcher()">
                                <i class="bi bi-play-circle"></i> Start
                            </button>
                            {% endif %}
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="d-flex align-items-center">
                            <span class="badge bg-success me-2">Running</span>
                            <strong>Web Dashboard</strong>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Statistics Cards -->
<div class="row mb-4">
    <div class="col-md-3">
        <div class="card bg-primary text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ stats.total_alerts }}</h4>
                        <p>Total Alerts</p>
                    </div>
                    <i class="bi bi-exclamation-triangle fa-2x"></i>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-warning text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ stats.alerts_24h }}</h4>
                        <p>Last 24 Hours</p>
                    </div>
                    <i class="bi bi-clock fa-2x"></i>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-info text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ stats.severity_breakdown.get(1, 0) }}</h4>
                        <p>High Severity</p>
                    </div>
                    <i class="bi bi-exclamation-circle fa-2x"></i>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-success text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ stats.severity_breakdown.get(3, 0) }}</h4>
                        <p>Low Severity</p>
                    </div>
                    <i class="bi bi-info-circle fa-2x"></i>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Filters -->
<div class="row mb-3">
    <div class="col">
        <form method="GET" class="d-flex gap-3 align-items-end">
            <div>
                <label class="form-label">Severity Filter</label>
                <select name="severity" class="form-select">
                    <option value="">All Severities</option>
                    <option value="1" {% if current_severity == 1 %}selected{% endif %}>High (1)</option>
                    <option value="2" {% if current_severity == 2 %}selected{% endif %}>Medium (2)</option>
                    <option value="3" {% if current_severity == 3 %}selected{% endif %}>Low (3)</option>
                </select>
            </div>
            <div>
                <label class="form-label">Time Filter</label>
                <select name="hours" class="form-select">
                    <option value="">All Time</option>
                    <option value="1" {% if current_hours == 1 %}selected{% endif %}>Last Hour</option>
                    <option value="6" {% if current_hours == 6 %}selected{% endif %}>Last 6 Hours</option>
                    <option value="24" {% if current_hours == 24 %}selected{% endif %}>Last 24 Hours</option>
                    <option value="168" {% if current_hours == 168 %}selected{% endif %}>Last Week</option>
                </select>
            </div>
            <div>
                <button type="submit" class="btn btn-primary">Filter</button>
                <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary">Clear</a>
            </div>
        </form>
    </div>
</div>

<!-- Alerts List -->
<div class="row">
    <div class="col">
        <h3>Recent Alerts</h3>
        {% if alerts %}
            <div class="row">
                {% for alert in alerts %}
                <div class="col-12 mb-3">
                    <div class="card alert-card severity-{{ alert.severity }}">
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-8">
                                    <h5 class="card-title">
                                        <i class="bi bi-exclamation-triangle text-warning"></i>
                                        {{ alert.alert_signature }}
                                    </h5>
                                    <p class="text-muted mb-2">
                                        <small>
                                            <i class="bi bi-clock"></i> {{ alert.timestamp }}
                                            <span class="ms-3">
                                                <i class="bi bi-hdd-network"></i> 
                                                {{ alert.src_ip }}:{{ alert.src_port }} → {{ alert.dest_ip }}:{{ alert.dest_port }}
                                            </span>
                                            <span class="ms-3">
                                                <i class="bi bi-tag"></i> {{ alert.alert_category }}
                                            </span>
                                        </small>
                                    </p>
                                    {% if alert.explanation %}
                                    <div class="explanation-box">
                                        <strong>AI Explanation:</strong>
                                        <div class="mt-2">{{ alert.explanation[:200] }}{% if alert.explanation|length > 200 %}...{% endif %}</div>
                                    </div>
                                    {% else %}
                                    <div class="text-muted">
                                        <em>No explanation available</em>
                                    </div>
                                    {% endif %}
                                </div>
                                <div class="col-md-4 text-end">
                                    <span class="badge bg-{% if alert.severity == 1 %}danger{% elif alert.severity == 2 %}warning{% else %}secondary{% endif %} mb-2">
                                        Severity {{ alert.severity }}
                                    </span><br>
                                    <a href="{{ url_for('alert_detail', alert_id=alert.id) }}" class="btn btn-outline-primary btn-sm">
                                        <i class="bi bi-eye"></i> View Details
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
        {% else %}
            <div class="alert alert-info">
                <i class="bi bi-info-circle"></i>
                No alerts found matching your criteria.
            </div>
        {% endif %}
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
function startSuricata() {
    fetch('/api/start_suricata')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('Failed to start Suricata: ' + data.message);
            }
        });
}

function stopSuricata() {
    fetch('/api/stop_suricata')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('Failed to stop Suricata: ' + data.message);
            }
        });
}

function startWatcher() {
    fetch('/api/start_watcher')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('Failed to start watcher: ' + data.message);
            }
        });
}

function stopWatcher() {
    fetch('/api/stop_watcher')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('Failed to stop watcher: ' + data.message);
            }
        });
}
</script>
{% endblock %}'''
    
    # Alert detail template
    detail_template = '''{% extends "base.html" %}

{% block title %}Alert Details - ChatIDS{% endblock %}

{% block content %}
<div class="row mb-3">
    <div class="col">
        <nav aria-label="breadcrumb">
            <ol class="breadcrumb">
                <li class="breadcrumb-item"><a href="{{ url_for('dashboard') }}">Dashboard</a></li>
                <li class="breadcrumb-item active">Alert #{{ alert.id }}</li>
            </ol>
        </nav>
    </div>
</div>

<div class="row">
    <div class="col">
        <div class="card severity-{{ alert.severity }}">
            <div class="card-header">
                <div class="d-flex justify-content-between align-items-center">
                    <h3 class="mb-0">
                        <i class="bi bi-exclamation-triangle text-warning"></i>
                        {{ alert.alert_signature }}
                    </h3>
                    <span class="badge bg-{% if alert.severity == 1 %}danger{% elif alert.severity == 2 %}warning{% else %}secondary{% endif %}">
                        Severity {{ alert.severity }}
                    </span>
                </div>
            </div>
            <div class="card-body">
                <!-- Basic Info -->
                <div class="row mb-4">
                    <div class="col-md-6">
                        <h5>Alert Information</h5>
                        <table class="table table-sm">
                            <tr><td><strong>Timestamp:</strong></td><td>{{ alert.timestamp }}</td></tr>
                            <tr><td><strong>Category:</strong></td><td>{{ alert.alert_category }}</td></tr>
                            <tr><td><strong>Protocol:</strong></td><td>{{ alert.protocol }}</td></tr>
                            <tr><td><strong>Source:</strong></td><td>{{ alert.src_ip }}:{{ alert.src_port }}</td></tr>
                            <tr><td><strong>Destination:</strong></td><td>{{ alert.dest_ip }}:{{ alert.dest_port }}</td></tr>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <h5>Status</h5>
                        <div class="alert alert-info">
                            <i class="bi bi-robot"></i>
                            {% if alert.explanation_cached %}
                            This explanation was generated using AI and cached for efficiency.
                            {% else %}
                            This alert has not been processed through AI explanation yet.
                            {% endif %}
                        </div>
                    </div>
                </div>
                
                <!-- AI Explanation -->
                {% if alert.explanation %}
                <div class="row mb-4">
                    <div class="col">
                        <h5>AI-Generated Explanation</h5>
                        <div class="explanation-box">
                            <pre style="white-space: pre-wrap; font-family: inherit;">{{ alert.explanation }}</pre>
                        </div>
                    </div>
                </div>
                {% endif %}
                
                <!-- Raw Alert Data -->
                {% if alert.raw_alert_parsed %}
                <div class="row">
                    <div class="col">
                        <h5>Technical Details</h5>
                        <div class="accordion" id="technicalDetails">
                            <div class="accordion-item">
                                <h2 class="accordion-header" id="rawDataHeader">
                                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#rawDataCollapse">
                                        <i class="bi bi-code-slash me-2"></i> Raw Alert Data
                                    </button>
                                </h2>
                                <div id="rawDataCollapse" class="accordion-collapse collapse" data-bs-parent="#technicalDetails">
                                    <div class="accordion-body">
                                        <pre><code>{{ alert.raw_alert_parsed | tojsonpretty }}</code></pre>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endblock %}'''
    
    # Write templates to files
    with open(f"{templates_dir}/base.html", "w") as f:
        f.write(base_template)
    
    with open(f"{templates_dir}/dashboard.html", "w") as f:
        f.write(dashboard_template)
    
    with open(f"{templates_dir}/alert_detail.html", "w") as f:
        f.write(detail_template)

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
    
    # Create templates
    create_templates()
    
    # Add custom filter
    app.jinja_env.filters['tojsonpretty'] = tojsonpretty
    
    print(f"Starting ChatIDS web dashboard on http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop the server")
    
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == "__main__":
    main()