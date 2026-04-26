# dashboard.py
# Web dashboard showing all 3 attack types

from flask import Flask, render_template, jsonify
import sqlite3
import config
from datetime import datetime

app = Flask(__name__)


def get_db_stats():
    """Get all statistics from database"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    stats = {
        "total_file_logs": 0,
        "total_alerts": 0,
        "total_security_events": 0,
        "total_blocked": 0,
        "recent_file_logs": [],
        "recent_alerts": [],
        "recent_security_events": [],
        "blocked_entities": [],
        "system_status": "MONITORING"
    }

    try:
        cursor.execute('SELECT COUNT(*) FROM file_logs')
        stats["total_file_logs"] = cursor.fetchone()[0]

        cursor.execute(
            'SELECT * FROM file_logs ORDER BY id DESC LIMIT 15'
        )
        stats["recent_file_logs"] = cursor.fetchall()

    except Exception:
        pass

    try:
        cursor.execute('SELECT COUNT(*) FROM alerts')
        stats["total_alerts"] = cursor.fetchone()[0]

        cursor.execute(
            'SELECT * FROM alerts ORDER BY id DESC LIMIT 10'
        )
        stats["recent_alerts"] = cursor.fetchall()

        # Check if any active ransomware alerts
        cursor.execute('''
            SELECT COUNT(*) FROM alerts
            WHERE alert_type IN
            ("RANSOMWARE_DETECTED", "BRUTE_FORCE_DETECTED",
             "UNAUTHORIZED_ACCESS_DETECTED")
            AND status = "ACTIVE"
        ''')
        active_threats = cursor.fetchone()[0]
        if active_threats > 0:
            stats["system_status"] = "UNDER_ATTACK"

    except Exception:
        pass

    try:
        cursor.execute('SELECT COUNT(*) FROM security_events')
        stats["total_security_events"] = cursor.fetchone()[0]

        cursor.execute('''
            SELECT * FROM security_events
            ORDER BY id DESC LIMIT 15
        ''')
        stats["recent_security_events"] = cursor.fetchall()

    except Exception:
        pass

    try:
        cursor.execute('SELECT COUNT(*) FROM blocked_entities')
        stats["total_blocked"] = cursor.fetchone()[0]

        cursor.execute('''
            SELECT * FROM blocked_entities
            ORDER BY id DESC LIMIT 10
        ''')
        stats["blocked_entities"] = cursor.fetchall()

    except Exception:
        pass

    conn.close()
    return stats


@app.route('/')
def home():
    """Main dashboard"""
    stats = get_db_stats()
    return render_template('index.html', stats=stats)


@app.route('/api/status')
def api_status():
    """Live status API"""
    stats = get_db_stats()
    return jsonify({
        "status": stats["system_status"],
        "total_file_logs": stats["total_file_logs"],
        "total_alerts": stats["total_alerts"],
        "total_security_events": stats["total_security_events"],
        "total_blocked": stats["total_blocked"],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


@app.route('/api/logs')
def api_logs():
    """File logs API"""
    stats = get_db_stats()
    logs = []
    for log in stats["recent_file_logs"]:
        logs.append({
            "id": log[0],
            "timestamp": log[1],
            "event_type": log[2],
            "file_name": log[3],
            "details": log[4]
        })
    return jsonify(logs)


@app.route('/api/security')
def api_security():
    """Security events API"""
    stats = get_db_stats()
    events = []
    for event in stats["recent_security_events"]:
        events.append({
            "id": event[0],
            "timestamp": event[1],
            "event_type": event[2],
            "username": event[3],
            "ip_address": event[4],
            "action": event[5],
            "target": event[6],
            "status": event[7],
            "details": event[8]
        })
    return jsonify(events)


@app.route('/api/blocked')
def api_blocked():
    """Blocked entities API"""
    stats = get_db_stats()
    blocked = []
    for entity in stats["blocked_entities"]:
        blocked.append({
            "id": entity[0],
            "timestamp": entity[1],
            "entity_type": entity[2],
            "entity_value": entity[3],
            "reason": entity[4],
            "status": entity[5]
        })
    return jsonify(blocked)


if __name__ == '__main__':
    print("Dashboard starting at http://localhost:5000")
    app.run(debug=True, port=5000)