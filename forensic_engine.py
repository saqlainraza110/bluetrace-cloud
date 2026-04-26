# forensic_engine.py
# Investigates ALL attacks - Ransomware + Brute Force + Unauthorized

import sqlite3
import config
from datetime import datetime
from security_logger import (
    get_all_security_events,
    get_all_blocked_entities
)


def get_all_file_logs():
    """Get all file monitoring logs"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    try:
        cursor.execute(
            'SELECT * FROM file_logs ORDER BY timestamp'
        )
        logs = cursor.fetchall()
    except Exception:
        logs = []

    conn.close()
    return logs


def get_all_alerts():
    """Get all alerts from database"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    try:
        cursor.execute(
            'SELECT * FROM alerts ORDER BY timestamp'
        )
        alerts = cursor.fetchall()
    except Exception:
        alerts = []

    conn.close()
    return alerts


def analyze_brute_force_data(security_events):
    """Analyze brute force attack details"""

    brute_events = [
        e for e in security_events
        if e[2] in ["LOGIN_FAILED", "BRUTE_FORCE_DETECTED"]
    ]

    if not brute_events:
        return None

    # Find attacker IPs
    attacker_ips = list(set([e[4] for e in brute_events]))

    # Count attempts per IP
    ip_attempts = {}
    for event in brute_events:
        ip = event[4]
        ip_attempts[ip] = ip_attempts.get(ip, 0) + 1

    # Find target usernames
    usernames_targeted = list(set([e[3] for e in brute_events]))

    # Find time of first and last attempt
    times = [e[1] for e in brute_events]
    first_attempt = min(times) if times else "Unknown"
    last_attempt = max(times) if times else "Unknown"

    return {
        "attack_type": "BRUTE_FORCE",
        "attacker_ips": attacker_ips,
        "ip_attempts": ip_attempts,
        "usernames_targeted": usernames_targeted,
        "total_attempts": len(brute_events),
        "first_attempt": first_attempt,
        "last_attempt": last_attempt
    }


def analyze_unauthorized_data(security_events):
    """Analyze unauthorized access attack details"""

    unauth_events = [
        e for e in security_events
        if e[2] in [
            "INVALID_ACCESS_KEY",
            "UNAUTHORIZED_ACCESS",
            "ACCESS_DENIED",
            "FORBIDDEN_BUCKET",
            "UNAUTHORIZED_ACCESS_DETECTED"
        ]
    ]

    if not unauth_events:
        return None

    # Find attacker IPs
    attacker_ips = list(set([e[4] for e in unauth_events]))

    # Find targets
    targets_accessed = list(set([e[6] for e in unauth_events]))

    # Count attempts per IP
    ip_attempts = {}
    for event in unauth_events:
        ip = event[4]
        ip_attempts[ip] = ip_attempts.get(ip, 0) + 1

    # Find time range
    times = [e[1] for e in unauth_events]
    first_attempt = min(times) if times else "Unknown"
    last_attempt = max(times) if times else "Unknown"

    return {
        "attack_type": "UNAUTHORIZED_ACCESS",
        "attacker_ips": attacker_ips,
        "ip_attempts": ip_attempts,
        "targets_accessed": targets_accessed,
        "total_attempts": len(unauth_events),
        "first_attempt": first_attempt,
        "last_attempt": last_attempt
    }


def analyze_ransomware_data(file_logs):
    """Analyze ransomware attack details"""

    suspicious = [
        l for l in file_logs
        if l[2] == "SUSPICIOUS"
    ]
    deleted = [
        l for l in file_logs
        if l[2] == "DELETED"
    ]
    locked = [
        l for l in file_logs
        if any(ext in str(l[3])
               for ext in config.SUSPICIOUS_EXTENSIONS)
    ]
    restored = [
        l for l in file_logs
        if l[2] == "RESTORED"
    ]
    emergency = [
        l for l in file_logs
        if l[2] == "EMERGENCY_STOP"
    ]

    if not suspicious and not locked:
        return None

    times = [l[1] for l in (suspicious + locked)]
    first_event = min(times) if times else "Unknown"
    last_event = max(times) if times else "Unknown"

    return {
        "attack_type": "RANSOMWARE",
        "suspicious_files_count": len(suspicious),
        "deleted_files_count": len(deleted),
        "locked_files_count": len(locked),
        "restored_files_count": len(restored),
        "emergency_stops": len(emergency),
        "first_event": first_event,
        "last_event": last_event,
        "locked_files": [l[3] for l in locked],
        "restored_files": [l[3] for l in restored]
    }


def build_full_timeline(file_logs, alerts, security_events):
    """Build complete attack timeline from all events"""

    timeline = []

    # Add file events
    for log in file_logs:
        timeline.append({
            "time": log[1],
            "category": "FILE_ACTIVITY",
            "event": log[2],
            "actor": "Unknown",
            "ip": "Internal",
            "target": log[3],
            "details": log[4]
        })

    # Add alerts
    for alert in alerts:
        timeline.append({
            "time": alert[1],
            "category": "SYSTEM_ALERT",
            "event": alert[2],
            "actor": "SYSTEM",
            "ip": "System",
            "target": "Security System",
            "details": alert[3]
        })

    # Add security events
    for event in security_events:
        timeline.append({
            "time": event[1],
            "category": "SECURITY_EVENT",
            "event": event[2],
            "actor": event[3],
            "ip": event[4],
            "target": event[6],
            "details": event[8]
        })

    # Sort everything by time
    timeline.sort(key=lambda x: x["time"])
    return timeline


def generate_forensic_report():
    """
    Main investigation function

    Collects all data from all 3 attack types
    Builds complete forensic report
    """

    print("\n" + "=" * 60)
    print("🔍 FORENSIC INVESTIGATION STARTED")
    print("=" * 60)

    # Collect all data
    file_logs = get_all_file_logs()
    alerts = get_all_alerts()
    security_events = get_all_security_events()
    blocked_entities = get_all_blocked_entities()

    if not file_logs and not security_events and not alerts:
        print("⚠️  No forensic data found yet.")
        return None

    # Analyze each attack type
    brute_force_data = analyze_brute_force_data(security_events)
    unauthorized_data = analyze_unauthorized_data(security_events)
    ransomware_data = analyze_ransomware_data(file_logs)

    # Build full timeline
    timeline = build_full_timeline(
        file_logs,
        alerts,
        security_events
    )

    # Count attacks detected
    attacks_detected = []
    if brute_force_data:
        attacks_detected.append("BRUTE_FORCE")
    if unauthorized_data:
        attacks_detected.append("UNAUTHORIZED_ACCESS")
    if ransomware_data:
        attacks_detected.append("RANSOMWARE")

    # Case ID
    case_id = f"FR-2026-{datetime.now().strftime('%H%M%S')}"

    # Build report
    report = {
        "case_id": case_id,
        "investigation_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attacks_detected": attacks_detected,
        "total_attacks": len(attacks_detected),

        # Attack details
        "brute_force": brute_force_data,
        "unauthorized_access": unauthorized_data,
        "ransomware": ransomware_data,

        # Statistics
        "total_file_events": len(file_logs),
        "total_alerts": len(alerts),
        "total_security_events": len(security_events),
        "total_blocked_entities": len(blocked_entities),

        # Blocked
        "blocked_entities": blocked_entities,

        # Full data
        "security_events": security_events,
        "alerts": alerts,
        "timeline": timeline
    }

    # Print summary
    print(f"\n📋 INVESTIGATION SUMMARY")
    print(f"{'='*50}")
    print(f"Case ID              : {case_id}")
    print(f"Investigation Time   : {report['investigation_time']}")
    print(f"Attacks Detected     : {len(attacks_detected)}")
    print(f"Attack Types         : {', '.join(attacks_detected) if attacks_detected else 'None'}")
    print(f"Total File Events    : {len(file_logs)}")
    print(f"Total Security Events: {len(security_events)}")
    print(f"Total Alerts         : {len(alerts)}")
    print(f"Blocked IPs/Users    : {len(blocked_entities)}")

    if brute_force_data:
        print(f"\n🔓 BRUTE FORCE:")
        print(f"   Attacker IPs  : {brute_force_data['attacker_ips']}")
        print(f"   Total Attempts: {brute_force_data['total_attempts']}")
        print(f"   Users Targeted: {brute_force_data['usernames_targeted']}")

    if unauthorized_data:
        print(f"\n🚫 UNAUTHORIZED ACCESS:")
        print(f"   Attacker IPs  : {unauthorized_data['attacker_ips']}")
        print(f"   Total Attempts: {unauthorized_data['total_attempts']}")
        print(f"   Targets       : {unauthorized_data['targets_accessed']}")

    if ransomware_data:
        print(f"\n🔒 RANSOMWARE:")
        print(f"   Locked Files  : {ransomware_data['locked_files_count']}")
        print(f"   Restored Files: {ransomware_data['restored_files_count']}")

    if blocked_entities:
        print(f"\n🚫 BLOCKED ENTITIES:")
        for entity in blocked_entities:
            print(f"   {entity[2]}: {entity[3]} - {entity[4][:50]}")

    print(f"\n✅ Investigation complete!")
    return report