# auth_monitor.py
# Detects brute force and unauthorized access attacks

import sqlite3
from datetime import datetime, timedelta
import config
from security_logger import (
    block_entity,
    log_security_event
)


def save_alert_to_db(alert_type, message):
    """Save alert to alerts table"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            alert_type TEXT,
            message TEXT,
            status TEXT
        )
    ''')

    cursor.execute('''
        INSERT INTO alerts
        (timestamp, alert_type, message, status)
        VALUES (?, ?, ?, ?)
    ''', (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        alert_type,
        message,
        "ACTIVE"
    ))

    conn.commit()
    conn.close()
    print(f"[ALERT] {alert_type}: {message}")


def get_recent_security_events(minutes=1):
    """Get security events from last X minutes"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    time_ago = datetime.now() - timedelta(minutes=minutes)

    try:
        cursor.execute('''
            SELECT * FROM security_events
            WHERE timestamp > ?
            ORDER BY timestamp DESC
        ''', (time_ago.strftime("%Y-%m-%d %H:%M:%S"),))

        events = cursor.fetchall()
    except Exception:
        events = []

    conn.close()
    return events


def detect_brute_force(events):
    """
    Detect repeated failed login attempts

    Rule 1: 5+ failed logins from same IP in 1 minute
    Rule 2: 5+ failed logins for same username in 1 minute
    """

    failed_logins = [
        e for e in events
        if e[2] == "LOGIN_FAILED"
    ]

    if not failed_logins:
        return {"detected": False}

    # Count by IP
    ip_count = {}
    ip_usernames = {}

    for event in failed_logins:
        username = event[3]
        ip_address = event[4]

        ip_count[ip_address] = ip_count.get(ip_address, 0) + 1

        if ip_address not in ip_usernames:
            ip_usernames[ip_address] = []
        if username not in ip_usernames[ip_address]:
            ip_usernames[ip_address].append(username)

    # Count by Username
    user_count = {}
    for event in failed_logins:
        username = event[3]
        user_count[username] = user_count.get(username, 0) + 1

    # Check IP threshold
    for ip, count in ip_count.items():
        if count >= config.BRUTE_FORCE_LIMIT:
            usernames = ip_usernames.get(ip, ["unknown"])
            return {
                "detected": True,
                "attack_type": "BRUTE_FORCE",
                "ip_address": ip,
                "username": ", ".join(usernames),
                "count": count,
                "message": (
                    f"BRUTE FORCE: {count} failed login attempts "
                    f"from IP {ip} targeting user(s): "
                    f"{', '.join(usernames)}"
                )
            }

    # Check Username threshold
    for user, count in user_count.items():
        if count >= config.BRUTE_FORCE_LIMIT:
            return {
                "detected": True,
                "attack_type": "BRUTE_FORCE",
                "ip_address": "multiple",
                "username": user,
                "count": count,
                "message": (
                    f"BRUTE FORCE: {count} failed attempts "
                    f"against username '{user}'"
                )
            }

    return {"detected": False}


def detect_unauthorized_access(events):
    """
    Detect invalid key or restricted resource access

    Rule 1: Invalid access key used
    Rule 2: Restricted bucket access attempt
    Rule 3: Multiple denied attempts from same IP
    """

    unauthorized_types = [
        "INVALID_ACCESS_KEY",
        "UNAUTHORIZED_ACCESS",
        "ACCESS_DENIED",
        "FORBIDDEN_BUCKET"
    ]

    unauthorized_events = [
        e for e in events
        if e[2] in unauthorized_types
    ]

    if not unauthorized_events:
        return {"detected": False}

    # Count by IP
    ip_count = {}
    ip_targets = {}

    for event in unauthorized_events:
        ip_address = event[4]
        target = event[6]

        ip_count[ip_address] = ip_count.get(ip_address, 0) + 1

        if ip_address not in ip_targets:
            ip_targets[ip_address] = []
        if target not in ip_targets[ip_address]:
            ip_targets[ip_address].append(target)

    # Check threshold
    for ip, count in ip_count.items():
        if count >= config.UNAUTHORIZED_LIMIT:
            targets = ip_targets.get(ip, ["unknown"])
            return {
                "detected": True,
                "attack_type": "UNAUTHORIZED_ACCESS",
                "ip_address": ip,
                "username": "unknown/invalid",
                "count": count,
                "targets": targets,
                "message": (
                    f"UNAUTHORIZED ACCESS: {count} denied attempts "
                    f"from IP {ip} targeting: "
                    f"{', '.join(targets)}"
                )
            }

    return {"detected": False}


def analyze_auth_threats():
    """
    Main function called every 5 seconds by main.py

    Checks for:
    1. Brute force attacks
    2. Unauthorized access attacks
    """

    events = get_recent_security_events(minutes=2)

    if not events:
        return {
            "threat_detected": False,
            "message": "Authentication system normal"
        }

    # Check brute force first
    brute_result = detect_brute_force(events)

    if brute_result["detected"]:
        ip = brute_result["ip_address"]
        username = brute_result["username"]

        print("\n" + "🚨" * 20)
        print("BRUTE FORCE ATTACK DETECTED!")
        print(f"IP Address : {ip}")
        print(f"Username   : {username}")
        print(f"Attempts   : {brute_result['count']}")
        print("🚨" * 20)

        # Block the attacker
        if ip != "multiple":
            block_entity(
                "IP",
                ip,
                brute_result["message"]
            )

        block_entity(
            "USER",
            username,
            brute_result["message"]
        )

        # Save alert
        save_alert_to_db(
            "BRUTE_FORCE_DETECTED",
            brute_result["message"]
        )

        # Log the detection
        log_security_event(
            event_type="BRUTE_FORCE_DETECTED",
            username=username,
            ip_address=ip,
            action="LOGIN",
            target_resource="MinIO Authentication",
            status="BLOCKED",
            details=brute_result["message"]
        )

        return {
            "threat_detected": True,
            "attack_type": "BRUTE_FORCE",
            "message": brute_result["message"],
            "ip_address": ip,
            "username": username,
            "count": brute_result["count"]
        }

    # Check unauthorized access
    unauth_result = detect_unauthorized_access(events)

    if unauth_result["detected"]:
        ip = unauth_result["ip_address"]

        print("\n" + "🚨" * 20)
        print("UNAUTHORIZED ACCESS DETECTED!")
        print(f"IP Address : {ip}")
        print(f"Attempts   : {unauth_result['count']}")
        print(f"Targets    : {unauth_result.get('targets', [])}")
        print("🚨" * 20)

        # Block the attacker IP
        block_entity(
            "IP",
            ip,
            unauth_result["message"]
        )

        # Save alert
        save_alert_to_db(
            "UNAUTHORIZED_ACCESS_DETECTED",
            unauth_result["message"]
        )

        # Log the detection
        log_security_event(
            event_type="UNAUTHORIZED_ACCESS_DETECTED",
            username="unknown",
            ip_address=ip,
            action="MULTIPLE_ACCESS_ATTEMPTS",
            target_resource=str(unauth_result.get("targets", [])),
            status="BLOCKED",
            details=unauth_result["message"]
        )

        return {
            "threat_detected": True,
            "attack_type": "UNAUTHORIZED_ACCESS",
            "message": unauth_result["message"],
            "ip_address": ip,
            "username": "unknown",
            "count": unauth_result["count"]
        }

    return {
        "threat_detected": False,
        "message": "Authentication system normal"
    }