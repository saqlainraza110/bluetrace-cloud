# brute_force_monitor.py
# Monitors and detects brute force login attacks
# Attack 1 Detection

import time
import config
from datetime import datetime
from database_manager import (
    log_brute_force_attempt,
    get_brute_force_attempts,
    block_ip,
    is_ip_blocked,
    log_incident,
    resolve_incident
)

# Track which IPs we already alerted on
alerted_ips = set()


def check_brute_force(ip, username, password):
    """
    Called every time a login attempt happens.
    Checks if this IP is doing brute force.
    """

    # Skip if already blocked
    if is_ip_blocked(ip):
        print(f"🚫 BLOCKED IP tried again: {ip}")
        return

    # Save this attempt to database
    log_brute_force_attempt(ip, username, password)

    # Count attempts from this IP in last 60 seconds
    attempt_count = get_brute_force_attempts(
        ip,
        seconds=config.BRUTE_FORCE_WINDOW_SECONDS
    )

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"🔑 [{timestamp}] Login attempt from {ip} | "
          f"User: {username} | "
          f"Attempt #{attempt_count}")

    # Warning level
    if attempt_count == 3:
        print(f"\n⚠️  WARNING: {ip} has made "
              f"{attempt_count} failed attempts!")

    # Brute force confirmed
    if attempt_count >= config.BRUTE_FORCE_THRESHOLD:
        if ip not in alerted_ips:
            alerted_ips.add(ip)
            handle_brute_force_detected(ip, attempt_count)


def handle_brute_force_detected(ip, attempt_count):
    """
    Called when brute force is confirmed.
    Takes all protective actions.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "🚨" * 25)
    print("   BRUTE FORCE ATTACK DETECTED!")
    print(f"   Attacker IP : {ip}")
    print(f"   Attempts    : {attempt_count} in 60 seconds")
    print(f"   Time        : {timestamp}")
    print("🚨" * 25)

    # Action 1: Block the IP
    block_ip(
        ip,
        f"Brute force: {attempt_count} attempts in 60 seconds",
        "BRUTE_FORCE"
    )
    print(f"\n✅ ACTION 1: IP {ip} has been BLOCKED")

    # Action 2: Log the incident
    log_incident(
        attack_type="BRUTE_FORCE",
        attacker_ip=ip,
        severity="HIGH",
        details=(
            f"Brute force detected from {ip}. "
            f"{attempt_count} failed login attempts "
            f"in 60 seconds. IP blocked immediately."
        )
    )
    print(f"✅ ACTION 2: Incident logged to database")

    # Action 3: Save evidence file
    save_brute_force_evidence(ip, attempt_count, timestamp)
    print(f"✅ ACTION 3: Evidence saved")

    # Action 4: Mark as resolved
    resolve_incident("BRUTE_FORCE")
    print(f"✅ ACTION 4: Incident marked as resolved")

    print("\n🛡️  BRUTE FORCE ATTACK STOPPED SUCCESSFULLY!")
    print(f"   IP {ip} cannot access the system anymore.\n")


def save_brute_force_evidence(ip, attempts, timestamp):
    """Save evidence of brute force attack to file"""
    import os
    os.makedirs("evidence", exist_ok=True)

    filename = (
        f"evidence/brute_force_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )

    content = f"""
╔══════════════════════════════════════════════════╗
║         BRUTE FORCE ATTACK - EVIDENCE FILE       ║
╚══════════════════════════════════════════════════╝

Attack Type   : BRUTE FORCE LOGIN ATTACK
Detected At   : {timestamp}
Attacker IP   : {ip}
Total Attempts: {attempts} failed login attempts
Time Window   : 60 seconds
Action Taken  : IP BLOCKED

WHAT HAPPENED:
─────────────
The attacker at IP {ip} tried to guess
the password for our cloud storage system.
They made {attempts} login attempts in 60 seconds.
Our system detected this pattern and blocked
the IP address automatically.

STATUS: ATTACK BLOCKED ✅
"""

    with open(filename, 'w') as f:
        f.write(content)

    print(f"📁 Evidence saved: {filename}")
    return filename


def get_brute_force_stats():
    """Get statistics for dashboard"""
    import sqlite3
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    stats = {}

    try:
        # Total attempts
        cursor.execute('SELECT COUNT(*) FROM brute_force_logs')
        stats['total_attempts'] = cursor.fetchone()[0]

        # Unique IPs that attacked
        cursor.execute(
            'SELECT COUNT(DISTINCT attacker_ip) FROM brute_force_logs'
        )
        stats['unique_attackers'] = cursor.fetchone()[0]

        # Blocked IPs count
        cursor.execute(
            'SELECT COUNT(*) FROM blocked_ips '
            'WHERE attack_type = "BRUTE_FORCE"'
        )
        stats['blocked_ips'] = cursor.fetchone()[0]

        # Recent attempts
        cursor.execute('''
            SELECT attacker_ip, COUNT(*) as attempts,
                   MAX(timestamp) as last_attempt
            FROM brute_force_logs
            GROUP BY attacker_ip
            ORDER BY attempts DESC
            LIMIT 5
        ''')
        stats['top_attackers'] = cursor.fetchall()

    except Exception as e:
        print(f"Stats error: {e}")
        stats = {
            'total_attempts': 0,
            'unique_attackers': 0,
            'blocked_ips': 0,
            'top_attackers': []
        }

    conn.close()
    return stats