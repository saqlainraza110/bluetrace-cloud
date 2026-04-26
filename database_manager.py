# database_manager.py
# Manages all database operations for all 3 attacks

import sqlite3
import config
from datetime import datetime


def initialize_all_tables():
    """Create all tables for all 3 attacks"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    # ── Attack 2: File activity logs ──
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            file_name   TEXT NOT NULL,
            details     TEXT
        )
    ''')

    # ── General alerts ──
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            alert_type  TEXT NOT NULL,
            message     TEXT NOT NULL,
            status      TEXT DEFAULT 'ACTIVE'
        )
    ''')

    # ── Attack 1: Brute force logs ──
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS brute_force_logs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT NOT NULL,
            attacker_ip   TEXT NOT NULL,
            username_tried TEXT,
            password_tried TEXT,
            attempt_count INTEGER DEFAULT 1,
            status        TEXT DEFAULT 'FAILED',
            blocked       INTEGER DEFAULT 0
        )
    ''')

    # ── Attack 1: Blocked IPs ──
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address  TEXT NOT NULL,
            blocked_at  TEXT NOT NULL,
            reason      TEXT,
            attack_type TEXT
        )
    ''')

    # ── Attack 3: Unauthorized access logs ──
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS unauthorized_logs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT NOT NULL,
            attacker_ip     TEXT NOT NULL,
            fake_key_used   TEXT,
            action_attempted TEXT,
            file_targeted   TEXT,
            status          TEXT DEFAULT 'BLOCKED'
        )
    ''')

    # ── Master incident log (all attacks combined) ──
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT NOT NULL,
            attack_type  TEXT NOT NULL,
            attacker_ip  TEXT,
            severity     TEXT DEFAULT 'HIGH',
            status       TEXT DEFAULT 'DETECTED',
            details      TEXT,
            resolved_at  TEXT
        )
    ''')

    conn.commit()
    conn.close()
    print("✅ All database tables initialized")


# ─────────────────────────────────────────────────
# Brute Force Database Functions
# ─────────────────────────────────────────────────

def log_brute_force_attempt(ip, username, password):
    """Save one brute force login attempt"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO brute_force_logs
        (timestamp, attacker_ip, username_tried, password_tried)
        VALUES (?, ?, ?, ?)
    ''', (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ip,
        username,
        password
    ))
    conn.commit()
    conn.close()


def get_brute_force_attempts(ip, seconds=60):
    """Count how many attempts from this IP in last X seconds"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()
    from datetime import timedelta
    time_ago = datetime.now() - timedelta(seconds=seconds)
    cursor.execute('''
        SELECT COUNT(*) FROM brute_force_logs
        WHERE attacker_ip = ?
        AND timestamp > ?
    ''', (ip, time_ago.strftime("%Y-%m-%d %H:%M:%S")))
    count = cursor.fetchone()[0]
    conn.close()
    return count


def block_ip(ip, reason, attack_type):
    """Add IP to blocked list"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    # Check if already blocked
    cursor.execute(
        'SELECT id FROM blocked_ips WHERE ip_address = ?', (ip,)
    )
    existing = cursor.fetchone()

    if not existing:
        cursor.execute('''
            INSERT INTO blocked_ips
            (ip_address, blocked_at, reason, attack_type)
            VALUES (?, ?, ?, ?)
        ''', (
            ip,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            reason,
            attack_type
        ))
        conn.commit()
        print(f"🚫 IP BLOCKED: {ip} | Reason: {reason}")

    conn.close()


def is_ip_blocked(ip):
    """Check if IP is blocked"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id FROM blocked_ips WHERE ip_address = ?', (ip,)
    )
    result = cursor.fetchone()
    conn.close()
    return result is not None


# ─────────────────────────────────────────────────
# Unauthorized Access Database Functions
# ─────────────────────────────────────────────────

def log_unauthorized_attempt(ip, fake_key, action, file_targeted=""):
    """Save unauthorized access attempt"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO unauthorized_logs
        (timestamp, attacker_ip, fake_key_used,
         action_attempted, file_targeted)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ip,
        fake_key,
        action,
        file_targeted
    ))
    conn.commit()
    conn.close()


def get_unauthorized_attempts(ip, seconds=60):
    """Count unauthorized attempts from this IP"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()
    from datetime import timedelta
    time_ago = datetime.now() - timedelta(seconds=seconds)
    cursor.execute('''
        SELECT COUNT(*) FROM unauthorized_logs
        WHERE attacker_ip = ?
        AND timestamp > ?
    ''', (ip, time_ago.strftime("%Y-%m-%d %H:%M:%S")))
    count = cursor.fetchone()[0]
    conn.close()
    return count


# ─────────────────────────────────────────────────
# Incident Database Functions
# ─────────────────────────────────────────────────

def log_incident(attack_type, attacker_ip, severity, details):
    """Log a confirmed security incident"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO incidents
        (timestamp, attack_type, attacker_ip, severity, details)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        attack_type,
        attacker_ip,
        severity,
        details
    ))
    conn.commit()
    conn.close()


def get_all_incidents():
    """Get all incidents for master report"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM incidents ORDER BY timestamp DESC'
    )
    incidents = cursor.fetchall()
    conn.close()
    return incidents


def resolve_incident(attack_type):
    """Mark incident as resolved"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE incidents
        SET status = 'RESOLVED',
            resolved_at = ?
        WHERE attack_type = ?
        AND status = 'DETECTED'
    ''', (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        attack_type
    ))
    conn.commit()
    conn.close()