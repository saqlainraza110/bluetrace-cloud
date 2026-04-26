# access_control.py
# Real IP blocking that actually works
# Blocked IPs cannot access any page

import sqlite3
import config
from datetime import datetime


def initialize_access_control():
    """Create access control tables"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE,
            reason TEXT,
            blocked_at TEXT,
            attempt_count INTEGER,
            status TEXT DEFAULT 'BLOCKED'
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            username TEXT,
            password_tried TEXT,
            timestamp TEXT,
            success INTEGER DEFAULT 0,
            user_agent TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS active_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            username TEXT,
            login_time TEXT,
            last_seen TEXT,
            status TEXT DEFAULT 'ACTIVE'
        )
    ''')

    conn.commit()
    conn.close()


def is_ip_blocked(ip_address):
    """
    Check if IP is blocked
    Returns True if blocked = deny access
    """
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    try:
        cursor.execute('''
            SELECT id FROM blocked_ips
            WHERE ip_address = ?
            AND status = 'BLOCKED'
        ''', (ip_address,))

        result = cursor.fetchone()
    except Exception:
        result = None

    conn.close()
    return result is not None


def block_ip(ip_address, reason, attempt_count=0):
    """
    Actually block an IP address
    Once blocked, they see blocked page
    """
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    try:
        cursor.execute('''
            INSERT OR REPLACE INTO blocked_ips
            (ip_address, reason, blocked_at, attempt_count, status)
            VALUES (?, ?, ?, ?, 'BLOCKED')
        ''', (
            ip_address,
            reason,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            attempt_count
        ))

        conn.commit()
        print(f"\n🚫 IP BLOCKED: {ip_address}")
        print(f"   Reason: {reason}")
        print(f"   They will now see BLOCKED page")

    except Exception as e:
        print(f"Error blocking IP: {e}")

    conn.close()


def unblock_ip(ip_address):
    """Unblock an IP (for admin use)"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        UPDATE blocked_ips
        SET status = 'UNBLOCKED'
        WHERE ip_address = ?
    ''', (ip_address,))

    conn.commit()
    conn.close()
    print(f"✅ IP UNBLOCKED: {ip_address}")


def record_login_attempt(ip_address, username,
                          password_tried, success, user_agent):
    """Record every login attempt with full details"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO login_attempts
        (ip_address, username, password_tried,
         timestamp, success, user_agent)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        ip_address,
        username,
        password_tried,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        1 if success else 0,
        user_agent
    ))

    conn.commit()
    conn.close()


def get_recent_failed_attempts(ip_address, minutes=2):
    """Count failed attempts from IP in last X minutes"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    from datetime import timedelta
    time_ago = (
        datetime.now() - timedelta(minutes=minutes)
    ).strftime("%Y-%m-%d %H:%M:%S")

    try:
        cursor.execute('''
            SELECT COUNT(*) FROM login_attempts
            WHERE ip_address = ?
            AND success = 0
            AND timestamp > ?
        ''', (ip_address, time_ago))

        count = cursor.fetchone()[0]
    except Exception:
        count = 0

    conn.close()
    return count


def get_all_blocked_ips():
    """Get all blocked IPs for dashboard"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    try:
        cursor.execute('''
            SELECT * FROM blocked_ips
            ORDER BY blocked_at DESC
        ''')
        result = cursor.fetchall()
    except Exception:
        result = []

    conn.close()
    return result


def get_all_login_attempts():
    """Get all login attempts for dashboard"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    try:
        cursor.execute('''
            SELECT * FROM login_attempts
            ORDER BY id DESC
            LIMIT 50
        ''')
        result = cursor.fetchall()
    except Exception:
        result = []

    conn.close()
    return result