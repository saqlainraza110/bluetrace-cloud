# security_logger.py
# Logs all security events for brute force and unauthorized access

import sqlite3
from datetime import datetime
import config


def initialize_security_tables():
    """Create security tables in database"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            username TEXT,
            ip_address TEXT,
            action TEXT,
            target_resource TEXT,
            status TEXT,
            details TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            entity_type TEXT,
            entity_value TEXT,
            reason TEXT,
            status TEXT
        )
    ''')

    conn.commit()
    conn.close()
    print("[SECURITY] Security tables initialized successfully")


def log_security_event(event_type, username, ip_address,
                       action, target_resource, status, details):
    """
    Save a security event to database

    event_type     = LOGIN_FAILED / UNAUTHORIZED_ACCESS / BRUTE_FORCE etc
    username       = who tried
    ip_address     = where from
    action         = what they tried to do
    target_resource = what they tried to access
    status         = FAILED / DENIED / BLOCKED / DETECTED
    details        = full description
    """
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            username TEXT,
            ip_address TEXT,
            action TEXT,
            target_resource TEXT,
            status TEXT,
            details TEXT
        )
    ''')

    cursor.execute('''
        INSERT INTO security_events
        (timestamp, event_type, username, ip_address,
         action, target_resource, status, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        event_type,
        username,
        ip_address,
        action,
        target_resource,
        status,
        details
    ))

    conn.commit()
    conn.close()

    print(f"[SECURITY LOG] {event_type} | "
          f"User: {username} | "
          f"IP: {ip_address} | "
          f"{details}")


def block_entity(entity_type, entity_value, reason):
    """
    Block an IP address or username

    entity_type  = IP or USER
    entity_value = 192.168.1.105 or username
    reason       = why blocked
    """
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            entity_type TEXT,
            entity_value TEXT,
            reason TEXT,
            status TEXT
        )
    ''')

    # Check if already blocked
    cursor.execute('''
        SELECT id FROM blocked_entities
        WHERE entity_type = ?
        AND entity_value = ?
        AND status = "BLOCKED"
    ''', (entity_type, entity_value))

    existing = cursor.fetchone()

    if not existing:
        cursor.execute('''
            INSERT INTO blocked_entities
            (timestamp, entity_type, entity_value, reason, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            entity_type,
            entity_value,
            reason,
            "BLOCKED"
        ))

        conn.commit()
        print(f"\n🚫 [BLOCKED] {entity_type}: {entity_value}")
        print(f"   Reason: {reason}")
    else:
        print(f"[INFO] {entity_type} {entity_value} already blocked")

    conn.close()


def is_blocked(entity_type, entity_value):
    """
    Check if IP or user is already blocked
    Returns True if blocked, False if not
    """
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    try:
        cursor.execute('''
            SELECT id FROM blocked_entities
            WHERE entity_type = ?
            AND entity_value = ?
            AND status = "BLOCKED"
        ''', (entity_type, entity_value))

        result = cursor.fetchone()
    except Exception:
        result = None

    conn.close()
    return result is not None


def get_all_security_events():
    """Get all security events from database"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    try:
        cursor.execute(
            'SELECT * FROM security_events ORDER BY timestamp'
        )
        events = cursor.fetchall()
    except Exception:
        events = []

    conn.close()
    return events


def get_all_blocked_entities():
    """Get all blocked IPs and users"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    try:
        cursor.execute(
            'SELECT * FROM blocked_entities ORDER BY timestamp'
        )
        blocked = cursor.fetchall()
    except Exception:
        blocked = []

    conn.close()
    return blocked