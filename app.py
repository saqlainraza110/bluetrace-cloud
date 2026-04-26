# app.py
# Security Monitoring Tool - Port 5000
# Monitors Company Cloud Portal (port 8080)
# Has its own login, dashboard, admin, evidence pages

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, jsonify
)
import sqlite3
import config
from datetime import datetime

app = Flask(__name__)
app.secret_key = "security_tool_secret_2026"

# ─────────────────────────────────────────
# Security Tool Admin Accounts
# These are DIFFERENT from cloud portal accounts
# ─────────────────────────────────────────
SECURITY_ADMINS = {
    "secadmin": "SecAdmin123",
    "analyst": "Analyst2026"
}


# ─────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────

def get_real_ip():
    """Get real IP address of visitor"""
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0]
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    return ip.strip()


def init_security_db():
    """
    Initialize all required database tables.
    These tables are SHARED with cloud_portal.py
    Both systems read and write to same database.
    """
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    # Security events table
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

    # Login attempts table
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

    # Alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            alert_type TEXT,
            message TEXT,
            status TEXT
        )
    ''')

    # Blocked IPs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE,
            reason TEXT,
            blocked_at TEXT,
            attempt_count INTEGER,
            status TEXT DEFAULT "BLOCKED"
        )
    ''')

    # Evidence logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS evidence_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            attack_type TEXT,
            ip_address TEXT,
            username TEXT,
            action TEXT,
            target TEXT,
            evidence_details TEXT,
            severity TEXT
        )
    ''')

    # File activity logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            file_name TEXT,
            details TEXT
        )
    ''')

    conn.commit()
    conn.close()
    print("✅ All database tables initialized")


def get_db_stats():
    """
    Get ALL statistics from database.
    Used by dashboard, admin, evidence pages.
    Reads data that cloud_portal.py has written.
    """
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    stats = {
        "total_file_logs": 0,
        "total_alerts": 0,
        "total_security_events": 0,
        "total_blocked": 0,
        "total_evidence": 0,
        "total_login_attempts": 0,
        "total_failed_logins": 0,
        "total_successful_logins": 0,
        "recent_file_logs": [],
        "recent_alerts": [],
        "recent_security_events": [],
        "blocked_ips": [],
        "login_attempts": [],
        "evidence_logs": [],
        "system_status": "SAFE",
        "brute_force_count": 0,
        "ransomware_count": 0,
        "unauthorized_count": 0
    }

    # ── File logs ──
    try:
        cursor.execute('SELECT COUNT(*) FROM file_logs')
        stats["total_file_logs"] = cursor.fetchone()[0]

        cursor.execute(
            'SELECT * FROM file_logs ORDER BY id DESC LIMIT 20'
        )
        stats["recent_file_logs"] = cursor.fetchall()

        # Count ransomware files
        cursor.execute('''
            SELECT COUNT(*) FROM file_logs
            WHERE event_type = "SUSPICIOUS"
        ''')
        stats["ransomware_count"] = cursor.fetchone()[0]

    except Exception:
        pass

    # ── Alerts ──
    try:
        cursor.execute('SELECT COUNT(*) FROM alerts')
        stats["total_alerts"] = cursor.fetchone()[0]

        cursor.execute(
            'SELECT * FROM alerts ORDER BY id DESC LIMIT 15'
        )
        stats["recent_alerts"] = cursor.fetchall()

        # Check system status
        cursor.execute('''
            SELECT COUNT(*) FROM alerts
            WHERE alert_type IN (
                "RANSOMWARE_DETECTED",
                "BRUTE_FORCE_DETECTED",
                "UNAUTHORIZED_ACCESS_DETECTED"
            )
        ''')
        threat_count = cursor.fetchone()[0]
        if threat_count > 0:
            stats["system_status"] = "THREATS_DETECTED"

    except Exception:
        pass

    # ── Security events ──
    try:
        cursor.execute('SELECT COUNT(*) FROM security_events')
        stats["total_security_events"] = cursor.fetchone()[0]

        cursor.execute(
            'SELECT * FROM security_events ORDER BY id DESC LIMIT 20'
        )
        stats["recent_security_events"] = cursor.fetchall()

        # Count brute force events
        cursor.execute('''
            SELECT COUNT(*) FROM security_events
            WHERE event_type = "BRUTE_FORCE_DETECTED"
        ''')
        stats["brute_force_count"] = cursor.fetchone()[0]

        # Count unauthorized events
        cursor.execute('''
            SELECT COUNT(*) FROM security_events
            WHERE event_type IN (
                "UNAUTHORIZED_ACCESS",
                "PRIVILEGE_ESCALATION"
            )
        ''')
        stats["unauthorized_count"] = cursor.fetchone()[0]

    except Exception:
        pass

    # ── Blocked IPs ──
    try:
        cursor.execute('SELECT COUNT(*) FROM blocked_ips')
        stats["total_blocked"] = cursor.fetchone()[0]

        cursor.execute(
            'SELECT * FROM blocked_ips ORDER BY id DESC'
        )
        stats["blocked_ips"] = cursor.fetchall()

    except Exception:
        pass

    # ── Login attempts ──
    try:
        cursor.execute('SELECT COUNT(*) FROM login_attempts')
        stats["total_login_attempts"] = cursor.fetchone()[0]

        cursor.execute('''
            SELECT COUNT(*) FROM login_attempts
            WHERE success = 0
        ''')
        stats["total_failed_logins"] = cursor.fetchone()[0]

        cursor.execute('''
            SELECT COUNT(*) FROM login_attempts
            WHERE success = 1
        ''')
        stats["total_successful_logins"] = cursor.fetchone()[0]

        cursor.execute(
            'SELECT * FROM login_attempts ORDER BY id DESC LIMIT 30'
        )
        stats["login_attempts"] = cursor.fetchall()

    except Exception:
        pass

    # ── Evidence logs ──
    try:
        cursor.execute('SELECT COUNT(*) FROM evidence_logs')
        stats["total_evidence"] = cursor.fetchone()[0]

        cursor.execute(
            'SELECT * FROM evidence_logs ORDER BY id DESC LIMIT 25'
        )
        stats["evidence_logs"] = cursor.fetchall()

    except Exception:
        pass

    conn.close()
    return stats


def unblock_ip_in_db(ip_address):
    """
    Unblock an IP address in the database.
    Sets status from BLOCKED to UNBLOCKED.
    """
    try:
        conn = sqlite3.connect(config.DATABASE_NAME)
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE blocked_ips
            SET status = "UNBLOCKED"
            WHERE ip_address = ?
        ''', (ip_address,))

        rows_updated = cursor.rowcount
        conn.commit()
        conn.close()

        if rows_updated > 0:
            print(f"\n✅ [UNBLOCKED] IP: {ip_address}")
            return True
        else:
            print(f"\n⚠️ [UNBLOCK] IP {ip_address} not found")
            return False

    except Exception as e:
        print(f"[UNBLOCK ERROR] {e}")
        return False


def log_security_event(event_type, username, ip_address,
                       action, target, status, details):
    """Log a security event"""
    try:
        conn = sqlite3.connect(config.DATABASE_NAME)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO security_events
            (timestamp, event_type, username, ip_address,
             action, target_resource, status, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            event_type, username, ip_address,
            action, target, status, details
        ))

        conn.commit()
        conn.close()

    except Exception as e:
        print(f"[LOG ERROR] {e}")


# ═══════════════════════════════════════════
# ROUTE 1: HOME
# ═══════════════════════════════════════════

@app.route('/')
def index():
    """
    Home page.
    If logged in go to dashboard.
    If not go to login.
    """
    if 'sec_admin' in session:
        return redirect(url_for('security_dashboard'))
    return redirect(url_for('sec_login'))


# ═══════════════════════════════════════════
# ROUTE 2: SECURITY TOOL LOGIN
# ═══════════════════════════════════════════

@app.route('/login', methods=['GET', 'POST'])
def sec_login():
    """
    Security monitoring tool login page.
    Separate from cloud portal login.
    Only security admins can login here.
    """
    error = None

    if 'sec_admin' in session:
        return redirect(url_for('security_dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if (username in SECURITY_ADMINS and
                SECURITY_ADMINS[username] == password):

            session['sec_admin'] = username
            session['sec_login_time'] = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            print(f"\n✅ [SECURITY TOOL] Admin logged in: {username}")
            return redirect(url_for('security_dashboard'))

        else:
            error = (
                "Invalid security admin credentials. "
                "Please try again."
            )
            print(f"\n❌ [SECURITY TOOL] Failed login: {username}")

    return render_template('sec_login.html', error=error)


# ═══════════════════════════════════════════
# ROUTE 3: LOGOUT
# ═══════════════════════════════════════════

@app.route('/logout')
def sec_logout():
    """Logout from security tool"""
    username = session.get('sec_admin', 'Unknown')
    print(f"\n[SECURITY TOOL] Admin logged out: {username}")
    session.clear()
    return redirect(url_for('sec_login'))


# ═══════════════════════════════════════════
# ROUTE 4: MAIN SECURITY DASHBOARD
# ═══════════════════════════════════════════

@app.route('/dashboard')
def security_dashboard():
    """
    Main security monitoring dashboard.
    Shows all attacks happening on Cloud Portal (port 8080).
    Auto refreshes every 5 seconds.
    Must be logged in to security tool.
    """
    if 'sec_admin' not in session:
        return redirect(url_for('sec_login'))

    stats = get_db_stats()

    return render_template(
        'dashboard.html',
        stats=stats,
        current_user=session.get('sec_admin'),
        login_time=session.get('sec_login_time', 'Unknown')
    )


# ═══════════════════════════════════════════
# ROUTE 5: EVIDENCE PAGE
# ═══════════════════════════════════════════

@app.route('/evidence')
def evidence_page():
    """
    Forensic evidence page.
    Shows all collected evidence from attacks.
    Shows IP addresses, usernames, attack details.
    """
    if 'sec_admin' not in session:
        return redirect(url_for('sec_login'))

    stats = get_db_stats()

    return render_template(
        'evidence.html',
        stats=stats,
        current_user=session.get('sec_admin')
    )


# ═══════════════════════════════════════════
# ROUTE 6: ADMIN PANEL
# ═══════════════════════════════════════════

@app.route('/admin')
def admin_panel():
    """
    Admin panel.
    Shows blocked IPs and login attempts.
    Admin can unblock IPs from here.
    """
    if 'sec_admin' not in session:
        return redirect(url_for('sec_login'))

    stats = get_db_stats()

    return render_template(
        'admin.html',
        stats=stats,
        blocked_ips=stats["blocked_ips"],
        login_attempts=stats["login_attempts"],
        current_user=session.get('sec_admin')
    )


# ═══════════════════════════════════════════
# ROUTE 7: UNBLOCK IP - FIXED
# ═══════════════════════════════════════════

@app.route('/admin/unblock/<path:ip_address>')
def admin_unblock(ip_address):
    """
    Unblock a blocked IP address.
    FULLY FIXED - works properly now.
    Uses <path:ip_address> to handle dots in IP correctly.
    """
    if 'sec_admin' not in session:
        return redirect(url_for('sec_login'))

    # Clean the IP address
    ip_address = ip_address.strip()

    print(f"\n[ADMIN] Attempting to unblock IP: {ip_address}")

    # Unblock in database
    success = unblock_ip_in_db(ip_address)

    if success:
        # Log the unblock action
        log_security_event(
            event_type="IP_UNBLOCKED_BY_ADMIN",
            username=session.get('sec_admin'),
            ip_address=get_real_ip(),
            action="UNBLOCK_IP",
            target=f"Blocked IP: {ip_address}",
            status="SUCCESS",
            details=(
                f"Security admin '{session.get('sec_admin')}' "
                f"manually unblocked IP address: {ip_address} | "
                f"Admin IP: {get_real_ip()} | "
                f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
        )
        print(f"✅ [UNBLOCKED] IP {ip_address} successfully unblocked")
    else:
        print(f"⚠️ [UNBLOCK FAILED] IP {ip_address} not found")

    return redirect(url_for('admin_panel'))


# ═══════════════════════════════════════════
# ROUTE 8: GENERATE PDF REPORT
# ═══════════════════════════════════════════

@app.route('/generate-report')
def generate_report():
    """
    Generate PDF forensic report.
    Covers all 3 attack types.
    Must be logged in.
    """
    if 'sec_admin' not in session:
        return redirect(url_for('sec_login'))

    try:
        from forensic_engine import generate_forensic_report
        from report_generator import create_pdf_report

        print("\n🔍 Generating forensic PDF report...")
        forensic_data = generate_forensic_report()

        if forensic_data:
            pdf = create_pdf_report(forensic_data)
            print(f"✅ PDF Report saved: {pdf}")
            return jsonify({
                "status": "success",
                "message": f"Report generated successfully: {pdf}",
                "file": pdf
            })
        else:
            return jsonify({
                "status": "error",
                "message": (
                    "No forensic data found yet. "
                    "Run some attacks on the cloud portal first."
                )
            })

    except Exception as e:
        print(f"[REPORT ERROR] {e}")
        return jsonify({
            "status": "error",
            "message": f"Report error: {str(e)}"
        })


# ═══════════════════════════════════════════
# API ROUTES - For live data refresh
# ═══════════════════════════════════════════

@app.route('/api/live-stats')
def api_live_stats():
    """
    Returns live statistics as JSON.
    Dashboard uses this to update numbers live.
    """
    stats = get_db_stats()
    return jsonify({
        "total_file_logs": stats["total_file_logs"],
        "total_alerts": stats["total_alerts"],
        "total_security_events": stats["total_security_events"],
        "total_blocked": stats["total_blocked"],
        "total_evidence": stats["total_evidence"],
        "total_login_attempts": stats["total_login_attempts"],
        "total_failed_logins": stats["total_failed_logins"],
        "brute_force_count": stats["brute_force_count"],
        "ransomware_count": stats["ransomware_count"],
        "unauthorized_count": stats["unauthorized_count"],
        "system_status": stats["system_status"],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


@app.route('/api/events')
def api_events():
    """Returns recent security events as JSON"""
    try:
        conn = sqlite3.connect(config.DATABASE_NAME)
        cursor = conn.cursor()
        events = []

        cursor.execute(
            'SELECT * FROM security_events ORDER BY id DESC LIMIT 20'
        )
        for row in cursor.fetchall():
            events.append({
                "id": row[0],
                "timestamp": row[1],
                "event_type": row[2],
                "username": row[3],
                "ip_address": row[4],
                "action": row[5],
                "target": row[6],
                "status": row[7],
                "details": row[8]
            })

        conn.close()
        return jsonify(events)

    except Exception as e:
        return jsonify({"error": str(e)})


@app.route('/api/login-attempts')
def api_login_attempts():
    """Returns login attempts as JSON"""
    try:
        conn = sqlite3.connect(config.DATABASE_NAME)
        cursor = conn.cursor()
        attempts = []

        cursor.execute(
            'SELECT * FROM login_attempts ORDER BY id DESC LIMIT 30'
        )
        for row in cursor.fetchall():
            attempts.append({
                "id": row[0],
                "ip": row[1],
                "username": row[2],
                "password": row[3],
                "timestamp": row[4],
                "success": row[5],
                "user_agent": row[6]
            })

        conn.close()
        return jsonify(attempts)

    except Exception as e:
        return jsonify({"error": str(e)})


@app.route('/api/blocked-ips')
def api_blocked_ips():
    """Returns blocked IPs as JSON"""
    try:
        conn = sqlite3.connect(config.DATABASE_NAME)
        cursor = conn.cursor()
        blocked = []

        cursor.execute(
            'SELECT * FROM blocked_ips ORDER BY id DESC'
        )
        for row in cursor.fetchall():
            blocked.append({
                "id": row[0],
                "ip_address": row[1],
                "reason": row[2],
                "blocked_at": row[3],
                "attempt_count": row[4],
                "status": row[5]
            })

        conn.close()
        return jsonify(blocked)

    except Exception as e:
        return jsonify({"error": str(e)})


@app.route('/api/evidence')
def api_evidence():
    """Returns evidence logs as JSON"""
    try:
        conn = sqlite3.connect(config.DATABASE_NAME)
        cursor = conn.cursor()
        evidence = []

        cursor.execute(
            'SELECT * FROM evidence_logs ORDER BY id DESC LIMIT 25'
        )
        for row in cursor.fetchall():
            evidence.append({
                "id": row[0],
                "timestamp": row[1],
                "attack_type": row[2],
                "ip_address": row[3],
                "username": row[4],
                "action": row[5],
                "target": row[6],
                "evidence_details": row[7],
                "severity": row[8]
            })

        conn.close()
        return jsonify(evidence)

    except Exception as e:
        return jsonify({"error": str(e)})


# ═══════════════════════════════════════════
# START APPLICATION
# ═══════════════════════════════════════════

if __name__ == '__main__':

    # Initialize database
    init_security_db()

    print("\n" + "=" * 65)
    print("  🛡️  CLOUD SECURITY MONITORING & FORENSICS TOOL")
    print("  Version 4.0 - Full Attack Detection System")
    print("  Port 5000 - Monitors Cloud Portal on Port 8080")
    print("=" * 65)

    print("\n📋 SECURITY TOOL LOGIN:")
    print("   Username: secadmin  Password: SecAdmin123")
    print("   Username: analyst   Password: Analyst2026")

    print("\n📋 PAGES IN SECURITY TOOL:")
    print("   http://localhost:5000/login     ← Security tool login")
    print("   http://localhost:5000/dashboard ← Live monitoring")
    print("   http://localhost:5000/evidence  ← Forensic evidence")
    print("   http://localhost:5000/admin     ← Manage blocked IPs")

    print("\n📋 COMPANY CLOUD PORTAL (TARGET):")
    print("   http://localhost:8080           ← Cloud portal")
    print("   Login: john.doe / Pass123")
    print("   Login: admin / Admin123")

    print("\n📋 HOW TO DEMO ALL 3 ATTACKS:")
    print("\n   ATTACK 1 - BRUTE FORCE:")
    print("   → Phone opens http://192.168.110.11:8080/login")
    print("   → Try wrong password 5 times")
    print("   → Phone gets BLOCKED")
    print("   → Security tool dashboard shows attack")

    print("\n   ATTACK 2 - RANSOMWARE:")
    print("   → Login to cloud portal: localhost:8080")
    print("   → Go to Files page")
    print("   → Click Encrypt button on any file")
    print("   → File becomes .locked")
    print("   → Encrypt 3 files → IP gets blocked")
    print("   → Security tool shows ransomware evidence")

    print("\n   ATTACK 3 - UNAUTHORIZED:")
    print("   → Without login open: localhost:8080/database")
    print("   → Try 3 times → IP blocked")
    print("   → Security tool shows unauthorized access")

    print("\n   UNBLOCK IP:")
    print("   → Security tool → Admin panel")
    print("   → Click Unblock IP button")

    print("\n   Press CTRL+C to stop\n")

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False
    )