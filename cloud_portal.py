# cloud_portal.py
# Company Cloud Storage Portal - Port 8080
# Real world simulation - No encrypt button
# Files monitored by extension change detection

from flask import (
    Flask, render_template, request,
    redirect, url_for, session
)
import sqlite3
import os
import io
import threading
import time
from datetime import datetime
from minio import Minio
import config

app = Flask(__name__, template_folder='cloud_templates')
app.secret_key = "company_cloud_portal_2026"

COMPANY_USERS = {
    "john.doe": {
        "password": "Pass123",
        "role": "Employee",
        "department": "Finance"
    },
    "jane.smith": {
        "password": "Smith2026",
        "role": "Manager",
        "department": "HR"
    },
    "admin": {
        "password": "Admin123",
        "role": "Administrator",
        "department": "IT"
    },
    "mike.wilson": {
        "password": "Wilson123",
        "role": "Employee",
        "department": "Operations"
    }
}

# Suspicious extensions - real world ransomware extensions
SUSPICIOUS_EXTENSIONS = [
    '.locked', '.encrypted', '.crypto',
    '.enc', '.rnsmwr', '.crypt', '.crypted',
    '.cryptolocker', '.locky', '.zepto',
    '.cerber', '.ccc', '.vvv', '.ecc',
    '.ezz', '.exx', '.zzz', '.xyz',
    '.aaa', '.abc', '.pzdc', '.good',
    '.like', '.gws', '.fun', '.hbdolan'
]

# Track session-based suspicious activity
# user -> count of suspicious renames
suspicious_rename_counts = {}


def get_minio_client():
    return Minio(
        config.MINIO_HOST,
        access_key=config.MINIO_ACCESS_KEY,
        secret_key=config.MINIO_SECRET_KEY,
        secure=config.MINIO_SECURE
    )


def get_real_ip():
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0]
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    return ip.strip()


def init_db():
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    tables = [
        '''CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, event_type TEXT, username TEXT,
            ip_address TEXT, action TEXT, target_resource TEXT,
            status TEXT, details TEXT)''',

        '''CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT, username TEXT, password_tried TEXT,
            timestamp TEXT, success INTEGER DEFAULT 0, user_agent TEXT)''',

        '''CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, alert_type TEXT,
            message TEXT, status TEXT)''',

        '''CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE, reason TEXT, blocked_at TEXT,
            attempt_count INTEGER, status TEXT DEFAULT "BLOCKED")''',

        '''CREATE TABLE IF NOT EXISTS evidence_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, attack_type TEXT, ip_address TEXT,
            username TEXT, action TEXT, target TEXT,
            evidence_details TEXT, severity TEXT)''',

        '''CREATE TABLE IF NOT EXISTS file_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, event_type TEXT,
            file_name TEXT, details TEXT)''',

        '''CREATE TABLE IF NOT EXISTS quarantine_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, bucket TEXT, reason TEXT,
            triggered_by_ip TEXT, triggered_by_user TEXT,
            status TEXT)''',

        '''CREATE TABLE IF NOT EXISTS forced_logouts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, username TEXT, ip_address TEXT,
            reason TEXT)'''
    ]

    for t in tables:
        cursor.execute(t)

    conn.commit()
    conn.close()


def log_security_event(event_type, username, ip,
                       action, target, status, details):
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
            event_type, username, ip, action, target, status, details
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[LOG ERROR] {e}")


def log_file_event(event_type, file_name, details):
    try:
        conn = sqlite3.connect(config.DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO file_logs
            (timestamp, event_type, file_name, details)
            VALUES (?, ?, ?, ?)
        ''', (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            event_type, file_name, details
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[FILE LOG ERROR] {e}")


def log_evidence(attack_type, ip, username,
                 action, target, details, severity):
    try:
        conn = sqlite3.connect(config.DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO evidence_logs
            (timestamp, attack_type, ip_address, username,
             action, target, evidence_details, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            attack_type, ip, username, action, target, details, severity
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[EVIDENCE ERROR] {e}")


def log_login_attempt(ip, username, password, success, user_agent):
    try:
        conn = sqlite3.connect(config.DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO login_attempts
            (ip_address, username, password_tried,
             timestamp, success, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            ip, username,
            "***hidden***" if success else password,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            1 if success else 0, user_agent
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[LOGIN LOG ERROR] {e}")


def save_alert(alert_type, message):
    try:
        conn = sqlite3.connect(config.DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts
            (timestamp, alert_type, message, status)
            VALUES (?, ?, ?, ?)
        ''', (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            alert_type, message, "ACTIVE"
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ALERT ERROR] {e}")


def block_ip(ip, reason, attempt_count):
    try:
        conn = sqlite3.connect(config.DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO blocked_ips
            (ip_address, reason, blocked_at, attempt_count, status)
            VALUES (?, ?, ?, ?, "BLOCKED")
        ''', (
            ip, reason,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            attempt_count
        ))
        conn.commit()
        conn.close()
        print(f"\n🚫 [BLOCKED] IP: {ip} | {reason}")
    except Exception as e:
        print(f"[BLOCK ERROR] {e}")


def is_ip_blocked(ip):
    try:
        conn = sqlite3.connect(config.DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id FROM blocked_ips
            WHERE ip_address = ? AND status = "BLOCKED"
        ''', (ip,))
        result = cursor.fetchone()
        conn.close()
        return result is not None
    except Exception:
        return False


def get_failed_count(ip, minutes=5):
    try:
        conn = sqlite3.connect(config.DATABASE_NAME)
        cursor = conn.cursor()
        from datetime import timedelta
        time_ago = (
            datetime.now() - timedelta(minutes=minutes)
        ).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('''
            SELECT COUNT(*) FROM login_attempts
            WHERE ip_address = ? AND success = 0
            AND timestamp > ?
        ''', (ip, time_ago))
        count = cursor.fetchone()[0]
        conn.close()
        return count
    except Exception:
        return 0


def log_forced_logout(username, ip, reason):
    """Log when a user is forcefully logged out"""
    try:
        conn = sqlite3.connect(config.DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO forced_logouts
            (timestamp, username, ip_address, reason)
            VALUES (?, ?, ?, ?)
        ''', (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            username, ip, reason
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[FORCED LOGOUT LOG ERROR] {e}")


def quarantine_bucket(bucket_name, reason, ip, username):
    """
    Isolate a bucket when ransomware detected.
    Saves quarantine log.
    In real world this would set bucket policy to deny all.
    We log it and alert the security team.
    """
    try:
        conn = sqlite3.connect(config.DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO quarantine_log
            (timestamp, bucket, reason, triggered_by_ip,
             triggered_by_user, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            bucket_name, reason, ip, username, "QUARANTINED"
        ))
        conn.commit()
        conn.close()

        print(f"\n🔒 [QUARANTINE] Bucket '{bucket_name}' ISOLATED")
        print(f"   Reason: {reason}")
        print(f"   Triggered by: {username} from {ip}")

    except Exception as e:
        print(f"[QUARANTINE ERROR] {e}")


def is_suspicious_extension(filename):
    """
    Check if filename has a suspicious extension.
    This is the REAL detection - same as how security tools work.
    """
    lower = filename.lower()
    for ext in SUSPICIOUS_EXTENSIONS:
        if lower.endswith(ext):
            return True, ext
    return False, None


def auto_recover_file(client, suspicious_filename,
                      original_filename):
    """
    Automatically recover a file that was renamed to suspicious extension.
    This is what our security system does automatically.
    """
    try:
        # Get the suspicious file content
        response = client.get_object(
            config.BUCKET_MAIN, suspicious_filename
        )
        content = response.read()
        response.close()

        # Upload it back with original name
        client.put_object(
            config.BUCKET_MAIN,
            original_filename,
            io.BytesIO(content),
            len(content)
        )

        # Remove the suspicious file
        client.remove_object(config.BUCKET_MAIN, suspicious_filename)

        print(
            f"\n✅ [AUTO RECOVERY] "
            f"{suspicious_filename} → {original_filename}"
        )
        return True

    except Exception as e:
        print(f"[RECOVERY ERROR] {e}")
        return False


def handle_ransomware_detection(username, ip, suspicious_file,
                                original_file, ext):
    """
    Full ransomware response:
    1. Auto-recover the file
    2. Log evidence
    3. Force logout the user
    4. Check if should block IP
    5. Quarantine bucket if multiple files affected
    """
    global suspicious_rename_counts

    # Count how many suspicious renames this user has done
    key = f"{username}_{ip}"
    suspicious_rename_counts[key] = (
        suspicious_rename_counts.get(key, 0) + 1
    )
    count = suspicious_rename_counts[key]

    print(f"\n🚨 [RANSOMWARE DETECTED]")
    print(f"   User: {username} | IP: {ip}")
    print(f"   File: {suspicious_file}")
    print(f"   Extension: {ext}")
    print(f"   Rename count: {count}")

    # 1. Auto-recover the file
    try:
        client = get_minio_client()
        recovered = auto_recover_file(
            client, suspicious_file, original_file
        )

        if recovered:
            log_file_event(
                event_type="RESTORED",
                file_name=original_file,
                details=(
                    f"Auto-recovered from ransomware attempt: "
                    f"'{suspicious_file}' restored to '{original_file}' | "
                    f"User: {username} | IP: {ip}"
                )
            )
    except Exception as e:
        print(f"[CLIENT ERROR] {e}")
        recovered = False

    # 2. Log security event
    log_security_event(
        event_type="RANSOMWARE_DETECTED",
        username=username,
        ip=ip,
        action="SUSPICIOUS_FILE_RENAME",
        target=f"cloud-files/{suspicious_file}",
        status="DETECTED_AND_RECOVERED" if recovered else "DETECTED",
        details=(
            f"RANSOMWARE DETECTED: User '{username}' renamed "
            f"'{original_file}' to '{suspicious_file}' "
            f"(suspicious extension: {ext}) | "
            f"IP: {ip} | "
            f"File auto-recovered: {recovered} | "
            f"Rename attempt #{count}"
        )
    )

    log_file_event(
        event_type="SUSPICIOUS",
        file_name=suspicious_file,
        details=(
            f"Ransomware attempt: '{suspicious_file}' "
            f"by {username} from {ip}"
        )
    )

    # 3. Save evidence
    log_evidence(
        attack_type="RANSOMWARE",
        ip=ip,
        username=username,
        action="SUSPICIOUS_RENAME",
        target=f"cloud-files/{suspicious_file}",
        details=(
            f"RANSOMWARE ATTACK DETECTED | "
            f"Original: {original_file} | "
            f"Renamed to: {suspicious_file} | "
            f"Extension: {ext} | "
            f"Attacker IP: {ip} | "
            f"Attacker: {username} | "
            f"Attempt #{count} | "
            f"File recovered: {recovered} | "
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        ),
        severity="CRITICAL"
    )

    # 4. Save alert
    save_alert(
        "RANSOMWARE_DETECTED",
        (
            f"RANSOMWARE on Cloud Portal: "
            f"'{suspicious_file}' detected. "
            f"File recovered. User {username} (IP:{ip}) "
            f"forced logout. Attempt #{count}"
        )
    )

    # 5. Log forced logout
    log_forced_logout(
        username=username,
        ip=ip,
        reason=(
            f"Ransomware activity: renamed file to {ext} extension. "
            f"Attempt #{count}"
        )
    )

    # 6. Block IP if multiple attempts
    if count >= 2:
        block_ip(
            ip=ip,
            reason=(
                f"Ransomware attack: {count} suspicious file "
                f"renames by user '{username}'"
            ),
            attempt_count=count
        )

        # 7. Quarantine the bucket
        quarantine_bucket(
            bucket_name=config.BUCKET_MAIN,
            reason=(
                f"Ransomware detected: {count} files targeted "
                f"by {username} from {ip}"
            ),
            ip=ip,
            username=username
        )

        log_evidence(
            attack_type="RANSOMWARE_BLOCKED",
            ip=ip,
            username=username,
            action="IP_BLOCKED_AND_BUCKET_QUARANTINED",
            target=config.BUCKET_MAIN,
            details=(
                f"IP BLOCKED AND BUCKET QUARANTINED | "
                f"Attacker: {username} | IP: {ip} | "
                f"Total attempts: {count} | "
                f"Bucket: {config.BUCKET_MAIN}"
            ),
            severity="CRITICAL"
        )

        save_alert(
            "RANSOMWARE_BUCKET_QUARANTINED",
            (
                f"BUCKET QUARANTINED: '{config.BUCKET_MAIN}' "
                f"isolated due to ransomware from IP {ip}"
            )
        )

    return True


# ─────────────────────────────────────────
# MIDDLEWARE
# ─────────────────────────────────────────
@app.before_request
def check_block():
    ip = get_real_ip()
    if request.path in ['/cloud-blocked', '/login']:
        return None
    if request.path.startswith('/static'):
        return None
    if is_ip_blocked(ip):
        return redirect('/cloud-blocked')


# ═══════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════

@app.route('/')
def cloud_home():
    if 'cloud_user' in session:
        return redirect('/dashboard')
    return redirect('/login')


@app.route('/login', methods=['GET', 'POST'])
def cloud_login():
    ip = get_real_ip()
    user_agent = request.headers.get('User-Agent', 'Unknown')
    error = None

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if is_ip_blocked(ip):
            return redirect('/cloud-blocked')

        failed_count = get_failed_count(ip, minutes=5)

        if (username in COMPANY_USERS and
                COMPANY_USERS[username]['password'] == password):

            log_login_attempt(ip, username, password, True, user_agent)
            log_security_event(
                "CLOUD_LOGIN_SUCCESS", username, ip,
                "LOGIN", "Cloud Portal", "SUCCESS",
                f"Login by {username} from {ip}"
            )
            log_evidence(
                "LOGIN_SUCCESS", ip, username,
                "SUCCESSFUL_LOGIN", "/login",
                f"User {username} logged in from IP {ip}", "INFO"
            )

            session['cloud_user'] = username
            session['cloud_ip'] = ip
            session['cloud_role'] = COMPANY_USERS[username]['role']
            session['cloud_dept'] = COMPANY_USERS[username]['department']
            session['login_time'] = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            session['force_logout'] = False

            return redirect('/dashboard')

        else:
            new_count = failed_count + 1
            log_login_attempt(ip, username, password, False, user_agent)
            log_security_event(
                "LOGIN_FAILED", username, ip,
                "LOGIN_ATTEMPT", "Cloud Portal", "FAILED",
                f"Attempt {new_count} for {username}"
            )
            log_evidence(
                "BRUTE_FORCE", ip, username,
                "FAILED_LOGIN", "/login",
                f"Failed attempt {new_count} by {username}",
                "HIGH" if new_count >= 3 else "MEDIUM"
            )

            if new_count >= 5:
                block_ip(
                    ip,
                    f"Brute force: {new_count} failed attempts on {username}",
                    new_count
                )
                log_security_event(
                    "BRUTE_FORCE_DETECTED", username, ip,
                    "BRUTE_FORCE", "Cloud Portal", "BLOCKED",
                    f"IP {ip} blocked after {new_count} attempts"
                )
                save_alert(
                    "BRUTE_FORCE_DETECTED",
                    f"IP {ip} blocked: {new_count} failed attempts"
                )
                log_evidence(
                    "BRUTE_FORCE_DETECTED", ip, username,
                    "IP_BLOCKED", "/login",
                    f"IP {ip} blocked after {new_count} attempts",
                    "CRITICAL"
                )
                return redirect('/cloud-blocked')

            remaining = 5 - new_count
            error = f"Invalid credentials. {remaining} attempt(s) left."

    return render_template(
        'cloud_login.html',
        error=error, ip=ip,
        users=COMPANY_USERS
    )


@app.route('/dashboard')
def cloud_dashboard():
    if 'cloud_user' not in session:
        return redirect('/login')

    # Check if forced logout is needed
    if session.get('force_logout'):
        username = session.get('cloud_user', 'Unknown')
        ip = session.get('cloud_ip', 'Unknown')
        session.clear()
        return render_template(
            'cloud_forced_logout.html',
            username=username,
            ip=ip,
            reason="Suspicious file activity detected by security system"
        )

    files = get_cloud_files()
    databases = get_company_databases()

    return render_template(
        'cloud_dashboard.html',
        files=files,
        databases=databases,
        current_user=session.get('cloud_user'),
        current_role=session.get('cloud_role'),
        current_dept=session.get('cloud_dept'),
        current_ip=session.get('cloud_ip'),
        login_time=session.get('login_time'),
        total_files=len(files)
    )


@app.route('/files')
def cloud_files():
    if 'cloud_user' not in session:
        return redirect('/login')

    # Check force logout
    if session.get('force_logout'):
        username = session.get('cloud_user', 'Unknown')
        ip = session.get('cloud_ip', 'Unknown')
        session.clear()
        return render_template(
            'cloud_forced_logout.html',
            username=username, ip=ip,
            reason="Suspicious file activity detected"
        )

    files = get_cloud_files()

    return render_template(
        'cloud_files.html',
        files=files,
        current_user=session.get('cloud_user'),
        current_role=session.get('cloud_role'),
        current_ip=session.get('cloud_ip')
    )


@app.route('/rename', methods=['POST'])
def rename_file():
    """
    REAL WORLD RENAME - This is how ransomware works.
    User renames file.txt to file.txt.locked
    Our system detects the extension change
    Auto-recovers, logs out user, blocks IP if repeated
    """
    if 'cloud_user' not in session:
        return redirect('/login')

    ip = get_real_ip()
    username = session.get('cloud_user')
    old_name = request.form.get('old_name', '').strip()
    new_name = request.form.get('new_name', '').strip()

    if not old_name or not new_name:
        return redirect('/files')

    if old_name == new_name:
        return redirect('/files')

    # Check if new name has suspicious extension
    is_suspicious, ext = is_suspicious_extension(new_name)

    try:
        client = get_minio_client()

        # Get original file
        response = client.get_object(config.BUCKET_MAIN, old_name)
        content = response.read()
        response.close()

        if is_suspicious:
            # RANSOMWARE DETECTED
            print(
                f"\n🚨 RANSOMWARE: {username} renamed "
                f"{old_name} → {new_name} | IP: {ip}"
            )

            # Upload with suspicious name temporarily
            # (so detection is visible in MinIO briefly)
            client.put_object(
                config.BUCKET_MAIN, new_name,
                io.BytesIO(content), len(content)
            )
            client.remove_object(config.BUCKET_MAIN, old_name)

            # Handle full ransomware response
            handle_ransomware_detection(
                username=username,
                ip=ip,
                suspicious_file=new_name,
                original_file=old_name,
                ext=ext
            )

            # Force logout this session
            session['force_logout'] = True

            return redirect('/files')

        else:
            # Normal rename - no suspicious extension
            client.put_object(
                config.BUCKET_MAIN, new_name,
                io.BytesIO(content), len(content)
            )
            client.remove_object(config.BUCKET_MAIN, old_name)

            log_security_event(
                "FILE_RENAMED", username, ip,
                "RENAME", f"{old_name} → {new_name}",
                "SUCCESS",
                f"File renamed: {old_name} → {new_name}"
            )
            log_file_event(
                "RENAMED", new_name,
                f"Renamed from {old_name} by {username} | IP: {ip}"
            )

            return redirect('/files')

    except Exception as e:
        print(f"[RENAME ERROR] {e}")
        return redirect('/files')


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'cloud_user' not in session:
        return redirect('/login')

    ip = get_real_ip()

    if 'file' not in request.files:
        return redirect('/files')

    file = request.files['file']
    if file.filename == '':
        return redirect('/files')

    try:
        client = get_minio_client()
        file_data = file.read()
        file_size = len(file_data)

        # Check if uploaded file itself has suspicious name
        is_suspicious, ext = is_suspicious_extension(file.filename)

        client.put_object(
            config.BUCKET_MAIN, file.filename,
            io.BytesIO(file_data), file_size
        )

        log_security_event(
            "FILE_UPLOADED", session.get('cloud_user'), ip,
            "UPLOAD", f"cloud-files/{file.filename}",
            "SUSPICIOUS" if is_suspicious else "SUCCESS",
            f"Uploaded {file.filename}"
        )
        log_file_event(
            "NEW_FILE", file.filename,
            f"Uploaded by {session.get('cloud_user')} from {ip}"
        )

        if is_suspicious:
            handle_ransomware_detection(
                username=session.get('cloud_user'),
                ip=ip,
                suspicious_file=file.filename,
                original_file=file.filename.replace(ext, '.txt'),
                ext=ext
            )
            session['force_logout'] = True

    except Exception as e:
        print(f"[UPLOAD ERROR] {e}")

    return redirect('/files')


@app.route('/delete/<filename>')
def delete_file(filename):
    if 'cloud_user' not in session:
        return redirect('/login')

    ip = get_real_ip()

    try:
        client = get_minio_client()
        client.remove_object(config.BUCKET_MAIN, filename)
        log_security_event(
            "FILE_DELETED", session.get('cloud_user'), ip,
            "DELETE", filename, "SUCCESS",
            f"Deleted {filename}"
        )
        log_file_event(
            "DELETED", filename,
            f"Deleted by {session.get('cloud_user')} from {ip}"
        )
    except Exception as e:
        print(f"[DELETE ERROR] {e}")

    return redirect('/files')


@app.route('/database')
def cloud_database():
    if 'cloud_user' not in session:
        ip = get_real_ip()
        log_security_event(
            "UNAUTHORIZED_ACCESS", "ANONYMOUS", ip,
            "ACCESS_DATABASE", "/database", "DENIED",
            "Unauthorized database access"
        )
        log_evidence(
            "UNAUTHORIZED_ACCESS", ip, "ANONYMOUS",
            "UNAUTHORIZED_DATABASE_ACCESS", "/database",
            f"Attempt from IP {ip}", "HIGH"
        )
        return render_template('cloud_unauthorized.html', ip=ip), 403

    databases = get_company_databases()

    return render_template(
        'cloud_database.html',
        databases=databases,
        current_user=session.get('cloud_user'),
        current_role=session.get('cloud_role')
    )


@app.route('/logout')
def cloud_logout():
    ip = get_real_ip()
    username = session.get('cloud_user', 'Unknown')
    log_security_event(
        "CLOUD_LOGOUT", username, ip,
        "LOGOUT", "Cloud Portal", "SUCCESS",
        f"User {username} logged out"
    )
    session.clear()
    return redirect('/login')


@app.route('/cloud-blocked')
def cloud_blocked():
    ip = get_real_ip()
    return render_template('cloud_blocked.html', ip=ip), 403


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def get_cloud_files():
    files = []
    try:
        client = get_minio_client()
        objects = client.list_objects(config.BUCKET_MAIN)
        for obj in objects:
            is_susp, _ = is_suspicious_extension(obj.object_name)
            files.append({
                "name": obj.object_name,
                "size": format_size(obj.size),
                "modified": str(obj.last_modified)[:19],
                "type": get_file_icon(obj.object_name),
                "is_locked": is_susp
            })
    except Exception as e:
        print(f"[MINIO ERROR] {e}")
    return files


def format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024*1024):.1f} MB"


def get_file_icon(filename):
    ext = filename.lower().split('.')[-1] if '.' in filename else ''
    icons = {
        'pdf': '📄', 'xlsx': '📊', 'xls': '📊',
        'csv': '📊', 'docx': '📝', 'doc': '📝',
        'txt': '📃', 'jpg': '🖼️', 'png': '🖼️',
        'locked': '🔒', 'encrypted': '🔒'
    }
    return icons.get(ext, '📁')


def get_company_databases():
    databases = {}
    try:
        conn = sqlite3.connect('company_data.db')
        cursor = conn.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS employees
            (id INTEGER PRIMARY KEY, name TEXT, department TEXT,
             salary INTEGER, email TEXT, join_date TEXT)''')
        cursor.execute('SELECT COUNT(*) FROM employees')
        count = cursor.fetchone()[0]

        if count == 0:
            sample = [
                ('John Doe', 'Finance', 75000, 'john.doe@company.com', '2020-01-15'),
                ('Jane Smith', 'HR', 68000, 'jane.smith@company.com', '2019-03-20'),
                ('Mike Wilson', 'Operations', 72000, 'mike.wilson@company.com', '2021-06-10'),
                ('Sarah Johnson', 'IT', 85000, 'sarah.j@company.com', '2018-11-05'),
                ('Tom Brown', 'Finance', 70000, 'tom.b@company.com', '2022-02-28'),
                ('Alice Davis', 'Marketing', 65000, 'alice.d@company.com', '2021-09-15'),
                ('Robert Lee', 'Operations', 73000, 'robert.l@company.com', '2020-07-22'),
                ('Emily Chen', 'IT', 88000, 'emily.c@company.com', '2019-12-01')
            ]
            cursor.executemany('''INSERT INTO employees
                (name, department, salary, email, join_date)
                VALUES (?, ?, ?, ?, ?)''', sample)
            conn.commit()
            count = len(sample)

        cursor.execute('SELECT * FROM employees')
        employees = cursor.fetchall()

        cursor.execute('''CREATE TABLE IF NOT EXISTS financial_records
            (id INTEGER PRIMARY KEY, transaction_id TEXT, amount REAL,
             type TEXT, department TEXT, date TEXT, description TEXT)''')
        cursor.execute('SELECT COUNT(*) FROM financial_records')
        fcount = cursor.fetchone()[0]

        if fcount == 0:
            finance_data = [
                ('TXN-001', 15000.00, 'EXPENSE', 'IT', '2026-01-05', 'Server infrastructure'),
                ('TXN-002', 8500.00, 'EXPENSE', 'HR', '2026-01-10', 'Training programs'),
                ('TXN-003', 250000.00, 'REVENUE', 'Sales', '2026-01-15', 'Q1 client contract'),
                ('TXN-004', 12000.00, 'EXPENSE', 'Marketing', '2026-01-20', 'Ad campaigns'),
                ('TXN-005', 180000.00, 'REVENUE', 'Sales', '2026-02-01', 'Product sales'),
                ('TXN-006', 45000.00, 'EXPENSE', 'Operations', '2026-02-10', 'Equipment'),
                ('TXN-007', 320000.00, 'REVENUE', 'Sales', '2026-02-15', 'Enterprise deal'),
                ('TXN-008', 9500.00, 'EXPENSE', 'IT', '2026-02-20', 'Software licenses')
            ]
            cursor.executemany('''INSERT INTO financial_records
                (transaction_id, amount, type, department, date, description)
                VALUES (?, ?, ?, ?, ?, ?)''', finance_data)
            conn.commit()
            fcount = len(finance_data)

        cursor.execute('SELECT * FROM financial_records')
        finance = cursor.fetchall()
        conn.close()

        databases['employees'] = {
            'title': 'Employee Records', 'icon': '👥',
            'count': count,
            'columns': ['ID', 'Name', 'Department', 'Salary', 'Email', 'Join Date'],
            'data': employees
        }
        databases['finance'] = {
            'title': 'Financial Records', 'icon': '💰',
            'count': fcount,
            'columns': ['ID', 'Transaction ID', 'Amount', 'Type', 'Department', 'Date', 'Description'],
            'data': finance
        }

    except Exception as e:
        print(f"[DB ERROR] {e}")

    return databases


if __name__ == '__main__':
    os.makedirs('cloud_templates', exist_ok=True)
    init_db()

    print("\n" + "=" * 60)
    print("  🏢  COMPANY CLOUD STORAGE PORTAL - Port 8080")
    print("=" * 60)
    print("\nAccounts:")
    print("  john.doe    / Pass123")
    print("  jane.smith  / Smith2026")
    print("  admin       / Admin123")
    print("  mike.wilson / Wilson123")
    print("\nHow to simulate ransomware (real world way):")
    print("  1. Login to cloud portal")
    print("  2. Go to Files")
    print("  3. Click Rename on any file")
    print("  4. Change name to: filename.txt.locked")
    print("  5. System detects, recovers file, logs you out")
    print("  6. Do it twice - IP gets blocked")
    print("\nPress CTRL+C to stop\n")

    app.run(host='0.0.0.0', port=8080, debug=False)