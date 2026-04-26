# main.py
# Starts the complete cloud security detection system
# Detects ALL 3 attack types

import threading
import time
import sqlite3
from datetime import datetime
import config
from file_monitor import start_monitoring, connect_to_cloud
from detection_engine import analyze_threat
from response_module import execute_response
from forensic_engine import generate_forensic_report
from report_generator import create_pdf_report
from security_logger import initialize_security_tables
from auth_monitor import analyze_auth_threats


def initialize_database():
    """Create all required database tables"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()

    # File logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_logs (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            event_type TEXT,
            file_name TEXT,
            details TEXT
        )
    ''')

    # Alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            alert_type TEXT,
            message TEXT,
            status TEXT
        )
    ''')

    conn.commit()
    conn.close()

    # Security tables
    initialize_security_tables()

    print("✅ All database tables initialized")


# Track what threats already responded to
ransomware_responded = False
auth_threat_responded = False


def ransomware_detection_loop():
    """
    Loop 1: Checks for ransomware every 5 seconds
    """
    global ransomware_responded

    print("✅ Ransomware detection engine started")

    while True:
        time.sleep(5)

        result = analyze_threat()

        if result["threat_detected"] and not ransomware_responded:
            ransomware_responded = True

            print("\n🚨 RANSOMWARE CONFIRMED BY DETECTION ENGINE")
            print(f"   Score   : {result.get('score', 0)}")
            print(f"   Reasons : {result.get('reasons', [])}")

            # Execute response
            execute_response(result)

            # Generate forensic report
            forensic_data = generate_forensic_report()

            if forensic_data:
                pdf_file = create_pdf_report(forensic_data)
                print(f"\n📄 PDF Report generated: {pdf_file}")

            # Allow re-detection after 60 seconds
            time.sleep(60)
            ransomware_responded = False

        else:
            # Show status every 30 seconds
            pass


def auth_detection_loop():
    """
    Loop 2: Checks for brute force and unauthorized access every 5 seconds
    """
    global auth_threat_responded

    print("✅ Authentication/Authorization monitor started")

    while True:
        time.sleep(5)

        result = analyze_auth_threats()

        if result["threat_detected"] and not auth_threat_responded:
            auth_threat_responded = True

            attack_type = result.get("attack_type", "UNKNOWN")
            ip = result.get("ip_address", "Unknown")
            username = result.get("username", "Unknown")

            print(f"\n🚨 AUTH THREAT DETECTED: {attack_type}")
            print(f"   IP Address : {ip}")
            print(f"   Username   : {username}")
            print(f"   Message    : {result.get('message', '')}")

            # Generate forensic report for this threat too
            print("\n🔍 Running forensic investigation...")
            forensic_data = generate_forensic_report()

            if forensic_data:
                pdf_file = create_pdf_report(forensic_data)
                print(f"\n📄 PDF Report generated: {pdf_file}")

            # Allow re-detection after 30 seconds
            time.sleep(30)
            auth_threat_responded = False


def status_printer():
    """
    Prints system status every 30 seconds
    """
    while True:
        time.sleep(30)
        now = datetime.now().strftime("%H:%M:%S")

        try:
            conn = sqlite3.connect(config.DATABASE_NAME)
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) FROM file_logs')
            file_count = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM alerts')
            alert_count = cursor.fetchone()[0]

            try:
                cursor.execute('SELECT COUNT(*) FROM security_events')
                sec_count = cursor.fetchone()[0]
            except Exception:
                sec_count = 0

            try:
                cursor.execute('SELECT COUNT(*) FROM blocked_entities')
                block_count = cursor.fetchone()[0]
            except Exception:
                block_count = 0

            conn.close()

            print(
                f"\n📊 [{now}] STATUS | "
                f"File Events: {file_count} | "
                f"Alerts: {alert_count} | "
                f"Security Events: {sec_count} | "
                f"Blocked: {block_count}"
            )

        except Exception:
            pass


def main():
    print("\n" + "=" * 65)
    print("  🛡️  CLOUD SECURITY DETECTION & FORENSICS TOOL  🛡️")
    print("  Version 3.0 - Full Attack Detection")
    print("  Detects: Ransomware | Brute Force | Unauthorized Access")
    print("=" * 65 + "\n")

    # Initialize database
    initialize_database()

    # Test cloud connection
    try:
        client = connect_to_cloud()
        buckets = client.list_buckets()
        print(f"✅ Cloud connection successful")
        print(f"✅ Found {len(buckets)} buckets in MinIO")
    except Exception as e:
        print(f"\n❌ Cannot connect to MinIO cloud: {e}")
        print("Please make sure Docker and MinIO are running!")
        print("Run: docker start minio-cloud")
        return

    print("\n" + "-" * 65)
    print("📋 SYSTEM INFORMATION:")
    print(f"   🌐 Dashboard     : http://localhost:5000")
    print(f"   ☁️  MinIO Console : http://localhost:9001")
    print(f"   🔍 Detection     : Every 5 seconds")
    print(f"   📁 Reports saved : ./reports/ folder")
    print(f"   💾 Database      : {config.DATABASE_NAME}")
    print("-" * 65)
    print("\n📋 WHAT IS BEING MONITORED:")
    print("   ✅ Attack 1: Brute Force Password Attacks")
    print("   ✅ Attack 2: Ransomware File Encryption")
    print("   ✅ Attack 3: Unauthorized Cloud Access")
    print("\n   Press CTRL+C to stop the system\n")
    print("=" * 65 + "\n")

    # Thread 1: File Monitor (watches MinIO files)
    monitor_thread = threading.Thread(
        target=start_monitoring,
        daemon=True,
        name="FileMonitor"
    )
    monitor_thread.start()
    time.sleep(1)

    # Thread 2: Ransomware Detection
    ransomware_thread = threading.Thread(
        target=ransomware_detection_loop,
        daemon=True,
        name="RansomwareDetector"
    )
    ransomware_thread.start()
    time.sleep(1)

    # Thread 3: Auth/Brute Force Detection
    auth_thread = threading.Thread(
        target=auth_detection_loop,
        daemon=True,
        name="AuthMonitor"
    )
    auth_thread.start()
    time.sleep(1)

    # Thread 4: Status Printer
    status_thread = threading.Thread(
        target=status_printer,
        daemon=True,
        name="StatusPrinter"
    )
    status_thread.start()

    # Start Dashboard (this runs in main thread)
    print("🌐 Starting dashboard...")
    from dashboard import app
    app.run(
        debug=False,
        port=5000,
        use_reloader=False
    )


if __name__ == "__main__":
    main()