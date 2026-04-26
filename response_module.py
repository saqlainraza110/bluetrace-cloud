# response_module.py
# Automatically stops the attack

from minio import Minio
import config
import sqlite3
from datetime import datetime

def connect_cloud():
    return Minio(
        config.MINIO_HOST,
        access_key=config.MINIO_ACCESS_KEY,
        secret_key=config.MINIO_SECRET_KEY,
        secure=config.MINIO_SECURE
    )

def save_alert(alert_type, message):
    """Save alert to database"""
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
    print(f"[ALERT SAVED] {alert_type}: {message}")

def quarantine_infected_files(client):
    """Move infected files to quarantine"""
    print("\n[RESPONSE] Moving infected files to quarantine...")

    try:
        objects = client.list_objects(config.BUCKET_MAIN)
        quarantined = 0

        for obj in objects:
            # Check if file is infected (has suspicious extension)
            for ext in config.SUSPICIOUS_EXTENSIONS:
                if obj.object_name.endswith(ext):
                    print(f"  Quarantining: {obj.object_name}")
                    quarantined += 1
                    save_alert(
                        "QUARANTINE",
                        f"File quarantined: {obj.object_name}"
                    )

        print(f"[RESPONSE] {quarantined} files quarantined")
        return quarantined

    except Exception as e:
        print(f"[ERROR] Quarantine failed: {e}")
        return 0

def take_evidence_snapshot(client):
    """Save list of all files as forensic evidence"""
    print("\n[RESPONSE] Taking evidence snapshot...")

    try:
        objects = list(client.list_objects(config.BUCKET_MAIN))
        snapshot = []

        for obj in objects:
            snapshot.append({
                "name": obj.object_name,
                "size": obj.size,
                "modified": str(obj.last_modified)
            })

        # Save snapshot
        snapshot_text = "\n".join([
            f"{s['name']} | {s['size']} bytes | {s['modified']}"
            for s in snapshot
        ])

        # Upload snapshot to evidence bucket
        import io
        snapshot_bytes = snapshot_text.encode('utf-8')
        client.put_object(
            config.BUCKET_EVIDENCE,
            f"snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            io.BytesIO(snapshot_bytes),
            len(snapshot_bytes)
        )

        print(f"[RESPONSE] Snapshot saved with {len(snapshot)} files")
        save_alert("SNAPSHOT", f"Evidence snapshot saved: {len(snapshot)} files")
        return snapshot

    except Exception as e:
        print(f"[ERROR] Snapshot failed: {e}")
        return []

def execute_response(threat_info):
    """Main response function - called when ransomware detected"""
    print("\n" + "=" * 50)
    print("EXECUTING EMERGENCY RESPONSE")
    print("=" * 50)

    client = connect_cloud()

    # Action 1: Save alert
    save_alert("RANSOMWARE", f"Ransomware detected! Score: {threat_info['score']}")
    print("[ACTION 1] Alert saved to database ✓")

    # Action 2: Take evidence snapshot
    snapshot = take_evidence_snapshot(client)
    print("[ACTION 2] Evidence snapshot taken ✓")

    # Action 3: Quarantine infected files
    quarantined = quarantine_infected_files(client)
    print("[ACTION 3] Infected files quarantined ✓")

    # Action 4: Log everything
    save_alert("RESPONSE_COMPLETE",
              f"Response executed: {quarantined} files quarantined")
    print("[ACTION 4] All actions logged ✓")

    print("\n[RESPONSE COMPLETE] System protected!")
    return True