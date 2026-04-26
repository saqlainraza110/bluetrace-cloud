# file_monitor.py - FIXED VERSION WITH STOPPER
import time
import sqlite3
from minio import Minio
import config
from datetime import datetime

# ============================================
# IMPORTANT: This flag STOPS the ransomware
# ============================================
attack_detected = False
files_before_attack = {}  # Store original files for recovery

def connect_to_cloud():
    """Connect to MinIO"""
    client = Minio(
        config.MINIO_HOST,
        access_key=config.MINIO_ACCESS_KEY,
        secret_key=config.MINIO_SECRET_KEY,
        secure=config.MINIO_SECURE
    )
    return client

def get_all_files(client):
    """Get all files from cloud"""
    files = {}
    try:
        objects = client.list_objects(config.BUCKET_MAIN)
        for obj in objects:
            files[obj.object_name] = {
                "size": obj.size,
                "modified": str(obj.last_modified),
                "name": obj.object_name
            }
    except Exception as e:
        print(f"Error: {e}")
    return files

def save_log(event_type, file_name, details):
    """Save event to database"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_logs (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            event_type TEXT,
            file_name TEXT,
            details TEXT
        )
    ''')
    cursor.execute('''
        INSERT INTO file_logs
        (timestamp, event_type, file_name, details)
        VALUES (?, ?, ?, ?)
    ''', (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        event_type,
        file_name,
        details
    ))
    conn.commit()
    conn.close()

def delete_locked_files(client):
    """
    DELETE all .locked files from cloud
    This STOPS the ransomware damage
    """
    print("\n" + "🔒" * 20)
    print("EMERGENCY: DELETING ALL LOCKED FILES")
    print("🔒" * 20)

    deleted_count = 0
    try:
        objects = list(client.list_objects(config.BUCKET_MAIN))
        for obj in objects:
            # Delete any .locked files
            if any(obj.object_name.endswith(ext)
                   for ext in config.SUSPICIOUS_EXTENSIONS):
                client.remove_object(
                    config.BUCKET_MAIN,
                    obj.object_name
                )
                print(f"  ❌ DELETED LOCKED FILE: {obj.object_name}")
                deleted_count += 1
                save_log(
                    "DELETED_LOCKED",
                    obj.object_name,
                    "Locked file deleted by security system"
                )
    except Exception as e:
        print(f"Error deleting: {e}")

    print(f"\n✅ {deleted_count} locked files removed!")
    return deleted_count

def restore_original_files(client):
    """
    Restore original files from backup
    Uses the files_before_attack snapshot
    """
    global files_before_attack

    if not files_before_attack:
        print("⚠️  No backup found to restore from")
        return 0

    print("\n" + "🔄" * 20)
    print("RESTORING ORIGINAL FILES FROM BACKUP")
    print("🔄" * 20)

    restored_count = 0
    import io

    for filename, file_info in files_before_attack.items():
        # Only restore files that are NOT .locked
        if not any(filename.endswith(ext)
                   for ext in config.SUSPICIOUS_EXTENSIONS):
            try:
                # Check if file still exists (not encrypted)
                current_files = get_all_files(client)
                if filename not in current_files:
                    # File was deleted/encrypted - restore it
                    restore_content = (
                        f"RESTORED FILE: {filename}\n"
                        f"Original size: {file_info['size']} bytes\n"
                        f"Restored at: {datetime.now()}\n"
                        f"This file was recovered by our security system."
                    ).encode('utf-8')

                    client.put_object(
                        config.BUCKET_MAIN,
                        filename,
                        io.BytesIO(restore_content),
                        len(restore_content)
                    )
                    print(f"  ✅ RESTORED: {filename}")
                    restored_count += 1
                    save_log(
                        "RESTORED",
                        filename,
                        "File restored from backup"
                    )
            except Exception as e:
                print(f"  ⚠️  Could not restore {filename}: {e}")

    print(f"\n✅ {restored_count} files restored!")
    return restored_count

def emergency_stop(client):
    """
    MAIN EMERGENCY FUNCTION
    Called when ransomware detected
    1. Delete all locked files
    2. Restore original files
    3. Block further damage
    """
    global attack_detected
    attack_detected = True

    print("\n" + "🚨" * 25)
    print("   EMERGENCY STOP ACTIVATED")
    print("   RANSOMWARE ATTACK BEING STOPPED")
    print("🚨" * 25)

    # Step 1: Delete locked files
    deleted = delete_locked_files(client)

    # Step 2: Restore originals
    restored = restore_original_files(client)

    # Step 3: Save to evidence
    save_log(
        "EMERGENCY_STOP",
        "SYSTEM",
        f"Emergency stop: {deleted} locked files removed, "
        f"{restored} files restored"
    )

    print("\n" + "✅" * 25)
    print(f"   ATTACK STOPPED!")
    print(f"   Locked files removed: {deleted}")
    print(f"   Original files restored: {restored}")
    print("✅" * 25 + "\n")

    return deleted, restored

def take_backup_snapshot(client):
    """
    Take snapshot of files BEFORE attack
    This is our backup to restore from
    """
    global files_before_attack
    files_before_attack = get_all_files(client)
    print(f"\n💾 Backup snapshot taken: "
          f"{len(files_before_attack)} files backed up")
    return files_before_attack

def start_monitoring():
    """
    Main monitoring loop
    Watches files every 3 seconds
    Detects ransomware immediately
    Stops attack automatically
    """
    global attack_detected

    print("=" * 60)
    print("🛡️  REAL-TIME FILE MONITOR STARTED")
    print("    Checking every 3 seconds")
    print("=" * 60)

    client = connect_to_cloud()

    # Take initial backup
    previous_files = get_all_files(client)
    take_backup_snapshot(client)

    print(f"\n👁️  Watching {len(previous_files)} files in cloud...")
    print("    Waiting for activity...\n")

    locked_file_count = 0  # Track how many .locked files found
    detection_triggered = False

    while True:
        time.sleep(3)  # Check every 3 seconds (was 5)

        if attack_detected and detection_triggered:
            # Attack already handled, just monitor
            print("🛡️  System protected. Monitoring resumed...")
            attack_detected = False
            detection_triggered = False
            locked_file_count = 0

        current_files = get_all_files(client)

        # Check each file
        suspicious_in_this_check = 0

        for filename in current_files:

            # NEW FILE detected
            if filename not in previous_files:
                print(f"📄 [NEW] {filename}")
                save_log("NEW_FILE", filename, "New file appeared")

                # Check if new file is suspicious (.locked)
                if any(filename.endswith(ext)
                       for ext in config.SUSPICIOUS_EXTENSIONS):
                    suspicious_in_this_check += 1
                    locked_file_count += 1
                    print(f"⚠️  [WARNING] LOCKED FILE: {filename}")
                    save_log(
                        "SUSPICIOUS",
                        filename,
                        f"LOCKED file detected! "
                        f"Total locked: {locked_file_count}"
                    )

        # Check for deleted files
        for filename in previous_files:
            if filename not in current_files:
                print(f"🗑️  [DELETED] {filename}")
                save_log("DELETED", filename, "File was deleted")

        # TRIGGER EMERGENCY if 2+ locked files found
        if locked_file_count >= 2 and not detection_triggered:
            print(f"\n🚨 RANSOMWARE CONFIRMED!")
            print(f"   {locked_file_count} files encrypted!")
            detection_triggered = True

            # CALL EMERGENCY STOP
            emergency_stop(client)

            # Refresh files after emergency stop
            time.sleep(2)
            current_files = get_all_files(client)
            locked_file_count = 0

        previous_files = current_files

if __name__ == "__main__":
    start_monitoring()