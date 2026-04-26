# detection_engine.py - FIXED VERSION
import sqlite3
import config
from datetime import datetime, timedelta

# Global flag to track if ransomware detected
ransomware_active = False

def get_recent_logs(minutes=1):
    """Get all logs from last X minutes"""
    conn = sqlite3.connect(config.DATABASE_NAME)
    cursor = conn.cursor()
    time_ago = datetime.now() - timedelta(minutes=minutes)
    try:
        cursor.execute('''
            SELECT * FROM file_logs
            WHERE timestamp > ?
            ORDER BY timestamp DESC
        ''', (time_ago.strftime("%Y-%m-%d %H:%M:%S"),))
        logs = cursor.fetchall()
    except:
        logs = []
    conn.close()
    return logs

def check_rule_1_extension(logs):
    """Rule 1: Suspicious file extensions"""
    suspicious_found = []
    for log in logs:
        file_name = str(log[3])
        for ext in config.SUSPICIOUS_EXTENSIONS:
            if file_name.endswith(ext):
                suspicious_found.append(file_name)
    if suspicious_found:
        return True, f"Locked files found: {suspicious_found}"
    return False, ""

def check_rule_2_mass_operations(logs):
    """Rule 2: Too many file changes in short time"""
    if len(logs) >= config.MAX_FILES_PER_MINUTE:
        return True, f"{len(logs)} file changes in 1 minute!"
    return False, ""

def check_rule_3_deletions(logs):
    """Rule 3: Mass file deletions"""
    deletions = [l for l in logs if l[2] == "DELETED"]
    if len(deletions) >= 2:
        return True, f"{len(deletions)} files deleted!"
    return False, ""

def analyze_threat():
    """Main detection - returns threat info"""
    global ransomware_active

    logs = get_recent_logs(minutes=1)
    score = 0
    reasons = []

    rule1, msg1 = check_rule_1_extension(logs)
    if rule1:
        score += 2  # Extension change = HIGH score
        reasons.append(f"Rule 1 TRIGGERED: {msg1}")
        print(f"\n⚠️  [RULE 1] {msg1}")

    rule2, msg2 = check_rule_2_mass_operations(logs)
    if rule2:
        score += 1
        reasons.append(f"Rule 2 TRIGGERED: {msg2}")
        print(f"⚠️  [RULE 2] {msg2}")

    rule3, msg3 = check_rule_3_deletions(logs)
    if rule3:
        score += 1
        reasons.append(f"Rule 3 TRIGGERED: {msg3}")
        print(f"⚠️  [RULE 3] {msg3}")

    if score >= config.ALERT_THRESHOLD:
        ransomware_active = True
        print("\n" + "🚨" * 20)
        print("RANSOMWARE DETECTED! SCORE:", score)
        print("🚨" * 20)
        return {
            "threat_detected": True,
            "score": score,
            "reasons": reasons,
            "message": "RANSOMWARE DETECTED",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    return {
        "threat_detected": False,
        "score": score,
        "message": "System Normal ✅"
    }