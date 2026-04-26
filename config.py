# config.py
# All settings for our complete security system

# ─────────────────────────────────────
# MinIO Cloud Storage Settings
# ─────────────────────────────────────
MINIO_HOST = "localhost:9000"
MINIO_ACCESS_KEY = "admin"
MINIO_SECRET_KEY = "password123"
MINIO_SECURE = False

# ─────────────────────────────────────
# Bucket Names
# ─────────────────────────────────────
BUCKET_MAIN = "cloud-files"
BUCKET_QUARANTINE = "quarantine-zone"
BUCKET_EVIDENCE = "forensic-evidence"

# ─────────────────────────────────────
# Attack 2: Ransomware Detection
# ─────────────────────────────────────
MAX_FILES_PER_MINUTE = 5
SUSPICIOUS_EXTENSIONS = [
    ".locked", ".encrypted",
    ".crypto", ".enc", ".rnsmwr"
]
ALERT_THRESHOLD = 2

# ─────────────────────────────────────
# Attack 1: Brute Force Detection
# ─────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 60
BRUTE_FORCE_BLOCK_DURATION = 300

# ─────────────────────────────────────
# Attack 3: Unauthorized Access
# ─────────────────────────────────────
VALID_ACCESS_KEYS = ["admin"]
UNAUTHORIZED_THRESHOLD = 3
SENSITIVE_FILES = [
    "financial_report.txt",
    "employee_records.txt",
    "customer_data.txt",
    "transaction_history.txt",
    "annual_report.txt"
]

# ─────────────────────────────────────
# Database
# ─────────────────────────────────────
DATABASE_NAME = "forensic_logs.db"

# ─────────────────────────────────────
# Fake Attacker IPs (for simulation)
# ─────────────────────────────────────
FAKE_ATTACKER_IP_1 = "192.168.1.105"
FAKE_ATTACKER_IP_2 = "192.168.1.106"
FAKE_ATTACKER_IP_3 = "10.0.0.55"

print("✅ Config loaded successfully!")