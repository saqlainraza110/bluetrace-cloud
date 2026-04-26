# ransomware_simulator.py - FIXED VERSION
# Now encrypts ONE FILE AT A TIME with delay
# Gives our detection tool time to react!

from minio import Minio
import config
import time
import io

def simulate_ransomware_attack():
    """
    Simulates ransomware attack
    NOW: Encrypts files with delay between each
    This gives our tool time to DETECT and STOP it
    """
    print("\n" + "=" * 60)
    print("🔴 RANSOMWARE SIMULATION STARTING")
    print("   Encrypting files one by one...")
    print("   Our tool should detect and stop this!")
    print("=" * 60)

    client = Minio(
        config.MINIO_HOST,
        access_key=config.MINIO_ACCESS_KEY,
        secret_key=config.MINIO_SECRET_KEY,
        secure=config.MINIO_SECURE
    )

    try:
        files = list(client.list_objects(config.BUCKET_MAIN))

        # Only encrypt normal files (not already locked)
        normal_files = [
            f for f in files
            if not any(f.object_name.endswith(ext)
                      for ext in config.SUSPICIOUS_EXTENSIONS)
        ]

        if len(normal_files) == 0:
            print("\n⚠️  No normal files found!")
            print("   Please restore files first or upload new ones")
            return

        print(f"\n🎯 Found {len(normal_files)} files to encrypt")
        print("   Encrypting with 3 second delay between files")
        print("   Watch the monitor terminal for detection!\n")

        for i, file_obj in enumerate(normal_files):
            original_name = file_obj.object_name
            new_name = original_name + ".locked"

            # Get file
            response = client.get_object(
                config.BUCKET_MAIN,
                original_name
            )
            content = response.read()

            # Fake encrypt
            fake_encrypted = b"ENCRYPTED_" + content

            # Upload locked version
            client.put_object(
                config.BUCKET_MAIN,
                new_name,
                io.BytesIO(fake_encrypted),
                len(fake_encrypted)
            )

            # Delete original
            client.remove_object(
                config.BUCKET_MAIN,
                original_name
            )

            print(f"🔐 [{i+1}/{len(normal_files)}] "
                  f"ENCRYPTED: {original_name} → {new_name}")

            # Wait 3 seconds between each file
            # This gives monitor time to detect!
            print(f"   ⏳ Waiting 3 seconds...")
            time.sleep(3)

        print("\n[SIMULATION COMPLETE]")

    except Exception as e:
        print(f"Error: {e}")

def restore_all_files():
    """
    Manually restore all files to original state
    Run this to reset after a test
    """
    print("\n🔄 RESTORING ALL FILES...")

    client = Minio(
        config.MINIO_HOST,
        access_key=config.MINIO_ACCESS_KEY,
        secret_key=config.MINIO_SECRET_KEY,
        secure=config.MINIO_SECURE
    )

    # Delete all locked files
    files = list(client.list_objects(config.BUCKET_MAIN))
    for f in files:
        if any(f.object_name.endswith(ext)
               for ext in config.SUSPICIOUS_EXTENSIONS):
            client.remove_object(config.BUCKET_MAIN, f.object_name)
            print(f"  ❌ Removed: {f.object_name}")

    # Upload fresh original files
    original_files = {
        "employee_records.txt": "Employee Records 2026\nJohn Doe - Manager\nJane Smith - Developer",
        "financial_report.txt": "Financial Report Q1 2026\nRevenue: $500,000\nExpenses: $200,000",
        "customer_data.txt": "Customer Database\nCustomer 1: ABC Corp\nCustomer 2: XYZ Ltd",
        "annual_report.txt": "Annual Report 2026\nCompany Performance: Excellent\nGrowth: 25%",
        "transaction_history.txt": "Transactions 2026\nTX001: $5000\nTX002: $3000\nTX003: $7500"
    }

    for filename, content in original_files.items():
        content_bytes = content.encode('utf-8')
        client.put_object(
            config.BUCKET_MAIN,
            filename,
            io.BytesIO(content_bytes),
            len(content_bytes)
        )
        print(f"  ✅ Restored: {filename}")

    print("\n✅ ALL FILES RESTORED!")
    print("   You can run the attack simulation again")

if __name__ == "__main__":
    print("=" * 50)
    print("RANSOMWARE SIMULATOR")
    print("=" * 50)
    print("\n1. Run ransomware attack")
    print("2. Restore all files (reset)")
    print("3. Exit")

    choice = input("\nEnter choice (1/2/3): ").strip()

    if choice == "1":
        simulate_ransomware_attack()
    elif choice == "2":
        restore_all_files()
    elif choice == "3":
        print("Exiting...")
    else:
        print("Invalid choice")