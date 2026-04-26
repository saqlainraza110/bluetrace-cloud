# attacker_simulator.py
# Simulates all three types of attacks for testing

import time
from datetime import datetime
from security_logger import log_security_event, is_blocked


def print_banner(text):
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)


def simulate_brute_force():
    """
    Simulates Attack 1: Brute Force Password Attack

    Hacker IP: 192.168.1.105
    Target: admin account
    Method: Trying many passwords
    """

    print_banner("ATTACK 1: BRUTE FORCE SIMULATION")

    attacker_ip = "192.168.1.105"
    target_username = "admin"

    # Common passwords hackers try
    password_attempts = [
        "123456",
        "password",
        "admin",
        "admin123",
        "company2026",
        "password123",
        "letmein",
        "qwerty"
    ]

    print(f"\nAttacker IP  : {attacker_ip}")
    print(f"Target User  : {target_username}")
    print(f"Total Attempts: {len(password_attempts)}")
    print(f"\nStarting attack at: {datetime.now().strftime('%H:%M:%S')}")
    print("-" * 40)

    for i, password in enumerate(password_attempts, 1):

        # Check if this IP got blocked by our tool
        if is_blocked("IP", attacker_ip):
            print(f"\n🛑 [ATTACK STOPPED]")
            print(f"   IP {attacker_ip} has been BLOCKED by security system!")
            print(f"   Attack stopped at attempt {i}")
            break

        # Check if user got blocked
        if is_blocked("USER", target_username):
            print(f"\n🛑 [ATTACK STOPPED]")
            print(f"   Username '{target_username}' has been BLOCKED!")
            print(f"   Attack stopped at attempt {i}")
            break

        # Simulate failed login attempt
        print(f"[ATTEMPT {i}] Password: '{password}' → ❌ FAILED")

        log_security_event(
            event_type="LOGIN_FAILED",
            username=target_username,
            ip_address=attacker_ip,
            action="LOGIN_ATTEMPT",
            target_resource="MinIO Console / Cloud Storage",
            status="FAILED",
            details=(
                f"Failed login attempt {i}: "
                f"Wrong password '{password}' "
                f"for user '{target_username}'"
            )
        )

        time.sleep(1)

    print(f"\n[SIMULATION DONE] Brute force attack simulated")
    print(f"Watch main.py terminal - should show BRUTE FORCE DETECTED!")


def simulate_unauthorized_access():
    """
    Simulates Attack 3: Unauthorized Access

    Hacker uses invalid keys or tries forbidden buckets
    Different IP from brute force attack
    """

    print_banner("ATTACK 3: UNAUTHORIZED ACCESS SIMULATION")

    attacker_ip = "192.168.1.200"
    attacker_username = "hacker_user"

    # What the hacker tries to access
    attack_scenarios = [
        {
            "event_type": "INVALID_ACCESS_KEY",
            "action": "CONNECT_WITH_INVALID_KEY",
            "target": "MinIO Cloud Storage",
            "details": "Connection attempt with invalid access key: 'HACKED_KEY_123'"
        },
        {
            "event_type": "FORBIDDEN_BUCKET",
            "action": "READ_BUCKET",
            "target": "forensic-evidence",
            "details": "Unauthorized attempt to read restricted bucket 'forensic-evidence'"
        },
        {
            "event_type": "FORBIDDEN_BUCKET",
            "action": "READ_BUCKET",
            "target": "quarantine-zone",
            "details": "Unauthorized attempt to read restricted bucket 'quarantine-zone'"
        },
        {
            "event_type": "UNAUTHORIZED_ACCESS",
            "action": "DELETE_FILES",
            "target": "cloud-files",
            "details": "Unauthorized attempt to delete files from 'cloud-files' bucket"
        },
        {
            "event_type": "ACCESS_DENIED",
            "action": "ADMIN_PANEL_ACCESS",
            "target": "MinIO Admin Panel",
            "details": "Unauthorized access attempt to admin panel with unknown credentials"
        }
    ]

    print(f"\nAttacker IP  : {attacker_ip}")
    print(f"Username     : {attacker_username}")
    print(f"Total Attacks: {len(attack_scenarios)}")
    print(f"\nStarting attack at: {datetime.now().strftime('%H:%M:%S')}")
    print("-" * 40)

    for i, scenario in enumerate(attack_scenarios, 1):

        # Check if IP got blocked
        if is_blocked("IP", attacker_ip):
            print(f"\n🛑 [ATTACK STOPPED]")
            print(f"   IP {attacker_ip} has been BLOCKED!")
            print(f"   Attack stopped at scenario {i}")
            break

        print(
            f"[ATTEMPT {i}] {scenario['event_type']} → "
            f"Target: {scenario['target']} → ❌ DENIED"
        )

        log_security_event(
            event_type=scenario["event_type"],
            username=attacker_username,
            ip_address=attacker_ip,
            action=scenario["action"],
            target_resource=scenario["target"],
            status="DENIED",
            details=scenario["details"]
        )

        time.sleep(1)

    print(f"\n[SIMULATION DONE] Unauthorized access attack simulated")
    print(f"Watch main.py terminal - should show UNAUTHORIZED ACCESS DETECTED!")


def simulate_all_attacks():
    """
    Run all 3 attacks one by one
    For full demo
    """

    print_banner("FULL ATTACK SIMULATION - ALL 3 ATTACKS")

    print("\nThis will simulate:")
    print("  Attack 1: Brute Force    (from 192.168.1.105)")
    print("  Attack 2: Ransomware     (encrypts files in MinIO)")
    print("  Attack 3: Unauthorized   (from 192.168.1.200)")
    print("\nMake sure main.py is running in another terminal!")

    input("\nPress ENTER to start Attack 1 (Brute Force)...")
    simulate_brute_force()

    print("\n\nWaiting 10 seconds before next attack...")
    time.sleep(10)

    input("\nPress ENTER to start Attack 2 (Ransomware)...")
    from ransomware_simulator import simulate_ransomware_attack
    simulate_ransomware_attack()

    print("\n\nWaiting 10 seconds before next attack...")
    time.sleep(10)

    input("\nPress ENTER to start Attack 3 (Unauthorized Access)...")
    simulate_unauthorized_access()

    print_banner("ALL ATTACKS COMPLETED")
    print("\nCheck your dashboard at http://localhost:5000")
    print("Check reports folder for PDF forensic report")
    print("Check MinIO at http://localhost:9001")


if __name__ == "__main__":
    print_banner("ATTACK SIMULATOR - CLOUD SECURITY PROJECT")

    print("\nSelect attack to simulate:")
    print("  1. Brute Force Attack Only")
    print("  2. Unauthorized Access Attack Only")
    print("  3. Run ALL 3 Attacks (Full Demo)")
    print("  4. Exit")

    choice = input("\nEnter choice (1/2/3/4): ").strip()

    if choice == "1":
        simulate_brute_force()
    elif choice == "2":
        simulate_unauthorized_access()
    elif choice == "3":
        simulate_all_attacks()
    elif choice == "4":
        print("Exiting...")
    else:
        print("Invalid choice. Please enter 1, 2, 3 or 4.")