# brute_force_simulator.py
# Simulates a hacker trying to brute force login
# Attack 1 Simulation

import time
import random
import config
from datetime import datetime
from brute_force_monitor import check_brute_force

# Common passwords hackers try
COMMON_PASSWORDS = [
    "123456", "password", "admin123", "letmein",
    "welcome", "monkey", "dragon", "master",
    "sunshine", "princess", "abc123", "qwerty",
    "baseball", "football", "shadow", "superman",
    "michael", "password1", "123123", "654321",
    "iloveyou", "admin", "root", "toor", "pass",
    "test", "guest", "login", "hello", "123"
]

COMMON_USERNAMES = [
    "admin", "administrator", "root", "user",
    "test", "guest", "support", "manager"
]


def simulate_brute_force_attack(
    attacker_ip=None,
    attempts=20,
    delay=0.5
):
    """
    Simulates a brute force attack.
    Tries many username/password combinations.
    """

    if attacker_ip is None:
        attacker_ip = config.FAKE_ATTACKER_IP_1

    print("\n" + "=" * 60)
    print("🔴 BRUTE FORCE SIMULATION STARTING")
    print(f"   Simulating hacker from IP: {attacker_ip}")
    print(f"   Will try {attempts} password combinations")
    print(f"   Delay between attempts: {delay} seconds")
    print("=" * 60)
    