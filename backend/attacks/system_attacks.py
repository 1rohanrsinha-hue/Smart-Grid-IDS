"""
attacks/system_attacks.py
============================
System / endpoint attack signatures: Command Injection, Malware,
Firmware Tampering, Sensor Jamming, Insider Privilege Escalation.

These are the TRAINING-time synthetic generators. Each one is
deliberately scoped to touch ONLY the features its real counterpart
in real_attacks/ can genuinely, honestly produce - so a live real
reading lands in the same statistical neighborhood as training data
instead of only partially matching the learned pattern.
"""

import random
from .base import normal_readings, AttackGenerator


def cmd_inject_readings(t, intensity):
    r = normal_readings(t)
    r["cmd_rate"] = 30 + intensity * 130 + random.gauss(0, 15)
    r["cmd_unknown"] = 0.7 + intensity * 0.3 + random.gauss(0, 0.03)
    return r


def malware_readings(t, intensity):
    r = normal_readings(t)
    r["packets_per_sec"] = 700 + intensity * 1800 + random.gauss(0, 150)
    r["packet_size_avg"] = 1400 + random.gauss(0, 40)  # large = data exfil
    r["unique_ips"] = float(random.randint(6, 14))
    r["retransmit_pct"] = 1 + intensity * 4 + random.gauss(0, 0.5)
    return r


def firmware_tamper_readings(t, intensity):
    r = normal_readings(t)
    r["firmware_checksum_mismatch"] = 0.5 + intensity * 0.5 + random.gauss(0, 0.02)
    return r


def jamming_readings(t, intensity):
    r = normal_readings(t)
    r["noise_floor_db"] = -95 + intensity * 70 + random.gauss(0, 4)
    r["retransmit_pct"] = 10 + intensity * 80 + random.gauss(0, 5)
    r["sensor_delta"] = 3 + intensity * 22 + random.gauss(0, 2.5)
    return r


def priv_esc_readings(t, intensity):
    r = normal_readings(t)
    r["auth_failures"] = 5 + intensity * 35 + random.gauss(0, 3)
    r["privilege_level"] = 1 + intensity * 4 + random.gauss(0, 0.3)
    return r


REGISTRY = [
    AttackGenerator(
        "CMD_INJECT", "Command Injection", "system",
        "Unauthorized SCADA commands injected from an untrusted source.",
        "Revoking command source credentials, enforcing command allow-list",
        cmd_inject_readings, mitigation_seconds=4,
    ),
    AttackGenerator(
        "MALWARE", "Malware Activity", "system",
        "Malicious process scanning the network and staging data for exfiltration.",
        "Isolating affected process/host, killing malicious process tree",
        malware_readings, mitigation_seconds=6,
    ),
    AttackGenerator(
        "FIRMWARE_TAMPER", "Firmware Tampering", "system",
        "Device firmware image fails checksum validation against the signed baseline.",
        "Halting firmware update, rolling back to signed firmware image",
        firmware_tamper_readings, mitigation_seconds=6,
    ),
    AttackGenerator(
        "JAMMING", "Sensor Jamming (DoS on sensors)", "system",
        "RF/communication channel noise floor rises, starving sensors of bandwidth.",
        "Switching to backup RF channel, engaging wired sensor fallback",
        jamming_readings, mitigation_seconds=5,
    ),
    AttackGenerator(
        "PRIV_ESC", "Insider Privilege Escalation", "system",
        "An account repeatedly fails auth then jumps to an elevated privilege level.",
        "Revoking elevated session, forcing credential reset & re-authentication",
        priv_esc_readings, mitigation_seconds=5,
    ),
]
