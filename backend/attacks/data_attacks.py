"""
attacks/data_attacks.py
=========================
Data-integrity / physical-state attack signatures: FDI, Load-Altering,
GPS/Time-Sync Spoofing.

These are the TRAINING-time synthetic generators. Each one is
deliberately scoped to touch ONLY the features its real counterpart
in real_attacks/ can genuinely, honestly produce.
"""

import random
from .base import normal_readings, AttackGenerator


def fdi_readings(t, intensity):
    r = normal_readings(t)
    r["voltage"] = 230 + (random.random() - 0.5) * 60 * intensity
    r["frequency"] = 50 + (random.random() - 0.5) * 4 * intensity
    r["sensor_delta"] = 15 + intensity * 45 + random.gauss(0, 5)
    return r


def load_alter_readings(t, intensity):
    r = normal_readings(t)
    r["load_variance"] = 15 + intensity * 65 + random.gauss(0, 6)
    r["current"] = 15 + intensity * 30 + random.gauss(0, 4)
    return r


def gps_spoof_readings(t, intensity):
    r = normal_readings(t)
    r["gps_drift"] = 15 + intensity * 480 + random.gauss(0, 20)
    r["time_offset_ms"] = 50 + intensity * 4300 + random.gauss(0, 100)
    return r


REGISTRY = [
    AttackGenerator(
        "FDI", "False Data Injection", "data",
        "Manipulated sensor telemetry (voltage/frequency) fed into state estimation.",
        "Quarantining sensor feed, reverting to last validated reading",
        fdi_readings, mitigation_seconds=5,
    ),
    AttackGenerator(
        "LOAD_ALTER", "Load-Altering Attack", "data",
        "Coordinated manipulation of controllable load to destabilize demand.",
        "Clamping load setpoints, reverting to manual dispatch control",
        load_alter_readings, mitigation_seconds=6,
    ),
    AttackGenerator(
        "GPS_SPOOF", "GPS/Time-Sync Spoofing", "data",
        "Falsified GPS/PTP timing source skews phasor measurement synchronization.",
        "Switching to holdover clock, rejecting spoofed GPS/time source",
        gps_spoof_readings, mitigation_seconds=5,
    ),
]
