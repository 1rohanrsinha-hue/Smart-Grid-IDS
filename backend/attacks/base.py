"""
attacks/base.py
================
Shared feature schema, baseline "normal" reading generator, and small
utility helpers used by every attack module.

All 12 attack generators + the NORMAL generator produce a dict with
exactly the keys in FEATURES. Each attack perturbs a distinct subset of
features strongly (its "signature") so the Random Forest model can tell
them apart, while touching the rest only mildly (realistic noise).
"""

import math
import random

# ─── FEATURE SCHEMA (shared by train_model.py, test_engine.py, app.py) ──────
FEATURES = [
    "voltage",              # V   - bus voltage
    "frequency",             # Hz  - grid frequency
    "current",                # A   - line current
    "power_factor",            #     - 0..1
    "packets_per_sec",          # network throughput
    "packet_size_avg",           # bytes
    "unique_ips",                  # distinct source IPs seen
    "cmd_rate",                     # SCADA commands / sec
    "cmd_unknown",                    # fraction of commands not in allow-list
    "latency_ms",                      # network latency
    "retransmit_pct",                   # % packets retransmitted
    "sensor_delta",                      # sensor reading jump magnitude
    "conn_duration_avg",                  # sec - avg connection lifetime
    "ttl_variance",                        # IP TTL variance (spoofing/MITM tell)
    "auth_failures",                        # failed logins / min
    "firmware_checksum_mismatch",            # 0..1 - fraction of checksum fails
    "gps_drift",                              # meters - GPS position drift
    "time_offset_ms",                          # clock sync offset
    "load_variance",                             # % - load setpoint volatility
    "noise_floor_db",                             # RF/sensor channel noise floor
    "duplicate_pkt_ratio",                          # fraction of duplicate packets
    "privilege_level",                                # 1 (guest) .. 5 (root/admin)
]

CLIP_BOUNDS = {
    "voltage":        (150, 320),
    "frequency":       (45, 55),
    "current":          (0, 80),
    "power_factor":      (0.3, 1.0),
    "packets_per_sec":    (0, 40000),
    "packet_size_avg":     (32, 1600),
    "unique_ips":           (1, 600),
    "cmd_rate":              (0, 200),
    "cmd_unknown":            (0, 1.0),
    "latency_ms":              (1, 3000),
    "retransmit_pct":           (0, 80),
    "sensor_delta":               (0, 60),
    "conn_duration_avg":           (0.00001, 120),
    "ttl_variance":                  (0, 40),
    "auth_failures":                  (0, 40),
    "firmware_checksum_mismatch":      (0, 1.0),
    "gps_drift":                         (0, 500),
    "time_offset_ms":                     (0, 5000),
    "load_variance":                        (0, 100),
    "noise_floor_db":                         (-110, -20),
    "duplicate_pkt_ratio":                      (0, 1.0),
    "privilege_level":                            (1, 5),
}


def normal_readings(t):
    """Baseline healthy smart-grid operating conditions."""
    return {
        "voltage":         230.0 + math.sin(t * 0.1) * 2 + random.gauss(0, 0.3),
        "frequency":        50.0 + math.sin(t * 0.07) * 0.08 + random.gauss(0, 0.02),
        "current":          15.0 + math.sin(t * 0.08) * 1.0 + random.gauss(0, 0.2),
        "power_factor":      0.92 + math.sin(t * 0.05) * 0.01 + random.gauss(0, 0.005),
        "packets_per_sec":  250.0 + random.gauss(0, 25),
        "packet_size_avg":  512.0 + random.gauss(0, 40),
        "unique_ips":       float(random.randint(2, 5)),
        "cmd_rate":          10.0 + random.gauss(0, 0.8),
        "cmd_unknown":        0.0 + random.uniform(0, 0.02),
        "latency_ms":        12.0 + random.gauss(0, 1.5),
        "retransmit_pct":     0.5 + random.uniform(0, 0.3),
        "sensor_delta":       0.1 + random.uniform(0, 0.05),
        "conn_duration_avg": 18.0 + random.gauss(0, 3.0),
        "ttl_variance":       1.0 + random.uniform(0, 0.8),
        "auth_failures":      0.2 + random.uniform(0, 0.3),
        "firmware_checksum_mismatch": 0.0 + random.uniform(0, 0.01),
        "gps_drift":          1.0 + random.uniform(0, 1.0),
        "time_offset_ms":     2.0 + random.uniform(0, 2.0),
        "load_variance":      3.0 + random.gauss(0, 1.0),
        "noise_floor_db":   -95.0 + random.gauss(0, 2.0),
        "duplicate_pkt_ratio": 0.01 + random.uniform(0, 0.01),
        "privilege_level":    1.0 + (1 if random.random() < 0.1 else 0),
    }


def clip(readings):
    """Clip every feature to a realistic physical/network range."""
    for key, (lo, hi) in CLIP_BOUNDS.items():
        if key in readings:
            readings[key] = max(lo, min(hi, readings[key]))
    return readings


def ramp_intensity(scenario_tick, ramp_ticks=3):
    """0 -> 1 linear ramp over the first `ramp_ticks` ticks of an attack."""
    return min(1.0, scenario_tick / float(ramp_ticks))


class AttackGenerator:
    """
    Lightweight descriptor for a single attack type.

    id           : short machine key, e.g. "DDOS"
    name         : display name, e.g. "DDoS Flood"
    category     : "network" | "data" | "system"
    description  : one-liner for the UI / README
    mitigation   : action text shown during MITIGATING phase
    fn           : callable(t, intensity) -> readings dict (attack-perturbed)
    mitigation_seconds : how long the MITIGATING phase runs for this attack
    """

    def __init__(self, id, name, category, description, mitigation, fn,
                 mitigation_seconds=5):
        self.id = id
        self.name = name
        self.category = category
        self.description = description
        self.mitigation = mitigation
        self.fn = fn
        self.mitigation_seconds = mitigation_seconds

    def generate(self, t, intensity):
        r = self.fn(t, intensity)
        return clip(r)
