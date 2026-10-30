"""
rule_engine.py
===============
Independent, threshold-based hybrid detection layer. Completely
separate from the ML model - it looks at the raw telemetry/network
reading and fires simple, explainable rules. Used to show a genuine
"ML vs rules" agree/disagree comparison on the dashboard.

Each rule is a (label, predicate, description) tuple. If ANY rule
fires, the verdict is SUSPICIOUS and we report the first (highest
priority) rule that tripped; otherwise NORMAL.
"""

RULES = [
    ("voltage_out_of_range",
     lambda r: r["voltage"] < 200 or r["voltage"] > 260,
     "Voltage outside 200-260V safe operating band"),
    ("frequency_out_of_range",
     lambda r: r["frequency"] < 49.0 or r["frequency"] > 51.0,
     "Grid frequency outside 49-51Hz band"),
    ("ddos_packet_flood",
     lambda r: r["packets_per_sec"] > 5000,
     "packets_per_sec exceeds 5000/s flood threshold"),
    ("high_unique_ip_fanout",
     lambda r: r["unique_ips"] > 60,
     "unique_ips exceeds 60 - possible distributed source"),
    ("unknown_command_ratio",
     lambda r: r["cmd_unknown"] > 0.5,
     "cmd_unknown exceeds 50% of SCADA commands"),
    ("command_flood",
     lambda r: r["cmd_rate"] > 30,
     "cmd_rate exceeds 30 commands/sec"),
    ("sensor_delta_spike",
     lambda r: r["sensor_delta"] > 8,
     "sensor_delta exceeds 8 - abnormal reading jump"),
    ("high_retransmit",
     lambda r: r["retransmit_pct"] > 15,
     "retransmit_pct exceeds 15%"),
    ("ttl_variance_spike",
     lambda r: r["ttl_variance"] > 6,
     "ttl_variance exceeds 6 - possible relay/spoofing"),
    ("duplicate_packet_flood",
     lambda r: r["duplicate_pkt_ratio"] > 0.25,
     "duplicate_pkt_ratio exceeds 25% - possible replay"),
    ("firmware_checksum_fail",
     lambda r: r["firmware_checksum_mismatch"] > 0.3,
     "firmware_checksum_mismatch exceeds 30%"),
    ("gps_drift_spike",
     lambda r: r["gps_drift"] > 25,
     "gps_drift exceeds 25m"),
    ("time_offset_spike",
     lambda r: r["time_offset_ms"] > 150,
     "time_offset_ms exceeds 150ms"),
    ("load_variance_spike",
     lambda r: r["load_variance"] > 25,
     "load_variance exceeds 25%"),
    ("noise_floor_spike",
     lambda r: r["noise_floor_db"] > -70,
     "noise_floor_db exceeds -70dB - possible jamming"),
    ("auth_failure_spike",
     lambda r: r["auth_failures"] > 4,
     "auth_failures exceeds 4/min"),
    ("privilege_jump",
     lambda r: r["privilege_level"] >= 4,
     "privilege_level reached 4 or higher"),
]


def evaluate(reading):
    """Run every rule against a telemetry reading dict.

    Returns: {
      verdict: "NORMAL" | "SUSPICIOUS",
      fired_rule: rule label or None,
      fired_description: human text or None,
      all_fired: [labels...]
    }
    """
    fired = []
    for label, predicate, desc in RULES:
        try:
            if predicate(reading):
                fired.append((label, desc))
        except (KeyError, TypeError):
            continue

    if not fired:
        return {
            "verdict": "NORMAL",
            "fired_rule": None,
            "fired_description": None,
            "all_fired": [],
        }
    return {
        "verdict": "SUSPICIOUS",
        "fired_rule": fired[0][0],
        "fired_description": fired[0][1],
        "all_fired": [label for label, _ in fired],
    }
