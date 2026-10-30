"""
severity.py
============
Simple, explainable severity scoring - deliberately NOT a black box,
so it can be defended in a viva: severity = base_severity(attack) x
confidence x node_repeat_factor, then bucketed into LOW/MEDIUM/HIGH/
CRITICAL.

base_severity: how dangerous this attack class inherently is to grid
operation (1-5 scale, assigned by hand based on impact - e.g. Load-
Altering and Command Injection can directly affect physical grid
state, so they're weighted higher than a Port Scan).

node_repeat_factor: if the SAME node has already been attacked more
than once in the current session, bump severity - repeated targeting
of one asset is a stronger signal than a one-off.
"""

BASE_SEVERITY = {
    "DDOS": 3,
    "FDI": 4,
    "CMD_INJECT": 5,
    "MALWARE": 4,
    "MITM": 3,
    "REPLAY": 3,
    "PORT_SCAN": 2,
    "FIRMWARE_TAMPER": 4,
    "GPS_SPOOF": 4,
    "LOAD_ALTER": 5,
    "JAMMING": 3,
    "PRIV_ESC": 5,
}

# score thresholds -> band. Max possible raw score = 5 (base) * 1.0 (conf) * 1.6 (repeat cap) = 8
BANDS = [
    (6.0, "CRITICAL"),
    (4.0, "HIGH"),
    (2.0, "MEDIUM"),
    (0.0, "LOW"),
]


def node_repeat_factor(node_hit_counts, node_id):
    """1.0 for a node's first hit this session, +0.2 per repeat, capped at 1.6."""
    count = node_hit_counts.get(node_id, 0)
    return min(1.6, 1.0 + 0.2 * count)


def score(attack_id, confidence, node_hit_counts, node_id):
    base = BASE_SEVERITY.get(attack_id, 3)
    repeat = node_repeat_factor(node_hit_counts, node_id)
    raw = base * max(0.0, min(1.0, confidence)) * repeat
    return round(raw, 2)


def band_for(raw_score):
    for threshold, label in BANDS:
        if raw_score >= threshold:
            return label
    return "LOW"


def evaluate(attack_id, confidence, node_hit_counts, node_id):
    raw = score(attack_id, confidence, node_hit_counts, node_id)
    return {
        "score": raw,
        "band": band_for(raw),
        "base_severity": BASE_SEVERITY.get(attack_id, 3),
        "confidence_factor": round(max(0.0, min(1.0, confidence)), 2),
        "node_repeat_factor": node_repeat_factor(node_hit_counts, node_id),
    }
