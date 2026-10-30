"""
mitigation.py
==============
Defines the SECURE -> DETECTED -> MITIGATING -> RESOLVED -> SECURE
state machine phases and timing. The actual phase transitions are
driven by test_engine.Engine; this module just centralizes the phase
name constants and the per-attack timing/action lookup so app.py and
test_engine.py share one source of truth.
"""

from attacks import ATTACKS

# ─── PHASES ──────────────────────────────────────────────────────────────
SECURE = "SECURE"
DETECTED = "DETECTED"
MITIGATING = "MITIGATING"
RESOLVED = "RESOLVED"

ALL_PHASES = [SECURE, DETECTED, MITIGATING, RESOLVED]

# How long (in ticks / seconds, since the engine ticks once a second)
# each non-SECURE phase holds, before advancing to the next one.
DETECTED_HOLD_SECONDS = 4
RESOLVED_HOLD_SECONDS = 4

# Max ticks the engine will feed attack-perturbed readings while waiting
# for the model to confidently detect it, before forcing detection.
MAX_RAMP_TICKS = 4
# The attack must stay in the EXECUTING stage (running, not yet declared
# detected) for this many ticks. Ramp tick 1 runs at launch, so EXECUTING is
# on screen for ticks 1..MIN_EXECUTING_TICKS (~MIN_EXECUTING_TICKS seconds) and
# DETECTED can be declared from the next tick. Detection itself (prediction +
# confidence threshold) is unchanged.
MIN_EXECUTING_TICKS = 3
assert MAX_RAMP_TICKS >= MIN_EXECUTING_TICKS + 1
DETECTION_CONFIDENCE_THRESHOLD = 0.55


def mitigation_action_for(attack_id):
    """Human-readable mitigation action text for a given attack id."""
    gen = ATTACKS.get(attack_id)
    return gen.mitigation if gen else "Investigating anomaly"


def mitigation_seconds_for(attack_id):
    gen = ATTACKS.get(attack_id)
    return gen.mitigation_seconds if gen else 5


def display_name_for(attack_id):
    gen = ATTACKS.get(attack_id)
    return gen.name if gen else attack_id
