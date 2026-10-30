"""
tests/test_mitigation.py
===========================
Verifies the state machine transitions SECURE -> DETECTED -> MITIGATING
-> RESOLVED -> SECURE in the right order and never skips a state.
"""

import os
import sys
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import mitigation as mit  # noqa: E402
from test_engine import Engine  # noqa: E402


def _run_ticks(engine, n):
    phases = []
    for _ in range(n):
        engine._tick()
        phases.append(engine.phase)
    return phases


def test_full_lifecycle_visits_every_phase_in_order():
    random.seed(1)
    engine = Engine()
    result = engine.trigger("DDOS")
    assert result["ok"] is True

    phases = _run_ticks(engine, 25)

    # First non-secure phase reached must be DETECTED, never MITIGATING/RESOLVED directly.
    first_attack_phase_idx = phases.index(mit.DETECTED)
    assert mit.MITIGATING not in phases[:first_attack_phase_idx]
    assert mit.RESOLVED not in phases[:first_attack_phase_idx]

    # Once DETECTED, the next distinct phase must be MITIGATING (never skip straight to RESOLVED).
    detected_idx = phases.index(mit.DETECTED)
    remaining = phases[detected_idx:]
    first_change = next(p for p in remaining if p != mit.DETECTED)
    assert first_change == mit.MITIGATING

    # Once MITIGATING, the next distinct phase must be RESOLVED.
    mitigating_idx = phases.index(mit.MITIGATING)
    remaining2 = phases[mitigating_idx:]
    first_change2 = next(p for p in remaining2 if p != mit.MITIGATING)
    assert first_change2 == mit.RESOLVED

    # Eventually returns to SECURE.
    assert phases[-1] in (mit.RESOLVED, mit.SECURE)


def test_manual_trigger_rejected_while_attack_in_progress():
    random.seed(2)
    engine = Engine()
    first = engine.trigger("FDI")
    assert first["ok"] is True
    engine._tick()  # moves into ramping/DETECTED
    second = engine.trigger("MALWARE")
    assert second["ok"] is False


def test_system_returns_to_secure_with_no_active_attack():
    random.seed(3)
    engine = Engine()
    engine.trigger("PORT_SCAN")
    _run_ticks(engine, 20)
    assert engine.phase == mit.SECURE
    assert engine.active_attack is None
