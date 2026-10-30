"""
tests/test_attack_visibility.py
=================================
Covers the live-attack visibility fields added to /api/status:
attack_stage, target_activity and attack_headline_metric.
"""

import os
import sys
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import mitigation as mit  # noqa: E402
import real_attacks as real_attacks_mod  # noqa: E402
from attacks import ATTACKS  # noqa: E402
from real_attacks import dummy_target  # noqa: E402
from test_engine import Engine, TARGET_FEED_LINES  # noqa: E402


def _undetected_engine():
    """Engine whose model reports NORMAL, so the attack stays in the
    ramp (EXECUTING) until the forced-detection tick."""
    engine = Engine()
    engine._predict = lambda reading: ("NORMAL", 1.0, {"NORMAL": 1.0})
    return engine


def test_attack_stage_goes_executing_detected_mitigating_resolved_none():
    random.seed(1)
    engine = _undetected_engine()
    assert engine.get_status()["attack_stage"] == "NONE"
    assert engine.trigger("DDOS")["ok"] is True

    stages = []
    try:
        for _ in range(40):
            engine._tick()
            s = engine.get_status()
            stages.append(s["attack_stage"])
            if s["attack_stage"] == "EXECUTING":
                assert s["phase"] == mit.SECURE
                assert s["attack_elapsed_s"] >= 0
            if s["attack_stage"] in ("MITIGATING", "RESOLVED"):
                assert s["mitigation_action"]
            if len(stages) > 5 and stages[-1] == "NONE":
                break
    finally:
        real_attacks_mod.manager.stop("DDOS")

    collapsed = [st for i, st in enumerate(stages) if i == 0 or st != stages[i - 1]]
    assert collapsed == ["EXECUTING", "DETECTED", "MITIGATING", "RESOLVED", "NONE"]
    assert engine.get_status()["attack_elapsed_s"] == 0.0


def test_target_activity_capped_and_cleared_on_new_attack():
    random.seed(1)
    engine = Engine()
    log = dummy_target.events
    log.clear()
    for i in range(dummy_target.EVENT_BUFFER_MAX * 3):
        log.record(f"k{i}", "TEST", f"stale event {i}")
    assert len(log.recent(1000)) == dummy_target.EVENT_BUFFER_MAX

    engine.active_attack = "DDOS"  # status shows the feed while an attack is active
    engine.attack_started_at = 0
    feed = engine.get_status()["target_activity"]
    assert len(feed["events"]) == TARGET_FEED_LINES
    assert feed["events"][0]["summary"] == f"stale event {dummy_target.EVENT_BUFFER_MAX * 3 - 1}"  # newest first
    engine.active_attack = None
    engine.attack_started_at = None

    assert engine.trigger("PRIV_ESC")["ok"] is True
    try:
        engine._tick()
        summaries = [e["summary"] for e in log.recent(1000)]
        assert not any(s.startswith("stale event") for s in summaries)
    finally:
        real_attacks_mod.manager.stop("PRIV_ESC")


def test_target_activity_empty_when_idle():
    engine = Engine()
    dummy_target.events.record("idle", "TEST", "should not be shown")
    assert engine.get_status()["target_activity"]["events"] == []


def test_aggregation_collapses_bursts():
    log = dummy_target.DeviceEventLog()
    for _ in range(500):
        log.record("flood", "HTTP", "GET / 200 OK", "HTTP flood: {n} requests in last 0.5s")
    assert len(log.recent(100)) <= 2


def test_headline_metric_covers_all_attacks():
    random.seed(1)
    engine = Engine()
    assert set(real_attacks_mod.HEADLINE_METRICS) == set(ATTACKS)
    for attack_id in ATTACKS:
        m = real_attacks_mod.headline_metric(attack_id, {})
        assert m["label"], attack_id
        assert m["value"] == "--"
        assert set(m) == {"label", "value", "unit"}
    assert real_attacks_mod.headline_metric("FIRMWARE_TAMPER", {"tampered": True})["value"] == "NO"
    assert real_attacks_mod.headline_metric("DDOS", {"packets_per_sec": 412.0})["value"] == 412.0
    assert engine.get_status()["attack_headline_metric"]["value"] == "--"


def test_executing_lasts_min_ticks_even_if_model_detects_instantly():
    random.seed(1)
    engine = Engine()
    engine._predict = lambda reading: ("DDOS", 0.99, {"DDOS": 0.99, "NORMAL": 0.01})
    assert engine.trigger("DDOS")["ok"] is True
    stages = []
    try:
        for _ in range(8):
            engine._tick()
            s = engine.get_status()
            stages.append(s["attack_stage"])
            if s["attack_stage"] == "EXECUTING":
                # prediction/confidence keep updating while the attack is still undeclared
                assert s["prediction"] == "DDOS" and s["confidence"] == 0.99
            if s["attack_stage"] == "DETECTED":
                break
    finally:
        real_attacks_mod.manager.stop("DDOS")
    assert stages == ["EXECUTING"] * mit.MIN_EXECUTING_TICKS + ["DETECTED"]
    assert mit.MAX_RAMP_TICKS >= mit.MIN_EXECUTING_TICKS + 1


def test_attack_timeline_is_ordered_and_kept_until_next_attack(monkeypatch):
    import itertools
    import test_engine
    clock = itertools.count(100)                      # fake clock: every reading is later than the last
    monkeypatch.setattr(test_engine, "_mono", lambda: float(next(clock)))
    random.seed(1)
    engine = _undetected_engine()
    assert engine.get_status()["attack_timeline"] is None
    assert engine.trigger("PRIV_ESC")["ok"] is True
    try:
        for _ in range(40):
            engine._tick()
            if engine.get_status()["attack_stage"] == "NONE" and engine.attack_times["resolved"]:
                break
    finally:
        real_attacks_mod.manager.stop("PRIV_ESC")

    t = engine.attack_times
    assert t["launched"] < t["detected"] < t["mitigation_started"] < t["resolved"]

    tl = engine.get_status()["attack_timeline"]          # stays after the attack has ended
    assert tl["active"] is False and tl["attack_id"] == "PRIV_ESC"
    assert 0 < tl["detected_s"] < tl["mitigation_started_s"] < tl["resolved_s"]
    assert tl["time_to_detect_s"] == tl["detected_s"]

    inc = list(engine.incident_records.values())[-1]
    assert inc["time_to_detect_s"] == tl["detected_s"]

    engine.trigger("DDOS")
    engine._tick()
    try:
        tl2 = engine.get_status()["attack_timeline"]     # replaced once the next attack launches
        assert tl2["attack_id"] == "DDOS" and tl2["active"] is True and tl2["detected_s"] is None
    finally:
        real_attacks_mod.manager.stop("DDOS")


def test_report_exports_time_to_detect():
    import report_generator
    event = {"id": 1, "attack": "X", "time_to_detect_s": 3.1}
    assert "time_to_detect_s" in report_generator.to_csv_bytes(event).decode().splitlines()[0]
    assert b"3.1" in report_generator.to_csv_bytes(event)
    assert report_generator.to_pdf_bytes(event).startswith(b"%PDF")


import time  # noqa: E402
import pytest  # noqa: E402


@pytest.mark.parametrize("attack_id", list(ATTACKS))
def test_headline_is_never_dashes_at_resolved_and_is_final(attack_id):
    random.seed(1)
    engine = Engine()
    assert engine.trigger(attack_id)["ok"] is True
    resolved = None
    try:
        engine._tick()
        time.sleep(1.2)                      # let the real runner produce real measurements
        for _ in range(60):
            engine._tick()
            s = engine.get_status()
            if s["attack_stage"] == "RESOLVED":
                resolved = s
                break
    finally:
        real_attacks_mod.manager.stop(attack_id)
    assert resolved is not None, attack_id
    m = resolved["attack_headline_metric"]
    assert m["value"] != "--" and m["final"] is True, (attack_id, m)
    # and it is still the final value during the post-attack linger (stage NONE)
    for _ in range(mit.RESOLVED_HOLD_SECONDS + 1):
        engine._tick()
    after = engine.get_status()
    assert after["attack_stage"] == "NONE"
    assert after["attack_headline_metric"]["value"] == m["value"]
    assert after["attack_headline_metric"]["final"] is True
    if attack_id == "FIRMWARE_TAMPER":
        assert m["value"] == "YES"
        ev = resolved["real_attack_evidence"]
        assert ev["tampered"] is False and ev["device_sha256"] == ev["golden_sha256"]
