"""
tests/test_rule_engine.py
===========================
Verifies each threshold rule fires correctly on known synthetic inputs.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import rule_engine  # noqa: E402


def _baseline_reading(**overrides):
    """A reading that should NOT trip any rule, with optional overrides."""
    r = {
        "voltage": 230.0, "frequency": 50.0, "current": 15.0, "power_factor": 0.92,
        "packets_per_sec": 250.0, "packet_size_avg": 512.0, "unique_ips": 3,
        "cmd_rate": 10.0, "cmd_unknown": 0.01, "latency_ms": 12.0,
        "retransmit_pct": 0.5, "sensor_delta": 0.1, "conn_duration_avg": 18.0,
        "ttl_variance": 1.0, "auth_failures": 0.2, "firmware_checksum_mismatch": 0.0,
        "gps_drift": 1.0, "time_offset_ms": 2.0, "load_variance": 3.0,
        "noise_floor_db": -95.0, "duplicate_pkt_ratio": 0.01, "privilege_level": 1.0,
    }
    r.update(overrides)
    return r


def test_normal_reading_produces_no_verdict():
    result = rule_engine.evaluate(_baseline_reading())
    assert result["verdict"] == "NORMAL"
    assert result["fired_rule"] is None
    assert result["all_fired"] == []


def test_voltage_out_of_range_fires():
    result = rule_engine.evaluate(_baseline_reading(voltage=300))
    assert result["verdict"] == "SUSPICIOUS"
    assert "voltage_out_of_range" in result["all_fired"]


def test_ddos_packet_flood_fires():
    result = rule_engine.evaluate(_baseline_reading(packets_per_sec=9000))
    assert result["verdict"] == "SUSPICIOUS"
    assert "ddos_packet_flood" in result["all_fired"]


def test_unknown_command_ratio_fires():
    result = rule_engine.evaluate(_baseline_reading(cmd_unknown=0.9))
    assert "unknown_command_ratio" in result["all_fired"]


def test_gps_and_time_offset_fire_together():
    result = rule_engine.evaluate(_baseline_reading(gps_drift=200, time_offset_ms=900))
    assert "gps_drift_spike" in result["all_fired"]
    assert "time_offset_spike" in result["all_fired"]


def test_privilege_jump_fires_at_threshold():
    just_below = rule_engine.evaluate(_baseline_reading(privilege_level=3.9))
    at_threshold = rule_engine.evaluate(_baseline_reading(privilege_level=4.0))
    assert "privilege_jump" not in just_below["all_fired"]
    assert "privilege_jump" in at_threshold["all_fired"]


def test_multiple_rules_report_all_fired():
    result = rule_engine.evaluate(_baseline_reading(voltage=300, packets_per_sec=9000, cmd_unknown=0.9))
    assert result["verdict"] == "SUSPICIOUS"
    assert len(result["all_fired"]) >= 3
