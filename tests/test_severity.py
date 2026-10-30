"""
tests/test_severity.py
=========================
Verifies severity scoring produces the expected band for a few known
input combinations.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import severity  # noqa: E402


def test_high_base_severity_high_confidence_first_hit_is_high_or_critical():
    # LOAD_ALTER base_severity=5, full confidence, first hit (factor 1.0) -> raw 5.0
    result = severity.evaluate("LOAD_ALTER", 1.0, node_hit_counts={}, node_id="SUB1")
    assert result["band"] in ("HIGH", "CRITICAL")
    assert result["score"] == 5.0


def test_low_confidence_low_base_severity_is_low():
    # PORT_SCAN base_severity=2, low confidence -> should land LOW
    result = severity.evaluate("PORT_SCAN", 0.3, node_hit_counts={}, node_id="FEEDER1")
    assert result["band"] == "LOW"


def test_repeated_node_hits_increase_score():
    first_hit = severity.evaluate("MITM", 0.8, node_hit_counts={}, node_id="SUB1")
    repeated = severity.evaluate("MITM", 0.8, node_hit_counts={"SUB1": 3}, node_id="SUB1")
    assert repeated["score"] > first_hit["score"]
    assert repeated["node_repeat_factor"] > first_hit["node_repeat_factor"]


def test_repeat_factor_is_capped():
    result = severity.evaluate("DDOS", 1.0, node_hit_counts={"SUB1": 50}, node_id="SUB1")
    assert result["node_repeat_factor"] == 1.6  # capped


def test_max_severity_combination_is_critical():
    # CMD_INJECT base_severity=5, full confidence, several repeats -> should hit CRITICAL
    result = severity.evaluate("CMD_INJECT", 1.0, node_hit_counts={"PLANT": 5}, node_id="PLANT")
    assert result["band"] == "CRITICAL"


def test_unknown_attack_id_falls_back_to_default_base_severity():
    result = severity.evaluate("NOT_A_REAL_ATTACK", 0.5, node_hit_counts={}, node_id="SUB1")
    assert result["base_severity"] == 3  # documented default
