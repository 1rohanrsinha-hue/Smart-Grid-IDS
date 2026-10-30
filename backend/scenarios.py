"""
scenarios.py
=============
Named multi-stage attacker "kill chains" - a scripted sequence of
individual attacks run back-to-back (with a short pause between each)
against the same targeted part of the grid, instead of one isolated
attack. Each stage still goes through the exact same genuine
SECURE -> DETECTED -> MITIGATING -> RESOLVED pipeline as a manual
trigger; scenarios.py only defines the *sequence*, the actual
execution/state machine lives in test_engine.py.
"""

from collections import OrderedDict

SCENARIOS = OrderedDict([
    ("recon_to_breach", {
        "name": "Reconnaissance to Breach",
        "description": "An attacker scans the network for open services, escalates "
                        "privileges on a discovered host, then deploys malware.",
        "stages": ["PORT_SCAN", "PRIV_ESC", "MALWARE"],
        "target_category": "system",
    }),
    ("grid_destabilization", {
        "name": "Grid Destabilization Chain",
        "description": "Falsified sensor data masks a coordinated load manipulation, "
                        "followed by unauthorized control commands to lock in the damage.",
        "stages": ["FDI", "LOAD_ALTER", "CMD_INJECT"],
        "target_category": "data",
    }),
    ("stealth_takeover", {
        "name": "Stealth Communications Takeover",
        "description": "A rogue relay intercepts traffic, replays captured commands, "
                        "then tampers with device firmware to persist access.",
        "stages": ["MITM", "REPLAY", "FIRMWARE_TAMPER"],
        "target_category": "network",
    }),
])

WAIT_TICKS_BETWEEN_STAGES = 3


def get_scenario(scenario_id):
    return SCENARIOS.get(scenario_id)


def list_scenarios():
    return [
        {"id": sid, "name": s["name"], "description": s["description"], "stages": s["stages"]}
        for sid, s in SCENARIOS.items()
    ]
