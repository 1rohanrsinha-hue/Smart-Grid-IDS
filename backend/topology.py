"""
topology.py
============
Fixed single-line-diagram-style layout for the smart grid:

    Power Plant -> Substations -> Distribution Feeders -> Smart Meter
    Clusters, with a Control Center observing everything.

This is intentionally static (coordinates + connections don't change at
runtime) so the frontend can render a stable SVG diagram. What DOES
change at runtime is each node's live `status`, tracked in test_engine.py
and exposed via GET /api/topology.
"""

from collections import OrderedDict

# Coordinates are in a normalized 0-100 (y) x 0-180 (x) space, laid out
# left-to-right to mirror real power flow: generation -> transmission ->
# distribution -> consumption. The frontend maps these to its own SVG
# viewBox (180 x 100) via topology.js.
NODES = OrderedDict([
    ("PLANT",     {"name": "Power Plant",           "type": "plant",      "x": 12,  "y": 50}),
    ("CTRL",      {"name": "Control Center",         "type": "control",    "x": 42,  "y": 8}),
    ("SUB1",      {"name": "Substation 1",            "type": "substation", "x": 42,  "y": 30}),
    ("SUB2",      {"name": "Substation 2",             "type": "substation", "x": 42,  "y": 72}),
    ("FEEDER1",   {"name": "Feeder 1",                  "type": "feeder",   "x": 98,  "y": 12}),
    ("FEEDER2",   {"name": "Feeder 2",                   "type": "feeder",   "x": 98,  "y": 36}),
    ("FEEDER3",   {"name": "Feeder 3",                    "type": "feeder",   "x": 98,  "y": 64}),
    ("FEEDER4",   {"name": "Feeder 4",                     "type": "feeder",   "x": 98,  "y": 88}),
    ("METERS_A",  {"name": "Smart Meter Cluster A",         "type": "meters",   "x": 160, "y": 12}),
    ("METERS_B",  {"name": "Smart Meter Cluster B",          "type": "meters",   "x": 160, "y": 36}),
    ("METERS_C",  {"name": "Smart Meter Cluster C",           "type": "meters",   "x": 160, "y": 64}),
    ("METERS_D",  {"name": "Smart Meter Cluster D",            "type": "meters",   "x": 160, "y": 88}),
])

EDGES = [
    ("PLANT", "SUB1"), ("PLANT", "SUB2"),
    ("SUB1", "FEEDER1"), ("SUB1", "FEEDER2"),
    ("SUB2", "FEEDER3"), ("SUB2", "FEEDER4"),
    ("FEEDER1", "METERS_A"), ("FEEDER2", "METERS_B"),
    ("FEEDER3", "METERS_C"), ("FEEDER4", "METERS_D"),
    ("CTRL", "SUB1"), ("CTRL", "SUB2"),
]

# Which nodes are a *plausible* target for each attack category - keeps
# random node selection realistic (e.g. GPS spoofing hits substations/
# control center, not a meter cluster).
CATEGORY_TARGETS = {
    "network": ["SUB1", "SUB2", "FEEDER1", "FEEDER2", "FEEDER3", "FEEDER4",
                "METERS_A", "METERS_B", "METERS_C", "METERS_D"],
    "data":    ["SUB1", "SUB2", "PLANT", "CTRL"],
    "system":  ["SUB1", "SUB2", "PLANT", "CTRL", "FEEDER1", "FEEDER2",
                "FEEDER3", "FEEDER4"],
}

NODE_IDS = list(NODES.keys())


def node_name(node_id):
    n = NODES.get(node_id)
    return n["name"] if n else node_id


def target_for_category(category):
    """Pick a plausible random target node id for an attack category."""
    import random
    pool = CATEGORY_TARGETS.get(category, NODE_IDS)
    return random.choice(pool)


def get_layout():
    return {
        "nodes": [
            {"id": nid, **info} for nid, info in NODES.items()
        ],
        "edges": [{"from": a, "to": b} for a, b in EDGES],
    }
