"""
tests/test_topology_fx.py
==========================
Runs tests/topology_fx_test.js (Node, no browser) against frontend/topology_effects.js:
effect selection per attack id, element cap, clean teardown, feed-link edge cases,
back-to-back incident handling, REPLAY phases and reduced-motion behaviour.
Skipped when Node is not installed.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "backend"))

import topology  # noqa: E402
from attacks import ATTACKS  # noqa: E402

NODE = shutil.which("node")


@pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
def test_topology_effects_in_node(tmp_path):
    layout = tmp_path / "layout.json"
    layout.write_text(json.dumps(topology.get_layout()))
    targets = tmp_path / "targets.json"
    targets.write_text(json.dumps({
        aid: topology.CATEGORY_TARGETS[a.category] for aid, a in ATTACKS.items()
    }))
    res = subprocess.run(
        [NODE, os.path.join(HERE, "topology_fx_test.js"), str(layout), str(targets)],
        capture_output=True, text=True, timeout=120,
    )
    assert res.returncode == 0, res.stdout + res.stderr
