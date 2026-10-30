"""
attacks package
================
Exposes ATTACKS: an ordered dict mapping attack_id -> AttackGenerator,
covering all 12 attack types the IDS can trigger and classify.
"""

from collections import OrderedDict

from .base import FEATURES, normal_readings, clip, ramp_intensity, AttackGenerator
from . import network_attacks
from . import data_attacks
from . import system_attacks

_ALL = network_attacks.REGISTRY + data_attacks.REGISTRY + system_attacks.REGISTRY

ATTACKS = OrderedDict((a.id, a) for a in _ALL)

# Full class list the ML model predicts over: NORMAL + all 12 attack ids.
CLASSES = ["NORMAL"] + list(ATTACKS.keys())

__all__ = ["ATTACKS", "CLASSES", "FEATURES", "normal_readings", "clip",
           "ramp_intensity", "AttackGenerator"]
