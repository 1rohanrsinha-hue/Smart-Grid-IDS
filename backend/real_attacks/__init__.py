"""
real_attacks/__init__.py
===========================
Wires the three real, executable attacks (DDoS load test, TCP port
scan, firmware checksum tamper) into the rest of the app. This is the
only file test_engine.py needs to talk to.

Design note on training vs. live demo
--------------------------------------
The ML models are still TRAINED on the synthetic generator functions
in attacks/ (attacks/network_attacks.py, attacks/system_attacks.py) -
that's necessary and honest: you cannot practically run 500 real DDoS
load tests or 500 real port scans just to generate training samples,
and no real-world dataset gives you a clean intensity-labeled ramp.
The synthetic generators exist purely to produce a statistically
representative TRAINING set.

What changes here is the LIVE DEMO path: when the operator actually
triggers DDOS, PORT_SCAN, or FIRMWARE_TAMPER from the dashboard, the
engine now runs the REAL code in real_ddos.py / real_port_scan.py /
real_firmware_tamper.py against the real local dummy_target.py device,
and feeds the model the REAL measured numbers those produce - not the
synthetic formula. The model making a live prediction on real,
just-measured attack data is what makes the detection genuine.
"""

import os

from .dummy_target import device  # noqa: E402
from .real_ddos import RealDDoSRunner  # noqa: E402
from .real_port_scan import RealPortScanRunner  # noqa: E402
from .real_firmware_tamper import RealFirmwareTamperRunner  # noqa: E402
from .real_cmd_inject import RealCmdInjectRunner  # noqa: E402
from .real_fdi import RealFDIRunner  # noqa: E402
from .real_load_alter import RealLoadAlterRunner  # noqa: E402
from .real_gps_spoof import RealGPSSpoofRunner  # noqa: E402
from .real_jamming import RealJammingRunner  # noqa: E402
from .real_priv_esc import RealPrivEscRunner  # noqa: E402
from .real_malware import RealMalwareRunner  # noqa: E402
from .real_replay import RealReplayRunner  # noqa: E402
from .real_mitm import RealMITMRunner  # noqa: E402

REAL_ATTACK_IDS = {
    "DDOS", "PORT_SCAN", "FIRMWARE_TAMPER", "CMD_INJECT", "FDI", "LOAD_ALTER",
    "GPS_SPOOF", "JAMMING", "PRIV_ESC", "MALWARE", "REPLAY", "MITM",
}

_RUNNER_CLASSES = {
    "DDOS": RealDDoSRunner,
    "PORT_SCAN": RealPortScanRunner,
    "FIRMWARE_TAMPER": RealFirmwareTamperRunner,
    "CMD_INJECT": RealCmdInjectRunner,
    "FDI": RealFDIRunner,
    "LOAD_ALTER": RealLoadAlterRunner,
    "GPS_SPOOF": RealGPSSpoofRunner,
    "JAMMING": RealJammingRunner,
    "PRIV_ESC": RealPrivEscRunner,
    "MALWARE": RealMalwareRunner,
    "REPLAY": RealReplayRunner,
    "MITM": RealMITMRunner,
}

# Which real, measured metric fields to overlay onto the baseline reading
# for each attack. Everything else in the reading stays at realistic
# baseline values - exactly like the synthetic generators only touch the
# features their attack genuinely affects.
_FEATURE_MAP = {
    "DDOS": ["packets_per_sec", "latency_ms", "retransmit_pct", "unique_ips", "packet_size_avg"],
    "PORT_SCAN": ["packets_per_sec", "conn_duration_avg", "unique_ips", "packet_size_avg"],
    "FIRMWARE_TAMPER": ["firmware_checksum_mismatch"],
    "CMD_INJECT": ["cmd_rate", "cmd_unknown"],
    "FDI": ["sensor_delta", "voltage", "frequency"],
    "LOAD_ALTER": ["load_variance", "current"],
    "GPS_SPOOF": ["gps_drift", "time_offset_ms"],
    "JAMMING": ["noise_floor_db", "retransmit_pct", "sensor_delta"],
    "PRIV_ESC": ["auth_failures", "privilege_level"],
    "MALWARE": ["packets_per_sec", "packet_size_avg", "unique_ips", "retransmit_pct"],
    "REPLAY": ["packets_per_sec", "duplicate_pkt_ratio"],
    "MITM": ["latency_ms", "ttl_variance", "duplicate_pkt_ratio", "packets_per_sec"],
}


# The one key live number per attack, shown in the dashboard's alert strip
# and map callout. (label, evidence field, unit). Display only: read from
# the same evidence dict the runners already expose, nothing is measured here.
HEADLINE_METRICS = {
    "DDOS": ("Requests/sec", "packets_per_sec", "req/s"),
    "PORT_SCAN": ("Open ports found", "open_ports_found", "ports"),
    "FIRMWARE_TAMPER": ("Hashes match", "tampered", ""),
    "CMD_INJECT": ("Commands rejected", "cmd_total_rejected", "cmds"),
    "FDI": ("Fake voltage accepted", "voltage", "V"),
    "LOAD_ALTER": ("Last setpoint", "last_setpoint", ""),
    "GPS_SPOOF": ("Clock offset", "time_offset_ms", "ms"),
    "JAMMING": ("Packet loss", "retransmit_pct", "%"),
    "PRIV_ESC": ("Failed logins", "auth_failures", "logins"),
    "MALWARE": ("Bytes uploaded", "bytes_uploaded_total", "B"),
    "REPLAY": ("Replays sent", "replays_sent", "pkts"),
    "MITM": ("Added latency", "added_latency_ms", "ms"),
}


def headline_metric(attack_id, evidence):
    """{label, value, unit} for the attack's headline number; value is
    "--" until the runner has produced it."""
    label, field, unit = HEADLINE_METRICS.get(attack_id, ("", None, ""))
    value = (evidence or {}).get(field) if field else None
    if value is None:
        value = "--"
    elif field == "tampered":
        value = "NO" if value else "YES"
    elif field == "open_ports_found":
        value = len(value) if (evidence.get("sweeps_completed") or value) else "--"
    return {"label": label, "value": value, "unit": unit if value != "--" else ""}


class RealAttackManager:
    """One instance shared by the Engine. Starts the dummy device once,
    then creates/starts/stops the appropriate real runner whenever a
    real attack begins or ends."""

    def __init__(self):
        self._runners = {}  # attack_id -> live runner instance, only while active

    def ensure_target_running(self):
        device.start(attack_active=bool(self._runners))

    @staticmethod
    def is_real(attack_id):
        return attack_id in REAL_ATTACK_IDS

    def start(self, attack_id):
        """Called exactly once, the moment a real attack begins."""
        self.ensure_target_running()
        runner_cls = _RUNNER_CLASSES.get(attack_id)
        if runner_cls is None:
            return
        runner = runner_cls()
        runner.start()
        self._runners[attack_id] = runner
        if attack_id == "FIRMWARE_TAMPER":
            device.check_firmware_integrity()   # the device hashes its own firmware and logs the result

    def stop(self, attack_id):
        """Called exactly once, the moment mitigation completes."""
        runner = self._runners.pop(attack_id, None)
        if runner is None:
            return
        if attack_id == "FIRMWARE_TAMPER":
            runner.resolve()  # real rollback: golden firmware copied back over the device file
            device.check_firmware_integrity()
        else:
            runner.stop()  # stops the real background load/scan/probe thread

    def get_reading(self, attack_id, baseline_reading):
        """Merges the real runner's live measured metrics onto a
        normal baseline reading, overriding only the fields that
        attack genuinely affects (see _FEATURE_MAP above)."""
        runner = self._runners.get(attack_id)
        r = dict(baseline_reading)
        if runner is None:
            return r

        metrics = runner.get_live_metrics()
        for field in _FEATURE_MAP.get(attack_id, []):
            if field in metrics and metrics[field] is not None:
                r[field] = metrics[field]
        return r

    @staticmethod
    def get_target_events(n=12):
        return device.get_recent_events(n)

    @staticmethod
    def clear_target_events():
        device.clear_events()

    @staticmethod
    def target_online():
        return device.is_running

    @staticmethod
    def firmware_integrity():
        """The device hashes its own firmware file right now (read-only, not logged)."""
        return device.check_firmware_integrity(log=False)

    def get_raw_metrics(self, attack_id):
        """Full real metrics (incl. non-feature fields like actual
        SHA-256 hashes or discovered open ports) for display in the UI
        / viva, beyond what the ML feature vector needs."""
        runner = self._runners.get(attack_id)
        if runner is None:
            return {}
        return runner.get_live_metrics()


manager = RealAttackManager()
