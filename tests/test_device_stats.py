"""
tests/test_device_stats.py
============================
The target device's read-only /stats endpoint and the device-side logging
of port probes and firmware integrity checks.
"""

import json
import os
import socket
import sys
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from real_attacks import dummy_target  # noqa: E402
from real_attacks import device  # noqa: E402

STATS_URL = f"http://127.0.0.1:{dummy_target.WEB_PORT}/stats"
EXPECTED_KEYS = {
    "cmd_total", "cmd_unauthorized", "sensor_submissions", "auth_failures", "auth_successes",
    "udp_received", "udp_gaps", "upload_count", "upload_bytes_total", "proxy_relayed_bytes",
    "proxy_relayed_connections", "http_requests_total", "connection_probes_total",
    "firmware", "server_time",
}


def _stats():
    with urllib.request.urlopen(STATS_URL, timeout=3) as resp:
        assert resp.status == 200
        assert resp.headers.get("Access-Control-Allow-Origin") is None  # no CORS
        return json.loads(resp.read())


def setup_module(_module):
    device.start()


def test_stats_is_valid_json_with_expected_keys():
    s = _stats()
    assert EXPECTED_KEYS <= set(s)
    assert set(s["firmware"]) == {"golden_sha256", "device_sha256", "match"}
    assert len(s["firmware"]["device_sha256"]) == 64


def test_stats_counters_increase_after_requests():
    before = _stats()
    urllib.request.urlopen(f"http://127.0.0.1:{dummy_target.WEB_PORT}/", timeout=3).read()
    s = socket.create_connection(("127.0.0.1", dummy_target.PROTOCOL_PORT), timeout=2)
    s.sendall(b"CMD PING\n")
    s.recv(64)
    s.close()
    time.sleep(0.2)
    after = _stats()
    assert after["http_requests_total"] == before["http_requests_total"] + 1  # /stats itself is not counted
    assert after["cmd_total"] == before["cmd_total"] + 1


def test_connection_probe_is_counted_and_logged_by_the_device():
    dummy_target.events.clear()
    before = _stats()["connection_probes_total"]
    for port in (dummy_target.PROTOCOL_PORT, dummy_target.ADMIN_PORT):
        socket.create_connection(("127.0.0.1", port), timeout=2).close()   # connect, send nothing
    time.sleep(0.4)
    assert _stats()["connection_probes_total"] >= before + 2
    assert any(e["summary"].startswith("Port scan:") for e in dummy_target.events.recent(40))


def test_firmware_integrity_is_computed_by_the_device():
    dummy_target.events.clear()
    r = device.check_firmware_integrity()
    assert r["match"] is True            # at rest the device image equals the golden image
    lines = [e for e in dummy_target.events.recent(10) if e["kind"] == "FIRMWARE"]
    assert lines and "SHA-256 OK" in lines[0]["summary"]
    assert device.check_firmware_integrity(log=False)["device_sha256"] == r["device_sha256"]


def _firmware_store(tmp_path, monkeypatch, corrupt):
    golden, current = tmp_path / "golden.bin", tmp_path / "device.bin"
    golden.write_bytes(bytes(range(256)) * 16)
    current.write_bytes(golden.read_bytes())
    if corrupt:
        data = bytearray(current.read_bytes())
        data[100] ^= 0xFF
        current.write_bytes(bytes(data))
    monkeypatch.setattr(dummy_target, "FIRMWARE_GOLDEN_PATH", str(golden))
    monkeypatch.setattr(dummy_target, "FIRMWARE_DEVICE_PATH", str(current))
    return golden, current


def test_corrupted_firmware_is_restored_when_the_device_starts(tmp_path, monkeypatch):
    golden, current = _firmware_store(tmp_path, monkeypatch, corrupt=True)
    assert golden.read_bytes() != current.read_bytes()
    dummy_target.events.clear()

    class _FakeServer:                        # start() must not bind the real ports in this test
        def __init__(self, *a, **k): pass
        def serve_forever(self): pass
        def shutdown(self): pass
        def server_close(self): pass

    monkeypatch.setattr(dummy_target, "_ThreadingHTTPServer", _FakeServer)
    for name in ("_protocol_listener", "_admin_listener", "_udp_listener", "_proxy_listener"):
        monkeypatch.setattr(dummy_target, name, lambda stop_event: None)
    fresh = dummy_target.DummyGridDevice()
    fresh.start()

    assert current.read_bytes() == golden.read_bytes()
    summaries = [e["summary"] for e in dummy_target.events.recent(10)]
    assert "Startup integrity check: restored device firmware from golden" in summaries


def test_firmware_is_left_alone_while_an_attack_is_active_or_when_intact(tmp_path, monkeypatch):
    golden, current = _firmware_store(tmp_path, monkeypatch, corrupt=True)
    corrupted = current.read_bytes()
    assert dummy_target.restore_firmware_if_corrupted(attack_active=True) is None
    assert current.read_bytes() == corrupted                   # an attack in progress owns the file
    assert dummy_target.restore_firmware_if_corrupted() is True
    assert dummy_target.restore_firmware_if_corrupted() is False   # intact: nothing to do
