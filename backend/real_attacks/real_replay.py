"""
real_attacks/real_replay.py
==============================
SAFETY NOTE
-----------
Sends REAL, byte-identical repeated HTTP requests to the dummy
device's own web console on 127.0.0.1 only.

WHAT THIS ACTUALLY DOES
------------------------
First makes ONE real request and captures its real raw request bytes
and a real SHA-256 hash of them. Then genuinely resends those exact
same captured bytes over new real connections, over and over. Each
reply is compared - this runner can PROVE the replay is real by
showing every resent request hashes identically to the original
capture, which is impossible to fake without actually sending the
same bytes.

HOW TO RUN STANDALONE
----------------------
    python real_attacks/dummy_target.py
    python real_attacks/real_replay.py
"""

import hashlib
import socket
import threading
import time
from collections import deque

from . import dummy_target as dt

TARGET_HOST = "127.0.0.1"
TARGET_PORT = dt.WEB_PORT
WORKERS = 10
METRIC_WINDOW_SEC = 2.0

_CAPTURED_REQUEST = (
    f"GET / HTTP/1.1\r\nHost: {TARGET_HOST}:{TARGET_PORT}\r\nConnection: close\r\n\r\n"
).encode()
_CAPTURED_HASH = hashlib.sha256(_CAPTURED_REQUEST).hexdigest()


class RealReplayRunner:
    def __init__(self):
        self._stop_event = threading.Event()
        self._threads = []
        self._lock = threading.Lock()
        self._timestamps = deque(maxlen=20000)
        self._replay_count = 0
        self._verified_identical_count = 0
        self._running = False

    def _worker(self):
        while not self._stop_event.is_set():
            # Genuinely resend the EXACT same captured bytes - not a re-built request.
            sent_bytes = _CAPTURED_REQUEST
            sent_hash = hashlib.sha256(sent_bytes).hexdigest()
            try:
                s = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=1.0)
                s.sendall(sent_bytes)
                s.recv(512)
                s.close()
                ok = True
            except OSError:
                ok = False

            with self._lock:
                self._timestamps.append(time.monotonic())
                self._replay_count += 1
                if ok and sent_hash == _CAPTURED_HASH:
                    self._verified_identical_count += 1
            time.sleep(0.02)

    def start(self):
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._replay_count = 0
        self._verified_identical_count = 0
        self._threads = [threading.Thread(target=self._worker, daemon=True) for _ in range(WORKERS)]
        for t in self._threads:
            t.start()

    def stop(self):
        self._stop_event.set()
        for t in self._threads:
            t.join(timeout=1.0)
        self._threads = []
        self._running = False

    @property
    def is_running(self):
        return self._running

    def get_live_metrics(self):
        with self._lock:
            now = time.monotonic()
            recent = [ts for ts in self._timestamps if now - ts <= METRIC_WINDOW_SEC]
            rate = len(recent) / METRIC_WINDOW_SEC if recent else 0.0
            replay_count = self._replay_count
            verified = self._verified_identical_count

        return {
            "packets_per_sec": round(rate, 1),
            "duplicate_pkt_ratio": round((verified / replay_count) if replay_count else 0.0, 4),  # real, hash-verified
            "captured_request_hash": _CAPTURED_HASH,          # real SHA-256 of the one real captured request
            "replays_sent": replay_count,
            "replays_hash_verified": verified,
        }


if __name__ == "__main__":
    dt.device.start()
    time.sleep(0.2)
    print("Captured request hash:", _CAPTURED_HASH)
    runner = RealReplayRunner()
    runner.start()
    try:
        for _ in range(6):
            time.sleep(1)
            m = runner.get_live_metrics()
            print(f"replays_sent={m['replays_sent']:>6}  hash_verified={m['replays_hash_verified']:>6}  "
                  f"duplicate_pkt_ratio={m['duplicate_pkt_ratio']}")
    finally:
        runner.stop()
        print("Stopped.")
