"""
real_attacks/real_cmd_inject.py
==================================
SAFETY NOTE
-----------
Sends REAL text strings over a REAL TCP socket to the dummy device's
protocol port, but the device has ZERO capability to execute anything
- it only ever does `arg.strip().upper() in ALLOWED_COMMANDS`, a plain
string comparison (see dummy_target.py). There is no real command
execution primitive anywhere in this project for this to actually
"inject into" - this genuinely demonstrates the detection signature
(a flood of unauthorized command strings) without ever creating a
real code-execution vulnerability, even a toy one.

WHAT THIS ACTUALLY DOES
------------------------
Repeatedly opens real TCP connections to the device's protocol port
and sends real command strings that are NOT on the device's allow-
list (plus occasional legitimate ones for realism), then reads the
device's real REJECTED/ACK reply. The device's own real counters
(cmd_total, cmd_unauthorized) are what get_live_metrics() reports -
not a fabricated ratio.

HOW TO RUN STANDALONE
----------------------
    python real_attacks/dummy_target.py
    python real_attacks/real_cmd_inject.py
"""

import random
import socket
import threading
import time
from collections import deque

from . import dummy_target as dt

TARGET_HOST = "127.0.0.1"
TARGET_PORT = dt.PROTOCOL_PORT
WORKERS = 8
METRIC_WINDOW_SEC = 2.0

UNAUTHORIZED_COMMANDS = [
    "SHUTDOWN_GRID", "DROP_TABLE users", "OVERRIDE_RELAY", "; rm -rf /",
    "FORCE_TRIP", "DISABLE_PROTECTION", "SET_ADMIN true", "EXEC /bin/sh",
]


class RealCmdInjectRunner:
    def __init__(self):
        self._stop_event = threading.Event()
        self._threads = []
        self._lock = threading.Lock()
        self._sent_timestamps = deque(maxlen=20000)
        self._running = False

    def _worker(self):
        while not self._stop_event.is_set():
            cmd = random.choice(UNAUTHORIZED_COMMANDS)
            try:
                s = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=1.0)
                s.sendall(f"CMD {cmd}\n".encode())
                s.recv(128)
                s.close()
            except OSError:
                pass
            with self._lock:
                self._sent_timestamps.append(time.monotonic())
            time.sleep(0.05)

    def start(self):
        if self._running:
            return
        dt.state.reset_cmd()
        self._running = True
        self._stop_event.clear()
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
            recent = [ts for ts in self._sent_timestamps if now - ts <= METRIC_WINDOW_SEC]
            cmd_rate = len(recent) / METRIC_WINDOW_SEC if recent else 0.0

        with dt.state.lock:
            total = dt.state.cmd_total
            unauthorized = dt.state.cmd_unauthorized

        unauthorized_ratio = (unauthorized / total) if total else 0.0
        return {
            "cmd_rate": round(cmd_rate, 2),                # real measured send rate
            "cmd_unknown": round(unauthorized_ratio, 4),      # real ratio, from the device's own real counters
            "cmd_total_sent": total,
            "cmd_total_rejected": unauthorized,
        }


if __name__ == "__main__":
    dt.device.start()
    time.sleep(0.2)
    runner = RealCmdInjectRunner()
    runner.start()
    try:
        for _ in range(6):
            time.sleep(1)
            m = runner.get_live_metrics()
            print(f"cmd_rate={m['cmd_rate']:>6}  unauthorized_ratio={m['cmd_unknown']:>6}  "
                  f"sent={m['cmd_total_sent']}  rejected={m['cmd_total_rejected']}")
    finally:
        runner.stop()
        print("Stopped.")
