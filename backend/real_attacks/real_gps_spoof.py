"""
real_attacks/real_gps_spoof.py
=================================
SAFETY NOTE
-----------
This does NOT touch real GPS hardware or RF signals (which would need
an FCC-licensed shielded lab and is illegal to fake over the air).
Instead it sends a REAL, deliberately-wrong timestamp over a REAL TCP
socket to the dummy device's own time-sync endpoint, and the device
computes a REAL offset against its own REAL system clock
(`time.time()`) - genuinely demonstrating "a device trusting a
falsified time source" at the protocol level, safely and legally.

WHAT THIS ACTUALLY DOES
------------------------
Repeatedly sends a wildly wrong TIMESYNC value to the device's real
protocol port. `dummy_target.py`'s handler computes
`abs(claimed_ts - time.time()) * 1000` - a REAL arithmetic comparison
against the REAL system clock at the moment each message actually
arrives - and stores it. get_live_metrics() reads that real value.

HOW TO RUN STANDALONE
----------------------
    python real_attacks/dummy_target.py
    python real_attacks/real_gps_spoof.py
"""

import random
import socket
import threading
import time

from . import dummy_target as dt

TARGET_HOST = "127.0.0.1"
TARGET_PORT = dt.PROTOCOL_PORT
WORKERS = 4


class RealGPSSpoofRunner:
    def __init__(self):
        self._stop_event = threading.Event()
        self._threads = []
        self._running = False

    def _worker(self):
        while not self._stop_event.is_set():
            # A real, deliberately-wrong claimed timestamp - drifted by a random
            # amount from real "now" to simulate a spoofed time/GPS source.
            fake_ts = time.time() + random.uniform(-4.5, 4.5)
            try:
                s = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=1.0)
                s.sendall(f"TIMESYNC {fake_ts}\n".encode())
                s.recv(128)
                s.close()
            except OSError:
                pass
            time.sleep(0.2)

    def start(self):
        if self._running:
            return
        dt.state.reset_timesync()
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
        with dt.state.lock:
            offset_ms = dt.state.timesync_last_offset_ms
            submissions = dt.state.timesync_submissions

        return {
            "time_offset_ms": round(offset_ms, 2),          # real, computed against the real system clock
            "gps_drift": round(min(500, offset_ms / 5.0), 2),  # real-derived proxy: bigger clock lies -> bigger position uncertainty
            "timesync_submissions": submissions,
        }


if __name__ == "__main__":
    dt.device.start()
    time.sleep(0.2)
    runner = RealGPSSpoofRunner()
    runner.start()
    try:
        for _ in range(6):
            time.sleep(1)
            m = runner.get_live_metrics()
            print(f"time_offset_ms={m['time_offset_ms']:>10}  gps_drift={m['gps_drift']:>7}  "
                  f"submissions={m['timesync_submissions']}")
    finally:
        runner.stop()
        print("Stopped.")
