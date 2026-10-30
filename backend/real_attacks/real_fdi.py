"""
real_attacks/real_fdi.py
===========================
SAFETY NOTE
-----------
Sends REAL JSON payloads via REAL HTTP POST to the dummy device's own
/sensor endpoint on 127.0.0.1 only. This is real network traffic
carrying fabricated readings - not a fabricated metric.

WHAT THIS ACTUALLY DOES
------------------------
Repeatedly POSTs erratic, out-of-range voltage/frequency values to
the device's real /sensor endpoint. The device genuinely stores
whatever it actually received (see dummy_target.py's do_POST) and
this runner reads that REAL stored state back, computing a REAL
deviation from the device's real declared baseline - not a formula
that invents the deviation number.

HOW TO RUN STANDALONE
----------------------
    python real_attacks/dummy_target.py
    python real_attacks/real_fdi.py
"""

import json
import random
import threading
import time
import urllib.request
from collections import deque

from . import dummy_target as dt

TARGET_URL = f"http://127.0.0.1:{dt.WEB_PORT}/sensor"
WORKERS = 10
METRIC_WINDOW_SEC = 2.0


class RealFDIRunner:
    def __init__(self):
        self._stop_event = threading.Event()
        self._threads = []
        self._lock = threading.Lock()
        self._sent_timestamps = deque(maxlen=20000)
        self._running = False

    def _worker(self):
        while not self._stop_event.is_set():
            fake_reading = {
                "voltage": 230 + random.uniform(-60, 60),
                "frequency": 50 + random.uniform(-3, 3),
            }
            try:
                req = urllib.request.Request(
                    TARGET_URL, data=json.dumps(fake_reading).encode(),
                    headers={"Content-Type": "application/json"}, method="POST",
                )
                urllib.request.urlopen(req, timeout=1.0).read()
            except OSError:
                pass
            with self._lock:
                self._sent_timestamps.append(time.monotonic())
            time.sleep(0.05)

    def start(self):
        if self._running:
            return
        dt.state.reset_sensor()
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
            submit_rate = len(recent) / METRIC_WINDOW_SEC if recent else 0.0

        with dt.state.lock:
            last = dict(dt.state.sensor_last)
            baseline = dict(dt.state.sensor_baseline)
            submissions = dt.state.sensor_submissions

        voltage_delta = abs(last["voltage"] - baseline["voltage"])
        freq_delta = abs(last["frequency"] - baseline["frequency"])
        return {
            "sensor_delta": round(voltage_delta + freq_delta * 10, 4),  # real deviation from real received values
            "voltage": round(last["voltage"], 2),        # real last-received (fabricated) value
            "frequency": round(last["frequency"], 3),      # real last-received (fabricated) value
            "submission_rate": round(submit_rate, 2),
            "total_submissions": submissions,
        }


if __name__ == "__main__":
    dt.device.start()
    time.sleep(0.2)
    runner = RealFDIRunner()
    runner.start()
    try:
        for _ in range(6):
            time.sleep(1)
            m = runner.get_live_metrics()
            print(f"voltage={m['voltage']:>7}  frequency={m['frequency']:>6}  "
                  f"sensor_delta={m['sensor_delta']:>8}  submissions={m['total_submissions']}")
    finally:
        runner.stop()
        print("Stopped.")
