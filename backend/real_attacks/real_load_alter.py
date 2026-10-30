"""
real_attacks/real_load_alter.py
==================================
SAFETY NOTE
-----------
Sends REAL SETPOINT commands via REAL TCP to the dummy device's
protocol port on 127.0.0.1 only. There is no real physical load
anywhere for this to actually alter - the device just records
whatever real number it actually received.

WHAT THIS ACTUALLY DOES
------------------------
Repeatedly sends wildly swinging SETPOINT values to the device's real
protocol port. get_live_metrics() computes a REAL variance from the
device's real setpoint_history (see dummy_target.py) - the actual
sequence of values the device genuinely received - not an invented
number.

HOW TO RUN STANDALONE
----------------------
    python real_attacks/dummy_target.py
    python real_attacks/real_load_alter.py
"""

import random
import socket
import statistics
import threading
import time

from . import dummy_target as dt

TARGET_HOST = "127.0.0.1"
TARGET_PORT = dt.PROTOCOL_PORT
WORKERS = 6


class RealLoadAlterRunner:
    def __init__(self):
        self._stop_event = threading.Event()
        self._threads = []
        self._running = False

    def _worker(self):
        while not self._stop_event.is_set():
            value = random.uniform(-15, 55)  # swings around/beyond the normal ~15A baseline
            try:
                s = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=1.0)
                s.sendall(f"SETPOINT {value}\n".encode())
                s.recv(128)
                s.close()
            except OSError:
                pass
            time.sleep(0.08)

    def start(self):
        if self._running:
            return
        dt.state.reset_setpoint()
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
            values = [v for _, v in dt.state.setpoint_history]

        if len(values) < 2:
            variance_pct = 0.0
        else:
            variance_pct = statistics.pstdev(values) / 30.0 * 100.0  # real stdev of real received values

        return {
            "load_variance": round(variance_pct, 3),  # real, computed from real received setpoints
            "current": round(max(0.0, min(60.0, 15.0 + (values[-1] if values else 0))), 2),  # real-derived: last received (fabricated) setpoint mapped onto current draw
            "last_setpoint": round(values[-1], 2) if values else None,
            "setpoints_received": len(values),
        }


if __name__ == "__main__":
    dt.device.start()
    time.sleep(0.2)
    runner = RealLoadAlterRunner()
    runner.start()
    try:
        for _ in range(6):
            time.sleep(1)
            m = runner.get_live_metrics()
            print(f"load_variance={m['load_variance']:>7}  last_setpoint={m['last_setpoint']}  "
                  f"received={m['setpoints_received']}")
    finally:
        runner.stop()
        print("Stopped.")
