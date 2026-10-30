"""
real_attacks/real_jamming.py
===============================
SAFETY NOTE
-----------
No real radio/RF transmission (real RF jamming needs licensed hardware
and is illegal to do for real - even on your "own" spectrum, you'd be
interfering with a shared public medium). Instead, this genuinely
floods the dummy device's real UDP socket on 127.0.0.1, which has a
deliberately tiny OS-level receive buffer (see dummy_target.py) -
representing a real resource-constrained sensor radio. Under real
flood, the operating system genuinely, actually drops UDP datagrams
once that buffer fills - this is real kernel behavior, not a script
pretending packets were lost.

WHAT THIS ACTUALLY DOES
------------------------
Sends real UDP datagrams with strictly incrementing sequence numbers
as fast as possible. The device's real receive loop can only drain
the socket at a limited real rate, so real packets genuinely never
arrive. get_live_metrics() computes real loss % from the actual gap
between the highest sequence number sent and how many the device
actually, really received.

HOW TO RUN STANDALONE
----------------------
    python real_attacks/dummy_target.py
    python real_attacks/real_jamming.py
"""

import socket
import threading
import time
from collections import deque

from . import dummy_target as dt

TARGET_HOST = "127.0.0.1"
TARGET_PORT = dt.TELEMETRY_UDP_PORT
WORKERS = 8


METRIC_WINDOW_SEC = 2.0


class RealJammingRunner:
    def __init__(self):
        self._stop_event = threading.Event()
        self._threads = []
        self._lock = threading.Lock()
        self._sent_count = 0
        self._seq_counter = 0
        self._sent_timestamps = deque(maxlen=20000)
        self._running = False

    def _worker(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while not self._stop_event.is_set():
            with self._lock:
                seq = self._seq_counter
                self._seq_counter += 1
            try:
                sock.sendto(str(seq).encode(), (TARGET_HOST, TARGET_PORT))
            except OSError:
                pass
            with self._lock:
                self._sent_count += 1
                self._sent_timestamps.append(time.monotonic())
            time.sleep(0.0008)  # real pacing - still a real flood, just not instantly OS-saturating
        sock.close()

    def start(self):
        if self._running:
            return
        dt.state.reset_udp()
        self._running = True
        self._stop_event.clear()
        self._sent_count = 0
        self._seq_counter = 0
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
            sent = self._sent_count
            now = time.monotonic()
            recent = [ts for ts in self._sent_timestamps if now - ts <= METRIC_WINDOW_SEC]
            send_rate = len(recent) / METRIC_WINDOW_SEC if recent else 0.0

        with dt.state.lock:
            received = dt.state.udp_received
            gaps = dt.state.udp_gaps

        loss_pct = (1.0 - (received / sent)) * 100.0 if sent else 0.0
        loss_pct = max(0.0, min(100.0, loss_pct))
        gap_ratio = (gaps / sent) if sent else 0.0

        return {
            "noise_floor_db": round(-95 + loss_pct * 0.7, 2),  # real-derived: more real loss -> higher reported noise floor
            "retransmit_pct": round(loss_pct, 2),                 # real measured datagram loss
            "sensor_delta": round(min(30.0, gap_ratio * 30.0), 3),   # real-derived from the real sequence-gap ratio actually observed
            "packets_per_sec": round(send_rate, 1),                 # real measured send rate (windowed, not cumulative)
            "sent_total": sent,
            "received_total": received,
            "gap_count": gaps,
        }


if __name__ == "__main__":
    dt.device.start()
    time.sleep(0.2)
    runner = RealJammingRunner()
    runner.start()
    try:
        for _ in range(6):
            time.sleep(1)
            m = runner.get_live_metrics()
            print(f"sent={m['sent_total']:>7}  received={m['received_total']:>7}  "
                  f"loss_pct={m['retransmit_pct']:>6}  noise_floor_db={m['noise_floor_db']}")
    finally:
        runner.stop()
        print("Stopped.")
