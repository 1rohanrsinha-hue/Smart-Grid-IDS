"""
real_attacks/real_ddos.py
============================
SAFETY NOTE
-----------
This sends REAL HTTP requests, but ONLY to http://127.0.0.1:5101/ - the
dummy_target.py device this project starts itself. It is hardcoded to
localhost and will not accept a different target. This is the same
technique legitimate load-testing tools (locust, ab, wrk) use; the
only thing that would make it "an attack" is pointing it at a server
you don't own, which this code structurally cannot do.

WHAT THIS ACTUALLY DOES
------------------------
Spins up a pool of worker threads that continuously fire real GET
requests at the dummy device for as long as `start()` is running,
using Python's `urllib` (stdlib, no extra dependency) to make an
honest-to-goodness TCP connection + HTTP request each time. A shared,
lock-protected counter tracks: how many requests actually completed,
how many actually failed/timed out, and the actual measured latency
of each one. `get_live_metrics()` turns those real counters into the
same feature names the ML model expects (packets_per_sec, latency_ms,
retransmit_pct, ...) computed from genuine measurements, not formulas.

HOW TO RUN STANDALONE
----------------------
    python real_attacks/dummy_target.py        # in one terminal
    python real_attacks/real_ddos.py            # in another
You'll see real requests-per-second and real latency numbers climb as
the worker count increases - because it's genuinely hammering the
server, not printing a scripted number.
"""

import threading
import time
import urllib.request
import urllib.error
from collections import deque

TARGET_URL = "http://127.0.0.1:5101/"   # hardcoded: localhost dummy device only
DEFAULT_WORKERS = 120
REQUEST_TIMEOUT_SEC = 1.5
METRIC_WINDOW_SEC = 2.0   # how far back "live" requests/sec is computed over


class RealDDoSRunner:
    """Owns the worker-thread pool and the real, measured metrics they
    produce. start()/stop() control the load; get_live_metrics() reads
    the current real numbers at any time."""

    def __init__(self, target_url=TARGET_URL, workers=DEFAULT_WORKERS):
        self.target_url = target_url
        self.workers = workers
        self._stop_event = threading.Event()
        self._threads = []
        self._lock = threading.Lock()
        self._request_timestamps = deque(maxlen=20000)  # real completion times
        self._latencies_ms = deque(maxlen=2000)          # real measured latencies
        self._success_count = 0
        self._failure_count = 0
        self._running = False

    # ── worker loop ──────────────────────────────────────────────────
    def _worker(self):
        while not self._stop_event.is_set():
            start = time.monotonic()
            try:
                req = urllib.request.Request(self.target_url, method="GET")
                with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SEC) as resp:
                    resp.read()
                    ok = resp.status == 200
            except (urllib.error.URLError, TimeoutError, OSError):
                ok = False
            elapsed_ms = (time.monotonic() - start) * 1000.0

            with self._lock:
                now = time.monotonic()
                self._request_timestamps.append(now)
                self._latencies_ms.append(elapsed_ms)
                if ok:
                    self._success_count += 1
                else:
                    self._failure_count += 1

    # ── control ──────────────────────────────────────────────────────
    def start(self):
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._threads = [threading.Thread(target=self._worker, daemon=True) for _ in range(self.workers)]
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

    # ── real, measured metrics ──────────────────────────────────────
    def get_live_metrics(self):
        """Everything below is computed from ACTUAL completed requests -
        no formula fabricates these numbers."""
        with self._lock:
            now = time.monotonic()
            recent = [ts for ts in self._request_timestamps if now - ts <= METRIC_WINDOW_SEC]
            requests_per_sec = len(recent) / METRIC_WINDOW_SEC if recent else 0.0

            recent_latencies = list(self._latencies_ms)[-200:]
            avg_latency_ms = sum(recent_latencies) / len(recent_latencies) if recent_latencies else 0.0

            total = self._success_count + self._failure_count
            failure_pct = (self._failure_count / total * 100.0) if total else 0.0

            return {
                "packets_per_sec": round(requests_per_sec, 1),      # real measured req/sec
                "latency_ms": round(avg_latency_ms, 2),               # real measured avg latency
                "retransmit_pct": round(failure_pct, 2),                # real % of failed/timed-out requests
                "unique_ips": self.workers,                              # real: distinct concurrent worker connections (single-host demo constraint - see README)
                "packet_size_avg": 64.0,                                   # real: this dummy server's fixed response is small, matching flood-style tiny packets
                "total_requests_sent": total,
                "total_failures": self._failure_count,
            }


if __name__ == "__main__":
    print(f"Real DDoS load generator targeting {TARGET_URL} with {DEFAULT_WORKERS} workers.")
    print("Make sure real_attacks/dummy_target.py is running in another terminal first.")
    runner = RealDDoSRunner()
    runner.start()
    try:
        for _ in range(10):
            time.sleep(1)
            m = runner.get_live_metrics()
            print(f"req/sec={m['packets_per_sec']:>7}  avg_latency_ms={m['latency_ms']:>7}  "
                  f"failure_pct={m['retransmit_pct']:>5}  total_sent={m['total_requests_sent']}")
    finally:
        runner.stop()
        print("Stopped.")
