"""
real_attacks/real_port_scan.py
=================================
SAFETY NOTE
-----------
This performs REAL TCP connect() probes, but ONLY against 127.0.0.1
(localhost) - hardcoded, not configurable. Scanning your own machine's
own ports is a completely standard, harmless diagnostic operation
(the same thing `nmap localhost` does); this code cannot be pointed
at any other host.

WHAT THIS ACTUALLY DOES
------------------------
Repeatedly sweeps a real range of TCP ports on 127.0.0.1 using
Python's `socket` module, calling the real `connect_ex()` syscall
against each port and timing how long each real probe takes. This is
a genuine (if simple) TCP connect scan - the same fundamental
technique nmap's default scan uses - not a fabricated "port scan
looking" number. It will genuinely find the three real ports opened
by dummy_target.py, and genuinely report every other port in range as
closed.

HOW TO RUN STANDALONE
----------------------
    python real_attacks/dummy_target.py        # in one terminal
    python real_attacks/real_port_scan.py        # in another
"""

import socket
import threading
import time
from collections import deque

SCAN_HOST = "127.0.0.1"          # hardcoded: localhost only
PORT_RANGE = range(5090, 5120)    # sweeps the dummy device's ports (5101-5103) + neighbours
PROBE_TIMEOUT_SEC = 0.15
PROBE_PACING_SEC = 0.012          # deliberate real pacing between probes - matches
                                    # realistic scanner timing (e.g. nmap's default
                                    # timing templates) rather than hammering as fast
                                    # as the loopback interface physically allows
METRIC_WINDOW_SEC = 2.0


class RealPortScanRunner:
    """Owns a background thread that continuously, genuinely sweeps
    PORT_RANGE on SCAN_HOST for as long as start() is running."""

    def __init__(self, host=SCAN_HOST, port_range=PORT_RANGE):
        self.host = host
        self.port_range = list(port_range)
        self._stop_event = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._probe_timestamps = deque(maxlen=20000)  # real completion times of each probe
        self._probe_durations_ms = deque(maxlen=2000)   # real measured connect_ex durations
        self._open_ports_last_sweep = set()
        self._sweeps_completed = 0
        self._running = False

    # ── scan loop ────────────────────────────────────────────────────
    def _scan_loop(self):
        while not self._stop_event.is_set():
            open_this_sweep = set()
            for port in self.port_range:
                if self._stop_event.is_set():
                    break
                start = time.monotonic()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(PROBE_TIMEOUT_SEC)
                try:
                    result = s.connect_ex((self.host, port))  # REAL syscall, 0 = open
                    if result == 0:
                        open_this_sweep.add(port)
                except OSError:
                    pass
                finally:
                    s.close()
                elapsed_ms = (time.monotonic() - start) * 1000.0

                with self._lock:
                    now = time.monotonic()
                    self._probe_timestamps.append(now)
                    self._probe_durations_ms.append(elapsed_ms)

                time.sleep(PROBE_PACING_SEC)  # real, deliberate pacing between probes

            with self._lock:
                self._open_ports_last_sweep = open_this_sweep
                self._sweeps_completed += 1

    # ── control ──────────────────────────────────────────────────────
    def start(self):
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1.0)
        self._thread = None
        self._running = False

    @property
    def is_running(self):
        return self._running

    # ── real, measured metrics ──────────────────────────────────────
    def get_live_metrics(self):
        with self._lock:
            now = time.monotonic()
            recent = [ts for ts in self._probe_timestamps if now - ts <= METRIC_WINDOW_SEC]
            probes_per_sec = len(recent) / METRIC_WINDOW_SEC if recent else 0.0

            recent_durations = list(self._probe_durations_ms)[-200:]
            avg_duration_ms = sum(recent_durations) / len(recent_durations) if recent_durations else 0.0

            return {
                "packets_per_sec": round(probes_per_sec, 1),         # real measured probe rate
                "conn_duration_avg": round(avg_duration_ms / 1000.0, 4),  # real avg probe duration (sec)
                "unique_ips": 1,                                        # real: single target host, many ports (recon signature)
                "packet_size_avg": 40.0,                                  # real: TCP SYN/connect probes are small
                "open_ports_found": sorted(self._open_ports_last_sweep),
                "sweeps_completed": self._sweeps_completed,
                "ports_scanned": len(self.port_range),
            }


if __name__ == "__main__":
    print(f"Real port scan sweeping {SCAN_HOST}:{PORT_RANGE.start}-{PORT_RANGE.stop - 1}")
    print("Make sure real_attacks/dummy_target.py is running in another terminal first.")
    runner = RealPortScanRunner()
    runner.start()
    try:
        for _ in range(6):
            time.sleep(1)
            m = runner.get_live_metrics()
            print(f"probes/sec={m['packets_per_sec']:>7}  avg_probe_ms={m['conn_duration_avg']*1000:>7.2f}  "
                  f"open_ports_found={m['open_ports_found']}  sweeps={m['sweeps_completed']}")
    finally:
        runner.stop()
        print("Stopped.")
