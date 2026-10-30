"""
real_attacks/dummy_target.py
==============================
SAFETY NOTE — READ THIS FIRST
------------------------------
Everything in this file binds ONLY to 127.0.0.1 (localhost). Nothing
here is reachable from any other machine. This is a small, real,
self-hosted stand-in for a piece of grid hardware, exposing real
endpoints so every attack in this project has a legitimate, owned
target instead of touching anyone else's infrastructure.

None of the "vulnerable-looking" endpoints below (the command port,
the auth port) have any real capability to execute code or access the
filesystem — they only ever parse a string and compare it to an
allow-list / credential table. There is no real exploit primitive
anywhere in this file; it is intentionally impossible to make this
code do anything except accept/reject a piece of text, exactly like a
real embedded relay's input validation would.

The single filesystem write in this file is restore_firmware_if_corrupted(): at device start
it copies the golden firmware image over the device's own firmware file if the two differ and no
attack is active (safety net for a server killed mid-FIRMWARE_TAMPER). No network input can reach it.

PORTS
-----
    127.0.0.1:5101  HTTP "device web console"
        GET  /            - device status (used by DDoS)
        POST /sensor      - submit a sensor reading (used by FDI)
        POST /upload      - submit a data blob (used by Malware/exfil)
        GET  /stats       - read-only JSON of the device's own counters (independent proof)
    127.0.0.1:5102  TCP "protocol port" - real line-based text protocol
        CMD <name>            - device checks a real allow-list (Cmd Injection)
        SETPOINT <float>      - device records a real load setpoint (Load-Altering)
        TIMESYNC <unix_ts>    - device compares against its real clock (GPS/Time Spoof)
    127.0.0.1:5103  TCP "admin port" - real (intentionally weak, disclosed) toy login
        LOGIN <user> <pass>   - checked against a real small credential table (Priv Esc)
    127.0.0.1:5104  UDP "sensor telemetry port" - real, capacity-limited (Jamming)
    127.0.0.1:5105  TCP "relay proxy" - real byte-forwarding proxy in front of 5101 (MITM)

HOW TO RUN STANDALONE
----------------------
    python real_attacks/dummy_target.py
"""

import http.server
import socketserver
import socket
import threading
import time
import json
import hashlib
import os
import shutil
from collections import deque

BIND_HOST = "127.0.0.1"  # never change this - localhost only

WEB_PORT = 5101
PROTOCOL_PORT = 5102
ADMIN_PORT = 5103
TELEMETRY_UDP_PORT = 5104
PROXY_PORT = 5105

# The dummy device intentionally behaves like a real resource-constrained
# embedded relay, not a beefy cloud server.
_CONCURRENCY_CAP = 12
_capacity_semaphore = threading.BoundedSemaphore(_CONCURRENCY_CAP)
_ACQUIRE_TIMEOUT_SEC = 0.05

# ── real allow-list for the command protocol (Command Injection target) ────
ALLOWED_COMMANDS = {"STATUS", "PING", "RESET_SIM", "HEARTBEAT"}

# ── real, intentionally weak, disclosed TOY credentials (Priv Esc target) ──
# These exist ONLY for this local demo service and are never reused anywhere
# else. This is the same pattern used by intentionally-vulnerable training
# labs (e.g. DVWA): the "vulnerability" is a known-weak password on a toy
# service we built ourselves, not a real exploit against a real system.
TOY_CREDENTIALS = {
    "guest": ("guest123", 1),
    "operator": ("operator123", 3),
    "svc_relay": ("changeme123", 5),  # the "elevated" account a real attacker targets
}


class DeviceState:
    """All the REAL, mutable state the device genuinely observes from
    real incoming traffic. Every attack-specific reset_*() clears just
    that attack's counters at the start of a fresh run."""

    def __init__(self):
        self.lock = threading.Lock()

        # command protocol / Cmd Injection
        self.cmd_total = 0
        self.cmd_unauthorized = 0

        # sensor ingest / FDI
        self.sensor_baseline = {"voltage": 230.0, "frequency": 50.0}
        self.sensor_last = dict(self.sensor_baseline)
        self.sensor_submissions = 0

        # setpoint / Load-Altering
        self.setpoint_history = deque(maxlen=200)

        # time-sync / GPS Spoof
        self.timesync_last_offset_ms = 0.0
        self.timesync_submissions = 0

        # auth / Priv Esc
        self.auth_failures = 0
        self.auth_successes = 0
        self.achieved_privilege_level = 1

        # UDP telemetry / Jamming
        self.udp_received = 0
        self.udp_highest_seq = -1
        self.udp_gaps = 0

        # upload / Malware
        self.upload_bytes_total = 0
        self.upload_count = 0

        # proxy relay / MITM
        self.proxy_relayed_bytes = 0
        self.proxy_relayed_connections = 0

        # totals kept for the read-only /stats endpoint (never reset)
        self.http_requests_total = 0
        self.connection_probes_total = 0

    def reset_cmd(self):
        with self.lock:
            self.cmd_total = 0
            self.cmd_unauthorized = 0

    def reset_sensor(self):
        with self.lock:
            self.sensor_last = dict(self.sensor_baseline)
            self.sensor_submissions = 0

    def reset_setpoint(self):
        with self.lock:
            self.setpoint_history.clear()

    def reset_timesync(self):
        with self.lock:
            self.timesync_last_offset_ms = 0.0
            self.timesync_submissions = 0

    def reset_auth(self):
        with self.lock:
            self.auth_failures = 0
            self.auth_successes = 0
            self.achieved_privilege_level = 1

    def reset_udp(self):
        with self.lock:
            self.udp_received = 0
            self.udp_highest_seq = -1
            self.udp_gaps = 0

    def reset_upload(self):
        with self.lock:
            self.upload_bytes_total = 0
            self.upload_count = 0

    def reset_proxy(self):
        with self.lock:
            self.proxy_relayed_bytes = 0
            self.proxy_relayed_connections = 0


state = DeviceState()


# ── device-side activity feed (logging only, read by the dashboard) ─────
EVENT_BUFFER_MAX = 40
EVENT_AGG_WINDOW_SEC = 0.5
EVENT_SUMMARY_MAX = 90


class DeviceEventLog:
    """Thread-safe ring buffer of what the device itself observes, e.g.
    "LOGIN svc_relay FAIL" or "HTTP flood: 412 requests in last 0.5s".

    High-rate events are aggregated: the first event for a key is logged
    immediately, further events for that key within EVENT_AGG_WINDOW_SEC
    are counted and emitted as ONE summary line when the window closes.
    This only records; it never changes how any handler behaves."""

    def __init__(self):
        self._lock = threading.Lock()
        self._events = deque(maxlen=EVENT_BUFFER_MAX)
        self._pending = {}     # key -> {kind, count, bytes, last, multi, tags}
        self._last_emit = {}   # key -> monotonic time of last emitted line

    def _emit_locked(self, kind, summary):
        self._events.append({"ts": time.time(), "kind": kind,
                             "summary": summary[:EVENT_SUMMARY_MAX]})

    def _flush_locked(self, key, now):
        p = self._pending.pop(key, None)
        if p:
            text = p["last"] if p["count"] == 1 else p["multi"].format(
                n=p["count"], b=p["bytes"], last=p["last"], t=len(p["tags"]))
            self._emit_locked(p["kind"], text)
            self._last_emit[key] = now

    def record(self, key, kind, single, multi=None, nbytes=0, tag=None):
        """single: text for a lone event. multi: template with {n} {b} {last} {t}
        used when several events for `key` arrive inside one window; {t} is the
        number of distinct `tag` values (e.g. destination ports) in the window."""
        now = time.monotonic()
        with self._lock:
            for k in [k for k, p in self._pending.items()
                      if now - self._last_emit.get(k, 0) >= EVENT_AGG_WINDOW_SEC]:
                self._flush_locked(k, now)
            p = self._pending.get(key)
            if p:
                p["count"] += 1
                p["bytes"] += nbytes
                p["last"] = single
                p["tags"].add(tag)
                return
            if now - self._last_emit.get(key, 0) >= EVENT_AGG_WINDOW_SEC or multi is None:
                self._emit_locked(kind, single)
                self._last_emit[key] = now
            else:
                self._pending[key] = {"kind": kind, "count": 1, "bytes": nbytes,
                                      "last": single, "multi": multi, "tags": {tag}}

    def recent(self, n):
        now = time.monotonic()
        with self._lock:
            for k in [k for k in self._pending
                      if now - self._last_emit.get(k, 0) >= EVENT_AGG_WINDOW_SEC]:
                self._flush_locked(k, now)
            return list(self._events)[-n:][::-1]

    def clear(self):
        with self._lock:
            self._events.clear()
            self._pending.clear()
            self._last_emit.clear()


events = DeviceEventLog()


def _note_probe(port):
    """A TCP connection that was accepted and closed without sending a single
    byte: what a port scan looks like from the device's side. Only ports the
    device actually listens on can ever be seen (closed ports are refused by
    the OS before reaching any device code)."""
    with state.lock:
        state.connection_probes_total += 1
    events.record("probe", "PROBE", f"Port scan: connection probe on port {port} (no data sent)",
                  "Port scan: {n} connection probes in last 0.5s across {t} ports", tag=port)


# ── firmware integrity (read-only) ──────────────────────────────────────
FIRMWARE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firmware_store")
FIRMWARE_GOLDEN_PATH = os.path.join(FIRMWARE_DIR, "golden.bin")
FIRMWARE_DEVICE_PATH = os.path.join(FIRMWARE_DIR, "device.bin")


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def restore_firmware_if_corrupted(attack_active=False):
    """Startup safety net: if the device firmware differs from the golden image (e.g. the server was
    killed between a FIRMWARE_TAMPER and its rollback) and no attack is active, restore it with the
    same real copy the mitigation uses. Returns True if it restored, else False/None."""
    if attack_active:
        return None
    try:
        if _sha256_file(FIRMWARE_GOLDEN_PATH) == _sha256_file(FIRMWARE_DEVICE_PATH):
            return False
        shutil.copyfile(FIRMWARE_GOLDEN_PATH, FIRMWARE_DEVICE_PATH)
    except OSError:
        return None            # no firmware store yet (created on the first FIRMWARE_TAMPER)
    events.record("startup_fw_restore", "FIRMWARE", "Startup integrity check: restored device firmware from golden")
    return True


def check_firmware_integrity(log=True):
    """The device reads its own firmware file from disk, computes the SHA-256
    itself and compares it with the golden image. Read-only. Returns
    {golden_sha256, device_sha256, match}, or None if the files are missing."""
    try:
        golden = _sha256_file(FIRMWARE_GOLDEN_PATH)
        current = _sha256_file(FIRMWARE_DEVICE_PATH)
    except OSError:
        return None
    result = {"golden_sha256": golden, "device_sha256": current, "match": golden == current}
    if log:
        text = ("Integrity check: SHA-256 OK (matches golden)" if result["match"] else
                f"Integrity check: SHA-256 MISMATCH vs golden ({current[:10]}... != {golden[:10]}...)")
        events.record("fw_check_" + ("ok" if result["match"] else "bad"), "FIRMWARE", text)
    return result


# ── HTTP web console (5101) ─────────────────────────────────────────────
class _DeviceConsoleHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _respond_json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle(self):
        self._served_request = False
        super().handle()
        if not self._served_request:
            _note_probe(WEB_PORT)   # connected and closed without sending a request

    def _send_stats(self):
        """Read-only JSON of the device's own counters. No CORS headers, no state changes."""
        with state.lock:
            counters = {
                "cmd_total": state.cmd_total,
                "cmd_unauthorized": state.cmd_unauthorized,
                "sensor_submissions": state.sensor_submissions,
                "auth_failures": state.auth_failures,
                "auth_successes": state.auth_successes,
                "udp_received": state.udp_received,
                "udp_gaps": state.udp_gaps,
                "upload_count": state.upload_count,
                "upload_bytes_total": state.upload_bytes_total,
                "proxy_relayed_bytes": state.proxy_relayed_bytes,
                "proxy_relayed_connections": state.proxy_relayed_connections,
                "http_requests_total": state.http_requests_total,
                "connection_probes_total": state.connection_probes_total,
            }
        counters["firmware"] = check_firmware_integrity(log=False)
        counters["server_time"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        counters["server_time_unix"] = round(time.time(), 3)
        self._respond_json(200, counters)

    def do_GET(self):
        self._served_request = True
        if self.path.split("?", 1)[0] == "/stats":
            self._send_stats()      # not counted and not logged: it is the observer
            return
        with state.lock:
            state.http_requests_total += 1
        acquired = _capacity_semaphore.acquire(timeout=_ACQUIRE_TIMEOUT_SEC)
        if not acquired:
            events.record("http_503", "HTTP", "GET / 503 overloaded (device at capacity)",
                          "HTTP overload: {n} requests rejected (503) in last 0.5s")
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        try:
            time.sleep(0.01)  # real per-request processing delay
            events.record("http_get", "HTTP", "GET / 200 OK",
                          "HTTP flood: {n} requests in last 0.5s")
            self._respond_json(200, {"device": "substation-relay-sim", "status": "ok"})
        finally:
            _capacity_semaphore.release()

    def do_POST(self):
        self._served_request = True
        with state.lock:
            state.http_requests_total += 1
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""

        if self.path == "/sensor":
            try:
                payload = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                payload = {}
            with state.lock:
                state.sensor_last = {
                    "voltage": float(payload.get("voltage", state.sensor_baseline["voltage"])),
                    "frequency": float(payload.get("frequency", state.sensor_baseline["frequency"])),
                }
                state.sensor_submissions += 1
                v, f = state.sensor_last["voltage"], state.sensor_last["frequency"]
            events.record("http_sensor", "HTTP", f"POST /sensor voltage={v:.1f}V freq={f:.2f}Hz",
                          "POST /sensor: {n} readings in last 0.5s ({last})")
            self._respond_json(200, {"ok": True})

        elif self.path == "/upload":
            with state.lock:
                state.upload_bytes_total += len(body)
                state.upload_count += 1
            events.record("http_upload", "HTTP", f"POST /upload {len(body):,} bytes",
                          "POST /upload: {n} uploads, {b:,} bytes in last 0.5s", len(body))
            self._respond_json(200, {"ok": True, "received_bytes": len(body)})

        else:
            self._respond_json(404, {"ok": False})


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        pass  # real dropped/reset connections under load are expected, not bugs


# ── protocol port (5102): CMD / SETPOINT / TIMESYNC ─────────────────────
def _protocol_listener(stop_event):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND_HOST, PROTOCOL_PORT))
    srv.listen(50)
    srv.settimeout(0.5)
    while not stop_event.is_set():
        try:
            conn, _addr = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=_handle_protocol_conn, args=(conn,), daemon=True).start()
    srv.close()


def _handle_protocol_conn(conn):
    try:
        conn.settimeout(1.0)
        buf = b""
        got_data = False
        while True:
            chunk = conn.recv(256)
            if not chunk:
                if not got_data:
                    _note_probe(PROTOCOL_PORT)
                break
            got_data = True
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                reply = _handle_protocol_line(line.decode(errors="ignore").strip())
                if reply:
                    conn.sendall((reply + "\n").encode())
    except OSError:
        pass
    finally:
        conn.close()


def _handle_protocol_line(line):
    parts = line.split(" ", 1)
    if not parts or not parts[0]:
        return "ERROR empty"
    verb = parts[0].upper()
    arg = parts[1] if len(parts) > 1 else ""

    if verb == "CMD":
        with state.lock:
            state.cmd_total += 1
            if arg.strip().upper() in ALLOWED_COMMANDS:
                accepted = True
            else:
                state.cmd_unauthorized += 1
                accepted = False
        shown = arg.strip()[:30]
        if accepted:
            events.record("cmd_ok", "CMD", f"CMD {shown} accepted",
                          "CMD: {n} commands accepted in last 0.5s")
            return f"ACK {arg}"
        events.record("cmd_rej", "CMD", f"CMD {shown} REJECTED (not on allow-list)",
                      "CMD: {n} commands REJECTED in last 0.5s ({last})")
        return f"REJECTED {arg}"

    if verb == "SETPOINT":
        try:
            value = float(arg)
        except ValueError:
            return "ERROR bad setpoint"
        with state.lock:
            state.setpoint_history.append((time.monotonic(), value))
        events.record("setpoint", "SETPOINT", f"SETPOINT {value:g} recorded",
                      "SETPOINT: {n} changes in last 0.5s (latest: {last})")
        return f"ACK SETPOINT {value}"

    if verb == "TIMESYNC":
        try:
            claimed_ts = float(arg)
        except ValueError:
            return "ERROR bad timestamp"
        real_now = time.time()
        offset_ms = abs(claimed_ts - real_now) * 1000.0
        with state.lock:
            state.timesync_last_offset_ms = offset_ms
            state.timesync_submissions += 1
        events.record("timesync", "TIMESYNC", f"TIMESYNC clock offset {offset_ms:,.0f} ms",
                      "TIMESYNC: {n} messages in last 0.5s ({last})")
        return "ACK TIMESYNC"

    return "ERROR unknown verb"


# ── admin port (5103): toy LOGIN protocol ───────────────────────────────
def _admin_listener(stop_event):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND_HOST, ADMIN_PORT))
    srv.listen(50)
    srv.settimeout(0.5)
    while not stop_event.is_set():
        try:
            conn, _addr = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=_handle_admin_conn, args=(conn,), daemon=True).start()
    srv.close()


def _handle_admin_conn(conn):
    try:
        conn.settimeout(1.0)
        data = conn.recv(256).decode(errors="ignore").strip()
        parts = data.split(" ")
        if len(parts) == 3 and parts[0].upper() == "LOGIN":
            username, password = parts[1], parts[2]
            entry = TOY_CREDENTIALS.get(username)
            with state.lock:
                if entry and entry[0] == password:
                    state.auth_successes += 1
                    state.achieved_privilege_level = max(state.achieved_privilege_level, entry[1])
                    ok = True
                    conn.sendall(f"OK {entry[1]}\n".encode())
                else:
                    state.auth_failures += 1
                    ok = False
                    conn.sendall(b"DENIED\n")
            shown_user = username[:20]
            if ok:
                events.record(f"login_ok_{shown_user}", "LOGIN", f"LOGIN {shown_user} OK (privilege {entry[1]})")
            else:
                events.record(f"login_fail_{shown_user}", "LOGIN", f"LOGIN {shown_user} FAIL",
                              f"LOGIN {shown_user} FAIL: ".replace("{", "{{").replace("}", "}}")
                              + "{n} attempts in last 0.5s")
        else:
            if not data:
                _note_probe(ADMIN_PORT)
            conn.sendall(b"ERROR malformed\n")
    except OSError:
        pass
    finally:
        conn.close()


# ── UDP telemetry port (5104): real, capacity-limited (Jamming target) ──
def _udp_listener(stop_event):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Deliberately tiny receive buffer - represents a real resource-constrained
    # sensor radio. Under real flood, the OS genuinely drops datagrams once
    # this fills, which is what produces a real, measurable loss percentage.
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    srv.bind((BIND_HOST, TELEMETRY_UDP_PORT))
    srv.settimeout(0.5)
    while not stop_event.is_set():
        try:
            data, _addr = srv.recvfrom(64)
        except socket.timeout:
            continue
        except OSError:
            continue
        try:
            seq = int(data.decode(errors="ignore").strip())
        except ValueError:
            continue
        with state.lock:
            state.udp_received += 1
            gap = 0
            if state.udp_highest_seq >= 0 and seq > state.udp_highest_seq + 1:
                gap = seq - state.udp_highest_seq - 1
                state.udp_gaps += gap
            state.udp_highest_seq = max(state.udp_highest_seq, seq)
        events.record("udp_rx", "UDP", f"UDP datagram #{seq} received",
                      "UDP flood: {n} datagrams received in last 0.5s")
        if gap:
            events.record("udp_gap", "UDP", f"UDP sequence gap: {gap} datagrams lost before #{seq}",
                          "UDP sequence gaps: loss detected {n} times in last 0.5s")
        time.sleep(0.002)  # real, deliberate limited processing rate
    srv.close()


# ── relay proxy (5105 -> 5101): real byte-forwarding (MITM target) ──────
def _proxy_listener(stop_event):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND_HOST, PROXY_PORT))
    srv.listen(50)
    srv.settimeout(0.5)
    while not stop_event.is_set():
        try:
            client_conn, _addr = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=_handle_proxy_conn, args=(client_conn,), daemon=True).start()
    srv.close()


def _handle_proxy_conn(client_conn):
    try:
        upstream = socket.create_connection((BIND_HOST, WEB_PORT), timeout=2.0)
    except OSError:
        client_conn.close()
        return
    with state.lock:
        state.proxy_relayed_connections += 1
    carried_data = []

    def relay(src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                carried_data.append(1)
                time.sleep(0.006)  # real added processing delay a relay device genuinely introduces
                dst.sendall(data)
                with state.lock:
                    state.proxy_relayed_bytes += len(data)
                events.record("proxy", "PROXY", f"PROXY relayed {len(data):,} bytes",
                              "PROXY: relayed {b:,} bytes in {n} chunks in last 0.5s", len(data))
        except OSError:
            pass

    t1 = threading.Thread(target=relay, args=(client_conn, upstream), daemon=True)
    t2 = threading.Thread(target=relay, args=(upstream, client_conn), daemon=True)
    t1.start()
    t2.start()
    t1.join(timeout=3.0)
    t2.join(timeout=3.0)
    if not carried_data:
        _note_probe(PROXY_PORT)
    client_conn.close()
    upstream.close()


class DummyGridDevice:
    def __init__(self):
        self._http_server = None
        self._http_thread = None
        self._stop_events = []
        self._threads = []
        self._running = False

    def start(self, attack_active=False):
        if self._running:
            return
        self._running = True
        restore_firmware_if_corrupted(attack_active)

        try:
            self._http_server = _ThreadingHTTPServer((BIND_HOST, WEB_PORT), _DeviceConsoleHandler)
            self._http_thread = threading.Thread(target=self._http_server.serve_forever, daemon=True)
            self._http_thread.start()
        except OSError as e:
            print(f"[real_attacks] WARNING: could not bind {BIND_HOST}:{WEB_PORT} ({e}). "
                  f"Probably already running from a previous instance - continuing.")

        listeners = [
            (_protocol_listener, PROTOCOL_PORT),
            (_admin_listener, ADMIN_PORT),
            (_udp_listener, TELEMETRY_UDP_PORT),
            (_proxy_listener, PROXY_PORT),
        ]
        for fn, port in listeners:
            stop_event = threading.Event()
            t = threading.Thread(target=fn, args=(stop_event,), daemon=True)
            t.start()
            self._stop_events.append(stop_event)
            self._threads.append(t)

        time.sleep(0.15)

    def stop(self):
        if not self._running:
            return
        self._running = False
        if self._http_server:
            self._http_server.shutdown()
            self._http_server.server_close()
        for ev in self._stop_events:
            ev.set()
        self._stop_events = []
        self._threads = []

    @property
    def is_running(self):
        return self._running

    def get_recent_events(self, n=12):
        """Newest first: [{ts, kind, summary}, ...]."""
        return events.recent(n)

    def clear_events(self):
        events.clear()

    @staticmethod
    def check_firmware_integrity(log=True):
        return check_firmware_integrity(log)


device = DummyGridDevice()


if __name__ == "__main__":
    print(f"Starting dummy grid device on {BIND_HOST} — "
          f"ports {WEB_PORT}, {PROTOCOL_PORT}, {ADMIN_PORT}, {TELEMETRY_UDP_PORT}(UDP), {PROXY_PORT}")
    device.start()
    print("Running. Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        device.stop()
        print("\nStopped.")
