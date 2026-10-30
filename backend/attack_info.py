"""
attack_info.py
================
Rich, human-readable detail for each attack, shown in the dashboard's
attack info panel (click/hover on any attack button). Kept separate
from attacks/*.py so the generator logic and the explanatory copy can
evolve independently.

Every attack in this project executes genuinely real code against a
genuinely real local target (backend/real_attacks/) - `real_method`
below describes exactly what that real code does, in plain language,
so this can be explained directly in a viva.
"""

INFO = {
    "DDOS": {
        "what_it_is": "A Distributed Denial-of-Service flood: overwhelming a system with "
                       "far more traffic than it can handle, so legitimate requests get "
                       "delayed or dropped.",
        "how_it_works": "An attacker (or, in a real DDoS, thousands of compromised devices) "
                         "sends requests far faster than the target can process them, "
                         "exhausting its connection capacity, CPU, or bandwidth.",
        "grid_impact": "A flooded substation gateway or relay can miss real control commands "
                        "or telemetry updates while it's busy handling junk traffic, effectively "
                        "blinding operators during the flood.",
        "real_method": "A real 120-thread pool sends real HTTP requests to a real local server "
                        "until it genuinely can't keep up - measuring actual requests/sec, actual "
                        "latency, and actual failure rate.",
    },
    "FDI": {
        "what_it_is": "False Data Injection: feeding fabricated sensor readings into a system "
                       "that trusts its sensors, so it makes decisions based on lies.",
        "how_it_works": "An attacker with access to a sensor feed (or the network carrying it) "
                         "substitutes real measurements with crafted false ones, carefully enough "
                         "that basic sanity checks don't catch it.",
        "grid_impact": "A grid's state estimator relies on sensor data to know real voltage and "
                        "frequency. Poisoned readings can mask a real fault, or trigger an "
                        "unnecessary (and disruptive) automatic response to a fault that isn't real.",
        "real_method": "Real fabricated voltage/frequency JSON is POSTed to a real ingest "
                        "endpoint; the deviation reported is computed from what the endpoint "
                        "genuinely received.",
    },
    "CMD_INJECT": {
        "what_it_is": "Command Injection: sending commands a system was never authorized to "
                       "receive or execute, from a source it shouldn't trust.",
        "how_it_works": "An attacker who gains network access to a control channel sends "
                         "commands directly, bypassing the operator interface and any "
                         "authorization checks that interface would normally enforce.",
        "grid_impact": "SCADA commands can open breakers, change setpoints, or trip relays. An "
                        "unauthorized command stream is a direct path to physical grid action.",
        "real_method": "Real command strings are sent over a real TCP socket to a real allow-list "
                        "parser (no real execution capability exists) - the rejection rate reported "
                        "is the endpoint's own real counter.",
    },
    "MALWARE": {
        "what_it_is": "Malicious software running on a compromised host, typically scanning "
                       "the network and staging data to send outside the network (exfiltration).",
        "how_it_works": "Once a foothold exists on one machine, malware often probes nearby "
                         "hosts and bundles up data (logs, configs, credentials) to transmit "
                         "out - producing a distinct large-payload, sustained-connection pattern.",
        "grid_impact": "A compromised engineering workstation or historian server could leak "
                        "network topology, credentials, or control logic - intelligence useful "
                        "for planning a more damaging follow-up attack.",
        "real_method": "Real large (1.4 KB) payloads are uploaded via real HTTP POST at a "
                        "sustained rate to a real endpoint; bytes-transferred and throughput are "
                        "both real, measured values.",
    },
    "MITM": {
        "what_it_is": "Man-in-the-Middle: an unauthorized party inserts itself between two "
                       "communicating systems, able to observe or alter traffic in transit.",
        "how_it_works": "Classically achieved via ARP spoofing or a rogue access point so "
                         "traffic is routed through the attacker's machine instead of directly "
                         "between the real endpoints.",
        "grid_impact": "A relay believing it's talking directly to a control center could "
                        "instead be talking to an intermediary that can read or subtly modify "
                        "commands and telemetry in both directions.",
        "real_method": "Real traffic is routed through a real relay proxy this project runs, "
                        "genuinely forwarding bytes between client and server - the added "
                        "latency and relayed-byte count are real measurements of that real hop.",
    },
    "REPLAY": {
        "what_it_is": "A Replay Attack: capturing a legitimate message and re-sending it later "
                       "to fraudulently repeat its effect.",
        "how_it_works": "If a protocol doesn't use timestamps or one-time tokens, a captured "
                         "'open breaker' command (for example) can be replayed at will, with the "
                         "receiving system unable to tell it apart from a fresh legitimate one.",
        "grid_impact": "A captured control command replayed later could re-trigger an action at "
                        "the wrong time - closing a breaker that should stay open, for instance.",
        "real_method": "One real request is captured once and hashed with SHA-256; the exact "
                        "same real bytes are then genuinely resent repeatedly, with every replay "
                        "hash-verified against the original capture.",
    },
    "PORT_SCAN": {
        "what_it_is": "Network Reconnaissance: systematically probing a host to discover which "
                       "services (ports) are open and reachable, usually the first step before "
                       "a more targeted attack.",
        "how_it_works": "An attacker attempts a connection to many ports in sequence; open ports "
                         "respond, closed ones don't - building a map of what's running on the "
                         "target.",
        "grid_impact": "Discovering an exposed engineering/admin interface on a relay or RTU "
                        "gives an attacker the target list for a real intrusion attempt.",
        "real_method": "Real TCP connect_ex() probes genuinely sweep a real port range on "
                        "localhost using Python's socket module - it genuinely finds the real "
                        "open ports on the dummy device.",
    },
    "FIRMWARE_TAMPER": {
        "what_it_is": "Firmware Tampering: a device's firmware image has been modified from its "
                       "signed, trusted version - potentially inserting a backdoor or corrupting "
                       "safety logic.",
        "how_it_works": "An attacker with write access to a device's storage (or its update "
                         "channel) alters the firmware image; without integrity checking, the "
                         "device will happily boot and run the modified code.",
        "grid_impact": "Tampered relay firmware could silently disable protection functions or "
                        "report false status while causing real damage.",
        "real_method": "Real bytes are flipped at random offsets in a real file on disk; a real "
                        "SHA-256 hash comparison (hashlib) genuinely detects the mismatch; "
                        "mitigation performs a real file-copy rollback to the golden image.",
    },
    "GPS_SPOOF": {
        "what_it_is": "GPS/Time-Sync Spoofing: feeding a device a falsified time or position "
                       "signal it trusts for synchronization.",
        "how_it_works": "Real-world GPS spoofing broadcasts a fake but stronger GPS signal that "
                         "a receiver locks onto instead of the genuine satellites.",
        "grid_impact": "Grid devices use GPS-derived time (via PTP/IEEE 1588) to precisely "
                        "timestamp measurements across the network. A falsified time source can "
                        "desynchronize phasor measurements, corrupting fault-location and "
                        "protection calculations that depend on precise timing.",
        "real_method": "This does NOT touch real GPS/RF hardware (illegal without a licensed "
                        "shielded lab). A real, deliberately-wrong timestamp is sent over a real "
                        "TCP socket to a real time-sync endpoint, which computes a real offset "
                        "against its own real system clock.",
    },
    "LOAD_ALTER": {
        "what_it_is": "A Load-Altering Attack: coordinated manipulation of controllable demand "
                       "(e.g. compromised smart devices) to destabilize grid balance.",
        "how_it_works": "By simultaneously switching many controllable loads on or off, an "
                         "attacker can create sudden demand swings the grid wasn't planning for.",
        "grid_impact": "Grid frequency depends on supply matching demand in real time. Large, "
                        "coordinated, unexpected load swings can push frequency out of safe "
                        "bounds, potentially triggering cascading protective trips.",
        "real_method": "Real fabricated setpoint values are sent over a real TCP socket to a "
                        "real control endpoint; the variance reported is computed from the real "
                        "sequence of values the endpoint actually received.",
    },
    "JAMMING": {
        "what_it_is": "Sensor Jamming: a denial-of-service against a sensor's communication "
                       "channel, so its readings never arrive.",
        "how_it_works": "Real-world jamming floods the radio frequency a sensor uses with noise, "
                         "drowning out its legitimate signal.",
        "grid_impact": "A jammed sensor channel means the control system loses visibility into "
                        "real conditions at that point in the grid - it can't detect a real fault "
                        "it can no longer see.",
        "real_method": "No real RF transmission (illegal without a license). A real UDP flood "
                        "targets a real, deliberately capacity-limited socket; the operating "
                        "system genuinely drops datagrams once its buffer fills - real kernel "
                        "behavior, not a simulated loss percentage.",
    },
    "PRIV_ESC": {
        "what_it_is": "Insider Privilege Escalation: an account with limited access repeatedly "
                       "attempts to gain higher (administrator-level) privileges it shouldn't have.",
        "how_it_works": "Often via credential guessing, exploiting a misconfiguration, or "
                         "abusing a legitimate feature in an unintended way to reach elevated "
                         "access.",
        "grid_impact": "An attacker who escalates from a read-only operator account to an admin "
                        "account gains the ability to issue control commands, change "
                        "configuration, or cover their tracks in logs.",
        "real_method": "Real login attempts are sent over a real TCP socket to a real (small, "
                        "intentionally weak, disclosed) toy credential table - the same pattern "
                        "used by intentionally-vulnerable training labs. Failures and the "
                        "achieved privilege level are the service's own real counters.",
    },
}


def get(attack_id):
    return INFO.get(attack_id, {})
