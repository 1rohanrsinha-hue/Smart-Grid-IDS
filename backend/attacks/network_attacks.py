"""
attacks/network_attacks.py
===========================
Network-layer attack signatures: DDoS, MITM, Replay, Port/Recon Scan.
"""

import random
from .base import normal_readings, AttackGenerator


def ddos_readings(t, intensity):
    r = normal_readings(t)
    # Calibrated to what a single real (ethical, localhost) load test against a
    # resource-constrained embedded relay can genuinely achieve — see
    # real_attacks/real_ddos.py, which produces real measurements in this same
    # range against the real dummy device.
    r["packets_per_sec"] = 500 + intensity * 1300 + random.gauss(0, 120)
    r["packet_size_avg"] = 64 + random.gauss(0, 8)
    r["unique_ips"] = float(random.randint(30, 300))
    r["latency_ms"] = 40 + intensity * 250 + random.gauss(0, 30)
    r["retransmit_pct"] = 5 + intensity * 25 + random.gauss(0, 3)
    return r


def mitm_readings(t, intensity):
    r = normal_readings(t)
    r["ttl_variance"] = 2 + intensity * 10 + random.gauss(0, 1.5)
    r["latency_ms"] = 15 + intensity * 30 + random.gauss(0, 5)
    r["duplicate_pkt_ratio"] = 0.3 + intensity * 0.65 + random.gauss(0, 0.04)
    r["packets_per_sec"] = 60 + intensity * 60 + random.gauss(0, 10)
    return r


def replay_readings(t, intensity):
    r = normal_readings(t)
    r["duplicate_pkt_ratio"] = 0.5 + intensity * 0.5 + random.gauss(0, 0.03)
    r["packets_per_sec"] = 150 + intensity * 250 + random.gauss(0, 30)
    return r


def port_scan_readings(t, intensity):
    r = normal_readings(t)
    # Calibrated to a real, paced TCP connect-scan against localhost — see
    # real_attacks/real_port_scan.py, which produces real measurements in
    # this same range against the real dummy device's ports.
    r["unique_ips"] = float(random.randint(1, 3))  # single scanning source
    r["conn_duration_avg"] = max(0.00005, 0.0006 - intensity * 0.0005 + random.gauss(0, 0.00005))
    r["packets_per_sec"] = 15 + intensity * 75 + random.gauss(0, 8)
    r["packet_size_avg"] = 40 + random.gauss(0, 6)
    return r


REGISTRY = [
    AttackGenerator(
        "DDOS", "DDoS Flood", "network",
        "Volumetric packet flood from many source IPs overwhelms the gateway.",
        "Rate-limiting traffic / blacklisting source IPs",
        ddos_readings, mitigation_seconds=5,
    ),
    AttackGenerator(
        "MITM", "Man-in-the-Middle", "network",
        "Traffic silently intercepted and relayed through a rogue node.",
        "Enforcing certificate pinning, forcing session re-authentication",
        mitm_readings, mitigation_seconds=6,
    ),
    AttackGenerator(
        "REPLAY", "Replay Attack", "network",
        "Previously captured legitimate packets re-transmitted to spoof state.",
        "Invalidating replayed session tokens, enforcing nonce/timestamp checks",
        replay_readings, mitigation_seconds=5,
    ),
    AttackGenerator(
        "PORT_SCAN", "Network Reconnaissance / Port Scan", "network",
        "Systematic sweep of ports/hosts probing for open services.",
        "Blocking scanning source, tightening firewall ACLs",
        port_scan_readings, mitigation_seconds=4,
    ),
]
