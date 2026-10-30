"""
test_engine.py (v3)
=====================
Extends the v2 engine with:
  - target_node: every attack now hits a specific grid topology node
  - multi-model detection: RF / SVM / MLP, switchable at runtime
  - hybrid verdicts: ML prediction AND an independent rule-engine
    verdict are computed every tick, with an agree/disagree flag
  - severity scoring per detection
  - simulated notifications on CRITICAL severity
  - append-only event_log.jsonl for the analytics page + report export
  - multi-stage attack scenarios ("kill chains")

The core SECURE -> DETECTED -> MITIGATING -> RESOLVED -> SECURE state
machine and its timing are UNCHANGED from v2 - every existing feature
keeps working exactly as before.
"""

import os
import json
import pickle
import random
import threading
import time
from collections import deque
from datetime import datetime

import numpy as np

from attacks import ATTACKS, CLASSES, FEATURES, normal_readings, clip, ramp_intensity
import mitigation as mit
import topology
import rule_engine
import severity as severity_mod
import notifier
import scenarios as scenarios_mod
import real_attacks as real_attacks_mod
import attack_info

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_EVENT_LOG_PATH = os.path.join(SCRIPT_DIR, "event_log.jsonl")


def event_log_path():
    """Incident log location. SGIDS_EVENT_LOG overrides the default so tests
    and verification runs never write into the real analytics log."""
    return os.environ.get("SGIDS_EVENT_LOG") or DEFAULT_EVENT_LOG_PATH

TICK_SECONDS = 1.0
TARGET_FEED_LINGER_SEC = 6.0      # device feed stays visible this long after an attack ends
TARGET_FEED_LINES = 12
MAX_LOG_ENTRIES = 100
MAX_NOTIFICATIONS = 50
AUTO_MIN_GAP_TICKS = 6
AUTO_MAX_GAP_TICKS = 14

MODEL_FILES = {
    "RF": "model_rf.pkl",
    "SVM": "model_svm.pkl",
    "MLP": "model_mlp.pkl",
}
MODEL_DISPLAY_NAMES = {
    "RF": "Random Forest",
    "SVM": "SVM (RBF)",
    "MLP": "Neural Net (MLP)",
}


def _now():
    return datetime.now().strftime("%H:%M:%S")


def _mono():
    """Monotonic clock for attack timing (a single seam so tests can fake it)."""
    return time.monotonic()


def _now_iso():
    return datetime.now().isoformat(timespec="seconds")


class Engine:
    def __init__(self):
        self._lock = threading.RLock()
        self._thread = None
        self._running = False

        self.models = self._load_models()
        self.active_model_name = "RF" if "RF" in self.models else next(iter(self.models))

        # ── core state (v2) ─────────────────────────────────────────
        self.t = 0
        self.phase = mit.SECURE
        self.active_attack = None
        self.pending_attack = None
        self.pending_node = None
        self.ramp_tick = 0
        self.phase_tick = 0
        self.mitigation_total = 5
        self.auto_mode = False
        self.auto_countdown = random.randint(AUTO_MIN_GAP_TICKS, AUTO_MAX_GAP_TICKS)

        self.last_reading = clip(normal_readings(0))
        self.last_prediction = "NORMAL"
        self.last_confidence = 1.0
        self.last_probabilities = {c: (1.0 if c == "NORMAL" else 0.0) for c in CLASSES}
        self.mitigation_action = ""
        self.mitigation_progress = 0
        self.attack_started_at = None      # monotonic time the current attack began
        self.attack_times = None           # launched/detected/mitigation_started/resolved (monotonic); kept until the next attack
        self.attack_meta = None
        self.last_headline = None          # last real headline metric measured during the attack (shown as final afterwards)
        self.target_feed_until = 0.0       # monotonic time after which target_activity is empty

        self.event_log = deque(maxlen=MAX_LOG_ENTRIES)

        # ── v3 additions ────────────────────────────────────────────
        self.target_node = None
        self.node_hit_counts = {}          # node_id -> count this session
        self.rule_verdict = rule_engine.evaluate(self.last_reading)
        self.current_severity = None       # dict from severity.evaluate(), or None when SECURE
        self.notifications = deque(maxlen=MAX_NOTIFICATIONS)

        self.event_id_counter = 0
        self.incident_records = {}          # id -> full incident dict (in-memory cache)
        self.current_incident = None        # in-progress incident dict

        self.active_scenario = None         # scenario_id or None
        self.scenario_stage_idx = 0
        self.scenario_target_node = None
        self.scenario_wait_remaining = 0
        self.scenario_stage_status = []     # ["done","running","pending",...]

        self._log("SYSTEM BOOT", "IDS engine initialized, RF/SVM/MLP models loaded", "ok")

    # ── model loading ────────────────────────────────────────────────
    def _load_models(self):
        models = {}
        for name, filename in MODEL_FILES.items():
            path = os.path.join(SCRIPT_DIR, filename)
            if os.path.exists(path):
                with open(path, "rb") as f:
                    models[name] = pickle.load(f)
        if not models:
            legacy = os.path.join(SCRIPT_DIR, "model.pkl")
            if not os.path.exists(legacy):
                raise FileNotFoundError(
                    "No trained models found. Run `python train_models.py` first."
                )
            with open(legacy, "rb") as f:
                models["RF"] = pickle.load(f)
        return models

    # ── logging ──────────────────────────────────────────────────────
    def _log(self, title, detail, kind="ok", event_id=None):
        self.event_log.appendleft({
            "time": _now(), "title": title, "detail": detail, "kind": kind, "event_id": event_id,
        })

    def _append_incident_jsonl(self, incident):
        try:
            with open(event_log_path(), "a") as f:
                f.write(json.dumps(incident) + "\n")
        except OSError:
            pass

    def _read_all_incidents(self):
        incidents = []
        path = event_log_path()
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        incidents.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return incidents

    # ── inference ────────────────────────────────────────────────────
    def _predict(self, reading):
        bundle = self.models[self.active_model_name]
        features = bundle["features"]
        vec = np.array([[reading[f] for f in features]])
        if "scaler" in bundle:
            vec = bundle["scaler"].transform(vec)
        model = bundle["model"]
        pred_idx = model.predict(vec)[0]
        probs = model.predict_proba(vec)[0]
        le = bundle["label_encoder"]
        pred_class = str(le.inverse_transform([pred_idx])[0])
        prob_map = {cls: float(p) for cls, p in zip(le.classes_, probs)}
        confidence = float(prob_map.get(pred_class, max(probs)))
        return pred_class, confidence, prob_map

    def _infer_and_store(self, reading):
        pred_class, confidence, prob_map = self._predict(reading)
        self.last_reading = reading
        self.last_prediction = pred_class
        self.last_confidence = confidence
        self.last_probabilities = prob_map
        self.rule_verdict = rule_engine.evaluate(reading)
        return pred_class, confidence, prob_map

    # ── public API: models ───────────────────────────────────────────
    def list_models(self):
        comparison_path = os.path.join(SCRIPT_DIR, "model_comparison.json")
        metrics = {}
        if os.path.exists(comparison_path):
            with open(comparison_path) as f:
                metrics = json.load(f).get("models", {})
        out = []
        for name in self.models:
            m = metrics.get(name, {})
            out.append({
                "id": name,
                "name": MODEL_DISPLAY_NAMES.get(name, name),
                "active": name == self.active_model_name,
                "accuracy": m.get("accuracy"),
                "f1_score": m.get("f1_score"),
                "train_time_sec": m.get("train_time_sec"),
                "confusion_matrix": m.get("confusion_matrix"),
            })
        return out

    def select_model(self, name):
        with self._lock:
            if name not in self.models:
                return {"ok": False, "reason": f"Unknown model '{name}'."}
            self.active_model_name = name
            self._log("MODEL SWITCHED", f"Active detection model set to {MODEL_DISPLAY_NAMES.get(name, name)}", "ok")
            return {"ok": True, "active_model": name}

    # ── public API: attacks / scenarios / triggers ───────────────────
    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        with self._lock:
            self._running = False

    def _busy(self):
        return self.phase != mit.SECURE or self.active_attack is not None or self.active_scenario is not None

    def trigger(self, attack_id, node_id=None):
        with self._lock:
            if self._busy():
                return {"ok": False, "reason": "An attack or scenario is already in progress."}
            if attack_id == "RANDOM":
                attack_id = random.choice(list(ATTACKS.keys()))
            if attack_id not in ATTACKS:
                return {"ok": False, "reason": f"Unknown attack id '{attack_id}'."}
            if node_id and node_id not in topology.NODE_IDS:
                return {"ok": False, "reason": f"Unknown node id '{node_id}'."}
            self.pending_attack = attack_id
            self.pending_node = node_id
            return {"ok": True, "attack": attack_id, "node": node_id}

    def trigger_scenario(self, scenario_id):
        with self._lock:
            if self._busy():
                return {"ok": False, "reason": "An attack or scenario is already in progress."}
            scenario = scenarios_mod.get_scenario(scenario_id)
            if not scenario:
                return {"ok": False, "reason": f"Unknown scenario '{scenario_id}'."}
            self.active_scenario = scenario_id
            self.scenario_stage_idx = 0
            self.scenario_target_node = topology.target_for_category(scenario["target_category"])
            self.scenario_stage_status = ["pending"] * len(scenario["stages"])
            self.scenario_stage_status[0] = "running"
            self._log(
                f"SCENARIO STARTED: {scenario['name']}",
                f"Targeting {topology.node_name(self.scenario_target_node)} \u00b7 "
                f"{len(scenario['stages'])} stages",
                "warn",
            )
            self.pending_attack = scenario["stages"][0]
            self.pending_node = self.scenario_target_node
            return {"ok": True, "scenario": scenario_id}

    def set_auto_mode(self, enabled):
        with self._lock:
            self.auto_mode = bool(enabled)
            if self.auto_mode:
                self.auto_countdown = random.randint(AUTO_MIN_GAP_TICKS, AUTO_MAX_GAP_TICKS)
            self._log(
                "AUTO MODE " + ("ENABLED" if self.auto_mode else "DISABLED"),
                "Random attacks will fire on a timer" if self.auto_mode else "Manual control only",
                "ok",
            )
            return {"ok": True, "auto": self.auto_mode}

    # ── public API: read-only ────────────────────────────────────────
    def get_status(self):
        with self._lock:
            r = self.last_reading
            gen = ATTACKS.get(self.active_attack)
            scenario = scenarios_mod.get_scenario(self.active_scenario) if self.active_scenario else None
            is_real = real_attacks_mod.manager.is_real(self.active_attack) if self.active_attack else False
            real_metrics = real_attacks_mod.manager.get_raw_metrics(self.active_attack) if is_real else {}
            if self.active_attack == "FIRMWARE_TAMPER" and not real_metrics:
                real_metrics = self._firmware_evidence_from_device()   # runner stopped: the device itself reports
            headline = self._headline(real_metrics)
            attack_stage = self._attack_stage()
            elapsed = round(_mono() - self.attack_started_at, 1) if (
                self.active_attack and self.attack_started_at is not None) else 0.0
            show_feed = self.active_attack is not None or _mono() < self.target_feed_until
            activity = real_attacks_mod.manager.get_target_events(TARGET_FEED_LINES) if show_feed else []
            now_wall = time.time()
            target_activity = {
                "events": [{"ts": e["ts"], "kind": e["kind"], "summary": e["summary"],
                            "age_s": round(max(0.0, now_wall - e["ts"]), 1)} for e in activity],
                "device_online": real_attacks_mod.manager.target_online(),
            }
            return {
                "tick": self.t,
                "phase": self.phase,
                "attack_stage": attack_stage,
                "attack_timeline": self._timeline(),
                "attack_elapsed_s": elapsed,
                "attack_headline_metric": headline,
                "target_activity": target_activity,
                "attack_type": self.active_attack or "NONE",
                "attack_display_name": gen.name if gen else "NONE",
                "attack_category": gen.category if gen else None,
                "is_real_attack": is_real,
                "real_attack_evidence": real_metrics,
                "target_node": self.target_node,
                "target_node_name": topology.node_name(self.target_node) if self.target_node else None,
                "prediction": self.last_prediction,
                "confidence": round(self.last_confidence, 4),
                "probabilities": {k: round(v, 4) for k, v in self.last_probabilities.items()},
                "active_model": self.active_model_name,
                "active_model_name": MODEL_DISPLAY_NAMES.get(self.active_model_name, self.active_model_name),
                "rule_engine": self.rule_verdict,
                "verdict_agreement": self._agreement(),
                "severity": self.current_severity,
                "mitigation_action": self.mitigation_action,
                "mitigation_progress": self.mitigation_progress,
                "auto_mode": self.auto_mode,
                "scenario": {
                    "active": self.active_scenario,
                    "name": scenario["name"] if scenario else None,
                    "stages": scenario["stages"] if scenario else [],
                    "stage_status": self.scenario_stage_status,
                    "stage_idx": self.scenario_stage_idx,
                    "target_node": self.scenario_target_node,
                    "target_node_name": topology.node_name(self.scenario_target_node)
                        if self.scenario_target_node else None,
                    "waiting": self.active_attack is None,   # between stages: SECURE, next stage pending
                    "starting_in_s": max(self.scenario_wait_remaining, 1) if self.active_attack is None else 0,
                } if self.active_scenario else None,
                "telemetry": {
                    "voltage": round(r["voltage"], 2),
                    "frequency": round(r["frequency"], 3),
                    "current": round(r["current"], 2),
                    "power_factor": round(r["power_factor"], 3),
                    "packets_per_sec": round(r["packets_per_sec"], 1),
                    "packet_size_avg": round(r["packet_size_avg"], 1),
                    "unique_ips": int(r["unique_ips"]),
                    "cmd_rate": round(r["cmd_rate"], 2),
                    "cmd_unknown": round(r["cmd_unknown"], 4),
                    "latency_ms": round(r["latency_ms"], 2),
                    "retransmit_pct": round(r["retransmit_pct"], 3),
                    "sensor_delta": round(r["sensor_delta"], 4),
                    "conn_duration_avg": round(r["conn_duration_avg"], 3),
                    "ttl_variance": round(r["ttl_variance"], 3),
                    "auth_failures": round(r["auth_failures"], 3),
                    "firmware_checksum_mismatch": round(r["firmware_checksum_mismatch"], 4),
                    "gps_drift": round(r["gps_drift"], 2),
                    "time_offset_ms": round(r["time_offset_ms"], 2),
                    "load_variance": round(r["load_variance"], 3),
                    "noise_floor_db": round(r["noise_floor_db"], 2),
                    "duplicate_pkt_ratio": round(r["duplicate_pkt_ratio"], 4),
                    "privilege_level": round(r["privilege_level"], 2),
                },
                "event_log": list(self.event_log)[:12],
                "model_meta": {"accuracy": self.models[self.active_model_name].get("accuracy"),
                                "classes": self.models[self.active_model_name].get("classes")},
            }

    def _firmware_evidence_from_device(self):
        """After the real rollback the runner is gone; the device hashes its own file instead."""
        fw = real_attacks_mod.manager.firmware_integrity()
        if not fw:
            return {}
        return {"firmware_checksum_mismatch": 0.0 if fw["match"] else 1.0,
                "golden_sha256": fw["golden_sha256"], "device_sha256": fw["device_sha256"],
                "corrupted_byte_offsets": [], "tampered": not fw["match"]}

    def _cache_headline(self):
        """Remember the last real headline value while the runner is still producing it."""
        if self.active_attack and real_attacks_mod.manager.is_real(self.active_attack):
            m = real_attacks_mod.headline_metric(
                self.active_attack, real_attacks_mod.manager.get_raw_metrics(self.active_attack))
            if m["value"] != "--":
                self.last_headline = m

    def _headline(self, real_metrics):
        """Headline metric for /api/status. Live while the runner runs; at RESOLVED and during the
        post-attack linger it is the last measured value, flagged final. FIRMWARE_TAMPER is always
        computed live by the device (so it reads YES once the rollback has really happened)."""
        empty = {"label": "", "value": "--", "unit": "", "final": False}
        lingering = self.active_attack is None and _mono() < self.target_feed_until
        if self.active_attack is None and not lingering:
            return empty
        aid = self.active_attack or (self.attack_meta or {}).get("attack_id")
        if not aid:
            return empty
        final = self.active_attack is None or self.phase == mit.RESOLVED
        if aid == "FIRMWARE_TAMPER":
            m = real_attacks_mod.headline_metric(aid, self._firmware_evidence_from_device() if not real_metrics or final else real_metrics)
            return {**m, "final": final}
        if self.active_attack and not final:
            m = real_attacks_mod.headline_metric(aid, real_metrics)
            if m["value"] != "--":
                self.last_headline = m
                return {**m, "final": False}
        if self.last_headline and self.last_headline.get("label") == real_attacks_mod.HEADLINE_METRICS[aid][0]:
            return {**self.last_headline, "final": final}
        return {**real_attacks_mod.headline_metric(aid, real_metrics), "final": final}

    def _timeline(self):
        """Seconds since launch for each milestone reached so far (None until reached).
        Kept after the attack ends and replaced when the next attack launches."""
        if not self.attack_times:
            return None
        t0 = self.attack_times["launched"]
        rel = lambda k: None if self.attack_times[k] is None else round(self.attack_times[k] - t0, 1)
        return {
            **(self.attack_meta or {}),
            "active": self.active_attack is not None,
            "detected_s": rel("detected"),
            "mitigation_started_s": rel("mitigation_started"),
            "resolved_s": rel("resolved"),
            "time_to_detect_s": rel("detected"),
        }

    def _attack_stage(self):
        """Finer-grained than phase: EXECUTING covers the ramp ticks where
        the attack is already running but the model has not flagged it yet."""
        if self.active_attack is None:
            return "NONE"
        if self.phase == mit.SECURE:
            return "EXECUTING"
        return self.phase

    def _agreement(self):
        ml_flagged = self.last_prediction != "NORMAL"
        rule_flagged = self.rule_verdict["verdict"] == "SUSPICIOUS"
        return ml_flagged == rule_flagged

    def get_history(self):
        with self._lock:
            return list(self.event_log)

    def get_attack_catalog(self):
        return [
            {"id": a.id, "name": a.name, "category": a.category,
             "description": a.description, "mitigation": a.mitigation,
             "is_real": real_attacks_mod.manager.is_real(a.id),
             "info": attack_info.get(a.id)}
            for a in ATTACKS.values()
        ]

    def get_topology(self):
        layout = topology.get_layout()
        with self._lock:
            active_target = self.target_node
            phase = self.phase
        for node in layout["nodes"]:
            if node["id"] == active_target and phase != mit.SECURE:
                node["status"] = "mitigating" if phase == "MITIGATING" else (
                    "resolved" if phase == "RESOLVED" else "attacked")
            else:
                node["status"] = "normal"
        layout["edges_active"] = []
        return layout

    def get_notifications(self):
        with self._lock:
            return list(self.notifications)

    def get_analytics(self):
        incidents = self._read_all_incidents()
        total = len(incidents)
        by_attack = {}
        by_hour = {}
        agree_count = 0
        confidences = []
        mitigation_times = {}
        for inc in incidents:
            atk = inc.get("attack_id", "UNKNOWN")
            by_attack[atk] = by_attack.get(atk, 0) + 1
            hour = (inc.get("detected_at") or "")[:13]
            by_hour[hour] = by_hour.get(hour, 0) + 1
            if inc.get("agreement"):
                agree_count += 1
            if isinstance(inc.get("ml_confidence"), (int, float)):
                confidences.append(inc["ml_confidence"])
            secs = inc.get("mitigation_seconds")
            if isinstance(secs, (int, float)):
                mitigation_times.setdefault(atk, []).append(secs)

        most_frequent = max(by_attack.items(), key=lambda kv: kv[1])[0] if by_attack else None
        avg_confidence = round(sum(confidences) / len(confidences), 4) if confidences else 0
        agreement_rate = round(agree_count / total, 4) if total else 0
        avg_mitigation = {atk: round(sum(v) / len(v), 2) for atk, v in mitigation_times.items()}

        return {
            "total_incidents": total,
            "by_attack_type": by_attack,
            "by_hour": dict(sorted(by_hour.items())),
            "most_frequent_attack": most_frequent,
            "avg_confidence": avg_confidence,
            "ml_rule_agreement_rate": agreement_rate,
            "avg_mitigation_seconds_by_attack": avg_mitigation,
        }

    def get_explain(self):
        import explainability
        with self._lock:
            bundle = self.models[self.active_model_name]
            reading = dict(self.last_reading)
            active_model_name = self.active_model_name
        return explainability.explain(bundle["model"], active_model_name, bundle["features"], reading)

    def get_incident(self, event_id):
        with self._lock:
            if event_id in self.incident_records:
                return self.incident_records[event_id]
        for inc in self._read_all_incidents():
            if str(inc.get("id")) == str(event_id):
                return inc
        return None

    # ── tick loop ────────────────────────────────────────────────────
    def _run_loop(self):
        while True:
            with self._lock:
                if not self._running:
                    return
            self._tick()
            time.sleep(TICK_SECONDS)

    def _tick(self):
        with self._lock:
            self.t += 1
            if self.phase == mit.SECURE and self.active_attack is None:
                self._tick_secure_idle()
            elif self.phase == mit.SECURE and self.active_attack is not None:
                self._tick_ramping()
            elif self.phase == mit.DETECTED:
                self._tick_detected()
            elif self.phase == mit.MITIGATING:
                self._tick_mitigating()
            elif self.phase == mit.RESOLVED:
                self._tick_resolved()

    def _tick_secure_idle(self):
        attack_to_start = None
        node_to_use = None

        if self.pending_attack:
            attack_to_start = self.pending_attack
            node_to_use = self.pending_node
            self.pending_attack = None
            self.pending_node = None
        elif self.scenario_wait_remaining > 0:
            self.scenario_wait_remaining -= 1
            if self.scenario_wait_remaining <= 0:
                scenario = scenarios_mod.get_scenario(self.active_scenario)
                attack_to_start = scenario["stages"][self.scenario_stage_idx]
                node_to_use = self.scenario_target_node
                self.scenario_stage_status[self.scenario_stage_idx] = "running"
        elif self.auto_mode:
            self.auto_countdown -= 1
            if self.auto_countdown <= 0:
                attack_to_start = random.choice(list(ATTACKS.keys()))
                self.auto_countdown = random.randint(AUTO_MIN_GAP_TICKS, AUTO_MAX_GAP_TICKS)

        if attack_to_start:
            self.active_attack = attack_to_start
            self.ramp_tick = 0
            self.attack_started_at = _mono()
            self.last_headline = None
            self.attack_times = {"launched": self.attack_started_at, "detected": None,
                                 "mitigation_started": None, "resolved": None}
            real_attacks_mod.manager.clear_target_events()
            gen = ATTACKS[self.active_attack]
            self.target_node = node_to_use or topology.target_for_category(gen.category)
            self.attack_meta = {"attack_id": self.active_attack, "attack_name": gen.name,
                                "target_node": self.target_node,
                                "target_node_name": topology.node_name(self.target_node),
                                "launched_at": _now_iso()}

            if real_attacks_mod.manager.is_real(self.active_attack):
                real_attacks_mod.manager.start(self.active_attack)
                self._log(
                    f"ATTACK INJECTED: {gen.name} (REAL)",
                    f"Target: {topology.node_name(self.target_node)} \u00b7 executing real code against "
                    f"real local target (see real_attacks/)",
                    "warn",
                )
            else:
                self._log(
                    f"ATTACK INJECTED: {gen.name}",
                    f"Target: {topology.node_name(self.target_node)}",
                    "warn",
                )
            self._tick_ramping()
            return

        reading = clip(normal_readings(self.t))
        self._infer_and_store(reading)
        self.current_severity = None

    def _reading_for_active_attack(self, intensity):
        """Returns the reading to feed the model for the current tick.
        For DDOS / PORT_SCAN / FIRMWARE_TAMPER this pulls REAL, just-
        measured metrics from the real_attacks runner (see
        real_attacks/__init__.py) merged onto a normal baseline. Every
        other attack still uses its synthetic generator function."""
        gen = ATTACKS[self.active_attack]
        if real_attacks_mod.manager.is_real(self.active_attack):
            baseline = clip(normal_readings(self.t))
            return clip(real_attacks_mod.manager.get_reading(self.active_attack, baseline))
        return gen.generate(self.t, intensity)

    def _tick_ramping(self):
        gen = ATTACKS[self.active_attack]
        self.ramp_tick += 1
        intensity = ramp_intensity(self.ramp_tick, mit.MAX_RAMP_TICKS)
        reading = self._reading_for_active_attack(intensity)
        pred_class, confidence, prob_map = self._infer_and_store(reading)

        detected = (pred_class == self.active_attack and confidence >= mit.DETECTION_CONFIDENCE_THRESHOLD)
        forced = self.ramp_tick >= mit.MAX_RAMP_TICKS
        # the model verdict is still required; it is only held back until the attack
        # has been visibly EXECUTING for MIN_EXECUTING_TICKS ticks
        if (detected and self.ramp_tick > mit.MIN_EXECUTING_TICKS) or forced:
            self.phase = mit.DETECTED
            self.phase_tick = 0
            self.attack_times["detected"] = _mono()

            self.node_hit_counts[self.target_node] = self.node_hit_counts.get(self.target_node, 0) + 1
            sev = severity_mod.evaluate(self.active_attack, confidence, self.node_hit_counts, self.target_node)
            self.current_severity = sev

            self.event_id_counter += 1
            event_id = self.event_id_counter
            self.current_incident = {
                "id": event_id,
                "time": _now(),
                "detected_at": _now_iso(),
                "attack": gen.name,
                "attack_id": self.active_attack,
                "target_node": self.target_node,
                "target_node_name": topology.node_name(self.target_node),
                "model_used": self.active_model_name,
                "ml_verdict": pred_class,
                "ml_confidence": round(confidence, 4),
                "rule_verdict": self.rule_verdict["verdict"],
                "rule_reason": self.rule_verdict["fired_description"],
                "agreement": self._agreement(),
                "severity_band": sev["band"],
                "severity_score": sev["score"],
                "scenario": self.active_scenario,
                "scenario_stage": self.scenario_stage_idx if self.active_scenario else None,
                "time_to_detect_s": round(self.attack_times["detected"] - self.attack_times["launched"], 1),
            }

            self._log(
                f"ATTACK DETECTED: {gen.name}",
                f"{topology.node_name(self.target_node)} \u00b7 AI confidence {confidence*100:.1f}% "
                f"\u00b7 severity {sev['band']}",
                "alert",
                event_id=event_id,
            )

            if notifier.should_notify(sev["band"]):
                note = notifier.build_notification(gen.name, topology.node_name(self.target_node),
                                                     sev["band"], confidence)
                self.notifications.appendleft(note)
                self._log("NOTIFICATION SENT", f"{note['channel']} -> {note['recipient']}: {note['subject']}", "warn")

    def _tick_detected(self):
        gen = ATTACKS[self.active_attack]
        self.phase_tick += 1
        reading = self._reading_for_active_attack(1.0)
        self._infer_and_store(reading)

        if self.phase_tick >= mit.DETECTED_HOLD_SECONDS:
            self.phase = mit.MITIGATING
            self.phase_tick = 0
            self.attack_times["mitigation_started"] = _mono()
            self.mitigation_total = mit.mitigation_seconds_for(self.active_attack)
            self.mitigation_action = mit.mitigation_action_for(self.active_attack)
            self.mitigation_progress = 0
            self._log(f"MITIGATING: {gen.name}", self.mitigation_action, "warn")

    def _tick_mitigating(self):
        gen = ATTACKS[self.active_attack]
        self.phase_tick += 1
        remaining = max(0.0, 1.0 - (self.phase_tick / float(self.mitigation_total)))
        reading = self._reading_for_active_attack(remaining)
        self._infer_and_store(reading)
        self.mitigation_progress = min(100, int((self.phase_tick / float(self.mitigation_total)) * 100))

        if self.phase_tick >= self.mitigation_total:
            self.phase = mit.RESOLVED
            self.phase_tick = 0
            self.attack_times["resolved"] = _mono()
            self.mitigation_progress = 100
            total_seconds = self.ramp_tick + mit.DETECTED_HOLD_SECONDS + self.mitigation_total

            if real_attacks_mod.manager.is_real(self.active_attack):
                # Real stop/rollback happens exactly now: for DDOS/PORT_SCAN this
                # kills the real background load/scan thread; for FIRMWARE_TAMPER
                # this performs a real file copy of the golden image back over
                # the (really) corrupted device file.
                self._cache_headline()
                real_attacks_mod.manager.stop(self.active_attack)

            if self.current_incident:
                self.current_incident["mitigation_action"] = self.mitigation_action
                self.current_incident["mitigation_seconds"] = total_seconds
                self.current_incident["resolved_at"] = _now_iso()
                self.incident_records[self.current_incident["id"]] = dict(self.current_incident)
                self._append_incident_jsonl(self.current_incident)

            if self.active_scenario:
                self.scenario_stage_status[self.scenario_stage_idx] = "done"

            self._log(
                f"RESOLVED: {gen.name}",
                f"Mitigation complete in ~{total_seconds}s. System restored.",
                "ok",
                event_id=self.current_incident["id"] if self.current_incident else None,
            )

    def _tick_resolved(self):
        self.phase_tick += 1
        reading = clip(normal_readings(self.t))
        self._infer_and_store(reading)

        if self.phase_tick >= mit.RESOLVED_HOLD_SECONDS:
            self.phase = mit.SECURE
            self.phase_tick = 0
            self.active_attack = None
            self.ramp_tick = 0
            self.attack_started_at = None
            self.target_feed_until = _mono() + TARGET_FEED_LINGER_SEC
            self.mitigation_action = ""
            self.mitigation_progress = 0
            self.target_node = None
            self.current_severity = None
            self.current_incident = None

            if self.active_scenario:
                scenario = scenarios_mod.get_scenario(self.active_scenario)
                self.scenario_stage_idx += 1
                if self.scenario_stage_idx < len(scenario["stages"]):
                    self.scenario_wait_remaining = scenarios_mod.WAIT_TICKS_BETWEEN_STAGES
                else:
                    self._log(
                        f"SCENARIO COMPLETE: {scenario['name']}",
                        "All stages resolved.",
                        "ok",
                    )
                    self.active_scenario = None
                    self.scenario_stage_idx = 0
                    self.scenario_target_node = None
                    self.scenario_stage_status = []


# Module-level singleton used by app.py
engine = Engine()
