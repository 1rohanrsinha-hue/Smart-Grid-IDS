"""
app.py (v3)
=============
Smart Grid IDS v3 - Flask backend.

Serves the dashboard (frontend/) and every REST endpoint from v2 PLUS
the v3 additions: topology, multi-model selection, hybrid rule-engine
verdicts (folded into /api/status), analytics, incident report export,
demo login/roles, explainability, and attack scenarios.

HOW TO RUN:
    cd backend
    python train_models.py     # once, trains RF + SVM + MLP
    python app.py                # starts the server
    open http://localhost:5001/login.html
"""

import io
import os

from flask import Flask, jsonify, request, send_from_directory, session, send_file

from test_engine import engine
import auth
import scenarios as scenarios_mod
import report_generator

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")

app = Flask(__name__, static_folder=None)
app.secret_key = "smart-grid-ids-v3-demo-secret-key-not-for-production"


# ─── FRONTEND ────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:filename>")
def frontend_assets(filename):
    return send_from_directory(FRONTEND_DIR, filename)


# ─── AUTH (v3) ───────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def api_login():
    body = request.get_json(silent=True) or {}
    result = auth.login(body.get("username", ""), body.get("role", ""))
    status_code = 200 if result.get("ok") else 400
    return jsonify(result), status_code


@app.route("/api/logout", methods=["POST"])
def api_logout():
    return jsonify(auth.logout())


@app.route("/api/session")
def api_session():
    sess = auth.current_session()
    return jsonify({"logged_in": sess is not None, "session": sess})


# ─── CORE STATUS / CONTROL (v2, unchanged behavior) ──────────────────────
@app.route("/api/status")
def api_status():
    return jsonify(engine.get_status())


@app.route("/api/trigger", methods=["POST"])
def api_trigger():
    body = request.get_json(silent=True) or {}
    attack_id = str(body.get("attack", "")).upper().strip()
    node_id = body.get("node")
    node_id = str(node_id).upper().strip() if node_id else None
    if not attack_id:
        return jsonify({"ok": False, "reason": "Missing 'attack' field."}), 400
    result = engine.trigger(attack_id, node_id)
    return jsonify(result), (200 if result.get("ok") else 409)


@app.route("/api/mode", methods=["POST"])
def api_mode():
    body = request.get_json(silent=True) or {}
    if "auto" not in body:
        return jsonify({"ok": False, "reason": "Missing 'auto' field."}), 400
    return jsonify(engine.set_auto_mode(bool(body.get("auto"))))


@app.route("/api/history")
def api_history():
    return jsonify({"events": engine.get_history()})


@app.route("/api/attacks")
def api_attacks():
    return jsonify({"attacks": engine.get_attack_catalog()})


# ─── TOPOLOGY (v3) ────────────────────────────────────────────────────────
@app.route("/api/topology")
def api_topology():
    return jsonify(engine.get_topology())


# ─── MULTI-MODEL (v3) ─────────────────────────────────────────────────────
@app.route("/api/models")
def api_models():
    return jsonify({"models": engine.list_models()})


@app.route("/api/models/select", methods=["POST"])
@auth.require_role("admin")
def api_models_select():
    body = request.get_json(silent=True) or {}
    name = str(body.get("model", "")).upper().strip()
    result = engine.select_model(name)
    return jsonify(result), (200 if result.get("ok") else 400)


# ─── ANALYTICS (v3) ────────────────────────────────────────────────────────
@app.route("/api/analytics")
def api_analytics():
    return jsonify(engine.get_analytics())


# ─── EXPLAINABILITY (v3) ───────────────────────────────────────────────────
@app.route("/api/explain")
def api_explain():
    return jsonify(engine.get_explain())


# ─── SCENARIOS (v3) ─────────────────────────────────────────────────────────
@app.route("/api/scenarios")
def api_scenarios():
    return jsonify({"scenarios": scenarios_mod.list_scenarios()})


@app.route("/api/scenario/trigger", methods=["POST"])
def api_scenario_trigger():
    body = request.get_json(silent=True) or {}
    scenario_id = str(body.get("scenario", "")).strip()
    if not scenario_id:
        return jsonify({"ok": False, "reason": "Missing 'scenario' field."}), 400
    result = engine.trigger_scenario(scenario_id)
    return jsonify(result), (200 if result.get("ok") else 409)


# ─── NOTIFICATIONS (v3) ─────────────────────────────────────────────────────
@app.route("/api/notifications")
def api_notifications():
    return jsonify({"notifications": engine.get_notifications()})


# ─── INCIDENT REPORT EXPORT (v3, Admin only) ─────────────────────────────────
@app.route("/api/report/<event_id>", methods=["POST"])
@auth.require_role("admin")
def api_report(event_id):
    body = request.get_json(silent=True) or {}
    fmt = str(body.get("format", "pdf")).lower().strip()
    incident = engine.get_incident(event_id)
    if incident is None:
        try:
            incident = engine.get_incident(int(event_id))
        except (TypeError, ValueError):
            incident = None
    if incident is None:
        return jsonify({"ok": False, "reason": f"No incident found with id '{event_id}'."}), 404

    if fmt == "csv":
        data = report_generator.to_csv_bytes(incident)
        return send_file(
            io.BytesIO(data), mimetype="text/csv", as_attachment=True,
            download_name=f"incident_{event_id}.csv",
        )
    else:
        data = report_generator.to_pdf_bytes(incident)
        return send_file(
            io.BytesIO(data), mimetype="application/pdf", as_attachment=True,
            download_name=f"incident_{event_id}.pdf",
        )


if __name__ == "__main__":
    import real_attacks
    real_attacks.manager.ensure_target_running()  # starts the real local dummy grid device (127.0.0.1 only)
    engine.start()
    print("\n" + "=" * 64)
    print("  SMART GRID IDS v3 - Flask server starting")
    print("  Login:     http://localhost:5001/login.html")
    print("  Dashboard: http://localhost:5001/")
    print("  Analytics: http://localhost:5001/analytics.html")
    print("  Real local target device: 127.0.0.1:5101 (HTTP), 5102/5103 (TCP)")
    print("  (DDoS / Port Scan / Firmware Tampering execute real code against it)")
    print("=" * 64 + "\n")
    app.run(host="127.0.0.1", port=5001, debug=False, threaded=True)
