# Smart Grid AI Cybersecurity IDS v3

MIT Manipal — School of Computer Engineering — Cybersecurity Minor Project

A multi-module smart-grid security platform: a live single-line grid
topology map, three switchable ML models (Random Forest / SVM / Neural
Net), a hybrid ML + rule-engine detection layer, severity scoring,
multi-stage attack "kill chain" scenarios, simulated alert notifications,
per-prediction explainability, historical analytics with a literature
benchmark table, incident report export (CSV/PDF), and a demo
Operator/Admin login — all built on top of the working v2 core (12 attack
types, manual + auto triggering, live RF detection, automatic
`SECURE → DETECTED → MITIGATING → RESOLVED` mitigation), which keeps
working exactly as it did before.

## Project layout

```
smart-grid-ids/
├── backend/
│   ├── app.py                 # Flask app: all v2 + v3 routes
│   ├── attacks/                # 12 attack generators (unchanged from v2)
│   ├── topology.py             # NEW: grid layout (nodes, edges, category targeting)
│   ├── train_models.py         # NEW: trains RF + SVM + MLP
│   ├── train_model.py          # legacy single-model trainer (v2), still works standalone
│   ├── model_rf.pkl / model_svm.pkl / model_mlp.pkl  # NEW: one per model
│   ├── model_comparison.json   # NEW: accuracy/F1/confusion matrix per model
│   ├── rule_engine.py          # NEW: independent threshold-based verdicts
│   ├── severity.py             # NEW: LOW/MEDIUM/HIGH/CRITICAL scoring
│   ├── report_generator.py     # NEW: CSV/PDF incident export
│   ├── auth.py                 # NEW: demo login + role-check decorator
│   ├── explainability.py       # NEW: per-prediction feature contribution
│   ├── scenarios.py            # NEW: multi-stage attack chains
│   ├── notifier.py             # NEW: simulated alert notifications
│   ├── event_log.jsonl         # NEW: append-only incident history (generated at runtime)
│   ├── mitigation.py           # phase constants + per-attack timing/action lookup
│   ├── test_engine.py          # UPDATED: node targeting, multi-model, dual verdicts, severity, scenarios
│   └── requirements.txt        # UPDATED: + fpdf2, pytest, shap (optional)
├── frontend/
│   ├── login.html              # NEW: username + Operator/Admin role picker
│   ├── analytics.html + .js + .css  # NEW: historical charts + literature benchmark
│   ├── topology.js             # NEW: SVG grid map + animated packet flow
│   ├── index.html              # UPDATED: topology tab, scenarios, dual-verdict, model
│   │                            #          selector, explainability, notifications panels
│   ├── dashboard.js            # UPDATED: wires in every v3 panel/endpoint
│   └── style.css               # UPDATED: styling for all new panels, v2 theme unchanged
├── tests/                      # NEW: pytest suite
│   ├── test_rule_engine.py
│   ├── test_mitigation.py
│   ├── test_severity.py
│   └── test_models.py
└── README.md
```

## How to run

1. **Install dependencies:**
   ```bash
   pip install -r backend/requirements.txt
   ```
   `shap` is optional — if it fails to install in your environment, the
   explainability panel automatically falls back to a lightweight
   deviation-weighted method that needs no extra dependency. Everything
   else still works.

2. **Train all three models (run once):**
   ```bash
   cd backend
   python train_models.py
   ```
   This generates the synthetic 13-class dataset, trains Random Forest +
   SVM + a small MLP neural net, and writes `model_rf.pkl`,
   `model_svm.pkl`, `model_mlp.pkl`, `model_comparison.json`, and
   `dataset.csv` into `backend/`.

3. **Start the Flask app:**
   ```bash
   python app.py
   ```

4. **Log in:** open **http://localhost:5001/login.html**, enter any
   username, and pick a role:
   - **Operator** — views everything, triggers manual attacks and
     scenarios.
   - **Admin** — everything Operator can do, plus switching the active
     detection model and exporting incident reports (CSV/PDF).

   You're then taken to the main dashboard at `/index.html`.

5. **On the dashboard:**
   - The **Live Threat Visualization** panel defaults to the **Grid
     Topology** tab — a single-line diagram (Power Plant → Substations →
     Feeders → Smart Meter Clusters, with a Control Center) with packets
     animating along every connection. Switch to the **Attack Detail**
     tab to see the original per-attack canvas animation from v2.
   - Fire any of the **12 attack buttons** (optionally picking a target
     node from the dropdown next to them), or run one of the three
     **Attack Scenarios** (multi-stage kill chains) at the bottom.
   - Toggle **Auto Mode** for random attacks on a timer, same as v2.
   - The **AI Classification** panel now also shows an **ML vs
     Rule-Engine** dual-verdict panel with an agree/disagree indicator,
     and a **"Why was this flagged?"** explainability panel while an
     attack is active.
   - **Admins** see a **Detection Model** panel to switch between RF /
     SVM / MLP live, plus a small accuracy/F1 comparison table.
   - The **Notifications** panel shows simulated alert messages sent
     when a detection reaches CRITICAL severity.
   - **Admins** see **PDF/CSV export buttons** next to each resolved
     entry in the Event Log.
   - Click **ANALYTICS →** in the top bar for aggregated incident
     history (bar/line charts, avg. time-to-mitigate, model comparison)
     and a literature benchmark table.

## REST API

### v2 (unchanged)
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/status` | Full live state (now includes `target_node`, `active_model`, `rule_engine`, `verdict_agreement`, `severity`, `scenario`) |
| POST | `/api/trigger` | `{ "attack": "DDOS", "node": "SUB1" }` — node is optional |
| POST | `/api/mode` | `{ "auto": true }` |
| GET | `/api/history` | Recent event log (entries now include `event_id` when tied to an incident) |
| GET | `/api/attacks` | Catalog of all 12 attack types |

### v3 (new)
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/topology` | Grid node/edge layout + current per-node status |
| GET | `/api/models` | List of trained models + accuracy/F1/confusion matrix |
| POST | `/api/models/select` | **Admin only.** `{ "model": "SVM" }` |
| GET | `/api/analytics` | Aggregated historical stats for the charts |
| POST | `/api/report/<event_id>` | **Admin only.** `{ "format": "pdf" | "csv" }` — downloads the incident report |
| POST | `/api/login` | `{ "username": "...", "role": "operator" | "admin" }` |
| POST | `/api/logout` | Clears the session |
| GET | `/api/session` | Current login state |
| GET | `/api/explain` | Top contributing features for the current prediction |
| GET | `/api/scenarios` | Catalog of multi-stage attack scenarios |
| POST | `/api/scenario/trigger` | `{ "scenario": "recon_to_breach" }` |
| GET | `/api/notifications` | Recent simulated alert log |

## The 12 attack types + 3 scenarios

Attack types and mitigation actions are unchanged from v2 (see the code
in `backend/attacks/`). The three multi-stage scenarios (`backend/scenarios.py`)
are:

| Scenario | Stages |
|---|---|
| Reconnaissance to Breach | Port Scan → Privilege Escalation → Malware Activity |
| Grid Destabilization Chain | False Data Injection → Load-Altering → Command Injection |
| Stealth Communications Takeover | MITM → Replay → Firmware Tampering |

Each stage runs through the exact same genuine detection → mitigation
pipeline as a single manual attack, targeting the same grid node in
sequence, with a short pause between stages.

## All 12 attacks genuinely execute real code

Every single attack in this project — not a subset — runs real code
against a real, self-hosted local "grid device" this project starts
on `127.0.0.1` only. Nothing here is simulated telemetry from a
formula:

| Attack | What genuinely happens | Code |
|---|---|---|
| DDoS Flood | A real 120-thread pool sends real HTTP requests against a real local server until it genuinely can't keep up. | `backend/real_attacks/real_ddos.py` |
| Network Recon / Port Scan | Real `socket.connect_ex()` TCP probes genuinely sweep a real port range on localhost. | `backend/real_attacks/real_port_scan.py` |
| Firmware Tampering | Real bytes are flipped in a real file on disk; a real SHA-256 comparison (`hashlib`) detects the mismatch; mitigation performs a real file rollback. | `backend/real_attacks/real_firmware_tamper.py` |
| Command Injection | Real unauthorized command strings are sent over a real TCP socket to a real allow-list parser (no real execution capability exists to inject into). | `backend/real_attacks/real_cmd_inject.py` |
| False Data Injection | Real fabricated sensor JSON is POSTed to a real ingest endpoint; deviation is computed from what the endpoint genuinely received. | `backend/real_attacks/real_fdi.py` |
| Load-Altering Attack | Real fabricated setpoint values are sent to a real control endpoint; variance is computed from the real received sequence. | `backend/real_attacks/real_load_alter.py` |
| GPS/Time-Sync Spoofing | A real, deliberately-wrong timestamp is sent over a real socket; a real offset is computed against the endpoint's own real system clock (no real GPS/RF hardware involved — see below). | `backend/real_attacks/real_gps_spoof.py` |
| Sensor Jamming | A real UDP flood targets a real, deliberately capacity-limited socket; the OS genuinely drops datagrams once its buffer fills. | `backend/real_attacks/real_jamming.py` |
| Insider Privilege Escalation | Real login attempts run against a real (small, intentionally weak, disclosed) toy credential table — the same pattern used by intentionally-vulnerable training labs. | `backend/real_attacks/real_priv_esc.py` |
| Malware Activity | Real large (1.4 KB) payloads are uploaded via real HTTP POST at a sustained real rate. | `backend/real_attacks/real_malware.py` |
| Replay Attack | One real request is captured and SHA-256 hashed once; the exact same real bytes are genuinely resent, with every replay hash-verified against the original. | `backend/real_attacks/real_replay.py` |
| Man-in-the-Middle | Real traffic is routed through a real relay proxy this project runs, genuinely forwarding bytes between client and server. | `backend/real_attacks/real_mitm.py` |

All twelve target **`backend/real_attacks/dummy_target.py`** — a
small, real, self-hosted stand-in for a piece of grid hardware,
exposing:
- an HTTP "web console" (port 5101) with `/`, `/sensor`, `/upload` endpoints,
- a text protocol port (5102) handling real `CMD`, `SETPOINT`, and `TIMESYNC` messages,
- an admin/login port (5103) with a real (intentionally weak) toy credential table,
- a UDP telemetry port (5104), deliberately capacity-limited like a real embedded sensor radio,
- a relay proxy (5105 → 5101) for the MITM demonstration.

None of the "vulnerable-looking" endpoints (the command port, the
auth port) have any real capability to execute code or access the
filesystem — they only ever parse a string and compare it against an
allow-list or credential table. There is no real exploit primitive
anywhere in this project.

**Every number fed to the ML model during a live attack is a genuine
measurement** — actual requests/sec, actual latency, actual open
ports found, actual SHA-256 hashes, actual login attempts against a
real service — not a formula. `GET /api/status` exposes this under
`real_attack_evidence` while an attack is active, and the dashboard's
**Real Attack Evidence** panel (with a "Live" badge) displays it as it
happens. Click the small **i** button next to any attack in the
operator console for a full explanation of what it is, how it works,
its impact on a real grid, and exactly what the real code does.

Because a real ML model still has to classify whatever these produce,
**every synthetic training generator was recalibrated** (see
`backend/attacks/`) to match what each attack can genuinely, ethically
achieve on a single local machine — and trimmed to touch only the
features its real counterpart can honestly provide, so a live reading
lands in the same statistical neighborhood the model was trained on
rather than only partially matching the learned pattern. Re-running
`train_models.py` regenerates this correctly.

### Why nothing here is a real exploit against real infrastructure

Real-world versions of GPS spoofing and RF jamming require actually
transmitting on shared radio spectrum — illegal without an FCC-licensed
shielded lab, regardless of intent. Command Injection and Privilege
Escalation against a *real* production system would mean writing actual
exploit code. Every attack here instead targets a toy service this
project builds, owns, and starts itself, using the real underlying
network/protocol technique (real floods, real TCP probes, real hash
mismatches, real credential attempts) but with zero capability to
affect anything outside `127.0.0.1`. This is the same principle
intentionally-vulnerable security training labs (DVWA, WebGoat, CTF
services) use.



```
severity = base_severity(attack_type) x confidence x node_repeat_factor
```
- `base_severity`: 1–5, hand-assigned by how directly the attack can
  affect physical grid state (see `backend/severity.py`).
- `node_repeat_factor`: 1.0 for a node's first hit this session, +0.2
  per repeat, capped at 1.6 — repeated targeting of one asset is a
  stronger signal than a one-off.
- The raw score is bucketed into `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`.
  CRITICAL detections trigger a simulated notification.

## How detection stays "genuine"

Unchanged from v2: when an attack is triggered (manually, via Auto
Mode, or as a scenario stage), the engine feeds attack-perturbed
readings into the **active** ML model (RF, SVM, or MLP — whichever is
selected) and only advances to `DETECTED` once the model's own
prediction matches the injected attack with sufficient confidence. The
independent rule-engine verdict (`backend/rule_engine.py`) is computed
from the same raw reading but has no knowledge of which model or
attack was injected — it's a genuinely separate second opinion, which
is why the dashboard can show a real agree/disagree indicator. For all
twelve attacks, "attack-perturbed readings" means real measured data
from real code — see the section above — not a formula.

## Attack info panel

Click the small **i** button next to any attack in the operator
console (or the attack's own button) to open a details panel covering
what the attack is, how it works in the real world, its impact on a
real grid, and exactly what the real code in this project does when
you trigger it — all sourced from `backend/attack_info.py` via
`GET /api/attacks`.

## Attack visibility

The dashboard shows an attack from the first second it runs until it is
resolved, not only after the model flags it. `/api/status` carries an
`attack_stage` (`NONE`, `EXECUTING`, `DETECTED`, `MITIGATING`, `RESOLVED`);
`EXECUTING` covers the ramp ticks where the real attack is already
running but the phase is still `SECURE`. It always lasts at least
`MIN_EXECUTING_TICKS` (3) ticks (about 3 s): the model's prediction and
confidence still update every tick and are shown live, but the engine only
declares DETECTED once that minimum has passed (detection itself is
unchanged). The total incident time is therefore about 2 s longer than before. The `SECURE -> DETECTED ->
MITIGATING -> RESOLVED` state machine itself is unchanged.

- **Live attack strip** (under the top bar): red and pulsing while
  executing ("LIVE ATTACK IN PROGRESS: attack -> node", elapsed seconds,
  headline metric), red on detection, amber while mitigating, green when
  neutralised. The top bar glows red while the attack is executing or
  detected, and the status banner reads "ATTACK IN PROGRESS" instead of
  "SECURE".
- **Node highlight**: the target node turns red on the first executing
  tick (strong pulsing ring), then amber while mitigating and green with a
  check mark once resolved, with an "UNDER ATTACK" / "MITIGATING" /
  "RESTORED" tag above it and a callout showing the attack name and its
  live headline metric (`attack_headline_metric`).
- **Attacker arrow**: a frontend-only "ATTACKER" marker outside the grid
  with an animated dashed arrow to the target. It fades while mitigating
  and disappears on resolution. It is not part of `/api/topology`.
- **Live Attack panel** (below the map): a 5-step tracker (Launched,
  Executing, Detected, Mitigating, Resolved), the mitigation action, the
  attacker-side evidence measured live, a "What the target device is
  receiving" feed, and a "Normal vs now" comparison.
- **Target-device feed**: `dummy_target.py` keeps a 40-entry ring buffer of
  what the device itself observes (HTTP, command/admin ports, UDP, proxy
  and so on). High-rate traffic is aggregated into one line per 0.5 s. It is
  exposed as `target_activity` in `/api/status`, only during an attack and
  for a few seconds after, and cleared when a new attack starts. Logging
  only: the device still binds 127.0.0.1 and gained no new behaviour.
  Port scans and firmware tampering send no application traffic, so their
  lines are bare-connection probes and the real SHA-256 integrity check.

`DETECTED_HOLD_SECONDS` and `RESOLVED_HOLD_SECONDS` are now 4 s so each
stage stays on screen. Tests for this are in `tests/test_attack_visibility.py`.

### How to verify the attack visibility

`scripts/verify_attack_ui.js` drives a headless Chrome (DevTools protocol, no npm
packages; needs Node 22+ and Google Chrome, or `CHROME_BIN=/path/to/chromium`):

```bash
# stop any running app.py first (the script starts its own server on :5001)
node scripts/verify_attack_ui.js                         # all 12 attacks + 3 scenarios, 1280 and 1920 px
node scripts/verify_attack_ui.js --widths 1280 --only DDOS,MITM --no-scenarios   # quick run
```

It logs in as admin through the real login form, clicks the real attack and
scenario buttons (each attack on a different node), polls `/api/status`, checks
the strip, node colour, attacker arrow, callout, tag, device feed, headline
metric (including the final value and, for FIRMWARE_TAMPER, `YES` after the
rollback), timeline, locked controls and layout at every stage, switches to the
Attack detail tab and back mid-attack (no console errors, callout and tag
restored), and writes screenshots to
`docs/attack_visibility_full/<width>/<attack>_<node>_<stage>.png` plus a
`report.json` per width. That folder is git-ignored (about 85 MB). It exits
non-zero on any failed check. `docs/attack_visibility/` holds only the two
`report.json` files and a small curated set of screenshots from such a run.

The server it starts uses `SGIDS_EVENT_LOG` pointing at a temp file, and the
script compares the checksum of `backend/event_log.jsonl` before and after.
`pytest tests/` uses the same variable (see `tests/conftest.py`), so neither the
tests nor the verification touch the Analytics data.

You can also check the target device yourself: open
<http://127.0.0.1:5101/stats> (linked from the Live Attack panel) while an attack
runs and refresh it to watch the device's own counters rise.

## Running tests

```bash
pip install -r backend/requirements.txt   # includes pytest
python train_models.py                      # from backend/, needed for test_models.py
cd ..
pytest tests/
```

The suite covers: rule-engine threshold firing (`test_rule_engine.py`),
the full `SECURE → DETECTED → MITIGATING → RESOLVED → SECURE` state
machine never skipping a step (`test_mitigation.py`), severity band
scoring (`test_severity.py`), and that every saved model loads and
predicts a valid class (`test_models.py`).

## Non-goals

Same as v2, plus: no real database (JSONL + in-memory session state is
enough), no real authentication/password hashing (role selection only —
this is a clearly-labeled demo login), and no real email/SMS sending
(notifications are simulated message objects only, never actually sent).


## Evaluation on a public dataset

> **Important:** the dashboard and its demo models (`model_rf.pkl`, `model_svm.pkl`,
> `model_mlp.pkl`) are trained on **synthetic data** from our own generators in
> `backend/attacks/`. Their ~100% accuracy is therefore not a meaningful measure of
> real-world performance. The results below come from **separate models trained
> offline on a public dataset**. They are **not** from the dashboard models and do not
> affect the dashboard, live detection, rule engine or tests.

**Dataset:** WUSTL-IIoT-2021 (network flows from an industrial IoT testbed, Argus
features, attacks: DoS, reconnaissance, command injection, backdoor).
**Source:** https://classes.engineering.wustl.edu/~jain/iiot2/index.html
**Citation (as given on the source page):** M. Zolanvari, M. A. Teixeira, L. Gupta,
K. M. Khan, and R. Jain. "WUSTL-IIOT-2021 Dataset for IIoT Cybersecurity Research,"
Washington University in St. Louis, USA, October 2021.
**Licence:** No licence stated on the source page; used for research and evaluation.

### How to run

1. Download `wustl_iiot_2021.zip` from the source page and unzip it so that
   `data/wustl_iiot_2021.csv` exists (`data/` is git-ignored; the file is not in the repo).
2. `cd backend && python3 eval_public_dataset.py` (about 6-7 minutes).

It writes `backend/real_dataset_eval.json` and confusion-matrix PNGs to `docs/eval_plots/`.

### Method (short)

- Rows: 1,194,464 raw -> 1,159,558 after cleaning (34,904 duplicate rows and 2 absurd-duration
  rows removed). Duplicates are removed *before* the split, so no identical row is in both train and test.
- Dropped columns: timestamps, IP addresses, IP-ID counters, ports (they identify the attack
  rather than describe its behaviour, as the dataset page advises), and three columns that are exact
  copies of `Sum` (`Min`, `Max`, `RunTime`). 36 features remain. Reasons are in comments in the script.
- Stratified 80/20 split (seed 42): 927,646 train / 231,912 test; plus 5-fold stratified cross-validation.
  Scalers are fitted on training data only.
- Models use the same settings as `backend/train_models.py`, plus a single decision-tree baseline.
  **The SVM is trained on at most 100,000 rows**: every attack row of the training split plus a random
  subsample of normal rows (an RBF SVM is too slow on ~930k rows). It is evaluated on the full test set.
  RF, MLP and the tree use the full training set.
- About 93% of the rows are normal traffic, so accuracy is not reported. **Weighted-F1 is not
  informative here** (it is 0.998-1.000 for every model because normal and DoS rows dominate), so
  the headline metric is macro-F1, which weights all five classes equally.
- Standard deviations (+/-) are population standard deviations over folds or seeds.

### Results

**Headline: 5-fold stratified cross-validation, macro-F1 (mean +/- std over folds)**

| Model | CV macro-F1 | Hold-out macro-F1 (seed 42) | False-positive rate on normal (hold-out) |
|---|---|---|---|
| Random Forest | 0.9844 +/- 0.0042 | 0.9748 | 0.0000 (1 of 219,867) |
| Decision tree (baseline) | 0.9769 +/- 0.0032 | 0.9708 | 0.0000 (8 of 219,867) |
| MLP (64,32) | 0.9503 +/- 0.0112 | 0.9547 | 0.0001 (13 of 219,867) |
| SVM (<=100k rows, all attacks kept) | 0.8353 +/- 0.0053 | 0.8348 | 0.0020 (446 of 219,867) |

**Per-class F1 on the hold-out test set (seed 42)**, test rows in the header (all classes have at least 30 test rows):

| Model | normal (219,867) | DoS (11,253) | Reconn (698) | CommInj (52) | Backdoor (42) |
|---|---|---|---|---|---|
| RF | 1.0000 | 1.0000 | 0.9993 | 0.9495 | 0.9250 |
| DT | 1.0000 | 0.9999 | 1.0000 | 0.9703 | 0.8837 |
| MLP | 0.9999 | 0.9997 | 0.9978 | 0.9623 | 0.8140 |
| SVM | 0.9990 | 0.9895 | 0.9978 | 0.9307 | 0.2568 |

Precision and recall per class, the binary normal/attack view and the confusion matrices are in
`backend/real_dataset_eval.json` and `docs/eval_plots/`.

**Seed stability: rare classes** (hold-out split and training repeated with seeds 1-5; mean +/- std over seeds)

| Model | Macro-F1 | CommInj F1 (52 test rows) | Backdoor F1 (42 test rows) |
|---|---|---|---|
| RF | 0.9845 +/- 0.0059 | 0.9902 +/- 0.0088 | 0.9330 +/- 0.0275 |
| DT | 0.9806 +/- 0.0016 | 0.9942 +/- 0.0047 | 0.9094 +/- 0.0105 |
| MLP | 0.9462 +/- 0.0106 | 0.9100 +/- 0.0186 | 0.8244 +/- 0.0376 |
| SVM | 0.8338 +/- 0.0039 | 0.9366 +/- 0.0183 | 0.2477 +/- 0.0079 |

The single seed-42 numbers above are within or close to this spread, but differences of a few points
between models on CommInj and Backdoor are within noise. The SVM's low Backdoor F1 is stable across seeds
(precision about 0.15, recall about 0.9: many normal flows are labelled Backdoor); we did not investigate why.

### Stress test: noise on the test features (macro-F1)

Gaussian noise is added to the raw test features at 0.25, 0.5 and 1.0 times each feature's standard
deviation, using the standard deviation after clipping each feature to its 1st-99th percentile (so the
noise is sized to the bulk of the data). The models are not retrained.

| Model | clean | noise 0.25 | 0.5 | 1.0 |
|---|---|---|---|---|
| MLP | 0.9547 | 0.9257 | 0.7300 | 0.3855 |
| SVM | 0.8348 | 0.7979 | 0.6072 | 0.3874 |
| RF | 0.9748 | 0.7056 | 0.6160 | 0.4682 |
| DT | 0.9708 | 0.3688 | 0.3488 | 0.3080 |

All four models are fragile to feature noise; the MLP holds up best at low noise and the single tree worst.

*Note on plain-std noise:* using each feature's plain standard deviation (the first version we ran) is much
harsher: macro-F1 at 0.25 / 0.5 / 1.0 is RF 0.2018 / 0.2000 / 0.2093, SVM 0.6401 / 0.4145 / 0.2543,
MLP 0.8766 / 0.5469 / 0.3176, DT 0.3254 / 0.3136 / 0.2675. Network features are heavy-tailed (for
example `Load` has a std near 5e7 while a typical flow is near 1e5), so plain-std noise swamps the typical
values of those features. Both versions are in the JSON.

### Extra: time-ordered check (not part of the main results)

Rows were sorted by `StartTime` (used only for ordering, never as a feature), trained on the first 80%
and tested on the last 20%. **This check could not be evaluated for attacks:** the last 20% of the capture
(15:26-16:48 on 2019-08-19) contains only normal traffic (231,912 rows, 0 attack rows). Every attack is a
single contiguous episode of 25-45 minutes, all earlier in the day (Reconn 11:04-11:29, DoS 12:25-13:07,
CommInj 13:40-14:04, Backdoor 14:17-14:43). RF and DT classify the normal-only test period perfectly
(F1 1.0000 on normal), but that says nothing about attack detection, so no attack macro-F1 or per-class F1 is reported.

### Limitations

- **Random splits and near-identical flows.** Each attack is one short episode of very similar flows.
  A random split puts neighbouring flows from the same episode into both train and test, which makes the
  scores optimistic. The time-ordered check would address this, but this capture has no attacks in its
  last 20%, so the optimism is not measured here. Duplicate rows were removed, but near-duplicates remain.
- **Tiny rare classes.** CommInj has 258 and Backdoor 212 rows in total (52 and 42 in the test split), so
  their scores are uncertain by several points.
- **Coverage.** Only four of our twelve attacks have a counterpart in this dataset (see the mapping
  below), and Backdoor-to-MALWARE is an approximate match.
- **One testbed.** All data come from one testbed on one day, so results do not show the models
  would work on other networks.

### Mapping to our attack types

| WUSTL-IIoT-2021 class | Our attack |
|---|---|
| DoS | DDOS |
| Reconn | PORT_SCAN |
| CommInj (command injection) | CMD_INJECT |
| Backdoor | MALWARE (approximate match) |

Our attacks with **no counterpart** in this dataset: MITM, REPLAY, FDI, LOAD_ALTER, GPS_SPOOF,
FIRMWARE_TAMPER, JAMMING, PRIV_ESC. Those are mostly smart-grid process or physical-layer attacks that a
network-flow dataset does not contain, so they can only be evaluated on our synthetic data.
