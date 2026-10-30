/* ============================================================
   Smart Grid AI Cybersecurity IDS v3 - dashboard.js
   Everything from v2 (status polling, telemetry, AI panel, event
   log, manual/auto attack control, per-attack canvas animation)
   PLUS: session/role gating, grid topology map, node targeting,
   multi-model selection, ML vs rule-engine dual verdict, severity
   badges, attack scenarios, explainability, notifications, and
   incident report export.
   ============================================================ */

const API = {
  status: '/api/status', trigger: '/api/trigger', mode: '/api/mode',
  attacks: '/api/attacks', topology: '/api/topology', models: '/api/models',
  modelsSelect: '/api/models/select', analytics: '/api/analytics',
  explain: '/api/explain', scenarios: '/api/scenarios', scenarioTrigger: '/api/scenario/trigger',
  notifications: '/api/notifications', session: '/api/session', logout: '/api/logout',
  report: (id) => `/api/report/${id}`,
};

const COLORS = { cyan: '#2fd9c8', red: '#e0616a', amber: '#e3a53d', blue: '#5b93d9' };

let latestStatus = null;
let attackCatalog = [];
let scenarioCatalog = [];
let currentRole = 'operator';
let lastPhaseForExplain = null;

/* ── boot ─────────────────────────────────────────────────── */
async function boot() {
  const sess = await fetchJSON(API.session);
  if (!sess || !sess.logged_in) {
    window.location.href = '/login.html';
    return;
  }
  applySession(sess.session);

  await Promise.all([loadAttackCatalog(), loadScenarioCatalog(), loadModelList(), initTopology('topology-container')]);
  wireControls();
  setInterval(updateClock, 1000);
  updateClock();
  pollStatus();
  setInterval(pollStatus, 800);
  pollNotifications();
  setInterval(pollNotifications, 2500);
  requestAnimationFrame(animateStage);
}

async function fetchJSON(url, opts) {
  try {
    const res = await fetch(url, opts);
    return await res.json();
  } catch (e) {
    console.error('fetch failed', url, e);
    return null;
  }
}

function applySession(sess) {
  currentRole = sess.role;
  document.body.classList.toggle('role-admin', currentRole === 'admin');
  document.getElementById('role-tag').textContent = currentRole.toUpperCase();
  document.getElementById('username-tag').textContent = sess.username;
  document.getElementById('logout-link').addEventListener('click', async (e) => {
    e.preventDefault();
    await fetchJSON(API.logout, { method: 'POST' });
    window.location.href = '/login.html';
  });
}

/* ── catalogs ─────────────────────────────────────────────── */
async function loadAttackCatalog() {
  const data = await fetchJSON(API.attacks);
  attackCatalog = (data && data.attacks) || [];
  renderAttackButtons();
}

async function loadScenarioCatalog() {
  const data = await fetchJSON(API.scenarios);
  scenarioCatalog = (data && data.scenarios) || [];
  renderScenarioCards();
}

async function loadModelList() {
  const data = await fetchJSON(API.models);
  renderModelSelect((data && data.models) || []);
  renderModelComparisonMini((data && data.models) || []);
}

function renderAttackButtons() {
  const wrap = document.getElementById('attack-buttons');
  wrap.innerHTML = '';
  attackCatalog.forEach(a => {
    const group = document.createElement('div');
    group.style.cssText = 'display:inline-flex;align-items:center;gap:4px;';

    const btn = document.createElement('button');
    btn.className = 'atk-btn';
    btn.dataset.cat = a.category;
    btn.dataset.attack = a.id;
    btn.textContent = a.name;
    btn.title = a.description;
    btn.addEventListener('click', () => triggerAttack(a.id));

    const infoBtn = document.createElement('button');
    infoBtn.className = 'info-btn';
    infoBtn.textContent = 'i';
    infoBtn.title = `About ${a.name}`;
    infoBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      openInfoModal(a);
    });

    group.appendChild(btn);
    group.appendChild(infoBtn);
    wrap.appendChild(group);
  });

  const randomGroup = document.createElement('div');
  randomGroup.style.cssText = 'display:inline-flex;align-items:center;';
  const randomBtn = document.createElement('button');
  randomBtn.className = 'atk-btn';
  randomBtn.dataset.cat = 'random';
  randomBtn.textContent = '\u2680 Random';
  randomBtn.addEventListener('click', () => triggerAttack('RANDOM'));
  randomGroup.appendChild(randomBtn);
  wrap.appendChild(randomGroup);
}

/* ── attack info modal ──────────────────────────────────────────── */
const CATEGORY_LABELS = { network: 'Network', data: 'Data Integrity', system: 'System' };

function openInfoModal(attack) {
  document.getElementById('info-modal-title').textContent = attack.name;

  const badgesWrap = document.getElementById('info-modal-badges');
  badgesWrap.innerHTML = `
    <span class="modal-badge cat-${attack.category}">${CATEGORY_LABELS[attack.category] || attack.category}</span>
    <span class="modal-badge real">Real — genuinely executes</span>`;

  const info = attack.info || {};
  const bodyWrap = document.getElementById('info-modal-body');
  bodyWrap.innerHTML = `
    <div class="info-section">
      <div class="info-section-label">What it is</div>
      <div class="info-section-body">${info.what_it_is || attack.description || ''}</div>
    </div>
    <div class="info-section">
      <div class="info-section-label">How it works</div>
      <div class="info-section-body">${info.how_it_works || ''}</div>
    </div>
    <div class="info-section">
      <div class="info-section-label">Impact on the grid</div>
      <div class="info-section-body">${info.grid_impact || ''}</div>
    </div>
    <div class="info-section real-method">
      <div class="info-section-label">What the real code genuinely does</div>
      <div class="info-section-body">${info.real_method || ''}</div>
    </div>
    <div class="info-section mitigation">
      <div class="info-section-label">Automated mitigation</div>
      <div class="info-section-body">${attack.mitigation || ''}</div>
    </div>`;

  document.getElementById('info-modal-overlay').classList.add('open');
}

function closeInfoModal() {
  document.getElementById('info-modal-overlay').classList.remove('open');
}

function renderScenarioCards() {
  const wrap = document.getElementById('scenario-cards');
  wrap.innerHTML = '';
  scenarioCatalog.forEach(sc => {
    const card = document.createElement('div');
    card.className = 'scenario-card';
    card.dataset.scenario = sc.id;
    const stageChips = sc.stages.map(s => `<span class="scenario-stage-chip" data-stage="${s}">${s}</span>`).join('');
    card.innerHTML = `
      <div class="scenario-card-title">${sc.name}</div>
      <div class="scenario-card-desc">${sc.description}</div>
      <div class="scenario-stages">${stageChips}</div>
      <button class="scenario-btn" data-scenario-btn="${sc.id}">Run scenario</button>`;
    wrap.appendChild(card);
    card.querySelector('.scenario-btn').addEventListener('click', () => triggerScenario(sc.id));
  });
}

function renderModelSelect(models) {
  const sel = document.getElementById('model-select');
  sel.innerHTML = '';
  models.forEach(m => {
    const opt = document.createElement('option');
    opt.value = m.id;
    opt.textContent = `${m.name} (${m.accuracy != null ? m.accuracy + '%' : '--'})`;
    if (m.active) opt.selected = true;
    sel.appendChild(opt);
  });
}

function renderModelComparisonMini(models) {
  const wrap = document.getElementById('model-comparison-mini');
  if (!models.length) { wrap.innerHTML = ''; return; }
  let html = '<table><thead><tr><th>Model</th><th style="text-align:right;">Accuracy</th><th style="text-align:right;">F1</th></tr></thead><tbody>';
  models.forEach(m => {
    html += `<tr class="${m.active ? 'active-row' : ''}">` +
      `<td>${m.id}${m.active ? ' \u2713' : ''}</td>` +
      `<td style="text-align:right;">${m.accuracy != null ? m.accuracy + '%' : '--'}</td>` +
      `<td style="text-align:right;">${m.f1_score != null ? m.f1_score : '--'}</td></tr>`;
  });
  html += '</tbody></table>';
  wrap.innerHTML = html;
}

function wireControls() {
  document.getElementById('auto-checkbox').addEventListener('change', (e) => setAutoMode(e.target.checked));
  document.getElementById('model-select').addEventListener('change', (e) => selectModel(e.target.value));
  document.querySelectorAll('.stage-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchStageTab(btn.dataset.tab));
  });
  document.getElementById('info-modal-close').addEventListener('click', closeInfoModal);
  document.getElementById('info-modal-overlay').addEventListener('click', (e) => {
    if (e.target.id === 'info-modal-overlay') closeInfoModal();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeInfoModal();
  });
  document.getElementById('console-toggle-btn').addEventListener('click', toggleConsole);
}

function toggleConsole() {
  const console_ = document.getElementById('control-console');
  const btn = document.getElementById('console-toggle-btn');
  const icon = document.getElementById('console-toggle-icon');
  const collapsed = console_.classList.toggle('collapsed');
  icon.textContent = collapsed ? '+' : '\u2212';
  btn.title = collapsed ? 'Maximize operator console' : 'Minimize operator console';
  btn.setAttribute('aria-label', btn.title);
}

function switchStageTab(tab) {
  document.querySelectorAll('.stage-tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  document.getElementById('topology-container').style.display = tab === 'topology' ? 'block' : 'none';
  document.getElementById('stage-canvas').style.display = tab === 'detail' ? 'block' : 'none';
  const legend = document.getElementById('topo-legend');
  if (legend) legend.style.display = tab === 'topology' ? '' : 'none';   // '' = the stylesheet's flex row (not 'block')
  if (tab === 'detail') resizeCanvas();
}

/* ── API calls ────────────────────────────────────────────── */
async function triggerAttack(id) {
  const nodeSel = document.getElementById('node-select');
  const node = nodeSel && nodeSel.value ? nodeSel.value : null;
  const body = { attack: id };
  if (node) body.node = node;
  await fetchJSON(API.trigger, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
}

async function triggerScenario(id) {
  await fetchJSON(API.scenarioTrigger, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scenario: id }),
  });
}

async function setAutoMode(enabled) {
  await fetchJSON(API.mode, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ auto: enabled }),
  });
}

async function selectModel(name) {
  const result = await fetchJSON(API.modelsSelect, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ model: name }),
  });
  if (result && result.ok) loadModelList();
}

async function pollStatus() {
  const data = await fetchJSON(API.status + '?t=' + Date.now());
  if (!data) return;
  latestStatus = data;
  render(data);
  if (typeof updateTopologyStatus === 'function') updateTopologyStatus(data);
}

async function pollNotifications() {
  const data = await fetchJSON(API.notifications);
  renderNotifications((data && data.notifications) || []);
}

async function exportReport(eventId, format) {
  try {
    const res = await fetch(API.report(eventId), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ format }),
    });
    if (!res.ok) { console.error('report export failed', res.status); return; }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `incident_${eventId}.${format}`;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  } catch (e) { console.error('export failed', e); }
}

/* ── rendering ────────────────────────────────────────────── */
function render(s) {
  const t = s.telemetry;

  document.getElementById('model-acc').textContent = s.model_meta && s.model_meta.accuracy != null ? Math.round(s.model_meta.accuracy * 100) : '--';
  document.getElementById('active-model-name').textContent = s.active_model;
  document.getElementById('verdict-model-name').textContent = s.active_model;

  setText('voltage-val', t.voltage.toFixed(1));
  setText('freq-val', t.frequency.toFixed(2));
  setText('current-val', t.current.toFixed(1));
  setText('pf-val', t.power_factor.toFixed(2));
  setWidth('voltage-bar', clampPct((t.voltage - 180) / 100 * 100));
  setWidth('freq-bar', clampPct((t.frequency - 47) / 6 * 100));
  setWidth('current-bar', clampPct(t.current / 40 * 100));
  setWidth('pf-bar', clampPct(t.power_factor * 100));

  setText('pps-val', Math.round(t.packets_per_sec).toLocaleString());
  setText('pktsize-val', Math.round(t.packet_size_avg) + ' B');
  setText('ips-val', t.unique_ips);
  setText('latency-val', Math.round(t.latency_ms) + ' ms');
  setText('retrans-val', t.retransmit_pct.toFixed(1) + '%');
  setText('cmdrate-val', t.cmd_rate.toFixed(1) + '/s');
  setText('cmdunk-val', (t.cmd_unknown * 100).toFixed(1) + '%');
  setText('authfail-val', t.auth_failures.toFixed(1) + '/min');
  setText('privlvl-val', t.privilege_level.toFixed(1) + '/5');

  const alertish = stageOf(s) === 'EXECUTING' || stageOf(s) === 'DETECTED';   // red while the attack is running or flagged
  colorAlert('voltage-val', alertish);
  colorAlert('current-val', alertish);
  colorAlert('pps-val', alertish);

  renderBanner(s);
  renderAttackStrip(s);
  renderLiveAttackPanel(s);

  const attackBox = document.getElementById('attack-box');
  attackBox.classList.toggle('alert', stageOf(s) !== 'NONE');
  if (stageOf(s) === 'EXECUTING') {
    // attack already running, model has not declared it yet: show its live guess
    setText('attack-type-value', predictionName(s.prediction) + ' \u2026 analysing');
  } else {
    setText('attack-type-value', s.phase === 'SECURE' ? 'NORMAL' : s.attack_display_name.toUpperCase());
  }
  setText('conf-pct', Math.round(s.confidence * 100) + '%');
  setWidth('confidence-fill', Math.round(s.confidence * 100));
  document.getElementById('confidence-fill').style.background =
    stageOf(s) === 'EXECUTING' ? COLORS.amber : (s.phase === 'SECURE' ? COLORS.cyan : (s.phase === 'MITIGATING' ? COLORS.amber : COLORS.red));
  renderProbabilities(s.probabilities);

  renderVerdictPanel(s);
  renderExplainPanel(s);
  renderLog(s.event_log);

  const label = document.getElementById('stage-label');
  label.style.visibility = (stageOf(s) === 'NONE' && !scenarioWaiting(s)) ? 'visible' : 'hidden';   // strip + map tags carry this during attacks and scenario gaps  // the strip + map tags carry this while an attack runs
  if (scenarioWaiting(s)) {
    label.textContent = `${scenarioLabel(s).toUpperCase()} \u00b7 STARTING`;
  } else if (stageOf(s) === 'NONE') {
    label.textContent = 'MONITORING \u00b7 NO ACTIVE THREAT';
  } else {
    label.textContent = `${s.attack_display_name.toUpperCase()} \u00b7 ${stageOf(s)} \u00b7 ${s.target_node_name || ''}`;
  }

  // locked for the whole attack (EXECUTING included) and for the gaps between scenario stages
  const busy = stageOf(s) !== 'NONE' || Boolean(s.scenario && s.scenario.active);
  document.getElementById('controls-lock-hint').hidden = !busy;
  document.querySelectorAll('.atk-btn').forEach(b => { b.disabled = busy; });
  document.querySelectorAll('.scenario-btn').forEach(b => { b.disabled = busy; });
  document.getElementById('auto-checkbox').checked = s.auto_mode;

  renderScenarioProgress(s.scenario);
}

function renderBanner(s) {
  const banner = document.getElementById('status-banner');
  const l1 = document.getElementById('status-line1');
  const l2 = document.getElementById('status-line2');
  const nodeRow = document.getElementById('target-node-row');
  banner.className = '';

  if (scenarioWaiting(s)) {
    nodeRow.style.display = 'block';
    document.getElementById('target-node-name').textContent = s.scenario.target_node_name;
  } else if (s.target_node_name && stageOf(s) !== 'NONE') {
    nodeRow.style.display = 'block';
    document.getElementById('target-node-name').textContent = s.target_node_name;
  } else {
    nodeRow.style.display = 'none';
  }

  const sevBadge = s.severity ? severityBadgeHTML(s.severity.band) : '';

  if (scenarioWaiting(s)) {
    banner.classList.add('scenario');
    l1.textContent = 'SCENARIO IN PROGRESS';
    l2.textContent = `${scenarioLabel(s)} starting\u2026 \u00b7 target ${s.scenario.target_node_name}`;
  } else if (stageOf(s) === 'EXECUTING') {
    banner.classList.add('executing');
    l1.textContent = 'ATTACK IN PROGRESS';
    l2.textContent = `${s.attack_display_name.toUpperCase()} is running \u00b7 AI classifier is analysing traffic`;
  } else if (s.phase === 'SECURE') {
    banner.classList.add('secure');
    l1.textContent = 'SECURE';
    l2.textContent = s.auto_mode ? 'All systems nominal \u00b7 Auto Mode armed' : 'All systems nominal';
  } else if (s.phase === 'DETECTED') {
    banner.classList.add('detected');
    l1.innerHTML = `ATTACK DETECTED: ${s.attack_display_name.toUpperCase()} ${sevBadge}`;
    l2.textContent = `AI confidence ${Math.round(s.confidence * 100)}%`;
  } else if (s.phase === 'MITIGATING') {
    banner.classList.add('mitigating');
    l1.innerHTML = `MITIGATING: ${s.mitigation_action} ${sevBadge}`;
    l2.textContent = `${s.attack_display_name.toUpperCase()} \u00b7 response in progress`;
    setWidth('mitigation-bar-fill', s.mitigation_progress);
    setText('mitigation-pct', s.mitigation_progress + '%');
  } else if (s.phase === 'RESOLVED') {
    banner.classList.add('resolved');
    l1.textContent = 'RESOLVED';
    l2.textContent = `${s.attack_display_name.toUpperCase()} neutralized \u00b7 restoring baseline`;
  }
}

function severityBadgeHTML(band) {
  return `<span class="sev-badge ${band}">${band}</span>`;
}

function renderProbabilities(probs) {
  const wrap = document.getElementById('prob-list');
  const entries = Object.entries(probs).sort((a, b) => b[1] - a[1]);
  wrap.innerHTML = '';
  entries.forEach(([cls, p]) => {
    const pct = Math.round(p * 100);
    const row = document.createElement('div');
    row.className = 'prob-row';
    row.innerHTML = `
      <span class="prob-label">${cls}</span>
      <span class="prob-bar-bg"><span class="prob-bar-fill" style="width:${pct}%"></span></span>
      <span class="prob-pct">${pct}%</span>`;
    wrap.appendChild(row);
  });
}

function renderVerdictPanel(s) {
  const mlVal = document.getElementById('ml-verdict-value');
  const ruleVal = document.getElementById('rule-verdict-value');
  const reasonEl = document.getElementById('rule-reason');
  const agreeEl = document.getElementById('agreement-badge');

  const mlFlagged = s.prediction !== 'NORMAL';
  mlVal.textContent = mlFlagged ? s.prediction : 'NORMAL';
  mlVal.className = 'verdict-value ' + (mlFlagged ? 'suspicious' : 'normal');

  const rule = s.rule_engine || { verdict: 'NORMAL' };
  ruleVal.textContent = rule.verdict;
  ruleVal.className = 'verdict-value ' + (rule.verdict === 'SUSPICIOUS' ? 'suspicious' : 'normal');
  reasonEl.textContent = rule.fired_description ? `Rule fired: ${rule.fired_description}` : '';

  agreeEl.textContent = s.verdict_agreement ? 'ENGINES AGREE' : 'ENGINES DISAGREE';
  agreeEl.className = s.verdict_agreement ? 'agree' : 'disagree';
}

async function renderExplainPanel(s) {
  const panel = document.getElementById('explain-panel');
  if (s.phase === 'SECURE') {
    panel.style.display = 'none';
    lastPhaseForExplain = s.phase;
    return;
  }
  panel.style.display = 'block';
  if (s.phase === lastPhaseForExplain && Math.random() > 0.3) return;
  lastPhaseForExplain = s.phase;
  const data = await fetchJSON(API.explain);
  if (!data || !data.top_features) return;
  const wrap = document.getElementById('explain-content');
  wrap.innerHTML = '';
  const max = Math.max(...data.top_features.map(f => f.share_pct), 1);
  data.top_features.forEach(f => {
    const row = document.createElement('div');
    row.className = 'explain-row';
    row.innerHTML = `
      <div class="explain-label"><span>${f.feature}</span><span>${f.share_pct}%</span></div>
      <div class="explain-bar-bg"><div class="explain-bar-fill" style="width:${(f.share_pct / max) * 100}%"></div></div>`;
    wrap.appendChild(row);
  });
}

/** Renders the per-attack evidence rows into the Live Attack panel. */
function renderRealEvidencePanel(s) {
  const wrap = document.getElementById('real-evidence-content');
  const titleEl = document.getElementById('real-evidence-title');
  const ev = s.real_attack_evidence || {};
  if (!s.is_real_attack) {
    titleEl.textContent = '';
    wrap.innerHTML = '';
    return;
  }
  if (stageOf(s) === 'RESOLVED' && !Object.keys(ev).length) {
    // the real runner has been stopped: nothing is being sent any more
    titleEl.textContent = '';
    wrap.innerHTML = '<div class="evidence-stopped">Attacker stopped &mdash; no more attack traffic is reaching the device.</div>';
    return;
  }

  if (s.attack_type === 'DDOS') {
    titleEl.textContent = 'Live HTTP Load Test';
    wrap.innerHTML = `
      <div class="evidence-row"><span class="evidence-label">Requests sent (real, cumulative)</span><span class="evidence-value">${ev.total_requests_sent ?? '--'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Requests/sec (real, measured)</span><span class="evidence-value">${ev.packets_per_sec ?? '--'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Avg latency (real, measured)</span><span class="evidence-value">${ev.latency_ms ?? '--'} ms</span></div>
      <div class="evidence-row"><span class="evidence-label">Failed/timed-out requests</span><span class="evidence-value">${ev.total_failures ?? '--'} (${ev.retransmit_pct ?? '--'}%)</span></div>
      <div class="evidence-row"><span class="evidence-label">Real target</span><span class="evidence-value">127.0.0.1:5101</span></div>`;
  } else if (s.attack_type === 'PORT_SCAN') {
    titleEl.textContent = 'Live TCP Port Scan';
    const ports = (ev.open_ports_found || []).join(', ') || 'scanning...';
    wrap.innerHTML = `
      <div class="evidence-row"><span class="evidence-label">Sweeps completed (real)</span><span class="evidence-value">${ev.sweeps_completed ?? '--'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Ports probed per sweep</span><span class="evidence-value">${ev.ports_scanned ?? '--'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Probes/sec (real, measured)</span><span class="evidence-value">${ev.packets_per_sec ?? '--'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Real open ports found</span><span class="evidence-value">${ports}</span></div>
      <div class="evidence-row"><span class="evidence-label">Real target</span><span class="evidence-value">127.0.0.1:5090&ndash;5119</span></div>`;
  } else if (s.attack_type === 'FIRMWARE_TAMPER') {
    titleEl.textContent = 'Live SHA-256 Firmware Check';
    const tampered = ev.tampered;
    const golden = ev.golden_sha256 || '';
    const device = ev.device_sha256 || '';
    wrap.innerHTML = `
      <div class="evidence-hash-row">
        <div class="evidence-hash-label">Golden (signed) firmware SHA-256</div>
        <div class="evidence-hash">${golden}</div>
      </div>
      <div class="evidence-hash-row">
        <div class="evidence-hash-label">Device firmware SHA-256 (live, on disk right now)</div>
        <div class="evidence-hash ${tampered ? 'evidence-mismatch' : 'evidence-match'}">${device}</div>
      </div>
      <div class="evidence-row"><span class="evidence-label">Hashes match?</span>
        <span class="evidence-value ${tampered ? 'evidence-mismatch' : 'evidence-match'}">${tampered ? 'NO — MISMATCH DETECTED' : 'YES'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Corrupted byte offsets (real)</span><span class="evidence-value">${(ev.corrupted_byte_offsets || []).join(', ') || '--'}</span></div>`;
  } else if (s.attack_type === 'CMD_INJECT') {
    titleEl.textContent = 'Live Command Protocol Probe';
    wrap.innerHTML = `
      <div class="evidence-row"><span class="evidence-label">Commands sent (real)</span><span class="evidence-value">${ev.cmd_total_sent ?? '--'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Rejected by allow-list (real)</span><span class="evidence-value">${ev.cmd_total_rejected ?? '--'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Send rate (real, measured)</span><span class="evidence-value">${ev.cmd_rate ?? '--'}/s</span></div>
      <div class="evidence-row"><span class="evidence-label">Real target</span><span class="evidence-value">127.0.0.1:5102 (protocol port)</span></div>`;
  } else if (s.attack_type === 'FDI') {
    titleEl.textContent = 'Live Sensor Ingest';
    wrap.innerHTML = `
      <div class="evidence-row"><span class="evidence-label">Fabricated voltage received</span><span class="evidence-value">${ev.voltage ?? '--'} V</span></div>
      <div class="evidence-row"><span class="evidence-label">Fabricated frequency received</span><span class="evidence-value">${ev.frequency ?? '--'} Hz</span></div>
      <div class="evidence-row"><span class="evidence-label">Submissions (real)</span><span class="evidence-value">${ev.total_submissions ?? '--'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Real target</span><span class="evidence-value">127.0.0.1:5101/sensor</span></div>`;
  } else if (s.attack_type === 'LOAD_ALTER') {
    titleEl.textContent = 'Live Setpoint Channel';
    wrap.innerHTML = `
      <div class="evidence-row"><span class="evidence-label">Last setpoint received (real)</span><span class="evidence-value">${ev.last_setpoint ?? '--'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Setpoints received (real)</span><span class="evidence-value">${ev.setpoints_received ?? '--'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Real target</span><span class="evidence-value">127.0.0.1:5102 (protocol port)</span></div>`;
  } else if (s.attack_type === 'GPS_SPOOF') {
    titleEl.textContent = 'Live Time-Sync Channel';
    wrap.innerHTML = `
      <div class="evidence-row"><span class="evidence-label">Clock offset vs. real system time</span><span class="evidence-value">${ev.time_offset_ms ?? '--'} ms</span></div>
      <div class="evidence-row"><span class="evidence-label">Timesync messages (real)</span><span class="evidence-value">${ev.timesync_submissions ?? '--'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Real target</span><span class="evidence-value">127.0.0.1:5102 (protocol port)</span></div>`;
  } else if (s.attack_type === 'JAMMING') {
    titleEl.textContent = 'Live UDP Flood';
    wrap.innerHTML = `
      <div class="evidence-row"><span class="evidence-label">Datagrams sent (real)</span><span class="evidence-value">${ev.sent_total ?? '--'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Datagrams received by device</span><span class="evidence-value">${ev.received_total ?? '--'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Real measured loss</span><span class="evidence-value">${ev.retransmit_pct ?? '--'}%</span></div>
      <div class="evidence-row"><span class="evidence-label">Real target</span><span class="evidence-value">127.0.0.1:5104 (UDP)</span></div>`;
  } else if (s.attack_type === 'PRIV_ESC') {
    titleEl.textContent = 'Live Auth Brute Force';
    wrap.innerHTML = `
      <div class="evidence-row"><span class="evidence-label">Failed logins (real)</span><span class="evidence-value">${ev.auth_failures ?? '--'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Successful logins (real)</span><span class="evidence-value">${ev.auth_successes ?? '--'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Privilege level achieved</span><span class="evidence-value ${ev.privilege_level >= 5 ? 'evidence-mismatch' : ''}">${ev.privilege_level ?? '--'} / 5</span></div>
      <div class="evidence-row"><span class="evidence-label">Real target</span><span class="evidence-value">127.0.0.1:5103 (admin port)</span></div>`;
  } else if (s.attack_type === 'MALWARE') {
    titleEl.textContent = 'Live Exfil-Pattern Upload';
    wrap.innerHTML = `
      <div class="evidence-row"><span class="evidence-label">Bytes uploaded (real, cumulative)</span><span class="evidence-value">${(ev.bytes_uploaded_total ?? 0).toLocaleString()}</span></div>
      <div class="evidence-row"><span class="evidence-label">Uploads completed (real)</span><span class="evidence-value">${ev.uploads_total ?? '--'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Upload rate (real, measured)</span><span class="evidence-value">${ev.packets_per_sec ?? '--'}/s</span></div>
      <div class="evidence-row"><span class="evidence-label">Real target</span><span class="evidence-value">127.0.0.1:5101/upload</span></div>`;
  } else if (s.attack_type === 'REPLAY') {
    titleEl.textContent = 'Live Hash-Verified Replay';
    wrap.innerHTML = `
      <div class="evidence-hash-row">
        <div class="evidence-hash-label">Captured request SHA-256 (sent once, resent verbatim)</div>
        <div class="evidence-hash">${ev.captured_request_hash || '--'}</div>
      </div>
      <div class="evidence-row"><span class="evidence-label">Replays sent (real)</span><span class="evidence-value">${ev.replays_sent ?? '--'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Hash-verified identical</span><span class="evidence-value evidence-match">${ev.replays_hash_verified ?? '--'}</span></div>`;
  } else if (s.attack_type === 'MITM') {
    titleEl.textContent = 'Live Relay Proxy';
    wrap.innerHTML = `
      <div class="evidence-row"><span class="evidence-label">Relayed bytes (real, cumulative)</span><span class="evidence-value">${(ev.relayed_bytes_total ?? 0).toLocaleString()}</span></div>
      <div class="evidence-row"><span class="evidence-label">Relayed connections (real)</span><span class="evidence-value">${ev.relayed_connections ?? '--'}</span></div>
      <div class="evidence-row"><span class="evidence-label">Added latency from real hop</span><span class="evidence-value">${ev.added_latency_ms ?? '--'} ms</span></div>
      <div class="evidence-row"><span class="evidence-label">Real target</span><span class="evidence-value">127.0.0.1:5105 &rarr; 5101</span></div>`;
  }
}

/* ── live attack: strip, panel, device feed, normal-vs-now ───────── */
const STAGE_ORDER = ['LAUNCHED', 'EXECUTING', 'DETECTED', 'MITIGATING', 'RESOLVED'];

function stageOf(s) {
  if (s.attack_stage) return s.attack_stage;
  return s.phase === 'SECURE' ? 'NONE' : s.phase;
}

function predictionName(id) {
  if (!id || id === 'NORMAL') return 'NORMAL';
  const a = attackCatalog.find(x => x.id === id);
  return (a ? a.name : id).toUpperCase();
}

function fmtMetric(m) {
  if (!m) return '';
  const v = typeof m.value === 'number' ? m.value.toLocaleString() : m.value;
  return `${m.label}: ${v}${m.unit ? ' ' + m.unit : ''}${m.final ? ' (final)' : ''}`;
}

/** Between scenario stages the engine is SECURE with the next stage pending. */
function scenarioWaiting(s) {
  return Boolean(s.scenario && s.scenario.active && s.scenario.waiting) && stageOf(s) === 'NONE';
}

function scenarioLabel(s) {
  const sc = s.scenario;
  return `SCENARIO: ${sc.name}, stage ${sc.stage_idx + 1} of ${sc.stages.length}`;
}

function renderAttackStrip(s) {
  const stage = stageOf(s);
  const strip = document.getElementById('attack-strip');
  document.getElementById('app').classList.toggle('attack-glow', stage === 'EXECUTING' || stage === 'DETECTED');
  if (stage === 'NONE' && scenarioWaiting(s)) {
    strip.hidden = false;
    strip.className = 'stage-SCENARIO';
    document.getElementById('strip-text').textContent =
      `${scenarioLabel(s)} starting\u2026 target: ${s.scenario.target_node_name}`;
    document.getElementById('strip-extra').innerHTML =
      `<span class="strip-chip">next stage in ~${s.scenario.starting_in_s}s</span>`;
    return;
  }
  if (stage === 'NONE') {
    strip.hidden = true;
    strip.className = '';
    return;
  }
  strip.hidden = false;
  strip.className = 'stage-' + stage;
  const name = (s.attack_display_name || '').toUpperCase();
  const node = s.target_node_name || '--';
  const text = document.getElementById('strip-text');
  const extra = document.getElementById('strip-extra');
  const chip = (t) => `<span class="strip-chip">${t}</span>`;
  const elapsed = (s.scenario && s.scenario.active
    ? chip(`stage ${s.scenario.stage_idx + 1}/${s.scenario.stages.length} \u00b7 ${s.scenario.name}`) : '')
    + chip(`${(s.attack_elapsed_s || 0).toFixed(0)}s elapsed`);
  const metric = fmtMetric(s.attack_headline_metric);

  if (stage === 'EXECUTING') {
    text.textContent = `LIVE ATTACK IN PROGRESS: ${name} \u2192 ${node}`;
    text.textContent = `LIVE ATTACK IN PROGRESS: ${name} \u2192 ${node} \u00b7 AI analysing, confidence ${Math.round(s.confidence * 100)}% (${predictionName(s.prediction)})`;
    extra.innerHTML = elapsed + (metric ? chip(metric) : '') + chip('not yet detected');
  } else if (stage === 'DETECTED') {
    text.innerHTML = `ATTACK DETECTED: ${name} \u2192 ${node} ${s.severity ? severityBadgeHTML(s.severity.band) : ''}`;
    extra.innerHTML = elapsed + (metric ? chip(metric) : '') + chip(`AI confidence ${Math.round(s.confidence * 100)}%`);
  } else if (stage === 'MITIGATING') {
    text.textContent = `MITIGATING: ${s.mitigation_action}`;
    extra.innerHTML = chip(`${node}`) + chip(`${s.mitigation_progress}%`);
  } else {
    text.textContent = `ATTACK NEUTRALISED: ${node} restored`;
    extra.innerHTML = chip(name) + (metric ? chip(metric) : '') + chip('baseline restoring');
  }
}

function renderTimeline(el, tl) {
  const fmt = (v) => (v == null ? '\u2014' : `+${v.toFixed(1)}s`);
  const items = [
    ['Launched', '+0.0s', 'k-launched', Boolean(tl)],
    ['Detected', fmt(tl && tl.detected_s), 'k-detected', Boolean(tl) && tl.detected_s != null],
    ['Mitigation', fmt(tl && tl.mitigation_started_s), 'k-mitigation', Boolean(tl) && tl.mitigation_started_s != null],
    ['Resolved', fmt(tl && tl.resolved_s), 'k-resolved', Boolean(tl) && tl.resolved_s != null],
  ];
  el.innerHTML = items.map(([n, t, k, on]) =>
    `<div class="tl-item ${k}${on ? ' reached' : ''}"><span class="tl-name">${n}</span><span class="tl-time">${on ? t : '\u2014'}</span></div>`).join('');
}

/** "Last attack" card: shown only between attacks, once the previous one has fully resolved. */
function renderLastAttackPanel(s) {
  const tl = s.attack_timeline;
  const panel = document.getElementById('last-attack-panel');
  const show = stageOf(s) === 'NONE' && tl && !tl.active && tl.resolved_s != null;
  panel.style.display = show ? 'block' : 'none';
  if (!show) return;
  document.getElementById('last-attack-name').textContent = `${tl.attack_name} \u2192 ${tl.target_node_name}`;
  renderTimeline(document.getElementById('last-timeline'), tl);
}

function renderLiveAttackPanel(s) {
  const stage = stageOf(s);
  const panel = document.getElementById('live-attack-panel');
  renderLastAttackPanel(s);
  if (stage === 'NONE') {
    panel.style.display = 'none';
    return;
  }
  panel.style.display = 'block';
  panel.className = 'panel stage-' + stage;

  // 5-step tracker: Launched -> Executing -> Detected -> Mitigating -> Resolved
  const idx = STAGE_ORDER.indexOf(stage);
  document.querySelectorAll('#la-steps .la-step').forEach((el, i) => {
    el.classList.toggle('done', i < idx || stage === 'RESOLVED' && i === idx);
    el.classList.toggle('current', i === idx && stage !== 'RESOLVED');
    el.classList.add('s-' + STAGE_ORDER[i]);
  });

  const fix = document.getElementById('la-fix');
  if (stage === 'MITIGATING' || stage === 'RESOLVED') {
    fix.style.display = 'flex';
    fix.classList.toggle('resolved', stage === 'RESOLVED');
    document.getElementById('la-fix-text').textContent = stage === 'MITIGATING'
      ? `${s.mitigation_action} (${s.mitigation_progress}%)`
      : `${s.mitigation_action} \u2014 complete, ${s.target_node_name || 'target'} restored`;
  } else {
    fix.style.display = 'none';
  }

  renderTimeline(document.getElementById('la-timeline'), s.attack_timeline);
  renderRealEvidencePanel(s);
  renderTargetFeed(s.target_activity, stage);
  renderComparison(s);
}

function renderTargetFeed(activity, stage) {
  const feed = document.getElementById('la-feed');
  const events = ((activity && activity.events) || []).slice(0, 12);
  document.getElementById('la-device-state').textContent =
    activity && activity.device_online ? 'device online \u00b7 127.0.0.1' : 'device offline';
  feed.textContent = '';
  if (!events.length) {
    const d = document.createElement('div');
    d.className = 'la-feed-empty';
    d.textContent = stage === 'RESOLVED' ? '-- no traffic: attack stopped --' : 'waiting for traffic on the device\u2026';
    feed.appendChild(d);
    return;
  }
  events.forEach(e => {
    const line = document.createElement('div');
    line.className = 'la-feed-line' + (/REJECT|FAIL|gap|overload|503/i.test(e.summary) ? ' bad' : '');
    const t = document.createElement('span'); t.className = 't'; t.textContent = `${Number(e.age_s).toFixed(1)}s ago`;
    const k = document.createElement('span'); k.className = 'k'; k.textContent = e.kind;
    line.append(t, k, document.createTextNode(e.summary));
    feed.appendChild(line);
  });
}

// Nominal values match backend/attacks/base.py normal_readings(); `warn`/`bad` are ratio-to-nominal
// (or absolute distance for voltage/frequency) thresholds for the amber/red colouring.
const NORMAL_VS_NOW = {
  voltage:      { name: 'Voltage', nominal: 230, unit: 'V', dec: 1, mode: 'abs', warn: 5, bad: 15 },
  frequency:    { name: 'Frequency', nominal: 50, unit: 'Hz', dec: 2, mode: 'abs', warn: 0.2, bad: 0.8 },
  current:      { name: 'Current', nominal: 15, unit: 'A', dec: 1, mode: 'ratio', warn: 1.3, bad: 2 },
  packets_per_sec: { name: 'Packets/sec', nominal: 250, unit: '', dec: 0, mode: 'ratio', warn: 1.5, bad: 3 },
  packet_size_avg: { name: 'Avg packet size', nominal: 512, unit: 'B', dec: 0, mode: 'ratio', warn: 1.5, bad: 2.5 },
  unique_ips:   { name: 'Unique IPs', nominal: 3, unit: '', dec: 0, mode: 'ratio', warn: 2, bad: 5 },
  latency_ms:   { name: 'Latency', nominal: 12, unit: 'ms', dec: 0, mode: 'ratio', warn: 1.8, bad: 4 },
  retransmit_pct: { name: 'Retransmit', nominal: 1, unit: '%', dec: 1, mode: 'ratio', warn: 3, bad: 8 },
  cmd_rate:     { name: 'Command rate', nominal: 10, unit: '/s', dec: 1, mode: 'ratio', warn: 1.8, bad: 4 },
  cmd_unknown:  { name: 'Unknown cmds', nominal: 0.01, unit: '', dec: 2, mode: 'abs', warn: 0.05, bad: 0.2 },
  auth_failures:{ name: 'Auth failures', nominal: 0.5, unit: '/min', dec: 1, mode: 'abs', warn: 2, bad: 6 },
  privilege_level: { name: 'Privilege level', nominal: 1, unit: '/5', dec: 1, mode: 'abs', warn: 0.5, bad: 1.5 },
  sensor_delta: { name: 'Sensor delta', nominal: 0.3, unit: '', dec: 2, mode: 'abs', warn: 1, bad: 4 },
  conn_duration_avg: { name: 'Conn. duration', nominal: 2, unit: 's', dec: 2, mode: 'ratio', warn: 2.5, bad: 6, invert: true },
  time_offset_ms: { name: 'Clock offset', nominal: 5, unit: 'ms', dec: 0, mode: 'abs', warn: 50, bad: 500 },
  gps_drift:    { name: 'GPS drift', nominal: 2, unit: 'm', dec: 1, mode: 'abs', warn: 10, bad: 50 },
  load_variance:{ name: 'Load variance', nominal: 3, unit: '%', dec: 1, mode: 'abs', warn: 8, bad: 20 },
  noise_floor_db: { name: 'Noise floor', nominal: -95, unit: 'dB', dec: 1, mode: 'abs', warn: 8, bad: 20 },
  duplicate_pkt_ratio: { name: 'Duplicate pkts', nominal: 0.01, unit: '', dec: 2, mode: 'abs', warn: 0.1, bad: 0.3 },
  ttl_variance: { name: 'TTL variance', nominal: 1, unit: '', dec: 1, mode: 'abs', warn: 3, bad: 8 },
  firmware_checksum_mismatch: { name: 'Checksum mismatch', nominal: 0, unit: '', dec: 2, mode: 'abs', warn: 0.1, bad: 0.5 },
};
const ATTACK_COMPARE_KEYS = {
  DDOS: ['packets_per_sec', 'latency_ms', 'retransmit_pct', 'unique_ips'],
  PORT_SCAN: ['packets_per_sec', 'unique_ips', 'packet_size_avg', 'conn_duration_avg'],
  FIRMWARE_TAMPER: ['firmware_checksum_mismatch', 'voltage', 'frequency'],
  CMD_INJECT: ['cmd_rate', 'cmd_unknown', 'current'],
  FDI: ['sensor_delta', 'voltage', 'frequency'],
  LOAD_ALTER: ['load_variance', 'current', 'frequency'],
  GPS_SPOOF: ['time_offset_ms', 'gps_drift', 'frequency'],
  JAMMING: ['noise_floor_db', 'retransmit_pct', 'sensor_delta'],
  PRIV_ESC: ['auth_failures', 'privilege_level', 'cmd_rate'],
  MALWARE: ['packets_per_sec', 'packet_size_avg', 'unique_ips', 'retransmit_pct'],
  REPLAY: ['duplicate_pkt_ratio', 'packets_per_sec', 'latency_ms'],
  MITM: ['latency_ms', 'ttl_variance', 'duplicate_pkt_ratio', 'packets_per_sec'],
};

function renderComparison(s) {
  const wrap = document.getElementById('la-compare');
  const keys = ATTACK_COMPARE_KEYS[s.attack_type] || ['voltage', 'frequency', 'packets_per_sec'];
  wrap.innerHTML = '';
  keys.forEach(key => {
    const def = NORMAL_VS_NOW[key];
    const now = s.telemetry && s.telemetry[key];
    if (!def || now == null) return;
    let sev, deltaText;
    if (def.mode === 'abs') {
      const d = now - def.nominal;
      const a = Math.abs(d);
      sev = a >= def.bad ? 'bad' : (a >= def.warn ? 'warn' : 'good');
      deltaText = `${d >= 0 ? '+' : '\u2212'}${a.toFixed(def.dec)}${def.unit ? ' ' + def.unit : ''} vs normal`;
    } else {
      // `invert` metrics get worse as they FALL (e.g. connection duration), so compare nominal/now
      const eff = def.invert ? def.nominal / Math.max(now, 1e-6) : now / def.nominal;
      sev = eff >= def.bad ? 'bad' : (eff >= def.warn ? 'warn' : 'good');
      const times = now / def.nominal;
      deltaText = times >= 1.1 ? `${times.toFixed(1)}\u00d7 normal` : (times <= 0.9 ? `${times.toFixed(2)}\u00d7 normal` : 'normal');
    }
    const card = document.createElement('div');
    card.className = 'cmp-card ' + sev;
    card.innerHTML = `
      <div class="cmp-name">${def.name}</div>
      <div class="cmp-vals"><span>normal ${def.nominal}${def.unit ? ' ' + def.unit : ''}</span><span class="cmp-now">${Number(now).toLocaleString(undefined, { maximumFractionDigits: def.dec })}${def.unit ? ' ' + def.unit : ''}</span></div>
      <div class="cmp-delta">${deltaText}</div>`;
    wrap.appendChild(card);
  });
}

function renderScenarioProgress(scenario) {
  document.querySelectorAll('.scenario-card').forEach(card => {
    const chips = card.querySelectorAll('.scenario-stage-chip');
    const isActive = scenario && scenario.active === card.dataset.scenario;
    chips.forEach((chip, i) => {
      chip.classList.remove('running', 'done');
      if (isActive && scenario.stage_status[i]) {
        if (scenario.stage_status[i] === 'running') chip.classList.add('running');
        if (scenario.stage_status[i] === 'done') chip.classList.add('done');
      }
    });
  });
}

function renderNotifications(notes) {
  const wrap = document.getElementById('notif-entries');
  if (!notes.length) {
    wrap.innerHTML = '<div style="font-size:8.5px;color:rgba(0,234,255,0.35);">No alerts sent yet.</div>';
    return;
  }
  wrap.innerHTML = '';
  notes.forEach(n => {
    const div = document.createElement('div');
    div.className = 'notif-entry';
    div.innerHTML = `
      <div class="notif-subject">\u{1F4E7} ${n.subject}</div>
      <div class="notif-meta">${n.sent_at} \u00b7 to ${n.recipient} \u00b7 ${n.channel}</div>`;
    wrap.appendChild(div);
  });
}

function renderLog(entries) {
  const wrap = document.getElementById('log-entries');
  wrap.innerHTML = '';
  entries.forEach(ev => {
    const div = document.createElement('div');
    div.className = `log-entry ${ev.kind}`;
    const canExport = currentRole === 'admin' && ev.event_id != null && ev.title.startsWith('RESOLVED');
    const exportBtns = canExport
      ? `<button class="export-btn" data-id="${ev.event_id}" data-fmt="pdf">PDF</button>
         <button class="export-btn" data-id="${ev.event_id}" data-fmt="csv">CSV</button>`
      : '';
    div.innerHTML = `
      <span class="log-time">${ev.time}</span><span class="log-title">${ev.title}</span>${exportBtns}
      <span class="log-detail">${ev.detail}</span>`;
    wrap.appendChild(div);
  });
  wrap.querySelectorAll('.export-btn').forEach(btn => {
    btn.addEventListener('click', () => exportReport(btn.dataset.id, btn.dataset.fmt));
  });
}

function setText(id, val) { document.getElementById(id).textContent = val; }
function setWidth(id, pct) { document.getElementById(id).style.width = Math.max(0, Math.min(100, pct)) + '%'; }
function clampPct(v) { return Math.max(0, Math.min(100, v)); }
function colorAlert(id, on) { document.getElementById(id).style.color = on ? COLORS.red : COLORS.cyan; }

function updateClock() {
  document.getElementById('clock').textContent =
    new Date().toLocaleTimeString('en-US', { hour12: false }) + ' LOCAL';
}

/* Populate the node-target dropdown once topology loads (topology.js sets topoData). */
const _origInitTopology = initTopology;
initTopology = async function (containerId) {
  await _origInitTopology(containerId);
  const sel = document.getElementById('node-select');
  if (sel && typeof topoData !== 'undefined' && topoData) {
    topoData.nodes.forEach(n => {
      const opt = document.createElement('option');
      opt.value = n.id;
      opt.textContent = n.name;
      sel.appendChild(opt);
    });
  }
};

/* ============================================================
   ATTACK STAGE - per-attack canvas animation (v2, unchanged)
   ============================================================ */
const canvas = document.getElementById('stage-canvas');
const ctx = canvas.getContext('2d');

function resizeCanvas() {
  const wrap = document.getElementById('stage-canvas-wrap');
  const dpr = window.devicePixelRatio || 1;
  canvas.width = wrap.clientWidth * dpr;
  canvas.height = wrap.clientHeight * dpr;
  canvas.style.width = wrap.clientWidth + 'px';
  canvas.style.height = wrap.clientHeight + 'px';
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}
window.addEventListener('resize', resizeCanvas);

function stageIntensity(s) {
  if (!s) return 0;
  const stage = stageOf(s);
  if (stage === 'EXECUTING') return Math.min(1, 0.35 + (s.attack_elapsed_s || 0) * 0.22);   // builds up while undetected
  if (stage === 'DETECTED') return 1;
  if (stage === 'MITIGATING') return Math.max(0.08, 1 - s.mitigation_progress / 100);
  return 0;
}

function animateStage(ts) {
  requestAnimationFrame(animateStage);
  if (document.getElementById('stage-canvas').style.display === 'none') return;
  if (!canvas.width) resizeCanvas();
  const w = canvas.clientWidth, h = canvas.clientHeight;
  ctx.clearRect(0, 0, w, h);

  const s = latestStatus;
  const intensity = stageIntensity(s);
  const attackId = s && stageOf(s) !== 'NONE' ? s.attack_type : null;
  const t = ts / 1000;

  if (!attackId) {
    drawIdle(ctx, w, h, t);
    return;
  }
  const fn = STAGE_DRAWERS[attackId] || drawIdle;
  fn(ctx, w, h, t, intensity);
}

function grid(ctx, w, h, color, spacing) {
  ctx.strokeStyle = color; ctx.lineWidth = 1;
  ctx.beginPath();
  for (let x = 0; x < w; x += spacing) { ctx.moveTo(x, 0); ctx.lineTo(x, h); }
  for (let y = 0; y < h; y += spacing) { ctx.moveTo(0, y); ctx.lineTo(w, y); }
  ctx.stroke();
}

function glowText(ctx, text, x, y, color, size, alpha) {
  ctx.save();
  ctx.globalAlpha = alpha;
  ctx.fillStyle = color;
  ctx.font = `bold ${size}px 'Courier New', monospace`;
  ctx.textAlign = 'center';
  ctx.shadowColor = color; ctx.shadowBlur = 12;
  ctx.fillText(text, x, y);
  ctx.restore();
}

function drawIdle(ctx, w, h, t) {
  grid(ctx, w, h, 'rgba(0,234,255,0.05)', 34);
  const cx = w / 2, cy = h / 2;
  for (let i = 0; i < 3; i++) {
    const r = 30 + i * 26 + Math.sin(t * 0.8 + i) * 4;
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.strokeStyle = `rgba(0,234,255,${0.18 - i * 0.04})`;
    ctx.lineWidth = 1.5;
    ctx.stroke();
  }
  ctx.beginPath(); ctx.arc(cx, cy, 4, 0, Math.PI * 2);
  ctx.fillStyle = '#00eaff'; ctx.shadowColor = '#00eaff'; ctx.shadowBlur = 10; ctx.fill();
  ctx.shadowBlur = 0;
}

function drawDDoS(ctx, w, h, t, intensity) {
  ctx.fillStyle = `rgba(255,0,0,${0.03 + intensity * 0.05})`;
  ctx.fillRect(0, 0, w, h);
  const cx = w * 0.85, cy = h / 2;
  const n = Math.round(30 + intensity * 90);
  for (let i = 0; i < n; i++) {
    const seed = i * 137.5;
    const speed = 1.2 + (i % 5) * 0.4;
    const prog = ((t * speed * (0.5 + intensity)) + seed) % 1;
    const sx = w * (Math.sin(seed) * 0.4 + 0.5) * 0.15;
    const x = sx + (cx - sx) * prog;
    const y = cy + Math.sin(seed + t * 2) * (h * 0.35) * (1 - prog * 0.3);
    ctx.beginPath();
    ctx.arc(x, y, 2 + intensity * 1.5, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(255,${60 - intensity * 40},${60 - intensity * 40},0.85)`;
    ctx.fill();
  }
  ctx.beginPath(); ctx.arc(cx, cy, 18 + Math.sin(t * 10) * 4 * intensity, 0, Math.PI * 2);
  ctx.strokeStyle = `rgba(255,50,50,${0.5 + intensity * 0.4})`; ctx.lineWidth = 2; ctx.stroke();
  glowText(ctx, 'GATEWAY', cx, cy + 40, '#ff3b3b', 10, 0.7);
  glowText(ctx, `${Math.round(8000 + intensity * 14000)} PPS`, w / 2, 24, '#ff3b3b', 11, 0.8);
}

function drawFDI(ctx, w, h, t, intensity) {
  grid(ctx, w, h, 'rgba(255,170,0,0.04)', 34);
  const rows = 4;
  const labels = ['VOLTAGE', 'FREQUENCY', 'CURRENT', 'PWR FACTOR'];
  for (let i = 0; i < rows; i++) {
    const y = h * 0.22 + i * (h * 0.18);
    const glitch = Math.random() < 0.15 + intensity * 0.3;
    const val = (Math.random() * 999).toFixed(glitch ? 0 : 2);
    ctx.save();
    if (glitch) ctx.translate((Math.random() - 0.5) * 14 * intensity, 0);
    glowText(ctx, labels[i], w * 0.28, y, 'rgba(255,170,0,0.6)', 10, 0.8);
    glowText(ctx, glitch ? `\u2588\u2588\u2588.${val}` : val, w * 0.68, y, glitch ? '#ff3b3b' : '#ffaa00', 15, glitch ? 1 : 0.7);
    ctx.restore();
  }
  if (Math.random() < intensity * 0.4) {
    ctx.fillStyle = `rgba(255,0,0,${0.05 + Math.random() * 0.1})`;
    ctx.fillRect(0, Math.random() * h, w, 3 + Math.random() * 6);
  }
}

function drawCmdInject(ctx, w, h, t, intensity) {
  const rows = Math.floor(h / 20);
  for (let i = 0; i < rows; i++) {
    const y = 16 + i * 20;
    const offset = (t * (40 + intensity * 260)) % (rows * 20);
    const rowY = (y + offset) % (rows * 20);
    const malicious = Math.random() < 0.35 + intensity * 0.4;
    ctx.font = "10px 'Courier New', monospace";
    ctx.textAlign = 'left';
    ctx.fillStyle = malicious ? 'rgba(255,59,59,0.85)' : 'rgba(0,234,255,0.35)';
    const cmd = malicious ? `CMD 0x${Math.floor(Math.random() * 4095).toString(16).toUpperCase()} SRC:UNK` : `CMD 0x${Math.floor(Math.random() * 4095).toString(16).toUpperCase()} SRC:PLC-0${1 + (i % 3)}`;
    ctx.fillText(cmd, 14, rowY);
    if (malicious) {
      ctx.fillStyle = 'rgba(255,59,59,0.9)';
      ctx.font = "bold 9px 'Courier New', monospace";
      ctx.fillText('[UNAUTHORIZED]', w - 130, rowY);
    }
  }
}

function drawMalware(ctx, w, h, t, intensity) {
  const cols = 6, rows = 4;
  const nodes = [];
  for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) {
    nodes.push({ x: (c + 0.5) * (w / cols), y: (r + 0.5) * (h / rows), idx: r * cols + c });
  }
  const infectedCount = Math.round(nodes.length * intensity);
  ctx.strokeStyle = 'rgba(0,234,255,0.08)'; ctx.lineWidth = 1;
  nodes.forEach((n, i) => {
    if (i % cols < cols - 1) { ctx.beginPath(); ctx.moveTo(n.x, n.y); ctx.lineTo(nodes[i + 1].x, nodes[i + 1].y); ctx.stroke(); }
    if (i + cols < nodes.length) { ctx.beginPath(); ctx.moveTo(n.x, n.y); ctx.lineTo(nodes[i + cols].x, nodes[i + cols].y); ctx.stroke(); }
  });
  nodes.forEach((n, i) => {
    const infected = i < infectedCount;
    const pulse = infected ? 5 + Math.sin(t * 6 + i) * 2 : 3.5;
    ctx.beginPath(); ctx.arc(n.x, n.y, pulse, 0, Math.PI * 2);
    ctx.fillStyle = infected ? 'rgba(255,59,59,0.9)' : 'rgba(0,234,255,0.4)';
    ctx.shadowColor = infected ? '#ff3b3b' : 'transparent'; ctx.shadowBlur = infected ? 10 : 0;
    ctx.fill();
    ctx.shadowBlur = 0;
  });
  glowText(ctx, `${infectedCount}/${nodes.length} HOSTS INFECTED`, w / 2, h - 14, '#ff3b3b', 10, 0.8);
}

function drawMitm(ctx, w, h, t, intensity) {
  const aX = w * 0.18, bX = w * 0.82, y = h / 2;
  ctx.strokeStyle = 'rgba(0,234,255,0.5)'; ctx.lineWidth = 2;
  ctx.setLineDash([6, 6]);
  ctx.beginPath(); ctx.moveTo(aX, y); ctx.lineTo(bX, y); ctx.stroke();
  ctx.setLineDash([]);
  ['A', 'B'].forEach((lab, i) => {
    const x = i === 0 ? aX : bX;
    ctx.beginPath(); ctx.arc(x, y, 14, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(0,234,255,0.12)'; ctx.strokeStyle = '#00eaff'; ctx.lineWidth = 1.5;
    ctx.fill(); ctx.stroke();
    glowText(ctx, lab, x, y + 4, '#00eaff', 12, 0.9);
  });
  const mx = w / 2, my = y - 4 + Math.sin(t * 3) * 6 * intensity;
  ctx.beginPath(); ctx.arc(mx, my, 16 + intensity * 4, 0, Math.PI * 2);
  ctx.fillStyle = `rgba(255,59,59,${0.15 + intensity * 0.15})`;
  ctx.strokeStyle = '#ff3b3b'; ctx.lineWidth = 2; ctx.fill(); ctx.stroke();
  glowText(ctx, '\u26A0', mx, my + 6, '#ff3b3b', 16, 1);
  ctx.strokeStyle = 'rgba(255,59,59,0.7)'; ctx.lineWidth = 2;
  ctx.beginPath(); ctx.moveTo(mx - 10, my - 14); ctx.lineTo(mx + 10, my - 4); ctx.stroke();
  glowText(ctx, 'ROGUE RELAY INTERCEPTING SESSION', w / 2, h - 14, '#ff3b3b', 9, 0.75);
}

function drawReplay(ctx, w, h, t, intensity) {
  const laneY = h / 2;
  ctx.strokeStyle = 'rgba(0,234,255,0.15)'; ctx.beginPath(); ctx.moveTo(0, laneY); ctx.lineTo(w, laneY); ctx.stroke();
  const n = Math.round(4 + intensity * 10);
  for (let i = 0; i < n; i++) {
    const speed = 0.15 + (i % 3) * 0.05;
    const prog = ((t * speed) + i * 0.11) % 1;
    const x = prog * w;
    for (let g = 0; g < 3; g++) {
      const gx = x - g * 22;
      if (gx < 0) continue;
      ctx.beginPath(); ctx.arc(gx, laneY, 5, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(0,234,255,${0.5 - g * 0.15})`;
      ctx.fill();
    }
    if (i % 2 === 0) {
      ctx.font = "8px 'Courier New', monospace"; ctx.fillStyle = 'rgba(0,234,255,0.4)'; ctx.textAlign = 'center';
      ctx.fillText('DUP', x, laneY - 14);
    }
  }
  glowText(ctx, 'CAPTURED PACKETS RE-TRANSMITTED', w / 2, h - 14, '#00eaff', 9, 0.6);
}

function drawPortScan(ctx, w, h, t, intensity) {
  const cols = 12, rows = 6;
  const cx = w / 2, cy = h / 2;
  const R = Math.min(w, h) * 0.42;
  ctx.strokeStyle = 'rgba(0,234,255,0.12)'; ctx.lineWidth = 1;
  [0.33, 0.66, 1].forEach(f => { ctx.beginPath(); ctx.arc(cx, cy, R * f, 0, Math.PI * 2); ctx.stroke(); });
  const angle = (t * (1 + intensity * 2)) % (Math.PI * 2);
  ctx.save();
  ctx.beginPath(); ctx.moveTo(cx, cy);
  ctx.arc(cx, cy, R, angle, angle + 0.5);
  ctx.closePath();
  ctx.fillStyle = 'rgba(0,234,255,0.12)';
  ctx.fill();
  ctx.restore();
  ctx.strokeStyle = 'rgba(0,234,255,0.7)'; ctx.lineWidth = 1.5;
  ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(cx + Math.cos(angle) * R, cy + Math.sin(angle) * R); ctx.stroke();

  for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) {
    const px = w * 0.06 + c * (w * 0.88 / (cols - 1));
    const py = h * 0.1 + r * (h * 0.8 / (rows - 1));
    const a = Math.atan2(py - cy, px - cx);
    let diff = Math.abs(((a - angle + Math.PI * 3) % (Math.PI * 2)) - Math.PI);
    const lit = diff > Math.PI - 0.4;
    ctx.beginPath(); ctx.arc(px, py, lit ? 3 : 1.5, 0, Math.PI * 2);
    ctx.fillStyle = lit ? '#00eaff' : 'rgba(0,234,255,0.25)';
    ctx.shadowColor = lit ? '#00eaff' : 'transparent'; ctx.shadowBlur = lit ? 8 : 0;
    ctx.fill(); ctx.shadowBlur = 0;
  }
  glowText(ctx, 'PORT SWEEP IN PROGRESS', w / 2, h - 14, '#00eaff', 9, 0.7);
}

function drawFirmwareTamper(ctx, w, h, t, intensity) {
  const cx = w / 2, cy = h / 2 - 6;
  ctx.strokeStyle = '#ffaa00'; ctx.lineWidth = 2;
  ctx.strokeRect(cx - 40, cy - 26, 80, 52);
  ctx.fillStyle = 'rgba(255,170,0,0.06)'; ctx.fillRect(cx - 40, cy - 26, 80, 52);
  for (let i = 0; i < 4; i++) {
    ctx.beginPath(); ctx.moveTo(cx - 40, cy - 16 + i * 12); ctx.lineTo(cx + 40, cy - 16 + i * 12);
    ctx.strokeStyle = 'rgba(255,170,0,0.25)'; ctx.lineWidth = 1; ctx.stroke();
  }
  const badgeX = cx + 34, badgeY = cy - 24;
  const flicker = Math.random() < 0.5 + intensity * 0.3;
  ctx.beginPath(); ctx.arc(badgeX, badgeY, 12, 0, Math.PI * 2);
  ctx.fillStyle = flicker ? '#ff3b3b' : '#ffaa00';
  ctx.shadowColor = ctx.fillStyle; ctx.shadowBlur = 10; ctx.fill(); ctx.shadowBlur = 0;
  glowText(ctx, '!', badgeX, badgeY + 4, '#000a14', 13, 1);
  glowText(ctx, 'DEVICE FW-CTRL-07', cx, cy + 44, '#ffaa00', 9, 0.7);
  const hash = flicker ? 'CHECKSUM: MISMATCH' : 'CHECKSUM: verifying...';
  glowText(ctx, hash, cx, h - 14, flicker ? '#ff3b3b' : '#ffaa00', 9, 0.85);
}

function drawGpsSpoof(ctx, w, h, t, intensity) {
  const cx = w / 2, cy = h / 2 - 10;
  const R = 46;
  ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2);
  ctx.strokeStyle = 'rgba(0,234,255,0.3)'; ctx.lineWidth = 1.5; ctx.stroke();
  for (let i = 0; i < 12; i++) {
    const a = (i / 12) * Math.PI * 2;
    ctx.beginPath();
    ctx.moveTo(cx + Math.cos(a) * (R - 4), cy + Math.sin(a) * (R - 4));
    ctx.lineTo(cx + Math.cos(a) * R, cy + Math.sin(a) * R);
    ctx.strokeStyle = 'rgba(0,234,255,0.25)'; ctx.stroke();
  }
  const jitter = intensity * 34;
  const px = cx + (Math.random() - 0.5) * jitter;
  const py = cy + (Math.random() - 0.5) * jitter;
  ctx.beginPath(); ctx.arc(px, py, 5, 0, Math.PI * 2);
  ctx.fillStyle = '#ff3b3b'; ctx.shadowColor = '#ff3b3b'; ctx.shadowBlur = 10; ctx.fill(); ctx.shadowBlur = 0;
  ctx.beginPath(); ctx.arc(cx, cy, 3, 0, Math.PI * 2); ctx.fillStyle = 'rgba(0,234,255,0.5)'; ctx.fill();

  const drift = Math.round(15 + intensity * 180 + Math.random() * 15);
  const offset = Math.round(30 + intensity * 900 + Math.random() * 40);
  glowText(ctx, `GPS DRIFT: ${drift} m`, cx, cy + R + 22, '#ff3b3b', 10, 0.85);
  glowText(ctx, `CLOCK OFFSET: ${offset} ms`, cx, cy + R + 36, '#ff3b3b', 9, 0.7);
}

function drawLoadAlter(ctx, w, h, t, intensity) {
  const cx = w / 2, cy = h / 2 + 20, R = 60;
  ctx.beginPath(); ctx.arc(cx, cy, R, Math.PI, Math.PI * 2); ctx.strokeStyle = 'rgba(0,234,255,0.2)'; ctx.lineWidth = 8; ctx.stroke();
  const grad = ctx.createLinearGradient(cx - R, cy, cx + R, cy);
  grad.addColorStop(0, '#00eaff'); grad.addColorStop(0.6, '#ffaa00'); grad.addColorStop(1, '#ff3b3b');
  ctx.beginPath(); ctx.arc(cx, cy, R, Math.PI, Math.PI * 2); ctx.strokeStyle = grad; ctx.lineWidth = 3; ctx.stroke();
  const swing = 0.5 + Math.sin(t * 8) * 0.45 * intensity;
  const needleAngle = Math.PI + swing * Math.PI;
  ctx.beginPath(); ctx.moveTo(cx, cy);
  ctx.lineTo(cx + Math.cos(needleAngle) * (R - 6), cy + Math.sin(needleAngle) * (R - 6));
  ctx.strokeStyle = '#ff3b3b'; ctx.lineWidth = 2.5; ctx.stroke();
  ctx.beginPath(); ctx.arc(cx, cy, 4, 0, Math.PI * 2); ctx.fillStyle = '#00eaff'; ctx.fill();
  glowText(ctx, `LOAD VARIANCE: ${Math.round(20 + intensity * 60)}%`, cx, cy + 30, '#ff3b3b', 10, 0.85);
}

function drawJamming(ctx, w, h, t, intensity) {
  const density = 200 + intensity * 1400;
  for (let i = 0; i < density; i++) {
    const x = Math.random() * w, y = Math.random() * h;
    const v = Math.random();
    ctx.fillStyle = `rgba(${v > 0.5 ? '0,234,255' : '255,59,59'},${0.15 + Math.random() * 0.25})`;
    ctx.fillRect(x, y, 1.5, 1.5);
  }
  ctx.font = "10px 'Courier New', monospace"; ctx.textAlign = 'left';
  ctx.fillStyle = 'rgba(0,234,255,0.3)';
  ctx.fillText('SENSOR CH-3', 12, 18);
  glowText(ctx, 'SIGNAL LOST', w / 2, h / 2, '#ff3b3b', 16, 0.5 + Math.random() * 0.5 * intensity);
  glowText(ctx, `NOISE FLOOR: ${Math.round(-95 + intensity * 55)} dB`, w / 2, h - 14, '#ff3b3b', 9, 0.8);
}

function drawPrivEsc(ctx, w, h, t, intensity) {
  const cx = w / 2, cy = h / 2;
  const level = 1 + intensity * 4;
  ctx.beginPath(); ctx.arc(cx, cy, 44, 0, Math.PI * 2);
  ctx.strokeStyle = `rgba(255,59,59,${0.3 + Math.sin(t * 6) * 0.2 * intensity + 0.2})`;
  ctx.lineWidth = 4; ctx.stroke();
  ctx.beginPath(); ctx.arc(cx, cy, 44, -Math.PI / 2, -Math.PI / 2 + (level / 5) * Math.PI * 2);
  ctx.strokeStyle = '#ff3b3b'; ctx.lineWidth = 4; ctx.stroke();
  glowText(ctx, `LVL ${level.toFixed(1)}`, cx, cy + 5, '#ff3b3b', 15, 0.95);
  glowText(ctx, 'PRIVILEGE ESCALATION', cx, cy + 62, '#ff3b3b', 10, 0.8);
  glowText(ctx, `AUTH FAILURES: ${Math.round(6 + intensity * 20)}/min`, cx, cy + 76, '#ffaa00', 9, 0.7);
}

const STAGE_DRAWERS = {
  DDOS: drawDDoS, FDI: drawFDI, CMD_INJECT: drawCmdInject, MALWARE: drawMalware,
  MITM: drawMitm, REPLAY: drawReplay, PORT_SCAN: drawPortScan, FIRMWARE_TAMPER: drawFirmwareTamper,
  GPS_SPOOF: drawGpsSpoof, LOAD_ALTER: drawLoadAlter, JAMMING: drawJamming, PRIV_ESC: drawPrivEsc,
};

boot();
