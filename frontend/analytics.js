/* ============================================================
   Smart Grid IDS v3 - analytics.js
   Fetches aggregated incident history + model comparison metrics
   and renders them as hand-rolled canvas charts (no chart library),
   plus a literature benchmark table for the viva.
   ============================================================ */

const ATTACK_DISPLAY_NAMES = {
  DDOS: 'DDoS Flood', FDI: 'False Data Injection', CMD_INJECT: 'Command Injection',
  MALWARE: 'Malware Activity', MITM: 'Man-in-the-Middle', REPLAY: 'Replay Attack',
  PORT_SCAN: 'Port Scan', FIRMWARE_TAMPER: 'Firmware Tampering', GPS_SPOOF: 'GPS Spoofing',
  LOAD_ALTER: 'Load-Altering', JAMMING: 'Sensor Jamming', PRIV_ESC: 'Privilege Escalation',
};

async function boot() {
  setInterval(updateClock, 1000);
  updateClock();
  const [analytics, models] = await Promise.all([fetchJSON('/api/analytics'), fetchJSON('/api/models')]);
  renderStats(analytics);
  renderBarChart(analytics.by_attack_type);
  renderLineChart(analytics.by_hour);
  renderMitigationTable(analytics.avg_mitigation_seconds_by_attack);
  renderModelTable(models.models || []);
  renderBenchmarkTable(models.models || []);
}

async function fetchJSON(url) {
  try {
    const res = await fetch(url);
    return await res.json();
  } catch (e) {
    console.error('fetch failed', url, e);
    return {};
  }
}

function updateClock() {
  document.getElementById('clock').textContent =
    new Date().toLocaleTimeString('en-US', { hour12: false }) + ' LOCAL';
}

function renderStats(a) {
  document.getElementById('stat-total').textContent = a.total_incidents ?? 0;
  document.getElementById('stat-frequent').textContent =
    a.most_frequent_attack ? (ATTACK_DISPLAY_NAMES[a.most_frequent_attack] || a.most_frequent_attack) : 'N/A';
  document.getElementById('stat-confidence').textContent = a.avg_confidence != null ? Math.round(a.avg_confidence * 100) + '%' : '--';
  document.getElementById('stat-agreement').textContent = a.ml_rule_agreement_rate != null ? Math.round(a.ml_rule_agreement_rate * 100) + '%' : '--';
}

function renderMitigationTable(byAttack) {
  const wrap = document.getElementById('mitigation-table');
  const entries = Object.entries(byAttack || {});
  if (!entries.length) { wrap.innerHTML = '<div style="font-size:9px;color:rgba(47,217,200,0.4);">No incidents recorded yet.</div>'; return; }
  let html = '<table><thead><tr><th>Attack</th><th>Avg. Seconds</th></tr></thead><tbody>';
  entries.sort((a, b) => b[1] - a[1]).forEach(([atk, secs]) => {
    html += `<tr><td>${ATTACK_DISPLAY_NAMES[atk] || atk}</td><td>${secs}s</td></tr>`;
  });
  html += '</tbody></table>';
  wrap.innerHTML = html;
}

function renderModelTable(models) {
  const wrap = document.getElementById('model-comparison-table');
  if (!models.length) { wrap.innerHTML = '<div style="font-size:9px;color:rgba(47,217,200,0.4);">Run train_models.py to populate model metrics.</div>'; return; }
  let html = '<table><thead><tr><th>Model</th><th>Accuracy</th><th>F1</th><th>Train Time</th></tr></thead><tbody>';
  models.forEach(m => {
    html += `<tr class="${m.active ? 'highlight' : ''}"><td>${m.name}${m.active ? ' \u2713' : ''}</td>` +
      `<td>${m.accuracy != null ? m.accuracy + '%' : '--'}</td>` +
      `<td>${m.f1_score != null ? m.f1_score : '--'}</td>` +
      `<td>${m.train_time_sec != null ? m.train_time_sec + 's' : '--'}</td></tr>`;
  });
  html += '</tbody></table>';
  wrap.innerHTML = html;
}

function renderBenchmarkTable(models) {
  const tbody = document.getElementById('benchmark-tbody');
  let html = '';
  models.forEach(m => {
    html += `<tr class="highlight"><td>This project - ${m.name}</td>` +
      `<td>${m.accuracy != null ? m.accuracy + '%' : '--'}</td>` +
      `<td>${m.f1_score != null ? m.f1_score : '--'}</td>` +
      `<td>Live test-set result, ${m.name} on 13-class synthetic smart-grid dataset</td></tr>`;
  });
  // Literature rows intentionally left blank for the figures - fill these in
  // directly from the project's own Literature Review section.
  const LIT_ROWS = [
    'Shees et al.',
    'Mohammed et al.',
    'Huang &amp; Su',
  ];
  LIT_ROWS.forEach(name => {
    html += `<tr><td>${name}</td><td>&mdash;</td><td>&mdash;</td>` +
      `<td>Insert reported figures from Literature Review</td></tr>`;
  });
  tbody.innerHTML = html;
}

/* ── hand-rolled canvas charts (no external library) ─────────── */
function setupCanvas(canvas) {
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, w: rect.width, h: rect.height };
}

function renderBarChart(byAttack) {
  const canvas = document.getElementById('bar-chart');
  const { ctx, w, h } = setupCanvas(canvas);
  ctx.clearRect(0, 0, w, h);
  const entries = Object.entries(byAttack || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    ctx.fillStyle = 'rgba(47,217,200,0.4)'; ctx.font = "10px 'JetBrains Mono', monospace"; ctx.textAlign = 'center';
    ctx.fillText('No incidents recorded yet', w / 2, h / 2);
    return;
  }
  const max = Math.max(...entries.map(e => e[1]));
  const padL = 10, padB = 34, padT = 10, padR = 10;
  const chartW = w - padL - padR, chartH = h - padT - padB;
  const barW = chartW / entries.length * 0.6;
  const gap = chartW / entries.length;

  ctx.strokeStyle = 'rgba(47,217,200,0.12)'; ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(padL, padT); ctx.lineTo(padL, h - padB); ctx.lineTo(w - padR, h - padB); ctx.stroke();

  entries.forEach(([atk, count], i) => {
    const barH = (count / max) * chartH;
    const x = padL + i * gap + (gap - barW) / 2;
    const y = h - padB - barH;
    ctx.fillStyle = 'rgba(47,217,200,0.55)';
    ctx.fillRect(x, y, barW, barH);
    ctx.fillStyle = 'rgba(47,217,200,0.8)';
    ctx.font = "9px 'JetBrains Mono', monospace"; ctx.textAlign = 'center';
    ctx.fillText(String(count), x + barW / 2, y - 4);
    ctx.save();
    ctx.translate(x + barW / 2, h - padB + 10);
    ctx.rotate(-Math.PI / 5);
    ctx.fillStyle = 'rgba(47,217,200,0.5)';
    ctx.font = "8px 'JetBrains Mono', monospace"; ctx.textAlign = 'right';
    ctx.fillText(atk, 0, 0);
    ctx.restore();
  });
}

function renderLineChart(byHour) {
  const canvas = document.getElementById('line-chart');
  const { ctx, w, h } = setupCanvas(canvas);
  ctx.clearRect(0, 0, w, h);
  const entries = Object.entries(byHour || {});
  if (!entries.length) {
    ctx.fillStyle = 'rgba(47,217,200,0.4)'; ctx.font = "10px 'JetBrains Mono', monospace"; ctx.textAlign = 'center';
    ctx.fillText('No incidents recorded yet', w / 2, h / 2);
    return;
  }
  const max = Math.max(...entries.map(e => e[1]), 1);
  const padL = 24, padB = 26, padT = 14, padR = 12;
  const chartW = w - padL - padR, chartH = h - padT - padB;

  ctx.strokeStyle = 'rgba(47,217,200,0.12)'; ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(padL, padT); ctx.lineTo(padL, h - padB); ctx.lineTo(w - padR, h - padB); ctx.stroke();
  for (let g = 0; g <= max; g++) {
    const y = h - padB - (g / max) * chartH;
    ctx.fillStyle = 'rgba(47,217,200,0.4)'; ctx.font = "8px 'JetBrains Mono', monospace"; ctx.textAlign = 'right';
    ctx.fillText(String(g), padL - 4, y + 3);
  }

  ctx.beginPath();
  entries.forEach(([hour, count], i) => {
    const x = padL + (entries.length === 1 ? chartW / 2 : (i / (entries.length - 1)) * chartW);
    const y = h - padB - (count / max) * chartH;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = '#2fd9c8'; ctx.lineWidth = 2; ctx.shadowColor = '#2fd9c8'; ctx.shadowBlur = 6; ctx.stroke();
  ctx.shadowBlur = 0;

  entries.forEach(([hour, count], i) => {
    const x = padL + (entries.length === 1 ? chartW / 2 : (i / (entries.length - 1)) * chartW);
    const y = h - padB - (count / max) * chartH;
    ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2);
    ctx.fillStyle = '#2fd9c8'; ctx.fill();
  });
}

boot();
