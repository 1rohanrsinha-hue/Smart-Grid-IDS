#!/usr/bin/env node
/*
 * verify_attack_ui.js
 * ===================
 * End-to-end check of the live-attack visibility UI, driven through headless
 * Chrome over the DevTools protocol (no npm dependencies; needs Node >= 22 and
 * Google Chrome / Chromium).
 *
 *   node scripts/verify_attack_ui.js [--widths 1280,1920] [--only DDOS,MITM]
 *                                    [--no-scenarios] [--no-attacks] [--scenarios id,id]
 *                                    [--out docs/attack_visibility_full]
 *
 * What it does
 *   - starts backend/app.py itself with SGIDS_EVENT_LOG pointing at a temp file
 *     (the real backend/event_log.jsonl is never written; its checksum is
 *     compared before/after),
 *   - logs in as admin through the real login form,
 *   - triggers each of the 12 attacks with the real UI buttons, each on a
 *     different node, then the 3 scenarios,
 *   - polls /api/status, probes the DOM/layout at each stage, asserts the
 *     expected behaviour and saves a screenshot per stage,
 *   - writes <out>/<width>/report.json and exits non-zero on any failure.
 *
 * Port 5001 must be free (stop any running app.py first).
 */
'use strict';
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.resolve(__dirname, '..');
const args = process.argv.slice(2);
const opt = (name, dflt) => { const i = args.indexOf('--' + name); return i >= 0 ? args[i + 1] : dflt; };
const flag = (name) => args.includes('--' + name);
const WIDTHS = opt('widths', '1280,1920').split(',').map(Number);
const ONLY = opt('only', '') ? opt('only', '').split(',') : null;
const OUT = path.resolve(ROOT, opt('out', 'docs/attack_visibility_full'));
const BASE = 'http://127.0.0.1:5001';
const CHROME = process.env.CHROME_BIN || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const DEBUG_PORT = 9340;

const ATTACKS = ['DDOS', 'MITM', 'REPLAY', 'PORT_SCAN', 'FDI', 'LOAD_ALTER', 'GPS_SPOOF', 'CMD_INJECT',
                 'MALWARE', 'FIRMWARE_TAMPER', 'JAMMING', 'PRIV_ESC'];
// Each attack is only run on nodes its category can really hit (topology.CATEGORY_TARGETS), read from the backend.
const LEGAL = JSON.parse(require('node:child_process').execFileSync('python3', ['-c',
  'import json; import topology; from attacks import ATTACKS; ' +
  'print(json.dumps({k: topology.CATEGORY_TARGETS[a.category] for k, a in ATTACKS.items()}))'],
  { cwd: path.join(ROOT, 'backend'), encoding: 'utf8' }));
const legalNode = (attack, i, widthIdx) => { const pool = LEGAL[attack]; return pool[(i * 3 + widthIdx * 5) % pool.length]; };
const ALL_SCENARIOS = ['recon_to_breach', 'grid_destabilization', 'stealth_takeover'];
const SCENARIOS = opt('scenarios', '') ? opt('scenarios', '').split(',') : ALL_SCENARIOS;
const STAGE_SHOT_DELAY = { EXECUTING: 1500, DETECTED: 1500, MITIGATING: 1800, RESOLVED: 1800 };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha = (f) => (fs.existsSync(f) ? crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex') : 'absent');
const log = (...a) => console.log(...a);

// ── process helpers ────────────────────────────────────────────────────────
async function up() { try { await fetch(BASE + '/api/session'); return true; } catch { return false; } }

async function startServer(eventLog) {
  if (await up()) throw new Error('Port 5001 is already in use. Stop the running app.py first.');
  const proc = spawn('python3', ['app.py'], {
    cwd: path.join(ROOT, 'backend'), stdio: 'ignore',
    env: { ...process.env, SGIDS_EVENT_LOG: eventLog },
  });
  for (let i = 0; i < 60 && !(await up()); i++) await sleep(500);
  if (!(await up())) throw new Error('server did not start');
  return proc;
}

async function startChrome(profileDir) {
  const proc = spawn(CHROME, ['--headless=new', `--remote-debugging-port=${DEBUG_PORT}`,
    `--user-data-dir=${profileDir}`, '--no-first-run', '--hide-scrollbars', 'about:blank'], { stdio: 'ignore' });
  let targets;
  for (let i = 0; i < 60; i++) {
    try { targets = await (await fetch(`http://127.0.0.1:${DEBUG_PORT}/json`)).json(); if (targets.length) break; } catch { /* retry */ }
    await sleep(250);
  }
  const ws = new WebSocket(targets.find((t) => t.type === 'page').webSocketDebuggerUrl);
  await new Promise((r) => { ws.onopen = r; });
  let id = 0; const pending = {}; const consoleErrors = [];
  ws.onmessage = (m) => {
    const d = JSON.parse(m.data);
    if (d.id && pending[d.id]) { pending[d.id](d.result || d.error); delete pending[d.id]; return; }
    // collect everything a developer would see as red in the console
    if (d.method === 'Runtime.exceptionThrown') consoleErrors.push('exception: ' + (d.params.exceptionDetails.exception?.description || d.params.exceptionDetails.text));
    else if (d.method === 'Runtime.consoleAPICalled' && ['error', 'assert'].includes(d.params.type)) consoleErrors.push('console.' + d.params.type + ': ' + d.params.args.map((a) => a.value ?? a.description).join(' '));
    else if (d.method === 'Log.entryAdded' && d.params.entry.level === 'error') consoleErrors.push('log: ' + d.params.entry.text + ' ' + (d.params.entry.url || ''));
  };
  const send = (method, params = {}) => new Promise((r) => { pending[++id] = r; ws.send(JSON.stringify({ id, method, params })); });
  const evaluate = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error('page error: ' + JSON.stringify(r.exceptionDetails.exception?.description || r.exceptionDetails.text));
    return r.result?.value;
  };
  await send('Runtime.enable'); await send('Log.enable');
  return { proc, ws, send, evaluate, consoleErrors };
}

// ── in-page probes (stringified and evaluated in the dashboard) ────────────
const SNAPSHOT = `(async () => {
  const s = await fetch('/api/status').then(r => r.json());
  const strip = document.getElementById('attack-strip');
  const l1 = document.getElementById('status-line1').textContent;
  return { s: {
      stage: s.attack_stage, phase: s.phase, attack: s.attack_type, node: s.target_node,
      elapsed: s.attack_elapsed_s, metric: s.attack_headline_metric,
      events: s.target_activity.events.length, timeline: s.attack_timeline,
      rendered: (typeof latestStatus !== 'undefined' && latestStatus) ? { stage: latestStatus.attack_stage, scenarioActive: !!(latestStatus.scenario && latestStatus.scenario.active) } : null,
      scenario: s.scenario ? { active: s.scenario.active, idx: s.scenario.stage_idx, waiting: s.scenario.waiting,
                               target: s.scenario.target_node, n: s.scenario.stages.length, name: s.scenario.name } : null },
    ui: { atkDisabled: [...document.querySelectorAll('.atk-btn')].every(b => b.disabled),
          scnDisabled: [...document.querySelectorAll('.scenario-btn')].every(b => b.disabled),
          atkEnabled: [...document.querySelectorAll('.atk-btn')].every(b => !b.disabled),
          hintVisible: !document.getElementById('controls-lock-hint').hidden },
    dom: { stripHidden: strip.hidden, stripClass: strip.className, stripText: document.getElementById('strip-text').textContent,
           banner: l1 } };
})()`;

const PROBE = `((targetId, scenarioTarget) => {
  const rect = (el) => { const r = el.getBoundingClientRect(); return { x: r.left, y: r.top, w: r.width, h: r.height, r: r.right, b: r.bottom }; };
  const hit = (a, b) => a.x < b.r - 0.5 && b.x < a.r - 0.5 && a.y < b.b - 0.5 && b.y < a.b - 0.5;
  const out = { problems: [], warnings: [] };
  const svg = document.getElementById('topology-svg');
  const m = svg.getScreenCTM();
  const vb = { x: m.e, y: m.f, r: m.e + 180 * m.a, b: m.f + 100 * m.d };
  const inside = (r) => r.x >= vb.x - 0.5 && r.y >= vb.y - 0.5 && r.r <= vb.r + 0.5 && r.b <= vb.b + 0.5;

  const target = targetId ? nodeEls[targetId] : null;
  out.nodeClass = target ? target.group.getAttribute('class') : null;
  out.allNormal = Object.values(nodeEls).every(n => n.group.classList.contains('topo-status-normal'));
  out.scenarioNodeMarked = scenarioTarget ? nodeEls[scenarioTarget].group.classList.contains('topo-status-scenario') : null;
  const arrow = document.getElementById('topo-attack-arrow');
  out.arrowOn = arrow.classList.contains('on'); out.arrowFading = arrow.classList.contains('fading');
  out.attackerOn = document.getElementById('topo-attacker').classList.contains('on');
  const callout = document.getElementById('topo-callout');
  out.calloutOn = callout.classList.contains('on');
  out.calloutText = out.calloutOn ? callout.textContent : '';
  out.placement = overlay.placement || null;
  const tag = document.querySelector('.topo-tag');
  out.tagOn = tag.classList.contains('on'); out.tagText = out.tagOn ? tag.textContent : '';
  out.feedLines = document.querySelectorAll('#la-feed .la-feed-line').length;
  out.feedFirst = (document.querySelector('#la-feed .la-feed-line') || {}).textContent || '';
  out.feedHeight = rect(document.getElementById('la-feed')).h;
  out.panelVisible = document.getElementById('live-attack-panel').style.display !== 'none';
  out.timeline = document.getElementById('la-timeline').textContent.replace(/\\s+/g, ' ').trim();
  out.evidence = document.getElementById('real-evidence-content').textContent.replace(/\\s+/g, ' ').trim().slice(0, 700);
  out.fixText = document.getElementById('la-fix').style.display !== 'none' ? document.getElementById('la-fix-text').textContent : '';
  out.lastPanelVisible = document.getElementById('last-attack-panel').style.display !== 'none';
  out.lastTimeline = document.getElementById('last-timeline').textContent.replace(/\\s+/g, ' ').trim();
  out.stripH = rect(document.getElementById('attack-strip')).h;
  out.bannerLine1 = document.getElementById('status-line1').textContent;

  // layout: overlay boxes must stay in the viewBox and clear every other node, circle and label
  const boxes = [];
  if (out.calloutOn) boxes.push(['callout', rect(callout.querySelector('.topo-callout-bg'))]);
  if (out.tagOn) boxes.push(['tag', rect(tag.querySelector('.topo-tag-bg'))]);
  if (out.attackerOn || out.arrowOn) boxes.push(['attacker', rect(document.getElementById('topo-attacker'))]);
  const cb = boxes.find((b) => b[0] === 'callout'), tb = boxes.find((b) => b[0] === 'tag');
  if (cb && tb && hit(cb[1], tb[1])) out.problems.push('callout overlaps the node tag');
  for (const [name, r] of boxes) {
    if (!inside(r)) out.problems.push(name + ' clipped by the viewBox');
    for (const [id, n] of Object.entries(nodeEls)) {
      const own = id === targetId || id === scenarioTarget;
      const shape = rect(n.group.querySelector('.topo-node-shape'));
      const label = rect(n.label);
      if (!own && hit(r, shape)) out.problems.push(name + ' overlaps node ' + id);
      if (hit(r, label)) out.problems.push(name + ' overlaps label of ' + id);
      if (name === 'attacker' && !own && hit(r, shape)) out.problems.push('attacker overlaps node ' + id);
    }
    document.querySelectorAll('.topo-voltage-label').forEach(v => { if (hit(r, rect(v))) out.warnings.push(name + ' covers a voltage label'); });
    if (name !== 'attacker') {
      const stageLabel = document.getElementById('stage-label');
      if (getComputedStyle(stageLabel).visibility !== 'hidden' && hit(r, rect(stageLabel))) out.problems.push(name + ' overlaps the stage label');
      const legend = document.getElementById('topo-legend');
      if (legend && hit(r, rect(legend))) out.problems.push(name + ' overlaps the legend');
    }
  }
  // per-attack effect layer (topology_effects.js): state, element cap, and keep-clear checks against callout / legend / viewBox
  const fxLayer = document.getElementById('topo-fx');
  out.fxActive = fxState.active ? fxState.active.ctx.id : null;
  out.fxCount = fxLayer ? fxLayer.querySelectorAll('*').length : -1;
  out.fxSerial = fxState.active ? fxState.active.serial : 0;
  out.fxText = fxLayer ? [...fxLayer.querySelectorAll('text')].filter((t) => t.style.display !== 'none' && t.parentNode.style.display !== 'none').map((t) => t.textContent).join('|') : '';
  const drawn = (e) => { const cs = getComputedStyle(e); const r = rect(e); return cs.display !== 'none' && +cs.opacity > 0.05 && r.w > 0 && r.h > 0; };
  const keep = fxLayer ? [...fxLayer.querySelectorAll('.fx-keepclear')].filter(drawn) : [];
  const calloutBg = out.calloutOn ? rect(callout.querySelector('.topo-callout-bg')) : null;
  const legendEl = document.getElementById('topo-legend');
  keep.forEach((k) => {
    const kr = rect(k);
    if (calloutBg && hit(kr, calloutBg)) out.problems.push('callout overlaps effect element ' + (k.getAttribute('class') || k.tagName));
    if (!inside(kr)) out.problems.push('effect element clipped by the viewBox: ' + (k.getAttribute('class') || k.tagName));
  });
  if (fxLayer && legendEl) {
    const lr = rect(legendEl);
    [...fxLayer.querySelectorAll('*')].filter(drawn).forEach((e) => { if (hit(rect(e), lr)) out.problems.push('legend overlaps effect element ' + (e.getAttribute('class') || e.tagName)); });
  }
  const legendBox = document.getElementById('topo-legend');
  if (legendBox) {
    const lr = rect(legendBox);
    for (const [id, n] of Object.entries(nodeEls)) {
      if (hit(lr, rect(n.label)) || hit(lr, rect(n.group.querySelector('.topo-node-shape')))) out.problems.push('legend overlaps ' + id);
    }
    if (hit(lr, rect(svg)) && lr.y < vb.b) out.problems.push('legend overlaps the map area (legend ' + JSON.stringify([lr.x, lr.y, lr.r, lr.b].map(Math.round)) + ', svg ' + JSON.stringify(Object.values(rect(svg)).map(Math.round)) + ', viewBox bottom ' + Math.round(vb.b) + ')');
  }
  const legend = document.getElementById('topo-legend');
  if (legend && target && hit(rect(target.group.querySelector('.topo-node-shape')), rect(legend))) out.problems.push('target node hidden under the legend');
  if (document.documentElement.scrollWidth > window.innerWidth + 1) out.problems.push('horizontal page overflow');
  const st = document.getElementById('strip-text');
  if (!document.getElementById('attack-strip').hidden && st.scrollWidth > st.clientWidth + 1) out.problems.push('strip text clipped');
  const cl = document.getElementById('la-feed');
  if (cl.scrollHeight > cl.clientHeight + 2 && out.feedLines <= 12) out.warnings.push('feed taller than its box');
  return out;
})`;

// ── driver ──────────────────────────────────────────────────────────────────
class Run {
  constructor(chrome, width, outDir) { this.c = chrome; this.width = width; this.dir = outDir; this.failures = []; this.shots = []; }

  fail(label, msg) { this.failures.push(`${label}: ${msg}`); log(`   FAIL  ${label}: ${msg}`); }
  check(label, cond, msg) { if (!cond) this.fail(label, msg); return cond; }

  async resize(h) {
    await this.c.send('Emulation.setDeviceMetricsOverride', { width: this.width, height: h, deviceScaleFactor: 1, mobile: false });
  }

  async shot(name) {
    const h = await this.c.evaluate('document.documentElement.scrollHeight');
    await this.resize(Math.max(1000, Math.min(h, 2600)));
    await sleep(150);
    const r = await this.c.send('Page.captureScreenshot', { format: 'png' });
    const file = path.join(this.dir, name + '.png');
    fs.writeFileSync(file, Buffer.from(r.data, 'base64'));
    this.shots.push(path.relative(ROOT, file));
  }

  async snap() { return this.c.evaluate(SNAPSHOT); }

  /** Switch to the Attack detail tab mid-attack and back: no console errors, callout and tag present again. */
  async tabSwitchTest(label, node, expectTag) {
    const before = this.c.consoleErrors.length;
    await this.c.evaluate(`document.querySelector('.stage-tab-btn[data-tab="detail"]').click()`);
    await sleep(900);                                   // several polls arrive while the map is hidden
    const detailShown = await this.c.evaluate(`getComputedStyle(document.getElementById('stage-canvas')).display !== 'none'`);
    await this.c.evaluate(`document.querySelector('.stage-tab-btn[data-tab="topology"]').click()`);
    await sleep(1100);
    const p = await this.probe(node);
    const errs = this.c.consoleErrors.slice(before);
    this.check(label, detailShown, 'Attack detail tab did not show the canvas');
    this.check(label, errs.length === 0, `console errors during the tab switch: ${JSON.stringify(errs)}`);
    this.check(label, p.calloutOn && p.tagOn && p.tagText === expectTag, `after switching back: callout=${p.calloutOn} tag="${p.tagText}" (expected "${expectTag}")`);
    p.problems.forEach((x) => this.fail(label, `[after tab switch] layout: ${x}`));
    return { detailShown, errors: errs.length, calloutBack: p.calloutOn, tagBack: p.tagOn };
  }
  async probe(target, scenarioTarget) { return this.c.evaluate(`${PROBE}(${JSON.stringify(target || null)}, ${JSON.stringify(scenarioTarget || null)})`); }

  async login() {
    await this.resize(1000);
    await this.c.send('Page.navigate', { url: BASE + '/login.html' });
    await sleep(1500);
    await this.c.evaluate(`(() => {
      document.getElementById('username').value = 'verifier';
      document.querySelector('.role-btn[data-role="admin"]').click();
      document.getElementById('login-btn').click(); })()`);
    for (let i = 0; i < 40; i++) {
      await sleep(400);
      const ok = await this.c.evaluate(`location.pathname !== '/login.html' && typeof latestStatus !== 'undefined' && !!latestStatus && !!document.querySelector('.atk-btn')`).catch(() => false);
      if (ok) return;
    }
    throw new Error('login through the UI failed');
  }

  async waitIdle() {
    for (let i = 0; i < 200; i++) {
      const { s } = await this.snap();
      const disabled = await this.c.evaluate(`document.querySelector('.atk-btn').disabled`);
      if (s.stage === 'NONE' && !(s.scenario && s.scenario.active) && !disabled) { await sleep(1200); return; }
      await sleep(500);
    }
    throw new Error('system never became idle');
  }

  async runAttack(attack, node) {
    const label = `${attack}@${node}@${this.width}`;
    log(`\n== ${label}`);
    await this.waitIdle();
    await this.c.evaluate(`(() => { document.getElementById('node-select').value = '${node}';
      document.querySelector('.atk-btn[data-attack="${attack}"]').click(); })()`);

    const seq = []; const firstSeen = {}; const probes = {};
    let maxEventsExecuting = 0; let metricAtDetected; let eventsAtDetected = 0;
    const pendingShots = {};
    const t0 = Date.now();
    let leftNoneAt = null; let tabTest = null; const lockSeen = {}; let metricAtResolved; const errorsBefore = this.c.consoleErrors.length;
    for (;;) {
      const { s, dom, ui } = await this.snap();
      const now = Date.now();
      if (s.stage !== 'NONE' && s.attack === attack && leftNoneAt === null) leftNoneAt = now;
      if (!seq.length || seq[seq.length - 1] !== s.stage) {
        if (seq.length || s.stage !== 'NONE') {
          seq.push(s.stage);
          firstSeen[s.stage] = now;
          if (STAGE_SHOT_DELAY[s.stage]) pendingShots[s.stage] = now + STAGE_SHOT_DELAY[s.stage];
        }
      }
      if (s.rendered && s.rendered.stage && s.rendered.stage !== 'NONE') { (lockSeen[s.rendered.stage] ??= []).push(ui.atkDisabled && ui.scnDisabled && ui.hintVisible); }
      if (s.stage === 'RESOLVED' && metricAtResolved === undefined) metricAtResolved = s.metric;
      if (s.stage === 'EXECUTING') maxEventsExecuting = Math.max(maxEventsExecuting, s.events);
      if (s.stage === 'DETECTED' && metricAtDetected === undefined) { metricAtDetected = s.metric; eventsAtDetected = s.events; }

      for (const [stage, due] of Object.entries(pendingShots)) {
        if (now >= due && s.stage === stage) {
          delete pendingShots[stage];
          probes[stage] = Object.assign(await this.probe(node), { dom });
          await this.shot(`${attack}_${node}_${stage}`);
          if (stage === 'DETECTED') tabTest = await this.tabSwitchTest(label, node, 'UNDER ATTACK');
        }
      }
      if (seq.includes('RESOLVED') && s.stage === 'NONE') break;
      if (now - t0 > 90000) { this.fail(label, 'timed out waiting for the attack to finish'); break; }
      await sleep(200);
    }
    await sleep(1200);
    const after = await this.probe(node);
    const afterDom = (await this.snap()).dom;

    // ── assertions ──
    const expectedSeq = ['EXECUTING', 'DETECTED', 'MITIGATING', 'RESOLVED', 'NONE'];
    this.check(label, JSON.stringify(seq) === JSON.stringify(expectedSeq), `stage sequence ${JSON.stringify(seq)}`);
    const dur = {
      EXECUTING: (firstSeen.DETECTED - firstSeen.EXECUTING) / 1000,
      DETECTED: (firstSeen.MITIGATING - firstSeen.DETECTED) / 1000,
      MITIGATING: (firstSeen.RESOLVED - firstSeen.MITIGATING) / 1000,
      RESOLVED: (firstSeen.NONE - firstSeen.RESOLVED) / 1000,
    };
    this.check(label, dur.EXECUTING >= 2.6, `EXECUTING lasted only ${dur.EXECUTING.toFixed(1)}s`);
    const ex = probes.EXECUTING, de = probes.DETECTED, mi = probes.MITIGATING, re = probes.RESOLVED;
    if (this.check(label, ex && de && mi && re, 'missing a stage probe')) {
      const stripOk = (p, cls, re) => !p.dom.stripHidden && p.dom.stripClass === cls && re.test(p.dom.stripText);
      this.check(label, stripOk(ex, 'stage-EXECUTING', /^LIVE ATTACK IN PROGRESS/), `EXECUTING strip: ${ex.dom.stripClass} "${ex.dom.stripText}"`);
      this.check(label, stripOk(de, 'stage-DETECTED', /^ATTACK DETECTED/), `DETECTED strip: ${de.dom.stripClass} "${de.dom.stripText}"`);
      this.check(label, stripOk(mi, 'stage-MITIGATING', /^MITIGATING/), `MITIGATING strip: ${mi.dom.stripClass} "${mi.dom.stripText}"`);
      this.check(label, stripOk(re, 'stage-RESOLVED', /^ATTACK NEUTRALISED/), `RESOLVED strip: ${re.dom.stripClass} "${re.dom.stripText}"`);
      this.check(label, /Detected\+\d/.test(mi.timeline) && /Mitigation\+\d/.test(re.timeline) && /Resolved\+\d/.test(re.timeline), `timeline not filled in: MIT "${mi.timeline}" RES "${re.timeline}"`);
      this.check(label, /topo-status-attacking/.test(ex.nodeClass), `EXECUTING node class: ${ex.nodeClass}`);
      this.check(label, ex.arrowOn && !ex.arrowFading, 'attacker arrow not shown during EXECUTING');
      this.check(label, ex.attackerOn, 'ATTACKER marker not shown during EXECUTING');
      for (const [st, p] of [['EXECUTING', ex], ['DETECTED', de], ['MITIGATING', mi]]) {
        this.check(label, p.fxActive === attack && p.fxCount > 0 && p.fxCount <= 120, `${st}: per-attack effect state (active=${p.fxActive}, elements=${p.fxCount})`);
      }
      if (attack === 'FIRMWARE_TAMPER') {            // this effect stays through RESOLVED to show the hash-match check
        this.check(label, re.fxActive === attack && /HASH MATCH/.test(re.fxText) && !/MISMATCH/.test(re.fxText), `RESOLVED: expected the hash-match check on the map (active=${re.fxActive}, text="${re.fxText}")`);
        this.check(label, /ROLLING BACK/.test(mi.fxText), `MITIGATING: expected the rollback title (text="${mi.fxText}")`);
        this.check(label, /MISMATCH/.test(de.fxText), `DETECTED: expected the hash-mismatch badge (text="${de.fxText}")`);
      } else {
        this.check(label, re.fxActive === null && re.fxCount === 0, `RESOLVED: effect not torn down (active=${re.fxActive}, elements=${re.fxCount})`);
      }
      this.check(label, de.fxSerial === ex.fxSerial, 'effect was rebuilt between EXECUTING and DETECTED (should persist for the incident)');
      this.check(label, ex.calloutOn && ex.calloutText.length > 5, 'callout missing during EXECUTING');
      this.check(label, ex.tagText === 'UNDER ATTACK', `EXECUTING tag: "${ex.tagText}"`);
      this.check(label, ex.bannerLine1 === 'ATTACK IN PROGRESS', `EXECUTING banner: "${ex.bannerLine1}"`);
      this.check(label, ex.panelVisible, 'Live Attack panel hidden during EXECUTING');
      this.check(label, /topo-status-attacked/.test(de.nodeClass), `DETECTED node class: ${de.nodeClass}`);
      this.check(label, /topo-status-mitigating/.test(mi.nodeClass), `MITIGATING node not amber: ${mi.nodeClass}`);
      this.check(label, mi.arrowFading, 'arrow should fade while MITIGATING');
      this.check(label, mi.tagText === 'MITIGATING', `MITIGATING tag: "${mi.tagText}"`);
      this.check(label, /topo-status-resolved/.test(re.nodeClass), `RESOLVED node not green: ${re.nodeClass}`);
      this.check(label, !re.arrowOn && !re.attackerOn, 'arrow/attacker still visible at RESOLVED');
      this.check(label, re.tagText === 'RESTORED', `RESOLVED tag: "${re.tagText}"`);
      for (const [st, p] of Object.entries(probes)) {
        p.problems.forEach((x) => this.fail(label, `[${st}] layout: ${x}`));
      }
    }
    for (const st of ['EXECUTING', 'DETECTED', 'MITIGATING', 'RESOLVED']) {
      const seenLocks = lockSeen[st] || [];
      this.check(label, seenLocks.length > 0 && seenLocks.every(Boolean), `controls not locked during ${st} (${seenLocks.filter((x) => !x).length}/${seenLocks.length} samples unlocked)`);
    }
    this.check(label, metricAtResolved && metricAtResolved.value !== '--' && metricAtResolved.final === true, `headline at RESOLVED: ${JSON.stringify(metricAtResolved)}`);
    if (attack === 'FIRMWARE_TAMPER') {
      this.check(label, metricAtResolved && metricAtResolved.value === 'YES', `FIRMWARE_TAMPER headline at RESOLVED should read YES: ${JSON.stringify(metricAtResolved)}`);
      this.check(label, re && /YES/.test(re.evidence) && !/MISMATCH/.test(re.evidence), `evidence panel at RESOLVED should show matching hashes: "${re && re.evidence}"`);
    }
    if (re) this.check(label, /\(final\)/.test(re.calloutText), `callout at RESOLVED should show the final value: "${re.calloutText}"`);
    this.check(label, this.c.consoleErrors.length === errorsBefore, `console errors during this attack: ${JSON.stringify(this.c.consoleErrors.slice(errorsBefore))}`);
    this.check(label, tabTest !== null, 'tab-switch test did not run (DETECTED stage missed)');
    this.check(label, maxEventsExecuting >= 1, 'no device-side feed line before DETECTED');
    this.check(label, metricAtDetected && metricAtDetected.value !== '--', `headline metric still "--" at DETECTED (${JSON.stringify(metricAtDetected)})`);
    this.check(label, after.fxActive === null && after.fxCount === 0, `effect layer not empty after the attack (${after.fxCount})`);
    this.check(label, after.allNormal && !after.tagOn && !after.calloutOn && !after.arrowOn, `map not back to normal afterwards (${after.nodeClass})`);
    const afterUi = (await this.snap()).ui;
    this.check(label, afterUi.atkEnabled && !afterUi.hintVisible, `controls should be unlocked after the attack (enabled=${afterUi.atkEnabled}, hint=${afterUi.hintVisible})`);
    this.check(label, afterDom.stripHidden && afterDom.banner === 'SECURE', `strip/banner after attack: hidden=${afterDom.stripHidden}, banner=${afterDom.banner}`);
    this.check(label, after.lastPanelVisible && /Resolved\+\d/.test(after.lastTimeline), `last-attack timeline card missing after the attack (${after.lastTimeline})`);

    log(`   stages ${seq.join(' > ')}  exec ${dur.EXECUTING.toFixed(1)}s det ${dur.DETECTED.toFixed(1)}s mit ${dur.MITIGATING.toFixed(1)}s res ${dur.RESOLVED.toFixed(1)}s`);
    log(`   metric@detected ${metricAtDetected && metricAtDetected.label}: ${metricAtDetected && metricAtDetected.value} ${metricAtDetected && metricAtDetected.unit}; feed lines before detection ${maxEventsExecuting}`);
    if (ex) log(`   EXEC strip: ${ex.dom.stripText}`);
    return { attack, node, width: this.width, seq, durations: dur, metricAtDetected, metricAtResolved, eventsBeforeDetected: maxEventsExecuting,
             execProbe: ex && { tag: ex.tagText, callout: ex.calloutText, feedFirst: ex.feedFirst },
             tabSwitch: tabTest,
             warnings: Object.values(probes).flatMap((p) => p.warnings), timelineAfter: after.timeline };
  }

  async runScenario(id) {
    const label = `scenario:${id}@${this.width}`;
    log(`\n== ${label}`);
    await this.waitIdle();
    await this.c.evaluate(`document.querySelector('.scenario-btn[data-scenario-btn="${id}"]').click()`);
    const seen = new Set(); const targets = new Set(); const timeline = [];
    let secureFlash = 0; let unlockedSamples = 0; let started = false; const t0 = Date.now();
    let target = null; let n = 3; let waitingProbeOk = 0;
    const pendingShots = {};
    for (;;) {
      const { s, dom, ui } = await this.snap();
      const now = Date.now();
      if (s.scenario && s.scenario.active) {
        started = true; n = s.scenario.n; target = s.scenario.target;
        const key = `s${s.scenario.idx + 1}_${s.scenario.waiting ? 'WAIT' : s.stage}`;
        if (!seen.has(key)) { seen.add(key); timeline.push(key); pendingShots[key] = now + (s.scenario.waiting ? 700 : (STAGE_SHOT_DELAY[s.stage] || 1000)); }
        if (s.node) targets.add(s.node);
        if (s.rendered && s.rendered.scenarioActive && !(ui.atkDisabled && ui.scnDisabled && ui.hintVisible)) unlockedSamples++;
        // judge the DOM against the status the dashboard itself last rendered (it polls every 800 ms)
        if (s.rendered && s.rendered.scenarioActive && (dom.banner === 'SECURE' || dom.stripHidden)) secureFlash++;
        for (const [key2, due] of Object.entries(pendingShots)) {
          if (now >= due && key2 === `s${s.scenario.idx + 1}_${s.scenario.waiting ? 'WAIT' : s.stage}`) {
            delete pendingShots[key2];
            const p = await this.probe(s.scenario.waiting ? null : s.node, s.scenario.waiting ? target : null);
            p.problems.forEach((x) => this.fail(label, `[${key2}] layout: ${x}`));
            if (s.scenario.waiting) {
              if (this.check(label, /^SCENARIO/.test(dom.stripText) && !dom.stripHidden, `gap strip: "${dom.stripText}"`)) waitingProbeOk++;
              this.check(label, dom.banner === 'SCENARIO IN PROGRESS', `gap banner: "${dom.banner}"`);
              this.check(label, p.scenarioNodeMarked === true && p.tagOn, 'scenario target not marked on the map during the gap');
            }
            await this.shot(`${id}_${key2}`);
          }
        }
      } else if (started) break;
      if (now - t0 > 240000) { this.fail(label, 'timed out'); break; }
      await sleep(200);
    }
    this.check(label, targets.size === 1, `target node changed across stages: ${[...targets].join(',')}`);
    this.check(label, unlockedSamples === 0, `controls were unlocked in ${unlockedSamples} samples while the scenario ran (incl. gaps)`);
    this.check(label, secureFlash === 0, `strip hidden / banner "SECURE" for ${secureFlash} samples while the scenario ran`);
    // a visible 'next stage starting' state before every stage after the first (the wait before stage 1 may or may not be caught)
    for (let i = 2; i <= n; i++) this.check(label, seen.has(`s${i}_WAIT`), `no gap state shown before stage ${i}`);
    for (let i = 1; i <= n; i++) {
      for (const st of ['EXECUTING', 'DETECTED', 'MITIGATING', 'RESOLVED']) this.check(label, seen.has(`s${i}_${st}`), `stage ${i} never showed ${st}`);
    }
    const chips = await this.c.evaluate(`[...document.querySelectorAll('.scenario-card[data-scenario="${id}"] .scenario-stage-chip')].map(c => c.className)`);
    log(`   transitions: ${timeline.join(' > ')}; target ${[...targets].join(',')}`);
    return { scenario: id, width: this.width, transitions: timeline, targets: [...targets], secureFlash, chipClasses: chips };
  }
}

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sgids-verify-'));
  const eventLog = path.join(tmp, 'event_log.jsonl');
  const realLog = path.join(ROOT, 'backend', 'event_log.jsonl');
  const before = sha(realLog);
  log(`temp incident log: ${eventLog}\nreal incident log checksum before: ${before}`);

  const server = await startServer(eventLog);
  const chrome = await startChrome(path.join(tmp, 'chrome-profile'));
  const report = { widths: {}, startedAt: new Date().toISOString() };
  let failed = 0;
  try {
    for (const [wi, width] of WIDTHS.entries()) {
      const dir = path.join(OUT, String(width));
      fs.mkdirSync(dir, { recursive: true });
      const run = new Run(chrome, width, dir);
      await run.login();
      const results = []; const scenarios = [];
      if (!flag('no-attacks')) {
        for (const [i, attack] of ATTACKS.entries()) {
          if (ONLY && !ONLY.includes(attack)) continue;
          results.push(await run.runAttack(attack, legalNode(attack, i, wi)));   // legal targets only; a different node per width
        }
      }
      if (!flag('no-scenarios') && (!ONLY || opt('scenarios', ''))) for (const id of SCENARIOS) scenarios.push(await run.runScenario(id));
      report.widths[width] = { attacks: results, scenarios, failures: run.failures, screenshots: run.shots };
      fs.writeFileSync(path.join(dir, 'report.json'), JSON.stringify(report.widths[width], null, 2));
      failed += run.failures.length;
    }
  } finally {
    chrome.ws.close(); chrome.proc.kill(); server.kill();
  }
  const after = sha(realLog);
  log(`\nreal incident log checksum after:  ${after}  ->  ${after === before ? 'UNCHANGED' : 'CHANGED (!)'}`);
  if (after !== before) failed++;
  const incidents = fs.existsSync(eventLog) ? fs.readFileSync(eventLog, 'utf8').trim().split('\n').length : 0;
  log(`incidents written to the temp log: ${incidents}`);
  log(failed ? `\nFAILED: ${failed} problem(s)` : '\nALL CHECKS PASSED');
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });
