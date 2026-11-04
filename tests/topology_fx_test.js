'use strict';
// Runs frontend/topology_effects.js against a tiny DOM stub (no browser). Usage: node topology_fx_test.js <layout.json>
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert');

const layout = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const CATEGORY = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));   // {attack: [target node ids]}

class El {
  constructor(tag) { this.tag = tag; this.attrs = {}; this.children = []; this.style = {}; this.parent = null; this.textContent = '';
    const set = new Set(); this.classList = { add: (c) => set.add(c), remove: (c) => set.delete(c), contains: (c) => set.has(c), toggle: (c, f) => (f ? set.add(c) : set.delete(c)) }; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return this.attrs[k]; }
  appendChild(c) { c.parent = this; this.children.push(c); return c; }
  removeChild(c) { this.children = this.children.filter((x) => x !== c); return c; }
  get firstChild() { return this.children[0] || null; }
  querySelector(sel) { const cls = sel.replace('.', ''); const f = (e) => { for (const c of e.children) { if ((c.attrs.class || '').split(' ').includes(cls)) return c; const r = f(c); if (r) return r; } return null; }; return f(this); }
  all() { return this.children.flatMap((c) => [c, ...c.all()]); }
}
const svgRoot = new El('svg'); svgRoot.id = 'topology-svg';
const sandbox = {
  console, Math, Number, Object, Array, Set, Error, Boolean, String, JSON, Infinity,
  document: { createElementNS: (_, t) => new El(t), getElementById: (id) => (id === 'topology-svg' ? svgRoot : null) },
  module: { exports: {} },
  matchMedia: () => sandbox.__mq,
  __mq: { matches: false },
};
vm.createContext(sandbox);
const src = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'topology_effects.js'), 'utf8');
vm.runInContext(`
const VIEWBOX_W = 180, VIEWBOX_H = 100;
const NODE_RADIUS = { plant: 4.6, control: 3.0, substation: 3.8, feeder: 2.3, meters: 1.7 };
const ATTACKER_POS = { x: 8, y: 14 }, ATTACKER_R = 2.4;
function svgEl(tag, attrs, parent) { const el = document.createElementNS('', tag); Object.entries(attrs || {}).forEach(([k, v]) => el.setAttribute(k, v)); if (parent) parent.appendChild(el); return el; }
`, sandbox);
vm.runInContext(src.replace(/^if \(typeof module[\s\S]*$/m, ''), sandbox);
vm.runInContext(`globalThis.__api = { ATTACK_EFFECTS, fxState, fxEffectFor, fxFeedLink, topoFxSync, topoFxFrame, topoFxObstacles, fxTeardown, fxInit, FX_MAX_ELEMENTS };`, sandbox);
const api = sandbox.__api;

// topology.js globals the effects read
const mkEl = (t) => new El(t);
function resetMap() {
  vm.runInContext('topoData = null', sandbox);
}
vm.runInContext(`
var topoData = ${JSON.stringify(layout)};
var nodeEls = {}; var edgeEls = []; var overlay = null;
topoData.nodes.forEach(n => { nodeEls[n.id] = { type: n.type, x: n.x, y: n.y }; });
topoData.edges.forEach(e => { const a = topoData.nodes.find(n => n.id === e.from), b = topoData.nodes.find(n => n.id === e.to);
  edgeEls.push({ from: e.from, to: e.to, ax: a.x, ay: a.y, bx: b.x, by: b.y, breaker: { style: {} }, vLabel: { style: {} } }); });
`, sandbox);
const attacker = new El('g'); attacker.appendChild(Object.assign(new El('text'), { attrs: { class: 'topo-attacker-label' }, textContent: 'ATTACKER' }));
sandbox.overlay = attacker && { attacker };
api.fxInit(svgRoot);
const layer = api.fxState.layer;

let n = 0;
const ok = (cond, msg) => { n++; assert.ok(cond, msg); };
const status = (attack, node, stage, extra) => Object.assign({ attack_type: attack, target_node: node, attack_stage: stage, attack_elapsed_s: 1, mitigation_progress: 40 }, extra || {});
const nodeObj = (id) => sandbox.nodeEls[id];
const frames = (k, t0 = 1000) => { for (let i = 0; i < k; i++) api.topoFxFrame(t0 + i * 16, 0.016); return t0 + k * 16; };
const noNaN = () => layer.all().forEach((e) => Object.entries(e.attrs).forEach(([k, v]) => ok(!/NaN|undefined|Infinity/.test(v), `${e.tag}.${k}=${v}`)));
const BATCH = (process.argv[4] || 'DDOS,MITM,REPLAY,PORT_SCAN,FDI,LOAD_ALTER,GPS_SPOOF,JAMMING,CMD_INJECT,MALWARE,FIRMWARE_TAMPER,PRIV_ESC').split(',');

// 1. effect selection per attack id
BATCH.forEach((id) => {
  const fx = api.fxEffectFor(id);
  ok(fx && ['setup', 'update'].every((m) => typeof fx[m] === 'function'), `effect for ${id}`);
});
ok(api.fxEffectFor('NOPE') === null && api.fxEffectFor('toString') === null && api.fxEffectFor('NONE') === null, 'unknown ids have no effect');

// 2. every effect x every node its category can hit x every stage: builds, animates, stays under the cap, tears down clean
BATCH.forEach((id) => {
  CATEGORY[id].forEach((node) => {
    ['EXECUTING', 'DETECTED', 'MITIGATING'].forEach((stage, si) => {
      api.topoFxSync(status(id, node, stage, { attack_elapsed_s: si }), nodeObj(node), stage, stage === 'MITIGATING' ? 0.5 : 1);
      ok(api.fxState.active && api.fxState.active.ctx.id === id, `${id}@${node} active`);
      frames(8);
      ok(layer.all().length <= api.FX_MAX_ELEMENTS, `${id} element cap (${layer.all().length})`);
      const before = layer.all().length; frames(30, 5000); ok(layer.all().length === before, `${id} grows DOM while running`);
      noNaN();
      // panels the effect placed (gauge, waveform, satellite, clock) stay inside the map
      api.fxState.active.ctx.placed.forEach((b) => ok(b.x >= 1 && b.y >= 1 && b.x + b.w <= 179 && b.y + b.h <= 99, `${id}@${node} panel inside the map ${JSON.stringify(b)}`));
      const ob = api.topoFxObstacles(); ok(ob && Array.isArray(ob.rects), 'obstacles');
      ob.rects.forEach((r) => [r.x, r.y, r.w, r.h].forEach((v) => ok(Number.isFinite(v), `${id} obstacle ${JSON.stringify(r)}`)));
    });
    api.topoFxSync(status(id, node, 'RESOLVED'), nodeObj(node), 'RESOLVED', 0);
    if (api.fxEffectFor(id).keepOnResolved) { ok(api.fxState.active !== null, `${id} stays through RESOLVED`); frames(5); noNaN(); api.topoFxSync({ attack_type: 'NONE' }, null, 'NONE', 0); }
    ok(api.fxState.active === null && layer.children.length === 0, `${id}@${node} teardown leaves layer empty`);
    ok(!attacker.classList.contains('fx-grey') && attacker.style.opacity === '' && attacker.attrs.transform === 'translate(8,14)', 'attacker restored');
    ok(attacker.children[0].textContent === 'ATTACKER', 'attacker label restored');
    ok(svgRoot.classList.contains('fx-on') === false, 'fx-on removed');
  });
});

// 2b. GPS satellite: top band, clear of every node disc / label (CTRL, FEEDER1 ...) and of the tag
CATEGORY.GPS_SPOOF.forEach((node) => {
  api.topoFxSync(status('GPS_SPOOF', node, 'EXECUTING'), nodeObj(node), 'EXECUTING', 1);
  const sat = api.fxState.active.ctx.sat;
  ok(sat.cy <= 12.5, `satellite in the top band for ${node} (cy=${sat.cy})`);
  layout.nodes.forEach((n) => {
    const r = { PLANT: 4.6, CTRL: 3.0, SUB1: 3.8 }[n.id] || { plant: 4.6, control: 3.0, substation: 3.8, feeder: 2.3, meters: 1.7 }[n.type];
    ok(!(sat.x < n.x + r && n.x - r < sat.x + sat.w && sat.y < n.y + r && n.y - r < sat.y + sat.h), `satellite overlaps node ${n.id} (target ${node})`);
  });
  api.fxTeardown();
});

// 2c. JAMMING backup channel follows the real feed link: parallel to it, never further than ~2.6 units away
CATEGORY.JAMMING.forEach((node) => {
  api.topoFxSync(status('JAMMING', node, 'MITIGATING'), nodeObj(node), 'MITIGATING', 0.5);
  const c = api.fxState.active.ctx, L = c.link;
  const cross = (b0, b1) => ((b1.x - b0.x) * (L.b.y - L.a.y) - (b1.y - b0.y) * (L.b.x - L.a.x));
  ok(Math.abs(cross(c.b0, c.b1)) < 1e-6, `backup of ${node} is parallel to the feed link`);
  const d = (p) => Math.abs((L.b.x - L.a.x) * (L.a.y - p.y) - (L.a.x - p.x) * (L.b.y - L.a.y)) / Math.hypot(L.b.x - L.a.x, L.b.y - L.a.y);
  ok(d(c.b0) > 1.5 && d(c.b0) < 3 && d(c.b1) > 1.5 && d(c.b1) < 3, `backup offset from the feed link for ${node}`);
  api.fxTeardown();
});

// 3. feed link edge cases: node with no upstream neighbour, control-only node, meter cluster
const L = (id) => api.fxFeedLink(id);
ok(L('METERS_A').upstream && L('METERS_A').neighbour === 'FEEDER1', 'meters fed by feeder');
ok(L('SUB1').upstream && L('SUB1').neighbour === 'PLANT', 'substation prefers the power edge over the SCADA edge');
ok(!L('PLANT').upstream && L('PLANT').neighbour !== null, 'PLANT has no upstream: falls back to an outgoing link');
ok(!L('CTRL').upstream && L('CTRL').neighbour !== null, 'CTRL has no upstream: falls back to an outgoing link');

// 4. back-to-back / same attack twice / scenario switch: clean teardown + setup
const s1 = status('DDOS', 'SUB1', 'EXECUTING', { attack_elapsed_s: 5 });
api.topoFxSync(s1, nodeObj('SUB1'), 'EXECUTING', 1); const ser1 = api.fxState.active.serial;
api.topoFxSync(status('DDOS', 'SUB1', 'DETECTED', { attack_elapsed_s: 6 }), nodeObj('SUB1'), 'DETECTED', 1);
ok(api.fxState.active.serial === ser1, 'same incident keeps its effect across polls');
api.topoFxSync(status('DDOS', 'SUB1', 'EXECUTING', { attack_elapsed_s: 0.2 }), nodeObj('SUB1'), 'EXECUTING', 0.4);   // same attack+node, elapsed reset
ok(api.fxState.active.serial === ser1 + 1, 'elapsed going backwards starts a fresh effect');
api.topoFxSync(status('DDOS', 'SUB1', 'MITIGATING', { attack_elapsed_s: 9 }), nodeObj('SUB1'), 'MITIGATING', 0.5);
api.topoFxSync(status('DDOS', 'SUB1', 'EXECUTING', { attack_elapsed_s: 10 }), nodeObj('SUB1'), 'EXECUTING', 0.4);       // stage regressed
ok(api.fxState.active.serial === ser1 + 2, 'stage regression starts a fresh effect');
api.topoFxSync(status('MITM', 'SUB2', 'EXECUTING'), nodeObj('SUB2'), 'EXECUTING', 0.5);
ok(api.fxState.active.ctx.id === 'MITM' && layer.all().every((e) => e.parent), 'attack change swaps the effect');
const mitmCount = layer.all().length;
api.topoFxSync({ attack_type: 'NONE' }, null, 'NONE', 0);
ok(api.fxState.active === null && layer.children.length === 0, 'NONE tears down');
api.topoFxSync(status('PORT_SCAN', 'FEEDER2', 'EXECUTING'), nodeObj('FEEDER2'), 'EXECUTING', 0.5);
api.topoFxSync(status('PORT_SCAN', 'FEEDER2', 'EXECUTING'), null, 'EXECUTING', 0.5);                                   // target vanished
ok(api.fxState.active === null && layer.children.length === 0, 'missing target tears down');
ok(mitmCount > 0, 'mitm built elements');

// 5. REPLAY phases are time-based: capture for the first 1.5 s only
api.topoFxSync(status('REPLAY', 'FEEDER1', 'EXECUTING', { attack_elapsed_s: 0 }), nodeObj('FEEDER1'), 'EXECUTING', 0.4);
const rctx = api.fxState.active.ctx;
const hero = layer.all().find((e) => /fx-pkt-hero/.test(e.attrs.class || ''));
api.topoFxFrame(1000, 0.016); api.topoFxFrame(1500, 0.016);                 // age ~0.5 s
ok(!hero.style.display, 'capture phase shows the captured packet');
api.topoFxFrame(2800, 0.016);                                               // age ~1.8 s > 1.5 s
ok(hero.style.display === 'none', 'replay phase hides the capture packet');
const ghostsShown = layer.all().filter((e) => /fx-ghost/.test(e.attrs.class || '') && e.style.display !== 'none').length;
ok(ghostsShown >= 2, `ghost duplicates fired during replay (${ghostsShown})`);
api.fxTeardown();
// late start (page loaded mid-attack, elapsed 8 s) goes straight to replay
api.topoFxSync(status('REPLAY', 'FEEDER1', 'DETECTED', { attack_elapsed_s: 8 }), nodeObj('FEEDER1'), 'DETECTED', 1);
const hero2 = layer.all().find((e) => /fx-pkt-hero/.test(e.attrs.class || ''));
api.topoFxFrame(100, 0.016);
ok(hero2.style.display === 'none', 'late start skips the capture phase');
api.fxTeardown();

// 6. prefers-reduced-motion: calmer (fewer / slower particles) but the same elements and labels
function runDDoS(calm) {
  sandbox.__mq.matches = calm;
  api.topoFxSync(status('DDOS', 'FEEDER3', 'DETECTED'), nodeObj('FEEDER3'), 'DETECTED', 1);
  api.fxState.active.ctx.intensity = 1;
  frames(20);
  const els = layer.all();
  const shown = els.filter((e) => /fx-pkt-bad/.test(e.attrs.class || '') && e.style.display !== 'none').length;
  const total = els.length; const m = api.fxState.active.ctx.m; api.fxTeardown();
  return { shown, total, m };
}
const full = runDDoS(false), calm = runDDoS(true);
ok(calm.total === full.total, 'same elements in calm mode');
ok(calm.shown < full.shown && calm.m < 0.5 && full.m === 1, `calm mode renders fewer particles and slower motion (${calm.shown} < ${full.shown})`);
sandbox.__mq.matches = false;

// 7. reduced motion: state transitions (shield, eject, flatten, backup, lock) still finish at normal speed
{
  sandbox.__mq.matches = true;
  const run = (id, node, field, secs) => {
    api.topoFxSync(status(id, node, 'MITIGATING'), nodeObj(node), 'MITIGATING', 0.5);
    const c = api.fxState.active.ctx;
    for (let i = 0; i < Math.round(secs / 0.016); i++) api.topoFxFrame(1000 + i * 16, 0.016);
    const v = c[field], m = c.m; api.fxTeardown(); return { v, m };
  };
  const eject = run('MITM', 'FEEDER1', 'eject', 1.3);
  ok(eject.m < 0.5 && eject.v >= 0.99, `MITM eject completes in calm mode within the mitigation window (eject=${eject.v}, m=${eject.m})`);
  ok(run('DDOS', 'SUB1', 'shield', 1.5).v > 0.95, 'DDOS shield completes in calm mode');
  ok(run('LOAD_ALTER', 'SUB1', 'flat', 2.5).v > 0.9, 'LOAD_ALTER flatten completes in calm mode');
  ok(run('JAMMING', 'FEEDER2', 'sw', 2.5).v > 0.9, 'JAMMING backup switch completes in calm mode');
  ok(run('GPS_SPOOF', 'SUB1', 'lock', 3.5).v > 0.9, 'GPS_SPOOF holdover lock completes in calm mode');
  ok(run('FDI', 'SUB1', 'snap', 2.5).v > 0.9, 'FDI snap-back completes in calm mode');
  sandbox.__mq.matches = false;
}

// 8. no invented numbers: effect text only carries digits that come from evidence
{
  const digits = (id, node, ev) => {
    api.topoFxSync(Object.assign(status(id, node, 'DETECTED'), ev ? { real_attack_evidence: ev } : {}), nodeObj(node), 'DETECTED', 1);
    frames(5);
    const txt = layer.all().filter((e) => e.tag === 'text').map((e) => e.textContent).join('|'); api.fxTeardown(); return txt;
  };
  Object.keys(api.ATTACK_EFFECTS).forEach((id) => ok(!/\d/.test(digits(id, CATEGORY[id][0], null)), `${id}: no digits on the map without evidence (${digits(id, CATEGORY[id][0], null)})`));
  ok(/241\.5/.test(digits('FDI', 'SUB1', { voltage: 241.5 })), 'FDI shows the evidence voltage');
  ok(/\+120 ms/.test(digits('GPS_SPOOF', 'SUB1', { time_offset_ms: 120.4 })), 'GPS_SPOOF shows the evidence offset');
}

// 9. PORT_SCAN open ticks come only from evidence
{
  const open = (ev) => { api.topoFxSync(Object.assign(status('PORT_SCAN', 'FEEDER1', 'DETECTED'), ev ? { real_attack_evidence: ev } : {}), nodeObj('FEEDER1'), 'DETECTED', 1);
    frames(5); const n = layer.all().filter((e) => /fx-port-open/.test(e.attrs.class || '')).length; api.fxTeardown(); return n; };
  ok(open(null) === 0 && open({ open_ports_found: [] }) === 0, 'no open ticks without evidence');
  ok(open({ open_ports_found: [5101, 5102, 5103] }) === 3, 'three real open ports light three ticks');
}

// 10. Batch C specifics
{
  // MALWARE: infection tint stays inside the map for every legal target; exfil obstacles cover the whole node -> attacker segment
  CATEGORY.MALWARE.forEach((node) => {
    api.topoFxSync(status('MALWARE', node, 'DETECTED', { attack_elapsed_s: 30 }), nodeObj(node), 'DETECTED', 1);
    const c = api.fxState.active.ctx; frames(3);
    ok(c.nbs.length >= 1, `MALWARE@${node} has neighbours to infect`);
    c.nbs.forEach((n) => ok(n.x - n.maxR >= -0.01 && n.x + n.maxR <= 180.01 && n.y - n.maxR >= -0.01 && n.y + n.maxR <= 100.01, `tint of ${node} neighbour stays inside the map`));
    c.nbs.forEach((n) => ok(n.maxR <= n.r + 4.3, `tint of ${node} neighbour stays a local halo`));
    const rects = api.topoFxObstacles().rects;
    for (let i = 0; i <= 10; i++) {
      const q = { x: c.exStart.x + (c.exEnd.x - c.exStart.x) * i / 10, y: c.exStart.y + (c.exEnd.y - c.exStart.y) * i / 10 };
      ok(rects.some((r) => q.x >= r.x && q.x <= r.x + r.w && q.y >= r.y && q.y <= r.y + r.h), `exfil stream point ${i} of ${node} is keep-clear`);
    }
    api.fxTeardown();
  });
  // CMD_INJECT uses the control link where the node has one
  api.topoFxSync(status('CMD_INJECT', 'SUB1', 'EXECUTING'), nodeObj('SUB1'), 'EXECUTING', 1);
  ok(api.fxState.active.ctx.cl.neighbour === 'CTRL', 'CMD_INJECT on SUB1 uses the CTRL control link');
  api.fxTeardown();
  api.topoFxSync(status('CMD_INJECT', 'FEEDER2', 'EXECUTING'), nodeObj('FEEDER2'), 'EXECUTING', 1);
  ok(api.fxState.active.ctx.cl.neighbour === 'SUB1', 'CMD_INJECT on a feeder falls back to its feed link');
  api.fxTeardown();
  // PRIV_ESC: the meter only exists when the evidence has a level; segments follow it
  const priv = (ev, stage) => { api.topoFxSync(Object.assign(status('PRIV_ESC', 'SUB1', stage || 'DETECTED', { attack_elapsed_s: 9 }), ev ? { real_attack_evidence: ev } : {}), nodeObj('SUB1'), stage || 'DETECTED', 1);
    const c = api.fxState.active.ctx; for (let i = 0; i < 200; i++) api.topoFxFrame(1000 + i * 16, 0.016);
    const r = { hidden: c.meter.style.display === 'none', on: c.segs.filter((x) => x.on).length, text: c.lvl.textContent, crack: c.crack }; api.fxTeardown(); return r; };
  const none = priv(null); ok(none.hidden && none.crack > 0.5, 'PRIV_ESC without a level: no meter, time-based lock cracking');
  const l3 = priv({ privilege_level: 3 }); ok(!l3.hidden && l3.on === 3 && l3.text === 'LEVEL 3', `meter follows the evidence level (${JSON.stringify(l3)})`);
  const rv = priv({ privilege_level: 5 }, 'MITIGATING'); ok(rv.on === 0 && /REVOKED/.test(rv.text), 'session revoked: meter drops');
  // FIRMWARE_TAMPER: hash-match claim only when the evidence supports it; rollback follows the real mitigation progress
  const fw = (stage, ev, prog) => { api.topoFxSync(Object.assign(status('FIRMWARE_TAMPER', 'SUB1', stage, { mitigation_progress: prog }), { real_attack_evidence: ev }), nodeObj('SUB1'), stage, 0);
    for (let i = 0; i < 200; i++) api.topoFxFrame(1000 + i * 16, 0.016); const c = api.fxState.active.ctx; const r = { title: c.title.textContent, roll: c.roll, dev: c.dLbl.textContent }; api.fxTeardown(); return r; };
  ok(fw('RESOLVED', { golden_sha256: 'abcdef123', device_sha256: 'abcdef123', tampered: false }, 100).title === 'HASH MATCH', 'matching hashes: HASH MATCH');
  ok(fw('RESOLVED', {}, 100).title === 'ROLLED BACK', 'no evidence: no hash-match claim');
  ok(fw('RESOLVED', { golden_sha256: 'abcdef123', device_sha256: '999999999' }, 100).title !== 'HASH MATCH', 'differing hashes: no match claim');
  const mid = fw('MITIGATING', { golden_sha256: 'abcdef123', device_sha256: '999999999' }, 50);
  ok(mid.title === 'ROLLING BACK' && Math.abs(mid.roll - 0.5) < 0.02 && mid.dev === 'D:999999', `rollback follows mitigation_progress (${JSON.stringify(mid)})`);
}

// 11. reduced motion for the Batch C transitions
{
  sandbox.__mq.matches = true;
  const run = (id, node, field, secs) => { api.topoFxSync(status(id, node, 'MITIGATING'), nodeObj(node), 'MITIGATING', 0.5);
    const c = api.fxState.active.ctx; for (let i = 0; i < Math.round(secs / 0.016); i++) api.topoFxFrame(1000 + i * 16, 0.016);
    const v = c[field]; api.fxTeardown(); return v; };
  ok(run('MALWARE', 'SUB1', 'retract', 6) > 0.95, 'MALWARE isolation completes in calm mode');
  ok(run('PRIV_ESC', 'SUB1', 'revoke', 3.5) > 0.95, 'PRIV_ESC revoke completes in calm mode');
  ok(run('CMD_INJECT', 'SUB1', 'gateAmt', 2.5) > 0.95, 'CMD_INJECT gate completes in calm mode');
  sandbox.__mq.matches = false;
}

console.log(`topology fx: ${n} assertions passed`);
