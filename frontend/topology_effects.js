/* ============================================================
   Smart Grid IDS - topology_effects.js
   Per-attack animations for the Grid Topology map. Loaded BEFORE
   topology.js; it only uses topology.js globals (topoData, nodeEls,
   edgeEls, overlay, NODE_RADIUS, ATTACKER_POS, ...) at call time.

   Each effect is  { setup(ctx), update(ctx), teardown(ctx)?, obstacles(ctx)? }
     setup    - build SVG elements ONCE into ctx.layer (via ctx.mk / ctx.parts)
     update   - per frame: only attribute writes on those elements (no DOM growth)
     teardown - optional extra cleanup; the manager always empties the layer,
                restores the attacker marker and removes the map-level classes.
     obstacles- extra keep-clear rects (viewBox units) for placeCallout.

   ctx fields an effect may read in update():
     stage ('EXECUTING'|'DETECTED'|'MITIGATING'), attacking (bool), mitigating (bool),
     intensity (0..1, smoothed), dt / clock (already scaled by the motion factor),
     age (real seconds since the incident began), calm (prefers-reduced-motion).

   Incident identity: /api/status exposes no incident id, so a new incident is
   detected by (attack_type, target_node) changing, OR attack_elapsed_s going
   backwards, OR the stage regressing; and the effect is always torn down whenever
   the stage is RESOLVED / NONE / has no target (see topoFxSync).
   ============================================================ */

const FX_MAX_ELEMENTS = 120;           // hard cap per effect (asserted by the tests / verify script)
const FX_CALM_MOTION = 0.12;           // motion factor under prefers-reduced-motion
const FX_REPLAY_CAPTURE_S = 1.5;       // REPLAY: length of the capture phase

const fxReducedMotionQuery = (typeof matchMedia === 'function') ? matchMedia('(prefers-reduced-motion: reduce)') : null;
const fxState = { active: null, key: null, lastElapsed: null, lastRank: 0, serial: 0, layer: null, status: null, stage: 'NONE' };

const fxClamp = (v, a, b) => Math.min(b, Math.max(a, v));
const fxLerp = (a, b, t) => a + (b - a) * t;
const fxSmooth = (t) => { t = fxClamp(t, 0, 1); return t * t * (3 - 2 * t); };
const fxStageRank = { EXECUTING: 1, DETECTED: 2, MITIGATING: 3 };

function fxInit(svg) {
  fxTeardown();
  fxState.layer = svgEl('g', { id: 'topo-fx', 'pointer-events': 'none' }, svg);
  return fxState.layer;
}

/** Link that feeds the target: incoming power edge, else any incoming edge, else any edge. Never null. */
function fxFeedLink(targetId) {
  const byId = (id) => topoData.nodes.find((n) => n.id === id);
  const isCtl = (e) => { const a = byId(e.from), b = byId(e.to); return a && b && (a.type === 'control' || b.type === 'control'); };
  const incoming = topoData.edges.filter((e) => e.to === targetId);
  const outgoing = topoData.edges.filter((e) => e.from === targetId);
  const pick = incoming.find((e) => !isCtl(e)) || incoming[0] || outgoing.find((e) => !isCtl(e)) || outgoing[0] || null;
  const t = byId(targetId);
  if (!pick) {                                   // isolated node: synthetic link from the attacker side
    return { a: { x: ATTACKER_POS.x + 12, y: ATTACKER_POS.y + 12 }, b: { x: t.x, y: t.y }, upstream: false, edge: null, neighbour: null };
  }
  const upstream = pick.to === targetId;
  const nb = byId(upstream ? pick.from : pick.to);
  const edge = edgeEls.find((e) => e.from === pick.from && e.to === pick.to) || null;
  return { a: { x: nb.x, y: nb.y }, b: { x: t.x, y: t.y }, upstream, edge, neighbour: nb.id };
}

/** Pick the candidate point that is inside the map and farthest from every node. */
function fxBestSpot(cands, margin) {
  let best = null;
  cands.forEach((c) => {
    if (c.x < margin || c.x > VIEWBOX_W - margin || c.y < margin || c.y > VIEWBOX_H - margin) return;
    const clear = Math.min(...topoData.nodes.map((n) => Math.hypot(n.x - c.x, n.y - c.y)));
    if (!best || clear > best.clear) best = { x: c.x, y: c.y, clear };
  });
  return best || { x: fxClamp(cands[0].x, margin, VIEWBOX_W - margin), y: fxClamp(cands[0].y, margin, VIEWBOX_H - margin), clear: 0 };
}

function fxMakeCtx(id, targetId, target, status) {
  const layer = fxState.layer;
  const tn = { id: targetId, x: target.x, y: target.y, type: target.type };
  const ctx = {
    id, layer, target: tn, R: NODE_RADIUS[target.type], link: fxFeedLink(targetId),
    stage: 'EXECUTING', attacking: true, mitigating: false, intensity: 0.35, targetIntensity: 0.35,
    resolved: false, dt: 0, rdt: 0, ts: 0, clock: 0, age: 0, age0: Number(status && status.attack_elapsed_s) || 0, t0: null, calm: false, m: 1,
    count: 0, placed: [], attackerMoved: false, touched: [], status: status || null,
    evidence() { return (ctx.status && ctx.status.real_attack_evidence) || {}; },
    mk(tag, attrs, parent) {
      if (ctx.count >= FX_MAX_ELEMENTS) throw new Error('topology effect element cap exceeded');
      ctx.count++;
      return svgEl(tag, attrs, parent || layer);
    },
    /** n reusable particles {el, prog, speed, k}; they are never re-created. */
    parts(n, tag, attrs) {
      const out = [];
      for (let i = 0; i < n; i++) out.push({ el: ctx.mk(tag, attrs), prog: i / n, speed: 0.8 + ((i * 37) % 11) / 20, k: i });
      return out;
    },
    pointToward(from, to, dist) {
      const d = Math.hypot(to.x - from.x, to.y - from.y) || 1;
      return { x: from.x + (to.x - from.x) / d * dist, y: from.y + (to.y - from.y) / d * dist };
    },
    lerpPt: (p, q, t) => ({ x: fxLerp(p.x, q.x, t), y: fxLerp(p.y, q.y, t) }),
    setAttackerLabel(text, below) {
      const l = overlay.attacker.querySelector('.topo-attacker-label');
      if (!l) return;
      l.textContent = text;
      if (below !== undefined) l.setAttribute('y', below ? ATTACKER_R + 3.9 : -ATTACKER_R - 1.2);
    },
    /** true when a label of the given size centred above `p` would hit another node's circle or label (so put it below). */
    labelWantsBelow(p, w) {
      const hits = (above) => {
        const y0 = above ? p.y - ATTACKER_R - 4.2 : p.y + ATTACKER_R + 1.4, box = { x: p.x - w / 2, y: y0, w, h: 3.2 };
        return topoData.nodes.filter((n) => {
          if (n.id === ctx.target.id) return false;
          const r = NODE_RADIUS[n.type] + 0.6;
          const lab = { x: n.x - 7.5, y: n.y + r, w: 15, h: 4.6 }, circ = { x: n.x - r, y: n.y - r, w: r * 2, h: r * 2 };
          return [lab, circ].some((b) => box.x < b.x + b.w && b.x < box.x + box.w && box.y < b.y + b.h && b.y < box.y + box.h);
        }).length;
      };
      return hits(true) > hits(false);
    },
    moveAttacker(p) { ctx.attackerMoved = true; overlay.attacker.setAttribute('transform', `translate(${p.x},${p.y})`); },
    attackerPos() { return ctx.attackerMoved ? ctx.curAttacker : ATTACKER_POS; },
    text(str, x, y, cls, parent) { const t = ctx.mk('text', { x, y, class: cls }, parent); t.textContent = str; return t; },
    freeBox(w, h, o) { const b = fxFreeBox(ctx, w, h, o || {}); ctx.placed.push(b); return b; },
    place(el, p) { el.setAttribute('transform', `translate(${p.x},${p.y})`); },
    hide(el, h) { if (el.__hidden !== h) { el.__hidden = h; el.style.display = h ? 'none' : ''; } },
    cls(el, c) { if (el.__cls !== c) { el.__cls = c; el.setAttribute('class', c); } },
  };
  return ctx;
}

function fxEffectFor(attackId) { return Object.prototype.hasOwnProperty.call(ATTACK_EFFECTS, attackId) ? ATTACK_EFFECTS[attackId] : null; }

function fxTeardown() {
  const a = fxState.active;
  if (a) {
    try { if (a.effect.teardown) a.effect.teardown(a.ctx); } catch (e) { /* teardown must never throw upwards */ }
    if (typeof overlay !== 'undefined' && overlay) {
      overlay.attacker.setAttribute('transform', `translate(${ATTACKER_POS.x},${ATTACKER_POS.y})`);
      overlay.attacker.classList.remove('fx-grey');
      overlay.attacker.style.opacity = '';
      const l = overlay.attacker.querySelector('.topo-attacker-label');
      if (l) { l.textContent = 'ATTACKER'; l.setAttribute('y', -ATTACKER_R - 1.2); l.style.fontSize = ''; }
    }
    if (a.ctx.link && a.ctx.link.edge) {          // MITM hides the breaker / voltage label under the attacker
      [a.ctx.link.edge.breaker, a.ctx.link.edge.vLabel].forEach((el) => { if (el) el.style.display = ''; });
    }
  }
  const layer = fxState.layer;
  if (layer) while (layer.firstChild) layer.removeChild(layer.firstChild);
  const svg = typeof document !== 'undefined' ? document.getElementById('topology-svg') : null;
  if (svg) svg.classList.remove('fx-on');
  fxState.active = null; fxState.key = null; fxState.lastElapsed = null; fxState.lastRank = 0; fxState.stage = 'NONE';
}

/**
 * Called from updateAttackOverlay on every status poll. Starts / keeps / tears down the effect.
 * `intensity` is the target intensity (0..1) computed in topology.js; the effect smooths toward it.
 */
function topoFxSync(status, target, stage, intensity) {
  if (!fxState.layer) return;
  const effectDef = status ? fxEffectFor(status.attack_type) : null;
  const rank = fxStageRank[stage] || (stage === 'RESOLVED' && effectDef && effectDef.keepOnResolved ? 4 : 0);   // keepOnResolved: shown until the stage leaves RESOLVED
  const live = Boolean(target) && rank > 0 && effectDef;
  if (!live) { if (fxState.active) fxTeardown(); return; }
  const key = `${status.attack_type}|${status.target_node}`;
  const elapsed = Number(status.attack_elapsed_s);
  const regressed = fxState.active && (rank < fxState.lastRank
    || (Number.isFinite(elapsed) && fxState.lastElapsed !== null && elapsed < fxState.lastElapsed - 0.5));
  if (fxState.active && (fxState.key !== key || regressed)) fxTeardown();   // same attack on the same node twice also lands here
  if (!fxState.active) {
    const effect = fxEffectFor(status.attack_type);
    const ctx = fxMakeCtx(status.attack_type, status.target_node, target, status);
    ctx.intensity = intensity;
    fxState.serial++;
    fxState.active = { effect, ctx, serial: fxState.serial };
    fxState.key = key;
    const svg = document.getElementById('topology-svg');
    if (svg) svg.classList.add('fx-on');
    try { effect.setup(ctx); } catch (e) { fxTeardown(); throw e; }
  }
  const ctx = fxState.active.ctx;
  ctx.stage = stage; ctx.attacking = stage === 'EXECUTING' || stage === 'DETECTED'; ctx.mitigating = stage === 'MITIGATING'; ctx.resolved = stage === 'RESOLVED';
  ctx.targetIntensity = intensity; ctx.status = status;
  fxState.lastRank = rank; fxState.stage = stage;
  if (Number.isFinite(elapsed)) fxState.lastElapsed = elapsed;
}

/** Per-frame driver (called from animateTopology only while the map is visible). */
function topoFxFrame(ts, dt) {
  const a = fxState.active;
  if (!a) return;
  const ctx = a.ctx;
  if (ctx.t0 === null) ctx.t0 = ts;
  ctx.calm = Boolean(fxReducedMotionQuery && fxReducedMotionQuery.matches);
  ctx.m = ctx.calm ? FX_CALM_MOTION : 1;
  ctx.rdt = dt; ctx.ts = ts;
  ctx.dt = dt * ctx.m;
  ctx.clock += ctx.dt;
  ctx.age = ctx.age0 + (ts - ctx.t0) / 1000;
  ctx.intensity += (ctx.targetIntensity - ctx.intensity) * Math.min(1, dt * 4);
  a.effect.update(ctx);
}

/** Keep-clear rects for placeCallout; { attackerMoved, rects } or null when no effect runs. */
function topoFxObstacles() {
  const a = fxState.active;
  if (!a) return null;
  const rects = a.effect.obstacles ? a.effect.obstacles(a.ctx) : [];
  return { attackerMoved: a.ctx.attackerMoved, rects };
}


/** Distance from point p to segment a-b. */
function fxSegDist(p, a, b) {
  const dx = b.x - a.x, dy = b.y - a.y, l2 = dx * dx + dy * dy || 1;
  const t = fxClamp(((p.x - a.x) * dx + (p.y - a.y) * dy) / l2, 0, 1);
  return Math.hypot(p.x - (a.x + t * dx), p.y - (a.y + t * dy));
}

/** Boxes (viewBox units) that effect panels must keep clear: node discs and labels, the target's tag, the attacker marker. */
function fxStaticObstacles(ctx) {
  const out = [];
  topoData.nodes.forEach((n) => {
    const r = NODE_RADIUS[n.type];
    out.push({ x: n.x - r - 1.4, y: n.y - r - 1.4, w: 2 * r + 2.8, h: 2 * r + 2.8 });
    const hw = (n.name.length * 0.62) + 0.8;                       // label text width at 2.3px font
    out.push({ x: n.x - hw, y: n.y + r + 2.8, w: hw * 2, h: 3.4 });
  });
  const T = ctx.target;
  out.push({ x: T.x - 13.5, y: T.y - ctx.R - 6.4, w: 27, h: 5 });   // "UNDER ATTACK" / "MITIGATING" tag
  out.push({ x: ATTACKER_POS.x - 8, y: ATTACKER_POS.y - 9, w: 16, h: 16 });
  return out.concat(ctx.placed);
}

/**
 * Nearest free w x h box (centre returned) to o.around (default: the target), inside the map and clear of
 * fxStaticObstacles. o.xMin/xMax/yMin/yMax limit the search band; o.penalty(x, y) adds to the distance score.
 */
function fxFreeBox(ctx, w, h, o) {
  const around = o.around || ctx.target, obst = fxStaticObstacles(ctx), m = 1.5;
  const x0 = Math.max(o.xMin ?? 0, m + w / 2), x1 = Math.min(o.xMax ?? VIEWBOX_W, VIEWBOX_W - m - w / 2);
  const y0 = Math.max(o.yMin ?? 0, m + h / 2), y1 = Math.min(o.yMax ?? VIEWBOX_H, VIEWBOX_H - m - h / 2);
  let best = null;
  for (let y = y0; y <= y1 + 1e-6; y += 1.5) {
    for (let x = x0; x <= x1 + 1e-6; x += 1.5) {
      const b = { x: x - w / 2, y: y - h / 2, w, h };
      if (obst.some((q) => b.x < q.x + q.w && q.x < b.x + b.w && b.y < q.y + q.h && q.y < b.y + b.h)) continue;
      const score = Math.hypot(x - around.x, (y - around.y) * 1.2) + (o.penalty ? o.penalty(x, y) : 0);
      if (!best || score < best.score) best = { cx: x, cy: y, x: b.x, y: b.y, w, h, score };
    }
  }
  if (!best) {                                                      // crowded: fall back to the clamped target-side position
    const cx = fxClamp(around.x, x0, x1), cy = fxClamp(around.y - ctx.R - 9, y0, y1);
    best = { cx, cy, x: cx - w / 2, y: cy - h / 2, w, h, score: 0 };
  }
  return best;
}

const fxRectOf = (b) => ({ x: b.x, y: b.y, w: b.w, h: b.h });
const fxEase = (cur, target, rdt, rate) => cur + (target - cur) * Math.min(1, rdt * rate);
const fxFinite = (v) => (typeof v === 'number' && Number.isFinite(v));

const fxBox = (cx, cy, hw, hh) => ({ x: cx - hw, y: cy - hh, w: hw * 2, h: hh * 2 });

/* ============================================================
   BATCH A - network attacks
   ============================================================ */

/* ---- DDOS: botnet swarm, converging flood, swelling node + shockwaves; shield when mitigating ---- */
const DDOS_BOTS = 8, DDOS_PARTICLES = 54;
const FX_DDOS = {
  setup(ctx) {
    ctx.setAttackerLabel('BOTNET');
    ctx.bots = [];
    for (let i = 0; i < DDOS_BOTS; i++) {                      // arc below / around the attacker, never over its label
      const th = (10 + i * (190 / (DDOS_BOTS - 1))) * Math.PI / 180;
      const p = { x: fxClamp(ATTACKER_POS.x + Math.cos(th) * 6.4, 1.8, VIEWBOX_W - 2), y: fxClamp(ATTACKER_POS.y + Math.sin(th) * 6.4, 1.8, VIEWBOX_H - 2) };
      p.el = ctx.mk('circle', { r: 0.95, cx: p.x, cy: p.y, class: 'fx-bot fx-keepclear' });
      ctx.bots.push(p);
    }
    ctx.swell = ctx.mk('circle', { r: ctx.R + 1, cx: ctx.target.x, cy: ctx.target.y, class: 'fx-swell' });
    ctx.rings = [0, 1, 2].map(() => ctx.mk('circle', { r: ctx.R, cx: ctx.target.x, cy: ctx.target.y, class: 'fx-ring' }));
    ctx.shieldEl = ctx.mk('circle', { r: ctx.R + 3.6, cx: ctx.target.x, cy: ctx.target.y, class: 'fx-shield fx-keepclear' });
    ctx.shield = 0;
    ctx.flood = ctx.parts(DDOS_PARTICLES, 'circle', { r: 0.7, class: 'fx-pkt-bad' });
    ctx.flood.forEach((p) => { p.bot = ctx.bots[p.k % DDOS_BOTS]; });
  },
  update(ctx) {
    const I = ctx.intensity, T = ctx.target;
    ctx.shield += ((ctx.mitigating ? 1 : 0) - ctx.shield) * Math.min(1, ctx.rdt * 3);
    const sh = ctx.shield;
    ctx.bots.forEach((b, i) => b.el.setAttribute('opacity', (0.55 + 0.45 * Math.sin(ctx.clock * 5 + i * 1.7)).toFixed(2)));
    const visible = Math.floor(DDOS_PARTICLES * (0.25 + 0.75 * I) * (ctx.calm ? 0.4 : 1));
    const endDist = ctx.R + 0.9 + sh * 2.7;
    ctx.flood.forEach((p, i) => {
      if (i >= visible) { ctx.hide(p.el, true); return; }
      ctx.hide(p.el, false);
      p.prog += p.speed * (0.45 + 0.7 * I) * ctx.dt * 0.9;
      if (p.prog >= 1) p.prog -= 1;
      const end = ctx.pointToward(T, p.bot, endDist);
      const q = ctx.lerpPt(p.bot, end, p.prog);
      p.el.setAttribute('cx', q.x.toFixed(2)); p.el.setAttribute('cy', q.y.toFixed(2));
      const fade = sh > 0.05 && p.prog > 0.8 ? 1 - (p.prog - 0.8) / 0.2 * sh : 1;
      p.el.setAttribute('opacity', fxClamp(fade, 0, 1).toFixed(2));
    });
    const calmK = ctx.mitigating ? 0.25 : 1;
    ctx.swell.setAttribute('r', (ctx.R + 1 + (0.5 + 0.9 * I) * (0.5 + 0.5 * Math.sin(ctx.clock * 6)) * calmK).toFixed(2));
    ctx.swell.setAttribute('opacity', (0.25 + 0.3 * I * calmK).toFixed(2));
    ctx.rings.forEach((r, i) => {
      const ph = (ctx.clock * 0.9 * (0.5 + I) + i / 3) % 1;
      r.setAttribute('r', (ctx.R + 0.6 + ph * 9).toFixed(2));
      r.setAttribute('opacity', ((1 - ph) * 0.55 * (ctx.mitigating ? 0.2 : 1)).toFixed(2));
    });
    ctx.shieldEl.setAttribute('opacity', sh.toFixed(2));
    ctx.shieldEl.setAttribute('stroke-dashoffset', (-ctx.clock * 5).toFixed(2));
  },
  obstacles(ctx) {
    const xs = ctx.bots.map((b) => b.x), ys = ctx.bots.map((b) => b.y);
    const x0 = Math.min(...xs) - 2, y0 = Math.min(...ys) - 2;
    return [{ x: x0, y: y0, w: Math.max(...xs) + 2 - x0, h: Math.max(...ys) + 2 - y0 },
            fxBox(ctx.target.x, ctx.target.y, ctx.R + 4.4, ctx.R + 4.4)];
  },
};

/* ---- MITM: attacker sits ON the feed link; packets pass through, copies go to the eye; padlock + eject ---- */
const MITM_PACKETS = 5;
const FX_MITM = {
  setup(ctx) {
    const L = ctx.link;
    ctx.mid = ctx.lerpPt(L.a, L.b, 0.5);
    const dx = L.b.x - L.a.x, dy = L.b.y - L.a.y, d = Math.hypot(dx, dy) || 1;
    const nx = -dy / d, ny = dx / d;                              // unit normal to the link
    const cand = (k) => [{ x: ctx.mid.x + nx * k, y: ctx.mid.y + ny * k }, { x: ctx.mid.x - nx * k, y: ctx.mid.y - ny * k }];
    ctx.eyePos = fxBestSpot(cand(7.5), 4);
    ctx.ejectPos = fxBestSpot(cand(14).concat(cand(10)), 4);
    ctx.curAttacker = ctx.mid;
    if (L.edge) [L.edge.breaker, L.edge.vLabel].forEach((el) => { if (el) el.style.display = 'none'; });
    ctx.hot = ctx.mk('line', { x1: L.a.x, y1: L.a.y, x2: L.b.x, y2: L.b.y, class: 'fx-link-hot' });
    ctx.tapLine = ctx.mk('line', { x1: ctx.mid.x, y1: ctx.mid.y, x2: ctx.eyePos.x, y2: ctx.eyePos.y, class: 'fx-tap' });
    ctx.eye = ctx.mk('g', { class: 'fx-eye fx-keepclear' });
    ctx.place(ctx.eye, ctx.eyePos);
    ctx.mk('circle', { r: 2.1, class: 'fx-eye-bg' }, ctx.eye);
    ctx.mk('path', { d: 'M -1.5 0 Q 0 -1.3 1.5 0 Q 0 1.3 -1.5 0 Z', class: 'fx-eye-shape' }, ctx.eye);
    ctx.mk('circle', { r: 0.5, class: 'fx-eye-pupil' }, ctx.eye);
    ctx.mk('line', { x1: 1.5, y1: 1.5, x2: 3, y2: 3, class: 'fx-eye-handle' }, ctx.eye);
    ctx.lock = ctx.mk('g', { class: 'fx-lock fx-keepclear' });
    ctx.place(ctx.lock, ctx.mid);
    ctx.mk('rect', { x: -1.5, y: -0.4, width: 3, height: 2.4, rx: 0.4, class: 'fx-lock-body' }, ctx.lock);
    ctx.mk('path', { d: 'M -0.9 -0.4 V -1.3 A 0.9 0.9 0 0 1 0.9 -1.3 V -0.4', class: 'fx-lock-shackle' }, ctx.lock);
    const lt = ctx.mk('text', { y: 4.4, class: 'fx-text fx-text-green' }, ctx.lock); lt.textContent = 'CERT PINNED';
    ctx.pk = ctx.parts(MITM_PACKETS, 'rect', { width: 1.3, height: 0.9, rx: 0.2, class: 'fx-pkt-ok' });
    ctx.copies = ctx.parts(MITM_PACKETS, 'rect', { width: 1.0, height: 0.7, rx: 0.2, class: 'fx-pkt-copy' });
    ctx.labelBelow = ctx.labelWantsBelow(ctx.mid, 17);
    ctx.setAttackerLabel('INTERCEPTING', ctx.labelBelow);
    overlay.attacker.querySelector('.topo-attacker-label').style.fontSize = '2px';   // narrower: fits between neighbouring labels
    ctx.eject = 0;
  },
  update(ctx) {
    const L = ctx.link, I = ctx.intensity, mit = ctx.mitigating;
    ctx.eject = mit ? fxClamp(ctx.eject + ctx.rdt * 0.9, 0, 1) : 0;
    const e = fxSmooth(ctx.eject);
    ctx.curAttacker = ctx.lerpPt(ctx.mid, ctx.ejectPos, e);
    ctx.moveAttacker(ctx.curAttacker);
    overlay.attacker.classList.toggle('fx-grey', mit);
    overlay.attacker.style.opacity = (1 - 0.7 * e).toFixed(2);
    ctx.setAttackerLabel(mit ? (e > 0.5 ? 'EJECTED' : 'BLOCKING') : 'INTERCEPTING');
    ctx.tapLine.setAttribute('opacity', mit ? Math.max(0, 0.7 - e * 1.4).toFixed(2) : 0.85);
    ctx.cls(ctx.eye, mit ? 'fx-eye fx-keepclear fx-eye-dead' : 'fx-eye fx-keepclear');
    ctx.lock.setAttribute('opacity', mit ? fxSmooth(e * 1.6).toFixed(2) : '0');
    const speed = 0.32 * (mit ? 0.8 : 0.9 + 0.5 * I);
    ctx.pk.forEach((p, i) => {
      p.prog = (p.prog + speed * ctx.dt) % 1;
      const q = ctx.lerpPt(L.a, L.b, p.prog);
      p.el.setAttribute('x', (q.x - 0.65).toFixed(2)); p.el.setAttribute('y', (q.y - 0.45).toFixed(2));
      const c = ctx.copies[i];
      const after = p.prog - 0.5;
      if (mit || after < 0 || after > 0.2) { ctx.hide(c.el, true); return; }
      ctx.hide(c.el, false);
      const cp = ctx.lerpPt(ctx.mid, ctx.eyePos, after / 0.2);
      c.el.setAttribute('x', (cp.x - 0.5).toFixed(2)); c.el.setAttribute('y', (cp.y - 0.35).toFixed(2));
    });
  },
  obstacles(ctx) {
    const a = ctx.attackerMoved ? ctx.curAttacker : ctx.mid;
    return [fxBox(a.x, a.y - 1.5, 14, 6), fxBox(ctx.eyePos.x, ctx.eyePos.y, 4, 4), fxBox(ctx.mid.x, ctx.mid.y + 1.5, 8, 5)];
  },
};

/* ---- REPLAY: 1) capture a legit packet (REC)  2) fire ghost duplicates with a stale timestamp ---- */
const REPLAY_GHOSTS = 6;
const FX_REPLAY = {
  setup(ctx) {
    const L = ctx.link;
    ctx.mid = ctx.lerpPt(L.a, L.b, 0.5);
    ctx.stop = ctx.pointToward(ctx.target, ATTACKER_POS, ctx.R + 0.9);
    ctx.hot = ctx.mk('line', { x1: L.a.x, y1: L.a.y, x2: L.b.x, y2: L.b.y, class: 'fx-link-hot' });
    ctx.capLine = ctx.mk('line', { x1: ctx.mid.x, y1: ctx.mid.y, x2: ATTACKER_POS.x, y2: ATTACKER_POS.y, class: 'fx-tap' });
    ctx.flow = ctx.parts(3, 'rect', { width: 1.1, height: 0.8, rx: 0.2, class: 'fx-pkt-ok' });
    ctx.hero = ctx.mk('rect', { width: 1.9, height: 1.3, rx: 0.3, class: 'fx-pkt-hero' });
    ctx.heroCopy = ctx.mk('rect', { width: 1.5, height: 1.0, rx: 0.3, class: 'fx-ghost' });
    ctx.held = ctx.mk('rect', { width: 1.5, height: 1.0, rx: 0.3, class: 'fx-ghost fx-keepclear', x: ATTACKER_POS.x + 3.4, y: ATTACKER_POS.y + 3.6 });
    ctx.rec = ctx.mk('g', { class: 'fx-rec fx-keepclear' });
    ctx.place(ctx.rec, { x: ATTACKER_POS.x - 4.2, y: ATTACKER_POS.y + 5.4 });
    ctx.recDot = ctx.mk('circle', { r: 0.9, class: 'fx-rec-dot' }, ctx.rec);
    const rt = ctx.mk('text', { x: 1.8, y: 0.8, class: 'fx-text fx-text-coral fx-text-left' }, ctx.rec); rt.textContent = 'REC';
    ctx.rewind = ctx.mk('g', { class: 'fx-rewind fx-keepclear' });
    ctx.place(ctx.rewind, { x: ATTACKER_POS.x - 3.2, y: ATTACKER_POS.y + 5.4 });
    ctx.mk('path', { d: 'M 0 0 L 2 -1.1 L 2 1.1 Z M 2 0 L 4 -1.1 L 4 1.1 Z', class: 'fx-rewind-shape' }, ctx.rewind);
    ctx.ghosts = ctx.parts(REPLAY_GHOSTS, 'rect', { width: 1.9, height: 1.3, rx: 0.3, class: 'fx-ghost' });
    ctx.stale = ctx.mk('text', { class: 'fx-text fx-text-coral fx-keepclear' }); ctx.stale.textContent = 'STALE TIMESTAMP';
    ctx.xmark = ctx.mk('g', { class: 'fx-xmark fx-keepclear' });
    ctx.place(ctx.xmark, ctx.stop);
    ctx.mk('path', { d: 'M -1 -1 L 1 1 M 1 -1 L -1 1', class: 'fx-xmark-shape' }, ctx.xmark);
    const xt = ctx.mk('text', { y: -2.1, class: 'fx-text fx-text-amber' }, ctx.xmark); xt.textContent = 'NONCE CHECK';
    ctx.setAttackerLabel('ATTACKER');
  },
  update(ctx) {
    const L = ctx.link, I = ctx.intensity, mit = ctx.mitigating;
    // the phase is a function of how long the incident has been running (real seconds), never of the motion factor;
    // an effect that starts late (page loaded mid-attack) goes straight to the replay phase
    const capturing = ctx.attacking && ctx.age < FX_REPLAY_CAPTURE_S;
    const A = ATTACKER_POS;
    ctx.flow.forEach((p) => {
      p.prog = (p.prog + 0.12 * ctx.dt) % 1;
      const q = ctx.lerpPt(L.a, L.b, p.prog);
      p.el.setAttribute('x', (q.x - 0.55).toFixed(2)); p.el.setAttribute('y', (q.y - 0.4).toFixed(2));
    });
    ctx.hide(ctx.hero, !capturing); ctx.hide(ctx.heroCopy, !capturing); ctx.hide(ctx.capLine, !capturing && !(ctx.attacking));
    ctx.capLine.setAttribute('opacity', capturing ? 0.9 : 0.25);
    if (capturing) {
      const a = ctx.age;                                    // hero crosses the link in ~1.1 s, the copy reaches the attacker by ~1.15 s
      const hp = ctx.lerpPt(L.a, L.b, fxClamp(a / 1.1, 0, 1));
      ctx.hero.setAttribute('x', (hp.x - 0.95).toFixed(2)); ctx.hero.setAttribute('y', (hp.y - 0.65).toFixed(2));
      const cprog = fxClamp((a - 0.55) / 0.6, 0, 1);
      ctx.hide(ctx.heroCopy, a < 0.55);
      const cp = ctx.lerpPt(ctx.mid, A, cprog);
      ctx.heroCopy.setAttribute('x', (cp.x - 0.75).toFixed(2)); ctx.heroCopy.setAttribute('y', (cp.y - 0.5).toFixed(2));
    }
    const blink = ctx.calm ? 1 : (0.35 + 0.65 * Math.abs(Math.sin(ctx.ts / 260)));
    ctx.recDot.setAttribute('opacity', blink.toFixed(2));
    ctx.hide(ctx.rec, !capturing);
    ctx.hide(ctx.rewind, capturing);
    ctx.hide(ctx.held, !(ctx.attacking || mit));

    const n = capturing ? 0 : Math.max(1, Math.round(REPLAY_GHOSTS * (0.35 + 0.65 * I) * (ctx.calm ? 0.5 : 1)));
    let lead = null;
    ctx.ghosts.forEach((g, i) => {
      if (i >= n) { ctx.hide(g.el, true); return; }
      ctx.hide(g.el, false);
      g.prog = (g.prog + 0.34 * (0.6 + I) * ctx.dt) % 1;
      const q = ctx.lerpPt({ x: A.x, y: A.y }, ctx.stop, g.prog);
      g.el.setAttribute('x', (q.x - 0.95).toFixed(2)); g.el.setAttribute('y', (q.y - 0.65).toFixed(2));
      g.el.setAttribute('opacity', (mit && g.prog > 0.82 ? 1 - (g.prog - 0.82) / 0.18 : 0.9).toFixed(2));
      if (i === 0 && g.prog > 0.3) lead = q;
    });
    ctx.hide(ctx.stale, !lead || mit);
    if (lead) { ctx.stale.setAttribute('x', lead.x.toFixed(2)); ctx.stale.setAttribute('y', (lead.y - 1.8).toFixed(2)); }
    ctx.hide(ctx.xmark, !mit);
    if (mit) ctx.xmark.setAttribute('opacity', (ctx.calm ? 1 : 0.4 + 0.6 * Math.abs(Math.sin(ctx.ts / 180))).toFixed(2));
  },
  obstacles(ctx) {
    return [fxBox(ATTACKER_POS.x, ATTACKER_POS.y + 3.5, 9, 9), fxBox(ctx.stop.x, ctx.stop.y, 7, 4)];
  },
};

/* ---- PORT_SCAN: radar sweep, sparse probe pings, port ticks lighting up (a few "open") ---- */
const SCAN_TICKS = 15;      // ring of ticks; a real open port p lights tick (p % SCAN_TICKS)
const FX_PORT_SCAN = {
  setup(ctx) {
    ctx.setAttackerLabel('SCANNING');
    ctx.beam = ctx.mk('path', { d: 'M 0 0', class: 'fx-beam' });
    ctx.beamLine = ctx.mk('line', { class: 'fx-beam-line' });
    ctx.ticks = [];
    for (let i = 0; i < SCAN_TICKS; i++) {
      const th = i / SCAN_TICKS * Math.PI * 2 - Math.PI / 2, r0 = ctx.R + 1.3, r1 = ctx.R + 2.4;
      const el = ctx.mk('line', { x1: ctx.target.x + Math.cos(th) * r0, y1: ctx.target.y + Math.sin(th) * r0,
                                  x2: ctx.target.x + Math.cos(th) * r1, y2: ctx.target.y + Math.sin(th) * r1, class: 'fx-port' });
      ctx.ticks.push({ el, st: '' });
    }
    ctx.pings = ctx.parts(4, 'circle', { r: 0.55, class: 'fx-ping' });
    ctx.fw = ctx.mk('circle', { r: ctx.R + 3.3, cx: ctx.target.x, cy: ctx.target.y, class: 'fx-shield fx-keepclear' });
  },
  update(ctx) {
    const A = ATTACKER_POS, T = ctx.target, I = ctx.intensity, mit = ctx.mitigating;
    const start = ctx.pointToward(A, T, 3.2), end = ctx.pointToward(T, A, ctx.R + 3.2);
    const th0 = Math.atan2(end.y - start.y, end.x - start.x);
    const len = Math.hypot(end.x - start.x, end.y - start.y);
    const th = th0 + 0.11 * Math.sin(ctx.clock * 2.6);
    const w = 0.028;
    const p1 = { x: start.x + Math.cos(th - w) * len, y: start.y + Math.sin(th - w) * len };
    const p2 = { x: start.x + Math.cos(th + w) * len, y: start.y + Math.sin(th + w) * len };
    ctx.beam.setAttribute('d', `M ${start.x.toFixed(2)} ${start.y.toFixed(2)} L ${p1.x.toFixed(2)} ${p1.y.toFixed(2)} L ${p2.x.toFixed(2)} ${p2.y.toFixed(2)} Z`);
    ctx.beam.setAttribute('opacity', (mit ? 0.1 * I : 0.2 + 0.15 * I).toFixed(2));
    ctx.beamLine.setAttribute('x1', start.x.toFixed(2)); ctx.beamLine.setAttribute('y1', start.y.toFixed(2));
    ctx.beamLine.setAttribute('x2', (start.x + Math.cos(th) * len).toFixed(2)); ctx.beamLine.setAttribute('y2', (start.y + Math.sin(th) * len).toFixed(2));
    ctx.beamLine.setAttribute('opacity', (mit ? 0.15 : 0.6).toFixed(2));
    const nPing = mit ? 1 : 2 + Math.round(I * 2);
    ctx.pings.forEach((p, i) => {
      if (i >= nPing) { ctx.hide(p.el, true); return; }
      ctx.hide(p.el, false);
      p.prog = (p.prog + 0.22 * ctx.dt * (mit ? 0.5 : 1)) % 1;
      const q = ctx.lerpPt(start, end, p.prog);
      p.el.setAttribute('cx', q.x.toFixed(2)); p.el.setAttribute('cy', q.y.toFixed(2));
      p.el.setAttribute('opacity', (mit ? Math.max(0, 1 - p.prog * 1.6) : 1).toFixed(2));
    });
    // open ports come ONLY from the real scan's evidence (real_attack_evidence.open_ports_found); none shown until it reports them
    const found = ctx.evidence().open_ports_found;
    const open = new Set((Array.isArray(found) ? found : []).map((p) => Math.abs(Math.trunc(Number(p))) % SCAN_TICKS));
    const cyc = SCAN_TICKS + 4, cur = Math.floor(ctx.clock * (2.2 + 2 * I)) % cyc;
    ctx.ticks.forEach((t, i) => {
      const st = mit ? 'blocked' : (open.has(i) ? 'open-green' : (i < cur ? 'scanned' : (i === cur ? 'probe' : 'idle')));
      if (st !== t.st) { t.st = st; t.el.setAttribute('class', `fx-port fx-port-${st}`); }
    });
    ctx.fw.setAttribute('opacity', mit ? 0.8 : 0);
    ctx.fw.setAttribute('stroke-dashoffset', (-ctx.clock * 4).toFixed(2));
  },
  obstacles(ctx) {
    return [fxBox(ctx.target.x, ctx.target.y, ctx.R + 4, ctx.R + 4), fxBox(ATTACKER_POS.x, ATTACKER_POS.y, 8, 5)];
  },
};


/* ============================================================
   BATCH B - data / signal attacks
   Anything numeric shown on the map comes from status.real_attack_evidence; otherwise labels are plain words.
   ============================================================ */

/* ---- FDI: legit packets mutate mid-transit; TRUE vs FAKE gauge diverges; quarantine + snap-back ---- */
const FDI_PACKETS = 6, FDI_MUTATE_AT = 0.45, FX_NOMINAL_VOLTAGE = 230;   // 230 V: same nominal the dashboard compares against
const FX_FDI = {
  setup(ctx) {
    const L = ctx.link;
    ctx.tp = ctx.lerpPt(L.a, L.b, FDI_MUTATE_AT);
    ctx.inj = ctx.mk('line', { x1: ATTACKER_POS.x, y1: ATTACKER_POS.y, x2: ctx.tp.x, y2: ctx.tp.y, class: 'fx-tap' });
    ctx.mk('circle', { cx: ctx.tp.x, cy: ctx.tp.y, r: 1.3, class: 'fx-tamper' });
    ctx.pk = ctx.parts(FDI_PACKETS, 'rect', { x: -0.65, y: -0.45, width: 1.3, height: 0.9, rx: 0.2, class: 'fx-pkt-ok' });
    const box = ctx.freeBox(23, 12.5);
    ctx.box = box;
    const g = ctx.gauge = ctx.mk('g', { class: 'fx-panel-g fx-keepclear' });
    ctx.place(g, { x: box.cx, y: box.cy });
    ctx.mk('rect', { x: -11.5, y: -6.2, width: 23, height: 12.4, rx: 1, class: 'fx-panel' }, g);
    ctx.title = ctx.text('FALSE READINGS', 0, -3.9, 'fx-text fx-text-coral', g);
    ctx.mk('path', { d: 'M -5.2 2.2 A 5.2 5.2 0 0 1 5.2 2.2', class: 'fx-dial' }, g);
    ctx.trueN = ctx.mk('line', { x1: 0, y1: 2.2, x2: 0, y2: -2.4, class: 'fx-needle-true' }, g);
    ctx.fakeN = ctx.mk('line', { x1: 0, y1: 2.2, x2: 0, y2: -2.8, class: 'fx-needle-fake' }, g);
    ctx.mk('circle', { cx: 0, cy: 2.2, r: 0.55, class: 'fx-hub' }, g);
    ctx.text('TRUE', -10.5, 5.1, 'fx-text fx-text-teal fx-text-left', g);
    ctx.fakeLbl = ctx.text('FAKE', 10.5, 5.1, 'fx-text fx-text-coral fx-text-right', g);
    const s = ctx.R + 2.6, k = 1.6, cx = ctx.target.x, cy = ctx.target.y;       // quarantine corner brackets around the node
    ctx.brackets = ctx.mk('path', { class: 'fx-bracket fx-keepclear',
      d: `M ${cx - s} ${cy - s + k} V ${cy - s} H ${cx - s + k} M ${cx + s - k} ${cy - s} H ${cx + s} V ${cy - s + k} M ${cx + s} ${cy + s - k} V ${cy + s} H ${cx + s - k} M ${cx - s + k} ${cy + s} H ${cx - s} V ${cy + s - k}` });
    const q0 = ctx.lerpPt(L.a, L.b, 0.55), q1 = ctx.lerpPt(L.a, L.b, 0.9);
    ctx.quar = ctx.mk('line', { x1: q0.x, y1: q0.y, x2: q1.x, y2: q1.y, class: 'fx-quarantine' });
    ctx.ang = 0; ctx.snap = 0;
  },
  update(ctx) {
    const L = ctx.link, I = ctx.intensity, mit = ctx.mitigating, ev = ctx.evidence();
    ctx.snap = fxEase(ctx.snap, mit ? 1 : 0, ctx.rdt, 1.4);
    const v = ev.voltage;
    // FAKE needle: deflection of the real last-received (injected) voltage from nominal; without data a plain wobble
    const raw = fxFinite(v) ? fxClamp((v - FX_NOMINAL_VOLTAGE) / 30, -1, 1) * 70
                            : Math.sin(ctx.clock * 2.1) * 35 * I + 25 * I;
    ctx.ang = fxEase(ctx.ang, raw * (1 - fxSmooth(ctx.snap)), ctx.rdt, 6);
    ctx.fakeN.setAttribute('transform', `rotate(${ctx.ang.toFixed(1)} 0 2.2)`);
    ctx.title.textContent = mit ? 'LAST VALIDATED' : 'FALSE READINGS';
    ctx.cls(ctx.title, mit ? 'fx-text fx-text-green' : 'fx-text fx-text-coral');
    ctx.fakeLbl.textContent = (!mit && fxFinite(v)) ? `FAKE ${v.toFixed(1)} V` : (mit ? 'RESTORED' : 'FAKE');
    ctx.hide(ctx.brackets, !mit); ctx.hide(ctx.quar, !mit);
    ctx.brackets.setAttribute('opacity', fxSmooth(ctx.snap * 1.5).toFixed(2));
    ctx.hide(ctx.inj, mit);
    ctx.inj.setAttribute('opacity', (0.5 + 0.4 * I).toFixed(2));
    const speed = 0.3 * (0.9 + 0.4 * I);
    ctx.pk.forEach((p) => {
      p.prog = (p.prog + speed * ctx.dt) % 1;
      const q = ctx.lerpPt(L.a, L.b, p.prog);
      const mutated = !mit && p.prog > FDI_MUTATE_AT;
      ctx.cls(p.el, mutated ? 'fx-pkt-fake' : 'fx-pkt-ok');
      p.el.setAttribute('transform', `translate(${q.x.toFixed(2)},${q.y.toFixed(2)})${mutated ? ' rotate(45) scale(1.2)' : ''}`);
    });
  },
  obstacles(ctx) { return [fxRectOf(ctx.box), fxBox(ctx.target.x, ctx.target.y, ctx.R + 3.4, ctx.R + 3.4)]; },
};

/* ---- LOAD_ALTER: oscillating load bars + distorted waveform; link surges / throttles; flattens when mitigated ---- */
const LOAD_BARS = 6, LOAD_WAVE_PTS = 20;
const FX_LOAD_ALTER = {
  setup(ctx) {
    const L = ctx.link;
    const box = ctx.freeBox(27, 15);
    ctx.box = box;
    const g = ctx.mk('g', { class: 'fx-panel-g fx-keepclear' });
    ctx.place(g, { x: box.cx, y: box.cy });
    ctx.mk('rect', { x: -13.5, y: -7.5, width: 27, height: 15, rx: 1, class: 'fx-panel' }, g);
    ctx.title = ctx.text('LOAD SWINGING', 0, -5.2, 'fx-text fx-text-amber', g);
    ctx.bars = [];
    for (let i = 0; i < LOAD_BARS; i++) ctx.bars.push(ctx.mk('rect', { x: -12 + i * 2.3, y: 0, width: 1.6, height: 1, class: 'fx-bar' }, g));
    ctx.mk('line', { x1: -12.4, y1: 3.4, x2: 1.6, y2: 3.4, class: 'fx-axis' }, g);
    ctx.mk('line', { x1: 3.4, y1: -0.6, x2: 12.4, y2: -0.6, class: 'fx-axis' }, g);
    ctx.wave = ctx.mk('polyline', { points: '', class: 'fx-wave' }, g);
    ctx.sub = ctx.text('DEMAND SPIKES', 0, 6.1, 'fx-text fx-text-muted', g);
    ctx.pk = ctx.parts(6, 'circle', { r: 0.6, class: 'fx-pkt-load' });
    ctx.flat = 0;
  },
  update(ctx) {
    const L = ctx.link, I = ctx.intensity, mit = ctx.mitigating, ev = ctx.evidence();
    ctx.flat = fxEase(ctx.flat, mit ? 1 : 0, ctx.rdt, 1.2);
    const swing = (1 - 0.92 * fxSmooth(ctx.flat)) * (0.35 + 0.65 * I);     // 1 = wild, ~0 = steady
    ctx.title.textContent = mit ? 'LOAD STEADYING' : 'LOAD SWINGING';
    ctx.cls(ctx.title, mit && ctx.flat > 0.6 ? 'fx-text fx-text-green' : 'fx-text fx-text-amber');
    ctx.sub.textContent = fxFinite(ev.last_setpoint) ? `SETPOINT ${ev.last_setpoint}` : (mit ? 'SETPOINT LIMITED' : 'DEMAND SPIKES');
    ctx.bars.forEach((b, i) => {
      const h = 1.2 + 4.6 * (0.18 + 0.82 * swing * Math.abs(Math.sin(ctx.clock * (2.6 + i * 0.55) + i * 1.7)));
      b.setAttribute('height', h.toFixed(2)); b.setAttribute('y', (3.4 - h).toFixed(2));
    });
    const pts = [];
    for (let k = 0; k < LOAD_WAVE_PTS; k++) {
      const u = k / (LOAD_WAVE_PTS - 1);
      const y = swing * 2.6 * (Math.sin(u * 9.4 + ctx.clock * 5) + 0.55 * Math.sin(u * 23 - ctx.clock * 8.3));
      pts.push(`${(3.4 + u * 9).toFixed(2)},${(-0.6 + y / 1.55).toFixed(2)}`);
    }
    ctx.wave.setAttribute('points', pts.join(' '));
    ctx.cls(ctx.wave, mit && ctx.flat > 0.6 ? 'fx-wave fx-wave-ok' : 'fx-wave');
    const surge = (0.12 + 1.5 * (0.5 + 0.5 * Math.sin(ctx.clock * 2.4))) * (0.4 + 0.6 * swing);   // waves of surge / throttle
    ctx.pk.forEach((p) => {
      p.prog = (p.prog + 0.28 * surge * ctx.dt) % 1;
      const q = ctx.lerpPt(ctx.link.a, ctx.link.b, p.prog);
      p.el.setAttribute('cx', q.x.toFixed(2)); p.el.setAttribute('cy', q.y.toFixed(2));
      p.el.setAttribute('r', (0.45 + 0.5 * Math.min(1, surge)).toFixed(2));
    });
  },
  obstacles(ctx) { return [fxRectOf(ctx.box), fxBox(ctx.target.x, ctx.target.y, ctx.R + 3.4, ctx.R + 3.4)]; },
};

/* ---- GPS_SPOOF: satellite beam vs rogue beam; clock whose hands drift; rogue beam cut + holdover ---- */
const FX_GPS_SPOOF = {
  setup(ctx) {
    const T = ctx.target, A = ATTACKER_POS;
    ctx.setAttackerLabel('SPOOFER');
    // satellite: top band, away from the top-row nodes / labels / tag, and not on the line from the attacker marker
    const sat = ctx.freeBox(14, 9, { yMin: 2, yMax: 12, around: T,
      penalty: (x, y) => (fxSegDist(A, { x, y }, T) < 9 ? 40 : 0) });
    ctx.sat = sat;
    const g = ctx.mk('g', { class: 'fx-sat fx-keepclear' });
    g.setAttribute('transform', `translate(${sat.cx},${sat.cy - 1.2}) scale(1.4)`);
    ctx.mk('rect', { x: -1.1, y: -1, width: 2.2, height: 2, rx: 0.3, class: 'fx-sat-body' }, g);
    ctx.mk('rect', { x: -4.6, y: -0.7, width: 3.2, height: 1.4, class: 'fx-sat-panel' }, g);
    ctx.mk('rect', { x: 1.4, y: -0.7, width: 3.2, height: 1.4, class: 'fx-sat-panel' }, g);
    ctx.mk('path', { d: 'M 0 1 L 0 2.1 M -0.9 2.1 H 0.9', class: 'fx-sat-dish' }, g);
    ctx.text('GPS', 0, 4.5, 'fx-text fx-text-teal', g);
    ctx.satPos = { x: sat.cx, y: sat.cy + 0.6 };
    ctx.legit = ctx.mk('line', { class: 'fx-beam-sat' });
    ctx.rogue = ctx.mk('line', { class: 'fx-tap' });
    ctx.pL = ctx.parts(3, 'circle', { r: 0.55, class: 'fx-ping-teal' });
    ctx.pR = ctx.parts(3, 'circle', { r: 0.6, class: 'fx-pkt-bad' });
    const box = ctx.freeBox(14, 11);
    ctx.box = box;
    const c = ctx.clockG = ctx.mk('g', { class: 'fx-clock-g fx-keepclear' });
    ctx.place(c, { x: box.cx, y: box.cy - 1.2 });
    ctx.mk('circle', { r: 3.1, class: 'fx-clock-face' }, c);
    ['M 0 -2.7 V -2.2', 'M 2.7 0 H 2.2', 'M 0 2.7 V 2.2', 'M -2.7 0 H -2.2'].forEach((d) => ctx.mk('path', { d, class: 'fx-clock-tick' }, c));
    ctx.trueH = ctx.mk('line', { x1: 0, y1: 0, x2: 0, y2: -2.3, class: 'fx-hand-true' }, c);
    ctx.driftH = ctx.mk('line', { x1: 0, y1: 0, x2: 0, y2: -2.6, class: 'fx-hand-drift' }, c);
    ctx.mk('circle', { r: 0.4, class: 'fx-hub' }, c);
    ctx.offLbl = ctx.text('OFFSET', 0, 6.1, 'fx-text fx-text-coral', c);
    ctx.ang = 0; ctx.lock = 0; ctx.cut = 0;
  },
  update(ctx) {
    const T = ctx.target, A = ATTACKER_POS, I = ctx.intensity, mit = ctx.mitigating, ev = ctx.evidence();
    ctx.lock = fxEase(ctx.lock, mit ? 1 : 0, ctx.rdt, 1.1);
    ctx.cut = fxEase(ctx.cut, mit ? 1 : 0, ctx.rdt, 2.2);
    const off = ev.time_offset_ms;
    // drift of the spoofed hand: real clock offset when the runner reports it (saturating), otherwise a plain wobble
    const raw = fxFinite(off) ? 120 * Math.tanh(off / 400) : (50 + 30 * Math.sin(ctx.clock * 1.7)) * I;
    ctx.ang = fxEase(ctx.ang, raw * (1 - fxSmooth(ctx.lock)), ctx.rdt, 4);
    ctx.driftH.setAttribute('transform', `rotate(${ctx.ang.toFixed(1)})`);
    ctx.offLbl.textContent = mit && ctx.lock > 0.45 ? 'HOLDOVER' : (fxFinite(off) ? `${off >= 0 ? '+' : '-'}${Math.abs(Math.round(off))} ms` : 'OFFSET');
    ctx.cls(ctx.offLbl, mit && ctx.lock > 0.45 ? 'fx-text fx-text-green' : 'fx-text fx-text-coral');
    const e1 = ctx.pointToward(T, ctx.satPos, ctx.R + 1.0), e2 = ctx.pointToward(T, A, ctx.R + 1.4);
    const s2 = ctx.pointToward(A, T, 3.2);
    const setLine = (el, p, q) => { el.setAttribute('x1', p.x.toFixed(2)); el.setAttribute('y1', p.y.toFixed(2)); el.setAttribute('x2', q.x.toFixed(2)); el.setAttribute('y2', q.y.toFixed(2)); };
    setLine(ctx.legit, ctx.satPos, e1);
    setLine(ctx.rogue, s2, ctx.lerpPt(s2, e2, 1 - ctx.cut));     // the rogue beam is cut back toward the attacker
    ctx.legit.setAttribute('stroke-dashoffset', (-ctx.clock * 3).toFixed(2));
    ctx.hide(ctx.rogue, ctx.cut > 0.97);
    ctx.pL.forEach((p) => {
      p.prog = (p.prog + 0.3 * ctx.dt) % 1;
      const q = ctx.lerpPt(ctx.satPos, e1, p.prog);
      p.el.setAttribute('cx', q.x.toFixed(2)); p.el.setAttribute('cy', q.y.toFixed(2));
    });
    ctx.pR.forEach((p, i) => {
      const live = ctx.cut < 0.9 && i < 1 + Math.round(2 * I);
      ctx.hide(p.el, !live);
      if (!live) return;
      p.prog = (p.prog + 0.34 * ctx.dt) % 1;
      const end = ctx.lerpPt(s2, e2, 1 - ctx.cut);
      const q = ctx.lerpPt(s2, end, p.prog);
      p.el.setAttribute('cx', q.x.toFixed(2)); p.el.setAttribute('cy', q.y.toFixed(2));
    });
  },
  obstacles(ctx) { return [fxRectOf(ctx.sat), fxRectOf(ctx.box), fxBox(ctx.target.x, ctx.target.y, ctx.R + 3, ctx.R + 3)]; },
};

/* ---- JAMMING: static rings, flickering broken link, packets die before the node; backup channel on the same geometry ---- */
const JAM_RINGS = 4, JAM_SPECKS = 10, JAM_PACKETS = 7;
const FX_JAMMING = {
  setup(ctx) {
    const L = ctx.link, T = ctx.target;
    ctx.setAttackerLabel('JAMMER');
    ctx.rings = [];
    for (let i = 0; i < JAM_RINGS; i++) ctx.rings.push(ctx.mk('circle', { cx: T.x, cy: T.y, r: ctx.R, class: 'fx-noise', 'stroke-dasharray': ['0.4,0.7', '0.9,0.5', '0.3,0.4', '0.7,0.9'][i] }));
    ctx.specks = [];
    for (let i = 0; i < JAM_SPECKS; i++) ctx.specks.push({ el: ctx.mk('circle', { r: 0.32, class: 'fx-speck' }), t: 0, x: T.x, y: T.y });
    ctx.broken = ctx.mk('line', { x1: L.a.x, y1: L.a.y, x2: L.b.x, y2: L.b.y, class: 'fx-link-broken' });
    const m = ctx.lerpPt(L.a, L.b, 0.62);
    ctx.cross = ctx.mk('path', { d: 'M -0.9 -0.9 L 0.9 0.9 M 0.9 -0.9 L -0.9 0.9', class: 'fx-xmark-shape fx-keepclear' });
    ctx.place(ctx.cross, m);
    // backup channel: parallel to the REAL feed link, offset to the side away from the voltage label
    const dx = L.b.x - L.a.x, dy = L.b.y - L.a.y, d = Math.hypot(dx, dy) || 1, ux = dx / d, uy = dy / d;
    let nx = -uy, ny = ux; if (ny < 0 || (ny === 0 && nx < 0)) { nx = -nx; ny = -ny; }
    const Ra = L.neighbour ? NODE_RADIUS[(topoData.nodes.find((n) => n.id === L.neighbour) || { type: 'meters' }).type] : 0;
    const off = 2.4;
    ctx.b0 = { x: L.a.x + ux * (Ra + 1.3) + nx * off, y: L.a.y + uy * (Ra + 1.3) + ny * off };
    ctx.b1 = { x: L.b.x - ux * (ctx.R + 1.3) + nx * off, y: L.b.y - uy * (ctx.R + 1.3) + ny * off };
    ctx.backup = ctx.mk('line', { x1: ctx.b0.x, y1: ctx.b0.y, x2: ctx.b1.x, y2: ctx.b1.y, class: 'fx-backup' });
    const bm = ctx.lerpPt(ctx.b0, ctx.b1, 0.5);
    ctx.bLbl = ctx.text('BACKUP CH', bm.x + nx * 2.4, bm.y + ny * 2.4 + 0.6, 'fx-text fx-text-green fx-keepclear');
    ctx.bBox = fxBox(bm.x + nx * 2.4, bm.y + ny * 2.4, 6.5, 2.2);
    ctx.pk = ctx.parts(JAM_PACKETS, 'rect', { width: 1.2, height: 0.8, rx: 0.2, class: 'fx-pkt-ok' });
    ctx.bpk = ctx.parts(4, 'rect', { width: 1.2, height: 0.8, rx: 0.2, class: 'fx-pkt-ok' });
    ctx.sw = 0;
  },
  update(ctx) {
    const L = ctx.link, T = ctx.target, I = ctx.intensity, mit = ctx.mitigating;
    ctx.sw = fxEase(ctx.sw, mit ? 1 : 0, ctx.rdt, 1.5);
    const sw = fxSmooth(ctx.sw), noise = 1 - sw;
    ctx.rings.forEach((r, i) => {
      const ph = (ctx.clock * 0.7 * (0.5 + I) + i / JAM_RINGS) % 1;
      r.setAttribute('r', (ctx.R + 0.8 + ph * 10).toFixed(2));
      r.setAttribute('opacity', ((1 - ph) * 0.7 * noise).toFixed(2));
      r.setAttribute('stroke-dashoffset', (ctx.clock * (i % 2 ? 6 : -6)).toFixed(2));
    });
    ctx.specks.forEach((sp, i) => {
      sp.t -= ctx.dt;
      if (sp.t <= 0) {                                           // visual static: re-seed position now and then
        sp.t = ctx.calm ? 99 : 0.06 + Math.random() * 0.2;
        const a = Math.random() * 6.283, r = ctx.R + 1.2 + Math.random() * 8;
        sp.x = T.x + Math.cos(a) * r; sp.y = T.y + Math.sin(a) * r;
        sp.el.setAttribute('cx', sp.x.toFixed(2)); sp.el.setAttribute('cy', sp.y.toFixed(2));
      }
      ctx.hide(sp.el, i >= Math.round(JAM_SPECKS * (0.3 + 0.7 * I)) || noise < 0.05);
      sp.el.setAttribute('opacity', noise.toFixed(2));
    });
    ctx.broken.setAttribute('opacity', (ctx.calm ? 0.5 : 0.15 + 0.7 * Math.pow(Math.random(), 2)) * (mit ? 0.45 : 1));
    const cut = 0.75 - 0.45 * I;                                 // packets die at this fraction of the link
    ctx.pk.forEach((p) => {
      p.prog = (p.prog + 0.26 * ctx.dt) % 1;
      const q = ctx.lerpPt(L.a, L.b, p.prog);
      const jit = ctx.calm ? 0 : (Math.random() - 0.5) * 0.9 * I * noise;
      p.el.setAttribute('x', (q.x - 0.6 + jit).toFixed(2)); p.el.setAttribute('y', (q.y - 0.4 + jit).toFixed(2));
      p.el.setAttribute('opacity', fxClamp(1 - (p.prog - cut) / 0.15, 0, 1).toFixed(2));
    });
    ctx.backup.setAttribute('opacity', sw.toFixed(2));
    ctx.bLbl.setAttribute('opacity', sw.toFixed(2));
    ctx.bpk.forEach((p) => {
      ctx.hide(p.el, sw < 0.05);
      p.prog = (p.prog + 0.3 * ctx.dt) % 1;
      const q = ctx.lerpPt(ctx.b0, ctx.b1, p.prog);
      p.el.setAttribute('x', (q.x - 0.6).toFixed(2)); p.el.setAttribute('y', (q.y - 0.4).toFixed(2));
      p.el.setAttribute('opacity', sw.toFixed(2));
    });
  },
  obstacles(ctx) { return [fxBox(ctx.target.x, ctx.target.y, ctx.R + 4, ctx.R + 4), ctx.bBox]; },
};

/* ============================================================
   BATCH C - system attacks
   ============================================================ */

/** Link between the control centre and `id` (a = the other end, b = the target); null when the node has none. */
function fxControlLink(id) {
  const byId = (i) => topoData.nodes.find((n) => n.id === i);
  const e = topoData.edges.find((x) => (x.from === id || x.to === id) && (byId(x.from).type === 'control' || byId(x.to).type === 'control'));
  if (!e) return null;
  const other = byId(e.from === id ? e.to : e.from), t = byId(id);
  return { a: { x: other.x, y: other.y }, b: { x: t.x, y: t.y }, neighbour: other.id, upstream: e.to === id, edge: null };
}

/* ---- CMD_INJECT: forged angular CMD packets injected onto the control link; breaker flips; allow-list gate ---- */
const FX_CMD_INJECT = {
  setup(ctx) {
    const L = ctx.cl = fxControlLink(ctx.target.id) || ctx.link;
    ctx.ip = ctx.lerpPt(L.a, L.b, 0.35);
    ctx.gp = ctx.lerpPt(L.a, L.b, 0.8);
    const dx = L.b.x - L.a.x, dy = L.b.y - L.a.y, d = Math.hypot(dx, dy) || 1;
    ctx.ux = dx / d; ctx.uy = dy / d;
    ctx.setAttackerLabel('ATTACKER');
    ctx.inj = ctx.mk('line', { x1: ATTACKER_POS.x, y1: ATTACKER_POS.y, x2: ctx.ip.x, y2: ctx.ip.y, class: 'fx-tap' });
    const side = fxBestSpot([{ x: ctx.ip.x - ctx.uy * 3.4, y: ctx.ip.y + ctx.ux * 3.4 }, { x: ctx.ip.x + ctx.uy * 3.4, y: ctx.ip.y - ctx.ux * 3.4 }], 3);
    ctx.tagPos = side;
    const tg = ctx.mk('g', { class: 'fx-cmd-tag fx-keepclear' }); ctx.place(tg, side);
    ctx.mk('rect', { x: -2.4, y: -1.1, width: 4.8, height: 2.2, rx: 0.4, class: 'fx-cmd-tag-bg' }, tg);
    ctx.text('CMD', 0, 0.62, 'fx-text fx-text-white', tg);
    ctx.flow = ctx.parts(3, 'circle', { r: 0.5, class: 'fx-pkt-ok' });
    ctx.forged = ctx.parts(5, 'polygon', { points: '-1.3,-0.8 0.9,-0.8 1.7,0 0.9,0.8 -1.3,0.8', class: 'fx-pkt-cmd' });
    const box = ctx.freeBox(9, 7); ctx.box = box;
    const g = ctx.brk = ctx.mk('g', { class: 'fx-breaker fx-keepclear' }); ctx.place(g, { x: box.cx, y: box.cy - 0.8 });
    ctx.mk('circle', { cx: -3, cy: 0.8, r: 0.7, class: 'fx-brk-term' }, g);
    ctx.mk('circle', { cx: 3, cy: 0.8, r: 0.7, class: 'fx-brk-term' }, g);
    ctx.blade = ctx.mk('line', { x1: -3, y1: 0.8, x2: 3, y2: 0.8, class: 'fx-brk-blade' }, g);
    ctx.brkLbl = ctx.text('CLOSED', 0, 4.4, 'fx-text fx-text-teal', g);
    const gt = ctx.gate = ctx.mk('g', { class: 'fx-gate fx-keepclear' }); ctx.place(gt, ctx.gp);
    ctx.mk('rect', { x: -0.4, y: -2.2, width: 0.8, height: 4.4, rx: 0.2, class: 'fx-gate-bar', transform: `rotate(${(Math.atan2(ctx.uy, ctx.ux) * 180 / Math.PI).toFixed(1)})` }, gt);
    ctx.mk('path', { d: 'M -0.9 -3.4 L -0.2 -2.7 L 1 -4.2', class: 'fx-gate-check' }, gt);
    ctx.text('ALLOW-LIST', 0, 5.2, 'fx-text fx-text-green', gt);
    ctx.xm = ctx.mk('path', { d: 'M -1 -1 L 1 1 M 1 -1 L -1 1', class: 'fx-xmark-shape' }); ctx.place(ctx.xm, ctx.gp);
    ctx.gateAmt = 0; ctx.ang = 0;
  },
  update(ctx) {
    const L = ctx.cl, I = ctx.intensity, mit = ctx.mitigating;
    ctx.gateAmt = fxEase(ctx.gateAmt, mit ? 1 : 0, ctx.rdt, 2.2);
    ctx.gate.setAttribute('opacity', fxSmooth(ctx.gateAmt).toFixed(2));
    ctx.hide(ctx.inj, mit && ctx.gateAmt > 0.9);
    ctx.inj.setAttribute('opacity', mit ? (0.5 * (1 - ctx.gateAmt)).toFixed(2) : (0.5 + 0.4 * I).toFixed(2));
    ctx.flow.forEach((p) => {
      p.prog = (p.prog + 0.2 * ctx.dt) % 1;
      const q = ctx.lerpPt(L.a, L.b, p.prog);
      p.el.setAttribute('cx', q.x.toFixed(2)); p.el.setAttribute('cy', q.y.toFixed(2));
    });
    const n = Math.max(1, Math.round(ctx.forged.length * (0.35 + 0.65 * I) * (ctx.calm ? 0.6 : 1)));
    const angDeg = Math.atan2(ctx.uy, ctx.ux) * 180 / Math.PI;
    let blocked = false;
    ctx.forged.forEach((p, i) => {
      if (i >= n) { ctx.hide(p.el, true); return; }
      p.prog = (p.prog + 0.3 * (0.6 + I) * ctx.dt) % 1;
      const t = 0.35 + p.prog * 0.55;                                // injected at 35 % of the link, runs toward the node
      const stopped = mit && t > 0.78;                                // the allow-list gate rejects it
      if (stopped) blocked = true;
      ctx.hide(p.el, stopped && ctx.gateAmt > 0.5);
      const q = ctx.lerpPt(L.a, L.b, t);
      p.el.setAttribute('transform', `translate(${q.x.toFixed(2)},${q.y.toFixed(2)}) rotate(${angDeg.toFixed(1)})`);
    });
    ctx.hide(ctx.xm, !(mit && ctx.gateAmt > 0.4));
    if (mit) ctx.xm.setAttribute('opacity', (blocked ? 1 : 0.35).toFixed(2));
    // breaker flips open / closed while forged commands land; locked closed once the allow-list is in place
    const open = ctx.attacking && Math.sin(ctx.clock * 2.4 + 0.6) > 0.15;
    ctx.ang = fxEase(ctx.ang, open ? -38 : 0, ctx.rdt, 9);
    ctx.blade.setAttribute('transform', `rotate(${ctx.ang.toFixed(1)} -3 0.8)`);
    const isOpen = ctx.ang < -19;
    ctx.brkLbl.textContent = isOpen ? 'OPEN' : 'CLOSED';
    ctx.cls(ctx.brkLbl, isOpen ? 'fx-text fx-text-coral' : 'fx-text fx-text-teal');
  },
  obstacles(ctx) { return [fxRectOf(ctx.box), fxBox(ctx.tagPos.x, ctx.tagPos.y, 3.2, 2), fxBox(ctx.gp.x, ctx.gp.y + 0.6, 6, 5.5), fxBox(ctx.target.x, ctx.target.y, ctx.R + 3, ctx.R + 3)]; },
};

/* ---- MALWARE: infected node, infection spreads along outgoing edges (inside the map), exfil stream to the attacker ---- */
const MAL_EXFIL = 10;
const FX_MALWARE = {
  setup(ctx) {
    const T = ctx.target, A = ATTACKER_POS;
    ctx.setAttackerLabel('C2 HOST');
    let edges = topoData.edges.filter((e) => e.from === T.id);
    if (!edges.length) edges = topoData.edges.filter((e) => e.to === T.id);          // leaf node: spread back up its only link
    ctx.nbs = edges.slice(0, 3).map((e, i) => {
      const id = e.from === T.id ? e.to : e.from, n = topoData.nodes.find((x) => x.id === id), r = NODE_RADIUS[n.type];
      const maxR = Math.max(r + 0.5, Math.min(n.x, VIEWBOX_W - n.x, n.y, VIEWBOX_H - n.y, r + 4.2) - 0.4);   // the tint never leaves the map
      return { x: n.x, y: n.y, r, maxR, i,
               line: ctx.mk('line', { x1: T.x, y1: T.y, x2: T.x, y2: T.y, class: 'fx-infect-line' }),
               tint: ctx.mk('circle', { cx: n.x, cy: n.y, r: r, class: 'fx-infect-tint' }) };
    });
    ctx.exStart = ctx.pointToward(T, A, ctx.R + 1.6); ctx.exEnd = ctx.pointToward(A, T, 3.4);
    ctx.exLine = ctx.mk('line', { x1: ctx.exStart.x, y1: ctx.exStart.y, x2: ctx.exEnd.x, y2: ctx.exEnd.y, class: 'fx-exfil-line' });
    ctx.exfil = ctx.parts(MAL_EXFIL, 'rect', { width: 0.9, height: 0.9, class: 'fx-exfil' });
    const g = ctx.virus = ctx.mk('g', { class: 'fx-virus fx-keepclear' });
    ctx.place(g, T);
    ctx.mk('circle', { r: 1.1, class: 'fx-virus-core' }, g);
    for (let k = 0; k < 8; k++) {
      const a = k * Math.PI / 4;
      ctx.mk('line', { x1: Math.cos(a) * 1.1, y1: Math.sin(a) * 1.1, x2: Math.cos(a) * 1.9, y2: Math.sin(a) * 1.9, class: 'fx-virus-spike' }, g);
      ctx.mk('circle', { cx: Math.cos(a) * 2.1, cy: Math.sin(a) * 2.1, r: 0.35, class: 'fx-virus-spike-end' }, g);
    }
    ctx.quar = ctx.mk('circle', { cx: T.x, cy: T.y, r: ctx.R + 3.2, class: 'fx-shield fx-keepclear' });
    ctx.retract = 0;
  },
  update(ctx) {
    const T = ctx.target, I = ctx.intensity, mit = ctx.mitigating;
    ctx.retract = fxEase(ctx.retract, mit ? 1 : 0, ctx.rdt, 0.9);
    const rt = fxSmooth(ctx.retract), k = (ctx.R + 0.8) / 2.1;
    const pulse = 1 + (mit ? 0.04 : 0.14) * Math.sin(ctx.clock * 6);
    ctx.virus.setAttribute('transform', `translate(${T.x},${T.y}) scale(${(k * pulse).toFixed(3)})`);
    ctx.cls(ctx.virus, mit && rt > 0.5 ? 'fx-virus fx-keepclear fx-virus-dead' : 'fx-virus fx-keepclear');
    ctx.nbs.forEach((n) => {
      const sp = fxClamp((ctx.age - n.i * 1.1) / 5, 0, 1) * (1 - rt);           // spreads with the incident's age, retracts when isolated
      n.tint.setAttribute('r', (n.r + 0.4 + sp * (n.maxR - n.r - 0.4)).toFixed(2));
      n.tint.setAttribute('opacity', (0.15 + 0.6 * sp).toFixed(2));
      const e = ctx.lerpPt(T, n, Math.min(1, sp * 1.4));
      n.line.setAttribute('x2', e.x.toFixed(2)); n.line.setAttribute('y2', e.y.toFixed(2));
      n.line.setAttribute('opacity', (sp > 0.02 ? 0.9 : 0).toFixed(2));
    });
    const vis = Math.round(MAL_EXFIL * (0.3 + 0.7 * I) * (ctx.calm ? 0.5 : 1)) * (1 - rt);
    ctx.exfil.forEach((p, i) => {
      ctx.hide(p.el, i >= vis);
      p.prog = (p.prog + 0.32 * ctx.dt) % 1;
      const q = ctx.lerpPt(ctx.exStart, ctx.exEnd, p.prog);
      p.el.setAttribute('x', (q.x - 0.45).toFixed(2)); p.el.setAttribute('y', (q.y - 0.45).toFixed(2));
    });
    ctx.exLine.setAttribute('opacity', (0.45 * (1 - rt)).toFixed(2));
    ctx.quar.setAttribute('opacity', rt.toFixed(2));
    ctx.quar.setAttribute('stroke-dashoffset', (-ctx.clock * 4).toFixed(2));
  },
  obstacles(ctx) {
    const out = [fxBox(ctx.target.x, ctx.target.y, ctx.R + 4, ctx.R + 4)];
    const a = ctx.exStart, b = ctx.exEnd, n = Math.max(2, Math.ceil(Math.hypot(b.x - a.x, b.y - a.y) / 6));
    for (let i = 0; i <= n; i++) { const q = ctx.lerpPt(a, b, i / n); out.push(fxBox(q.x, q.y, 3.6, 2.8)); }   // keep the callout off the exfil stream
    return out;
  },
};

/* ---- FIRMWARE_TAMPER: chip with glitching bits + hash badge; rollback during MITIGATING; hash-match check kept through RESOLVED ---- */
const FW_BITS = 12;
const FX_FIRMWARE_TAMPER = {
  keepOnResolved: true,
  setup(ctx) {
    const box = ctx.freeBox(22, 15); ctx.box = box;
    const g = ctx.panel = ctx.mk('g', { class: 'fx-panel-g fx-keepclear' }); ctx.place(g, { x: box.cx, y: box.cy });
    ctx.mk('rect', { x: -11, y: -7.5, width: 22, height: 15, rx: 1, class: 'fx-panel' }, g);
    ctx.title = ctx.text('HASH MISMATCH', 0, -5.3, 'fx-text fx-text-coral', g);
    const chip = ctx.mk('g', { transform: 'translate(-6.4,-0.4)' }, g);
    ctx.mk('rect', { x: -3, y: -2.4, width: 6, height: 4.8, rx: 0.5, class: 'fx-chip' }, chip);
    for (let i = 0; i < 3; i++) {
      [-3, 3].forEach((x) => ctx.mk('line', { x1: x, y1: -1.5 + i * 1.5, x2: x + (x < 0 ? -1 : 1), y2: -1.5 + i * 1.5, class: 'fx-chip-pin' }, chip));
      [-1.5 + i * 1.5].forEach((x) => { ctx.mk('line', { x1: x, y1: -2.4, x2: x, y2: -3.4, class: 'fx-chip-pin' }, chip); ctx.mk('line', { x1: x, y1: 2.4, x2: x, y2: 3.4, class: 'fx-chip-pin' }, chip); });
    }
    ctx.badge = ctx.mk('path', { d: 'M -1 0 L -0.2 0.9 L 1.3 -0.9', class: 'fx-fw-check' }, chip);
    ctx.rollG = ctx.mk('g', { transform: 'translate(-6.4,-0.4)' }, g);
    ctx.mk('path', { d: 'M 2 -2.2 A 2.9 2.9 0 1 0 2.9 0.6', class: 'fx-rollback' }, ctx.rollG);
    ctx.mk('path', { d: 'M 2.9 -3.2 L 2.3 -1.8 L 3.9 -1.6 Z', class: 'fx-rollback-head' }, ctx.rollG);
    ctx.bits = [];
    for (let i = 0; i < FW_BITS; i++) ctx.bits.push({ el: ctx.mk('rect', { x: -10 + i * 1.65, y: 4.3, width: 1.25, height: 1.7, class: 'fx-bit' }, g), st: '', t: 0, v: i % 3 === 0 });
    ctx.gLbl = ctx.text('', 2.6, -2.4, 'fx-text fx-text-muted fx-text-left fx-text-hash', g);
    ctx.dLbl = ctx.text('', 2.6, 0.9, 'fx-text fx-text-coral fx-text-left fx-text-hash', g);
    ctx.wr = ctx.mk('line', { x1: ATTACKER_POS.x, y1: ATTACKER_POS.y, x2: box.cx, y2: box.cy, class: 'fx-tap' });
    ctx.roll = 0;
  },
  update(ctx) {
    const mit = ctx.mitigating, res = ctx.resolved, ev = ctx.evidence();
    const prog = fxFinite(ctx.status && ctx.status.mitigation_progress) ? fxClamp(ctx.status.mitigation_progress / 100, 0, 1) : (mit ? 0.5 : 0);
    ctx.roll = fxEase(ctx.roll, res ? 1 : (mit ? prog : 0), ctx.rdt, 5);         // rollback progress = the real mitigation progress
    const golden = typeof ev.golden_sha256 === 'string' ? ev.golden_sha256 : null, dev = typeof ev.device_sha256 === 'string' ? ev.device_sha256 : null;
    const match = res && ((golden && dev) ? golden === dev : ev.tampered === false);   // only claim a match the evidence supports
    ctx.title.textContent = match ? 'HASH MATCH' : (res ? 'ROLLED BACK' : (mit ? 'ROLLING BACK' : 'HASH MISMATCH'));
    ctx.cls(ctx.title, match ? 'fx-text fx-text-green' : (mit || res ? 'fx-text fx-text-amber' : 'fx-text fx-text-coral'));
    ctx.hide(ctx.badge, !match);
    ctx.hide(ctx.rollG, !mit);
    if (mit) ctx.rollG.setAttribute('transform', `translate(-6.4,-0.4) rotate(${(-ctx.clock * 200 % 360).toFixed(1)})`);
    ctx.gLbl.textContent = golden ? `G:${golden.slice(0, 6)}` : '';
    ctx.dLbl.textContent = dev ? `D:${dev.slice(0, 6)}` : '';
    ctx.cls(ctx.dLbl, (match || (mit && ctx.roll > 0.95)) ? 'fx-text fx-text-green fx-text-left fx-text-hash' : 'fx-text fx-text-coral fx-text-left fx-text-hash');
    ctx.bits.forEach((b, i) => {
      const reverted = (i + 1) / FW_BITS <= ctx.roll + 1e-6;
      if (!reverted && ctx.attacking && !ctx.calm) { b.t -= ctx.dt; if (b.t <= 0) { b.t = 0.08 + Math.random() * 0.3; b.v = !b.v; } }
      const st = reverted ? 'ok' : (b.v ? 'hi' : 'lo');
      if (st !== b.st) { b.st = st; b.el.setAttribute('class', `fx-bit fx-bit-${st}`); }
    });
    ctx.hide(ctx.wr, !ctx.attacking);
    ctx.wr.setAttribute('opacity', 0.55);
  },
  obstacles(ctx) { return [fxRectOf(ctx.box), fxBox(ctx.target.x, ctx.target.y, ctx.R + 3, ctx.R + 3)]; },
};

/* ---- PRIV_ESC: lock on the node, key particles knock and bounce, lock cracks; privilege meter only from evidence ---- */
const PRIV_LEVELS = 5;      // the dashboard shows the achieved privilege as "n / 5"
const FX_PRIV_ESC = {
  setup(ctx) {
    const T = ctx.target, A = ATTACKER_POS;
    ctx.setAttackerLabel('INSIDER');
    ctx.stop = ctx.pointToward(T, A, ctx.R + 1.2);
    const k = (ctx.R + 1.2) / 2.6;
    const g = ctx.lock = ctx.mk('g', { class: 'fx-lock-node fx-keepclear' }); g.setAttribute('transform', `translate(${T.x},${T.y}) scale(${k.toFixed(3)})`);
    ctx.mk('rect', { x: -1.9, y: -0.5, width: 3.8, height: 2.9, rx: 0.5, class: 'fx-lock-body-dk' }, g);
    ctx.shackle = ctx.mk('path', { d: 'M -1.1 -0.5 V -1.6 A 1.1 1.1 0 0 1 1.1 -1.6 V -0.5', class: 'fx-lock-shackle-dk' }, g);
    ctx.mk('circle', { cx: 0, cy: 1, r: 0.45, class: 'fx-lock-key' }, g);
    ctx.crackEl = ctx.mk('path', { d: 'M -0.4 -0.5 L 0.4 0.6 L -0.6 1.3 L 0.2 2.4', class: 'fx-crack' }, g);
    ctx.keys = ctx.parts(5, 'circle', { r: 0.55, class: 'fx-key' });
    const box = ctx.freeBox(17, 7); ctx.box = box;
    const m = ctx.meter = ctx.mk('g', { class: 'fx-panel-g fx-keepclear' }); ctx.place(m, { x: box.cx, y: box.cy });
    ctx.mk('rect', { x: -8.5, y: -3.5, width: 17, height: 7, rx: 1, class: 'fx-panel' }, m);
    ctx.text('PRIVILEGE', 0, -1.5, 'fx-text fx-text-coral', m);
    ctx.segs = [];
    for (let i = 0; i < PRIV_LEVELS; i++) ctx.segs.push({ el: ctx.mk('rect', { x: -7.6 + i * 3.1, y: -0.3, width: 2.7, height: 1.6, rx: 0.3, class: 'fx-seg' }, m), on: null });
    ctx.lvl = ctx.text('', 0, 3.1, 'fx-text fx-text-muted', m);
    ctx.crack = 0; ctx.revoke = 0;
  },
  update(ctx) {
    const mit = ctx.mitigating, A = ATTACKER_POS, ev = ctx.evidence();
    const lvl = fxFinite(ev.privilege_level) ? fxClamp(Math.round(ev.privilege_level), 1, PRIV_LEVELS) : null;
    ctx.revoke = fxEase(ctx.revoke, mit ? 1 : 0, ctx.rdt, 1.3);
    const rv = fxSmooth(ctx.revoke);
    // crack: from the real achieved privilege when the evidence has it, otherwise a plain time-based cracking animation
    const crackT = lvl !== null ? (lvl - 1) / (PRIV_LEVELS - 2) : ctx.age / 7;
    ctx.crack = fxEase(ctx.crack, fxClamp(crackT, 0, 1) * (1 - rv), ctx.rdt, 3);
    ctx.crackEl.setAttribute('opacity', Math.min(1, ctx.crack * 1.6).toFixed(2));
    ctx.shackle.setAttribute('transform', `rotate(${(-ctx.crack * 40).toFixed(1)} 1.1 -0.5) translate(0 ${(-ctx.crack * 0.5).toFixed(2)})`);
    ctx.cls(ctx.lock, ctx.crack > 0.6 ? 'fx-lock-node fx-keepclear fx-lock-open' : (mit && rv > 0.5 ? 'fx-lock-node fx-keepclear fx-lock-shut' : 'fx-lock-node fx-keepclear'));
    const bounce = 1 - ctx.crack;                                   // once cracked, the keys get through instead of bouncing
    ctx.keys.forEach((p, i) => {
      ctx.hide(p.el, mit && rv > 0.6 && i > 0);
      p.prog = (p.prog + 0.55 * ctx.dt) % 1;
      const u = p.prog < 0.6 ? p.prog / 0.6 : 1 - (p.prog - 0.6) / 0.4 * 0.55 * bounce;   // knock, then bounce back
      const q = ctx.lerpPt({ x: A.x, y: A.y }, ctx.stop, fxClamp(u, 0, 1));
      p.el.setAttribute('cx', q.x.toFixed(2)); p.el.setAttribute('cy', q.y.toFixed(2));
    });
    ctx.hide(ctx.meter, lvl === null);
    if (lvl !== null) {
      const shown = Math.round(lvl * (1 - rv));
      ctx.segs.forEach((sg, i) => {
        const on = i < shown;
        if (on !== sg.on) { sg.on = on; sg.el.setAttribute('class', `fx-seg${on ? (i >= 3 ? ' fx-seg-hot' : ' fx-seg-on') : ''}`); }
      });
      ctx.lvl.textContent = (mit && rv > 0.5) ? 'SESSION REVOKED' : `LEVEL ${lvl}`;
    }
  },
  obstacles(ctx) { return [fxRectOf(ctx.box), fxBox(ctx.target.x, ctx.target.y, ctx.R + 3, ctx.R + 3)]; },
};

const ATTACK_EFFECTS = {
  DDOS: FX_DDOS,
  MITM: FX_MITM,
  REPLAY: FX_REPLAY,
  PORT_SCAN: FX_PORT_SCAN,
  FDI: FX_FDI,
  LOAD_ALTER: FX_LOAD_ALTER,
  GPS_SPOOF: FX_GPS_SPOOF,
  JAMMING: FX_JAMMING,
  CMD_INJECT: FX_CMD_INJECT,
  MALWARE: FX_MALWARE,
  FIRMWARE_TAMPER: FX_FIRMWARE_TAMPER,
  PRIV_ESC: FX_PRIV_ESC,
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ATTACK_EFFECTS, fxState, fxEffectFor, fxFeedLink, topoFxSync, topoFxFrame, topoFxObstacles, fxTeardown, fxInit, FX_MAX_ELEMENTS };
}
