/* ============================================================
   Smart Grid IDS v3 - topology.js
   Renders the fixed grid single-line-diagram as SVG and animates
   packet-flow dots along every edge - slow/steady/cyan normally,
   fast/erratic/red along the edges touching whichever node is
   currently under attack. Pure SVG + requestAnimationFrame, no
   dependency.

   Visual conventions borrowed from real single-line diagrams (SLDs):
   generation/substation nodes are drawn as a transformer symbol (two
   overlapping circles), each edge carries a small breaker (switch)
   marker at its midpoint, and each edge is labeled with the voltage
   level it plausibly carries (transmission -> distribution -> LV).
   ============================================================ */

const SVG_NS = 'http://www.w3.org/2000/svg';
const VIEWBOX_W = 180;
const VIEWBOX_H = 100;

const NODE_RADIUS = {
  plant: 4.6, control: 3.0, substation: 3.8, feeder: 2.3, meters: 1.7,
};
const NODE_COLOR = {
  plant: '#e3a53d', control: '#5b93d9', substation: '#2fd9c8', feeder: '#2fd9c8', meters: 'rgba(47,217,200,0.65)',
};
// Nodes drawn with a double-ring "transformer" symbol, matching real SLD convention.
const TRANSFORMER_TYPES = new Set(['plant', 'substation']);

// Voltage label shown on each power edge, inferred from the node types it
// connects - mirrors a real grid's generation -> transmission ->
// distribution -> LV chain. Control/SCADA links (to/from the control
// center) are communication links, not power circuits, so they get a
// dashed line instead of a voltage label or breaker.
function voltageForEdge(aType, bType) {
  if (aType === 'plant' || bType === 'plant') return '132 kV';
  if ((aType === 'substation' && bType === 'feeder') || (aType === 'feeder' && bType === 'substation')) return '11 kV';
  if ((aType === 'feeder' && bType === 'meters') || (aType === 'meters' && bType === 'feeder')) return '415 V';
  return '';
}
function isControlEdge(aType, bType) {
  return aType === 'control' || bType === 'control';
}

let topoData = null;
let nodeEls = {};      // id -> { group, shape, label }
let edgeEls = [];      // { from, to, pathEl, length, baseParticles:[], attackParticles:[] }
let lastTs = null;
let currentTargetNode = null;
let currentStage = 'NONE';
let overlay = null;
let lastTopoStatus = null;      // most recent /api/status, kept so the overlay can be re-placed when the map becomes visible
let overlayNeedsPlacement = false;    // attacker marker, arrow, tag and callout (frontend-only, not in /api/topology)

// Virtual attacker sits outside the grid, top-left of the viewBox.
const ATTACKER_POS = { x: 8, y: 14 };
const ATTACKER_R = 2.4;

async function initTopology(containerId) {
  try {
    const res = await fetch('/api/topology');
    topoData = await res.json();
  } catch (e) {
    console.error('topology fetch failed', e);
    return;
  }
  buildSVG(containerId);
  buildLegend(containerId);
  requestAnimationFrame(animateTopology);
}

function buildSVG(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = '';
  nodeEls = {};
  edgeEls = [];

  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${VIEWBOX_W} ${VIEWBOX_H}`);
  svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
  svg.id = 'topology-svg';
  container.appendChild(svg);

  // edges first so nodes render above them
  topoData.edges.forEach(e => {
    const a = topoData.nodes.find(n => n.id === e.from);
    const b = topoData.nodes.find(n => n.id === e.to);
    if (!a || !b) return;

    const path = document.createElementNS(SVG_NS, 'path');
    path.setAttribute('d', `M ${a.x} ${a.y} L ${b.x} ${b.y}`);
    const controlEdge = isControlEdge(a.type, b.type);
    path.setAttribute('class', controlEdge ? 'topo-edge topo-edge-control' : 'topo-edge');
    svg.appendChild(path);

    const midX = (a.x + b.x) / 2;
    const midY = (a.y + b.y) / 2;
    let breakerEl = null, vLabelEl = null;

    if (!controlEdge) {
      // breaker (switch) symbol at the edge midpoint - real SLD convention,
      // and a voltage-level label - only meaningful on real power circuits.
      const angle = Math.atan2(b.y - a.y, b.x - a.x) * (180 / Math.PI);
      const breaker = document.createElementNS(SVG_NS, 'rect');
      breaker.setAttribute('class', 'topo-breaker');
      breaker.setAttribute('width', 2.6);
      breaker.setAttribute('height', 2.6);
      breaker.setAttribute('x', midX - 1.3);
      breaker.setAttribute('y', midY - 1.3);
      breaker.setAttribute('transform', `rotate(${angle} ${midX} ${midY})`);
      svg.appendChild(breaker);
      breakerEl = breaker;

      const vLabel = voltageForEdge(a.type, b.type);
      if (vLabel) {
        const text = document.createElementNS(SVG_NS, 'text');
        text.setAttribute('class', 'topo-voltage-label');
        text.setAttribute('x', midX);
        text.setAttribute('y', midY - 2.6);
        text.textContent = vLabel;
        svg.appendChild(text);
        vLabelEl = text;
      }
    }

    // edges are straight lines, so length and points are plain arithmetic (no SVG geometry API calls)
    const length = Math.hypot(b.x - a.x, b.y - a.y);
    edgeEls.push({
      from: e.from, to: e.to, pathEl: path, length, ax: a.x, ay: a.y, bx: b.x, by: b.y,
      baseParticles: makeParticles(svg, 2, 0.06, 'topo-particle-base'),
      attackParticles: [],
      breaker: breakerEl, vLabel: vLabelEl,
      active: false,
    });
  });

  topoData.nodes.forEach(n => {
    const g = document.createElementNS(SVG_NS, 'g');
    g.setAttribute('class', `topo-node topo-node-${n.type} topo-status-normal`);
    g.setAttribute('transform', `translate(${n.x},${n.y})`);

    const r = NODE_RADIUS[n.type];
    const glow = document.createElementNS(SVG_NS, 'circle');
    glow.setAttribute('r', r + 2.4);
    glow.setAttribute('class', 'topo-node-glow');
    g.appendChild(glow);

    const ping = document.createElementNS(SVG_NS, 'circle');
    ping.setAttribute('r', r + 0.8);
    ping.setAttribute('class', 'topo-ping');
    g.appendChild(ping);

    if (TRANSFORMER_TYPES.has(n.type)) {
      // Real SLD transformer symbol: two overlapping circles, same color,
      // the "back" one drawn slightly dimmer to read as depth rather than
      // a second element.
      const c1 = document.createElementNS(SVG_NS, 'circle');
      c1.setAttribute('r', r * 0.72);
      c1.setAttribute('cx', -r * 0.42);
      c1.setAttribute('class', 'topo-node-shape topo-node-shape-secondary');
      c1.style.fill = NODE_COLOR[n.type];
      g.appendChild(c1);

      const c2 = document.createElementNS(SVG_NS, 'circle');
      c2.setAttribute('r', r * 0.72);
      c2.setAttribute('cx', r * 0.42);
      c2.setAttribute('class', 'topo-node-shape');
      c2.style.fill = NODE_COLOR[n.type];
      g.appendChild(c2);
    } else {
      const shape = document.createElementNS(SVG_NS, 'circle');
      shape.setAttribute('r', r);
      shape.setAttribute('class', 'topo-node-shape');
      shape.style.fill = NODE_COLOR[n.type];
      g.appendChild(shape);
    }

    const check = document.createElementNS(SVG_NS, 'path');
    check.setAttribute('class', 'topo-check');
    const k = Math.min(r * 0.55, 1.3);
    check.setAttribute('d', `M ${-k} 0 L ${-k * 0.25} ${k * 0.7} L ${k} ${-k * 0.7}`);
    g.appendChild(check);

    const label = document.createElementNS(SVG_NS, 'text');
    label.setAttribute('class', 'topo-label');
    label.setAttribute('y', r + 5.2);
    label.textContent = n.name;
    g.appendChild(label);

    svg.appendChild(g);
    nodeEls[n.id] = { group: g, type: n.type, x: n.x, y: n.y, name: n.name, label };
  });

  buildAttackOverlay(svg);
}

function svgEl(tag, attrs, parent) {
  const el = document.createElementNS(SVG_NS, tag);
  Object.entries(attrs || {}).forEach(([k, v]) => el.setAttribute(k, v));
  if (parent) parent.appendChild(el);
  return el;
}

/** Everything that visualises the attack itself. Drawn last so it sits above edges and nodes. */
function buildAttackOverlay(svg) {
  fxInit(svg);                       // per-attack effect layer (topology_effects.js), under the attacker / tag / callout
  const attacker = svgEl('g', { id: 'topo-attacker', transform: `translate(${ATTACKER_POS.x},${ATTACKER_POS.y})` }, svg);
  svgEl('circle', { r: ATTACKER_R, class: 'topo-attacker-ring' }, attacker);
  svgEl('path', { d: `M -1 -1 L 1 1 M 1 -1 L -1 1`, class: 'topo-attacker-x' }, attacker);
  const attackerLabel = svgEl('text', { class: 'topo-attacker-label', y: -ATTACKER_R - 1.2 }, attacker);
  attackerLabel.textContent = 'ATTACKER';

  const arrow = svgEl('g', { id: 'topo-attack-arrow' }, svg);
  const line = svgEl('line', { class: 'topo-arrow-line' }, arrow);
  const head = svgEl('polygon', { class: 'topo-arrow-head' }, arrow);
  const particles = [];
  for (let i = 0; i < 6; i++) {
    particles.push({ el: svgEl('circle', { r: 0.75, class: 'topo-arrow-particle' }, arrow), prog: i / 6 });
  }

  const tag = svgEl('g', { class: 'topo-tag' }, svg);
  const tagBg = svgEl('rect', { class: 'topo-tag-bg', height: 4.2, rx: 0.9 }, tag);
  const tagText = svgEl('text', { class: 'topo-tag-text' }, tag);

  const leader = svgEl('line', { class: 'topo-leader' }, svg);
  const callout = svgEl('g', { id: 'topo-callout' }, svg);
  const calloutBg = svgEl('rect', { class: 'topo-callout-bg', rx: 0.9, height: 9.4 }, callout);
  const calloutName = svgEl('text', { class: 'topo-callout-name' }, callout);
  const calloutMetric = svgEl('text', { class: 'topo-callout-metric' }, callout);

  overlay = { attacker, arrow, line, head, particles, tag, tagBg, tagText,
              callout, calloutBg, calloutName, calloutMetric, leader, target: null };
}

function buildLegend(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const existing = container.parentElement.querySelector('#topo-legend');
  if (existing) existing.remove();

  const legend = document.createElement('div');
  legend.id = 'topo-legend';
  legend.innerHTML = `
    <div class="topo-legend-row"><span class="topo-legend-swatch" style="background:#e3a53d"></span>Power plant</div>
    <div class="topo-legend-row"><span class="topo-legend-swatch" style="background:#5b93d9"></span>Control center</div>
    <div class="topo-legend-row"><span class="topo-legend-swatch" style="background:#2fd9c8"></span>Substation / feeder</div>
    <div class="topo-legend-row"><span class="topo-legend-swatch" style="background:rgba(47,217,200,0.65)"></span>Smart meter cluster</div>
    <div class="topo-legend-row"><span class="topo-legend-mark">&#9632;</span>Breaker</div>
    <div class="topo-legend-row"><span class="topo-legend-mark">&#8231;&#8231;</span>SCADA / control link</div>
  `;
  container.parentElement.appendChild(legend);
}

function makeParticles(svg, count, speed, className) {
  const particles = [];
  for (let i = 0; i < count; i++) {
    const el = document.createElementNS(SVG_NS, 'circle');
    el.setAttribute('r', className.includes('attack') ? 1.0 : 0.6);
    el.setAttribute('class', className);
    svg.appendChild(el);
    particles.push({ el, prog: Math.random(), speed: speed * (0.7 + Math.random() * 0.6) });
  }
  return particles;
}

function setEdgeActive(edge, active, svg) {
  if (active === edge.active) return;
  edge.active = active;
  if (active) {
    edge.attackParticles = makeParticles(svg, 5, 0.35, 'topo-particle-attack');
    edge.pathEl.classList.add('topo-edge-active');
  } else {
    edge.attackParticles.forEach(p => p.el.remove());
    edge.attackParticles = [];
    edge.pathEl.classList.remove('topo-edge-active');
  }
}

/** attack_stage when the backend sends it; derived from phase for older payloads. */
function stageOf(status) {
  if (status.attack_stage) return status.attack_stage;
  return status.phase === 'SECURE' ? 'NONE' : status.phase;
}

const STAGE_NODE_CLASS = {
  EXECUTING: 'topo-status-attacking',
  DETECTED: 'topo-status-attacked',
  MITIGATING: 'topo-status-mitigating',
  RESOLVED: 'topo-status-resolved',
};
const ALL_NODE_CLASSES = ['topo-status-normal', 'topo-status-scenario', 'topo-status-attacking', 'topo-status-attacked',
                          'topo-status-mitigating', 'topo-status-resolved'];
const TAG_FOR_STAGE = {
  EXECUTING: ['UNDER ATTACK', 'tag-attacking'],
  DETECTED: ['UNDER ATTACK', 'tag-attacked'],
  MITIGATING: ['MITIGATING', 'tag-mitigating'],
  RESOLVED: ['RESTORED', 'tag-resolved'],
};

/** Called by dashboard.js on every /api/status poll. */
function updateTopologyStatus(status) {
  if (!topoData) return;
  const svg = document.getElementById('topology-svg');
  if (!svg) return;

  lastTopoStatus = status;
  currentTargetNode = status.target_node;
  currentStage = stageOf(status);
  const hasTarget = Boolean(currentTargetNode) && currentStage !== 'NONE';
  // between scenario stages the same node stays marked, so the target never "disappears"
  const sc = status.scenario;
  const scenarioTarget = (currentStage === 'NONE' && sc && sc.active && sc.target_node) ? sc.target_node : null;

  edgeEls.forEach(edge => {
    const touchesTarget = hasTarget && (edge.from === currentTargetNode || edge.to === currentTargetNode);
    setEdgeActive(edge, Boolean(touchesTarget && currentStage !== 'RESOLVED'), svg);
  });

  Object.entries(nodeEls).forEach(([id, ne]) => {
    if (!ne) return;
    const statusClass = (hasTarget && id === currentTargetNode && STAGE_NODE_CLASS[currentStage])
      || (id === scenarioTarget ? 'topo-status-scenario' : 'topo-status-normal');
    ne.group.classList.remove(...ALL_NODE_CLASSES);
    ne.group.classList.add(statusClass);
  });

  updateAttackOverlay(status, hasTarget, scenarioTarget);
}

/** Put a small label tag centred just above a node (clamped inside the viewBox). */
function placeTag(node, label, cls) {
  const o = overlay;
  o.tag.setAttribute('class', `topo-tag on ${cls}`);
  o.tagText.textContent = label;
  const tagW = label.length * 1.85 + 3.4;
  const tagY = Math.max(0.2, node.y - NODE_RADIUS[node.type] - 6);
  const tagX = Math.min(VIEWBOX_W - tagW / 2 - 0.5, Math.max(tagW / 2 + 0.5, node.x));
  o.tagBg.setAttribute('width', tagW);
  o.tagBg.setAttribute('x', -tagW / 2);
  o.tagBg.setAttribute('y', 0);
  o.tagText.setAttribute('y', 2.15);
  o.tag.setAttribute('transform', `translate(${tagX},${tagY})`);
  return { x: tagX - tagW / 2, y: tagY, w: tagW, h: 4.2 };
}

/** Same ramp as stageIntensity() in dashboard.js (kept separate so the Attack detail tab is untouched). */
function topoIntensity(status, stage) {
  if (stage === 'EXECUTING') return Math.min(1, 0.35 + (status.attack_elapsed_s || 0) * 0.22);
  if (stage === 'DETECTED') return 1;
  if (stage === 'MITIGATING') return Math.max(0.08, 1 - (status.mitigation_progress || 0) / 100);
  return 0;
}

function updateAttackOverlay(status, hasTarget, scenarioTarget) {
  if (!overlay) return;
  const o = overlay;
  const target = hasTarget ? nodeEls[currentTargetNode] : null;
  try { topoFxSync(status, target, currentStage, topoIntensity(status, currentStage)); }
  catch (err) { console.error('topology effect failed', err); }
  o.target = target;
  const streaming = Boolean(target) && (currentStage === 'EXECUTING' || currentStage === 'DETECTED');
  const fading = Boolean(target) && currentStage === 'MITIGATING';

  o.attacker.classList.toggle('on', streaming || fading);
  o.arrow.classList.toggle('on', streaming);
  o.arrow.classList.toggle('fading', fading);
  if (fading) o.arrow.classList.add('on');   // keep it visible but dim while traffic is being blocked
  if (!target) {
    overlayNeedsPlacement = false;
    o.callout.classList.remove('on');
    o.leader.classList.remove('on');
    if (scenarioTarget && nodeEls[scenarioTarget]) {
      const sc = status.scenario;
      placeTag(nodeEls[scenarioTarget], `STAGE ${sc.stage_idx + 1} NEXT`, 'tag-scenario');
    } else {
      o.tag.classList.remove('on');
    }
    return;
  }

  // arrow: attacker edge -> just short of the target node
  const r = NODE_RADIUS[target.type] + 1.2;
  const dx = target.x - ATTACKER_POS.x, dy = target.y - ATTACKER_POS.y;
  const dist = Math.hypot(dx, dy) || 1;
  const ux = dx / dist, uy = dy / dist;
  const x1 = ATTACKER_POS.x + ux * (ATTACKER_R + 0.8), y1 = ATTACKER_POS.y + uy * (ATTACKER_R + 0.8);
  const x2 = target.x - ux * r, y2 = target.y - uy * r;
  o.line.setAttribute('x1', x1); o.line.setAttribute('y1', y1);
  o.line.setAttribute('x2', x2 - ux * 1.6); o.line.setAttribute('y2', y2 - uy * 1.6);
  const px = -uy, py = ux;
  o.head.setAttribute('points',
    `${x2},${y2} ${x2 - ux * 2.4 + px * 1.1},${y2 - uy * 2.4 + py * 1.1} ${x2 - ux * 2.4 - px * 1.1},${y2 - uy * 2.4 - py * 1.1}`);
  o.arrowGeom = { x1, y1, x2, y2 };

  // tag directly above the node
  const [tagLabel, tagClass] = TAG_FOR_STAGE[currentStage];
  const tagRect = placeTag(target, tagLabel, tagClass);

  // callout beside the node: needs text measurements, so it is skipped while the map is hidden and
  // re-run by animateTopology() as soon as it is visible again
  if (!topologyVisible()) {
    overlayNeedsPlacement = true;
    o.callout.classList.remove('on');
    o.leader.classList.remove('on');
    return;
  }
  try {
    placeCallout(status, target, tagRect);
    overlayNeedsPlacement = false;
  } catch (err) {
    overlayNeedsPlacement = true;       // measuring failed (e.g. element not rendered yet): retry on the next frame
    o.callout.classList.remove('on');
    o.leader.classList.remove('on');
  }
}

/** Callout (attack name + live headline metric) placed at the nearest collision-free spot. May throw if the SVG is not rendered. */
function placeCallout(status, target, tagRect) {
  const o = overlay;
  const m = status.attack_headline_metric || {};
  const metricText = `${m.label || ''}: ${typeof m.value === 'number' ? m.value.toLocaleString() : (m.value ?? '--')}${m.unit ? ' ' + m.unit : ''}${m.final ? ' (final)' : ''}`;
  o.calloutName.textContent = (status.attack_display_name || '').toUpperCase();
  o.calloutMetric.textContent = metricText;
  o.callout.setAttribute('class', `on stage-${currentStage}`);
  o.calloutName.setAttribute('x', 1.8); o.calloutName.setAttribute('y', 3.4);
  o.calloutMetric.setAttribute('x', 1.8); o.calloutMetric.setAttribute('y', 7.4);
  const w = Math.max(o.calloutName.getComputedTextLength(), o.calloutMetric.getComputedTextLength()) + 3.8;
  o.calloutBg.setAttribute('width', w);
  // Nearest collision-free position (see the grid search below); the least-colliding one if none is free.
  const h = 9.4;
  const hit = (a, b) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
  const obstacles = [tagRect];
  const fx = topoFxObstacles();
  if (fx) fx.rects.forEach(r => obstacles.push(r));
  Object.values(nodeEls).forEach(n => {
    const rr = NODE_RADIUS[n.type] + 0.8;
    obstacles.push({ x: n.x - rr, y: n.y - rr, w: rr * 2, h: rr * 2 });
    const lb = n.label.getBBox();
    obstacles.push({ x: n.x + lb.x, y: n.y + lb.y, w: lb.width, h: lb.height });
  });
  const gap = NODE_RADIUS[target.type] + 3;
  // the ATTACKER marker (and its label above it) is an obstacle too
  if (!fx || !fx.attackerMoved) obstacles.push({ x: ATTACKER_POS.x - 6, y: ATTACKER_POS.y - ATTACKER_R - 4.8, w: 12, h: ATTACKER_R * 2 + 5.6 });
  // search a grid around the node for the closest position that collides with nothing
  let best = null;
  for (let dx = -64; dx <= 64; dx += 2) {
    for (let dy = -26; dy <= 26; dy += 1.6) {
      const box = { x: target.x + dx - w / 2, y: target.y + dy - h / 2, w, h };
      if (box.x < 1 || box.x + w > VIEWBOX_W - 1 || box.y < 1 || box.y + h > VIEWBOX_H - 1) continue;
      const hits = obstacles.filter(ob => hit(box, ob)).length;
      const dist = Math.hypot(dx * 0.8, dy);                  // prefer beside the node over above/below
      if (hits === 0 && (!best || best.hits > 0 || dist < best.dist)) best = { x: box.x, y: box.y, hits: 0, dist };
      else if (!best) best = { x: box.x, y: box.y, hits, dist };
      else if (best.hits > 0 && hits < best.hits) best = { x: box.x, y: box.y, hits, dist };
    }
  }
  if (!best) best = { x: Math.max(1, target.x + gap), y: Math.max(1, target.y - 2.4), hits: 99 };
  o.placement = { ...best, w, h, clamped: best.x < 1 || best.x + w > VIEWBOX_W - 1 };
  const cx = Math.min(VIEWBOX_W - 1 - w, Math.max(1, best.x));
  const cy = Math.min(VIEWBOX_H - 1 - h, Math.max(1, best.y));
  o.callout.setAttribute('transform', `translate(${cx},${cy})`);
  // thin leader from the callout box to the node when they are not adjacent
  const nx = Math.min(cx + w, Math.max(cx, target.x)), ny = Math.min(cy + h, Math.max(cy, target.y));
  const ld = Math.hypot(target.x - nx, target.y - ny);
  const showLeader = ld > NODE_RADIUS[target.type] + 3;
  if (showLeader) {
    const k = (ld - NODE_RADIUS[target.type] - 1.2) / ld;
    o.leader.setAttribute('x1', nx); o.leader.setAttribute('y1', ny);
    o.leader.setAttribute('x2', nx + (target.x - nx) * k); o.leader.setAttribute('y2', ny + (target.y - ny) * k);
  }
  o.leader.setAttribute('class', `topo-leader${showLeader ? ' on' : ''} stage-${currentStage}`);
}

function pointOnEdge(edge, prog) {
  return { x: edge.ax + (edge.bx - edge.ax) * prog, y: edge.ay + (edge.by - edge.ay) * prog };
}

/** False while the map is not rendered (e.g. the Attack detail tab is active): text measuring is meaningless then. */
function topologyVisible() {
  const c = document.getElementById('topology-container');
  return Boolean(c) && c.getClientRects().length > 0;
}

function animateTopology(ts) {
  requestAnimationFrame(animateTopology);
  if (overlayNeedsPlacement && lastTopoStatus && topologyVisible()) updateTopologyStatus(lastTopoStatus);
  if (lastTs === null) lastTs = ts;
  const dt = Math.min(0.05, (ts - lastTs) / 1000);
  lastTs = ts;

  edgeEls.forEach(edge => {
    edge.baseParticles.forEach(p => {
      p.prog = (p.prog + p.speed * dt) % 1;
      const pt = pointOnEdge(edge, p.prog);
      p.el.setAttribute('cx', pt.x);
      p.el.setAttribute('cy', pt.y);
    });
    const mitigating = currentStage === 'MITIGATING';
    edge.attackParticles.forEach((p, i) => {
      // while mitigating: slower and thinner (traffic is being blocked)
      const visible = !mitigating || i < 2;
      p.el.style.display = visible ? '' : 'none';
      p.prog = (p.prog + p.speed * dt * (mitigating ? 0.25 : 1)) % 1;
      const pt = pointOnEdge(edge, p.prog);
      const jitter = (Math.random() - 0.5) * (mitigating ? 0.3 : 1.2);
      p.el.setAttribute('cx', pt.x + jitter);
      p.el.setAttribute('cy', pt.y + jitter);
    });
  });

  if (fxState.active && topologyVisible()) topoFxFrame(ts, dt);

  if (overlay && overlay.arrowGeom && overlay.target) {
    const { x1, y1, x2, y2 } = overlay.arrowGeom;
    const mitigating = currentStage === 'MITIGATING';
    overlay.particles.forEach((p, i) => {
      const show = (currentStage === 'EXECUTING' || currentStage === 'DETECTED') || (mitigating && i < 2);
      p.el.style.display = show ? '' : 'none';
      p.prog = (p.prog + dt * (mitigating ? 0.3 : 0.9)) % 1;
      p.el.setAttribute('cx', x1 + (x2 - x1) * p.prog);
      p.el.setAttribute('cy', y1 + (y2 - y1) * p.prog);
    });
  }
}
