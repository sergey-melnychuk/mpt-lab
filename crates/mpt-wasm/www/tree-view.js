// Shared canvas renderer for a `NodeView`-shaped JSON tree (see lib.rs's
// `NodeView`/`to_view`) -- used by both index.html (a trie reconstructed
// from a real eth_getProof witness) and build.html (a trie built from
// scratch). Draws it as a single selectable "spine": one box per depth
// level, following the SELECTED nibble at each Fork, with the other 15
// nibbles shown as a compact strip of tiny cells to the right (never to the
// left -- the spine's left edge never moves, so navigating never re-flows
// the whole diagram, only grows it rightward). Only a present, non-Stub
// child is selectable: a Stub carries nothing beyond its hash, so there's
// nothing to drill into.
//
// Callers must define the same set of CSS custom properties this reads via
// `cssVar` (--leaf/--leaf-bg/--skip/--skip-bg/--fork/--fork-bg/--stub/
// --stub-bg/--null/--border/--panel/--muted/--bg/--text) on :root.

const COLORS = {
  Leaf: ["--leaf", "--leaf-bg"],
  Skip: ["--skip", "--skip-bg"],
  Fork: ["--fork", "--fork-bg"],
  Stub: ["--stub", "--stub-bg"],
  Null: ["--null", "--stub-bg"],
};

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function nibblesToBytes(nibbles) {
  const bytes = new Uint8Array(nibbles.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = (nibbles[2 * i] << 4) | nibbles[2 * i + 1];
  }
  return bytes;
}

function nibbleStringToArray(s) {
  return [...s].map((c) => parseInt(c, 16));
}

function tryDecodeKey(nibbleArray) {
  if (nibbleArray.length % 2 !== 0) return "0x" + nibbleArray.map((n) => n.toString(16)).join("");
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(nibblesToBytes(nibbleArray));
  } catch {
    return "0x" + nibbleArray.map((n) => n.toString(16)).join("");
  }
}

function decodeHexValue(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return "0x" + hex;
  }
}

function buildSpine(view, selection) {
  const spine = [];
  let node = view;
  let prefix = [];
  while (node) {
    const entry = { view: node, prefix };
    spine.push(entry);

    if (node.kind === "Skip") {
      prefix = prefix.concat(nibbleStringToArray(node.path));
      node = node.child;
      continue;
    }

    if (node.kind !== "Fork") break; // Leaf, Stub, Null, __value__: terminal

    const cells = [];
    for (let n = 0; n < 16; n++) {
      const c = (node.children ?? []).find((c) => c.nibble === n);
      cells.push({ nibble: n, present: !!c, isStub: !!c && c.node.kind === "Stub", child: c ? c.node : null });
    }
    const forkKey = prefix.join(".") || "root";
    // An explicitly selected Stub is honoured -- only a focus can set one,
    // never a click (hit regions skip Stubs) -- so a story frame can show
    // the hash-only node a collapse lands on. The fallback still avoids them.
    const selectable = (n) => cells[n]?.present;

    let sel = selection.get(forkKey);
    if (sel === undefined || (sel === "value" ? node.value === undefined : !selectable(sel))) {
      const first = cells.findIndex((c) => c.present && !c.isStub);
      sel = first !== -1 ? first : undefined;
      selection.set(forkKey, sel);
    }

    entry.forkKey = forkKey;
    entry.cells = cells;
    entry.hasValue = node.value !== undefined;
    entry.selected = sel;

    if (sel === undefined) node = null;
    else if (sel === "value") node = { kind: "__value__", value: node.value };
    else {
      prefix = prefix.concat([sel]);
      node = cells[sel].child;
    }
  }
  return spine;
}

const NODE_W = 150;
const NODE_H = 46;
const GAP_Y = 58;
const PAD = 24;
// The nibble strip is the one thing meant to be visibly bigger: it's the
// actual click target, and 15px cells were too small to hit reliably.
const CELL = 30;
const CELL_GAP = 4;
const STRIP_MARGIN = 20;

export function placeholder(canvas, text) {
  const ctx = canvas.getContext("2d");
  canvas.width = 340;
  canvas.height = 60;
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = cssVar("--muted");
  ctx.font = "13px sans-serif";
  ctx.fillText(text, 12, 30);
}

function drawBox(ctx, entry, x, y) {
  const view = entry.view;
  const kind = view.kind === "__value__" ? "Leaf" : view.kind;
  const [fgVar, bgVar] = COLORS[kind] ?? COLORS.Null;
  const fg = cssVar(fgVar), bg = cssVar(bgVar);
  const cx = x + NODE_W / 2;

  ctx.beginPath();
  ctx.roundRect ? ctx.roundRect(x, y, NODE_W, NODE_H, 8) : ctx.rect(x, y, NODE_W, NODE_H);
  ctx.fillStyle = bg;
  ctx.fill();
  ctx.strokeStyle = fg;
  ctx.lineWidth = 1.5;
  if (view.kind === "Stub") ctx.setLineDash([4, 3]);
  ctx.stroke();
  ctx.setLineDash([]);

  ctx.fillStyle = fg;
  ctx.textAlign = "center";
  ctx.font = "bold 11.5px sans-serif";
  ctx.fillText(view.unknown ? "?" : view.kind === "__value__" ? "value" : view.kind, cx, y + 15);

  ctx.font = "10.5px ui-monospace, monospace";
  ctx.fillStyle = cssVar("--muted");
  let sub;
  if (view.kind === "Leaf") {
    sub = tryDecodeKey(entry.prefix.concat(nibbleStringToArray(view.path)));
  } else if (view.kind === "__value__") {
    sub = decodeHexValue(view.value);
  } else if (view.hash) {
    sub = view.hash.slice(0, 12) + "…";
  } else if (view.pending) {
    // A synthesized in-between frame (transitions.js): this node's subtree
    // changed and its real hash is unknown until the trie is canonical again.
    sub = "rehash pending";
  } else {
    sub = "";
  }
  if (sub) {
    sub = sub.length > 20 ? sub.slice(0, 20) + "…" : sub;
    ctx.fillText(sub, cx, y + 30);
  }
  ctx.font = "9px ui-monospace, monospace";
  ctx.fillText(view.inlined ? "inline" : `${view.size}b`, cx, y + 41);
}

// The strip: one tiny cell per nibble 0-f, plus a small "ε" pill for the
// value slot if present. Grows only to the right of `stripX` -- that's the
// "right-side gravity": the main spine's x-position never depends on how
// many siblings a Fork has.
function drawStrip(ctx, entry, stripX, centerY, hitRegions, cellMarks = {}) {
  const rowY = centerY - CELL / 2;
  for (let n = 0; n < 16; n++) {
    const cell = entry.cells[n];
    const x = stripX + n * (CELL + CELL_GAP);
    const selected = entry.selected === n;
    let fg, bg, dashed = false;
    if (!cell.present) {
      fg = cssVar("--border");
      bg = "transparent";
    } else if (cell.isStub) {
      fg = cssVar("--stub");
      bg = cssVar("--stub-bg");
      dashed = true;
    } else {
      fg = cssVar("--skip");
      bg = selected ? cssVar("--skip") : cssVar("--panel");
    }

    ctx.beginPath();
    ctx.roundRect ? ctx.roundRect(x, rowY, CELL, CELL, 6) : ctx.rect(x, rowY, CELL, CELL);
    ctx.fillStyle = bg;
    ctx.fill();
    ctx.strokeStyle = fg;
    ctx.lineWidth = 1.5;
    if (dashed) ctx.setLineDash([4, 3]);
    ctx.stroke();
    ctx.setLineDash([]);

    ctx.font = "14px ui-monospace, monospace";
    ctx.textAlign = "center";
    ctx.fillStyle = selected ? cssVar("--bg") : cell.present ? fg : cssVar("--muted");
    ctx.fillText(n.toString(16), x + CELL / 2, rowY + CELL / 2 + 5);

    if (cell.present && !cell.isStub) {
      hitRegions?.push({ x, y: rowY, w: CELL, h: CELL, forkKey: entry.forkKey, nibble: n });
    }

    // A ring around a cell the current story frame points at (the survivor
    // of a collapse, say), in that mark's colour.
    const cm = cellMarks[n];
    if (cm) {
      ctx.strokeStyle = ringColor(cm);
      ctx.lineWidth = 2;
      ctx.setLineDash(MARKS[cm]?.dash ?? []);
      ctx.beginPath();
      ctx.roundRect ? ctx.roundRect(x - 3, rowY - 3, CELL + 6, CELL + 6, 8) : ctx.rect(x - 3, rowY - 3, CELL + 6, CELL + 6);
      ctx.stroke();
      ctx.setLineDash([]);
    }
  }

  if (entry.hasValue) {
    const vy = rowY + CELL + 8;
    const selected = entry.selected === "value";
    const label = "ε";
    ctx.font = "15px ui-monospace, monospace";
    const w = Math.max(CELL, ctx.measureText(label).width + 18);
    ctx.beginPath();
    ctx.roundRect ? ctx.roundRect(stripX, vy, w, CELL, 6) : ctx.rect(stripX, vy, w, CELL);
    ctx.fillStyle = selected ? cssVar("--leaf") : cssVar("--panel");
    ctx.fill();
    ctx.strokeStyle = cssVar("--leaf");
    ctx.lineWidth = 1.5;
    ctx.stroke();
    ctx.fillStyle = selected ? cssVar("--bg") : cssVar("--leaf");
    ctx.textAlign = "center";
    ctx.fillText(label, stripX + w / 2, vy + CELL / 2 + 5);
    hitRegions?.push({ x: stripX, y: vy, w, h: CELL, forkKey: entry.forkKey, nibble: "value" });
  }
}

// A few px of slack around each tiny cell -- easier to hit than the exact
// drawn rectangle, at this size a couple of pixels off is not visible.
const HIT_PAD = 3;

function hitAt(canvas, x, y) {
  for (const r of canvas._hitRegions ?? []) {
    if (x >= r.x - HIT_PAD && x <= r.x + r.w + HIT_PAD && y >= r.y - HIT_PAD && y <= r.y + r.h + HIT_PAD) return r;
  }
  return null;
}

function ensureClickHandler(canvas) {
  if (canvas._hasClickHandler) return;
  canvas._hasClickHandler = true;

  // Hover feedback doubles as a diagnostic: if the pointer cursor never
  // shows up over what looks like a real (non-Stub) cell, hit-testing isn't
  // matching what got drawn there.
  canvas.addEventListener("mousemove", (e) => {
    canvas.style.cursor = hitAt(canvas, e.offsetX, e.offsetY) ? "pointer" : "default";
  });
  canvas.addEventListener("mouseleave", () => {
    canvas.style.cursor = "default";
  });

  canvas.addEventListener("click", (e) => {
    const r = hitAt(canvas, e.offsetX, e.offsetY);
    if (!r) return;
    if (r.leafKey) {
      canvas._onLeafClick?.(r.leafKey);
      return;
    }
    canvas._selection.set(r.forkKey, r.nibble);
    try {
      canvas._onSelect?.();
    } catch (err) {
      // A render failure here would otherwise fail SILENTLY: the click
      // handler doesn't rethrow into anything that surfaces to the page.
      console.error("re-render after selecting a branch failed:", err);
    }
  });
}

// Make Leaf boxes (and a Fork's value pill) clickable: `handler` receives
// the clicked box's full key as a nibble array. A page that never calls
// this gets no leaf hit regions, so nothing looks clickable that is not.
export function onLeafClick(canvas, handler) {
  ensureClickHandler(canvas);
  canvas._onLeafClick = handler;
}

// ---------------------------------------------------------------------------
// Layout, focus, marks, and animated transitions.
//
// A spine is a column of boxes, so one key changing is a one-dimensional
// event: boxes enter, leave, or slide to another depth while their labels
// change. Boxes are matched across two layouts by `entryId`: the node's
// kind plus the key range it covers (prefix + own path for a Leaf or Skip,
// prefix for a Fork). A Leaf keeps its full key when a collapse pulls it up
// a level and grows its path, so it slides instead of vanishing and
// reappearing -- the nibble visibly moving from the Fork's edge into the
// Leaf's own path is the whole point of animating a delete-collapse.

const hexOf = (nibbles) => nibbles.map((n) => n.toString(16)).join("");
const lerp = (a, b, t) => a + (b - a) * t;
const easeInOut = (t) => (t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2);
const DEFAULT_DURATION = 480;

function endPrefix(entry) {
  const v = entry.view;
  return v.kind === "Leaf" || v.kind === "Skip" ? entry.prefix.concat(nibbleStringToArray(v.path)) : entry.prefix;
}

export function entryId(entry) {
  return entry.view.kind + "@" + hexOf(endPrefix(entry));
}

// Everything a box shows, to decide whether a matched box needs a crossfade.
function contentSig(entry) {
  const v = entry.view;
  return [v.kind, v.path ?? "", v.hash ?? "", v.value ?? "", v.size ?? "", v.inlined ? 1 : 0, v.pending ? 1 : 0, v.unknown ? 1 : 0, hexOf(entry.prefix)].join("|");
}

// Steer `selection` so the spine follows `key` (a nibble array) as far as
// the trie has it. Forks the key never reaches keep whatever they had, and
// so does a Fork whose slot for the next nibble is empty (a key that was
// just removed) -- `buildSpine`'s fallback then picks a present child.
export function applyFocus(view, selection, key) {
  let node = view;
  let prefix = [];
  let i = 0;
  while (node) {
    if (node.kind === "Skip") {
      const p = nibbleStringToArray(node.path);
      if (hexOf(key.slice(i, i + p.length)) !== node.path) return;
      prefix = prefix.concat(p);
      i += p.length;
      node = node.child;
      continue;
    }
    if (node.kind !== "Fork") return;
    const forkKey = prefix.join(".") || "root";
    if (i >= key.length) {
      if (node.value !== undefined) selection.set(forkKey, "value");
      return;
    }
    const n = key[i];
    const c = (node.children ?? []).find((c) => c.nibble === n);
    if (!c) return;
    selection.set(forkKey, n);
    prefix = prefix.concat([n]);
    i += 1;
    node = c.node;
  }
}

// Positions for one tree: the spine, a y per box, and which marks apply to
// each box (by its prefix) and to each Fork's strip cells (by the cell's
// prefix, i.e. the Fork's prefix followed by the nibble).
export function layoutFor(view, selection, marks = {}) {
  const spine = buildSpine(view, selection);
  const hasFork = spine.some((e) => e.view.kind === "Fork");
  const stripWidth = 16 * (CELL + CELL_GAP) - CELL_GAP;
  const width = PAD * 2 + NODE_W + (hasFork ? STRIP_MARGIN + stripWidth : 0);
  const height = PAD * 2 + spine.length * NODE_H + Math.max(0, spine.length - 1) * GAP_Y;
  const items = spine.map((entry, i) => {
    const p = hexOf(entry.prefix);
    const cellMarks = {};
    if (entry.view.kind === "Fork") {
      for (let n = 0; n < 16; n++) {
        const m = marks[p + n.toString(16)];
        if (m) cellMarks[n] = m;
      }
    }
    return { entry, id: entryId(entry), sig: contentSig(entry), y: PAD + i * (NODE_H + GAP_Y), mark: marks[p] ?? null, cellMarks };
  });
  return { view, items, width, height };
}

const MARKS = {
  removed: { color: () => "#c0392b", label: "removed", dash: [] },
  collapsing: { color: () => cssVar("--fork"), label: "must collapse", dash: [] },
  survivor: { color: () => cssVar("--leaf"), label: "survivor", dash: [] },
  unknown: { color: () => cssVar("--stub"), label: "lookup needed", dash: [4, 3] },
  resolved: { color: () => cssVar("--leaf"), label: "looked up", dash: [] },
  rehashed: { color: () => cssVar("--muted"), label: "", dash: [] },
};

function ringColor(mark) {
  return (MARKS[mark] ?? MARKS.rehashed).color();
}

// A ring just outside the box, with the mark's label above its right edge.
function drawMark(ctx, mark, x, y, alpha) {
  const m = MARKS[mark];
  if (!m || alpha <= 0) return;
  const prev = ctx.globalAlpha;
  ctx.globalAlpha = prev * alpha;
  ctx.strokeStyle = m.color();
  ctx.lineWidth = 2;
  ctx.setLineDash(m.dash);
  ctx.beginPath();
  ctx.roundRect ? ctx.roundRect(x - 4, y - 4, NODE_W + 8, NODE_H + 8, 11) : ctx.rect(x - 4, y - 4, NODE_W + 8, NODE_H + 8);
  ctx.stroke();
  ctx.setLineDash([]);
  if (m.label) {
    ctx.font = "bold 10px sans-serif";
    ctx.textAlign = "right";
    ctx.fillStyle = m.color();
    ctx.fillText(m.label, x + NODE_W + 4, y - 8);
  }
  ctx.globalAlpha = prev;
}

function drawEdge(ctx, centerX, yTop, yBottom, label, alpha) {
  if (alpha <= 0) return;
  const prev = ctx.globalAlpha;
  ctx.globalAlpha = prev * alpha;
  ctx.strokeStyle = cssVar("--border");
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.moveTo(centerX, yTop);
  ctx.lineTo(centerX, yBottom);
  ctx.stroke();
  if (label && yBottom - yTop > 18) {
    const ly = (yTop + yBottom) / 2;
    ctx.font = "11px ui-monospace, monospace";
    ctx.textAlign = "center";
    const w = ctx.measureText(label).width + 6;
    ctx.fillStyle = cssVar("--panel");
    ctx.fillRect(centerX - w / 2, ly - 7, w, 14);
    ctx.fillStyle = cssVar("--muted");
    ctx.fillText(label, centerX, ly + 4);
  }
  ctx.globalAlpha = prev;
}

function edgeLabel(prev) {
  if (prev.view.kind === "Skip") return prev.view.path;
  if (prev.view.kind === "Fork") return prev.selected === "value" ? "ε" : prev.selected?.toString(16) ?? null;
  return null;
}

// `pos` overrides a box's resting y (used mid-transition); boxes not in it
// sit where their layout put them.
function drawEdges(ctx, layout, pos, alpha) {
  const centerX = PAD + NODE_W / 2;
  for (let i = 1; i < layout.items.length; i++) {
    const prev = layout.items[i - 1];
    const cur = layout.items[i];
    const yPrev = pos.get(prev.id) ?? prev.y;
    const yCur = pos.get(cur.id) ?? cur.y;
    drawEdge(ctx, centerX, yPrev + NODE_H, yCur, edgeLabel(prev.entry), alpha);
  }
}

function drawItem(ctx, item, y, alpha, hitRegions, withMark, leafHits = false) {
  if (alpha <= 0) return;
  const prev = ctx.globalAlpha;
  ctx.globalAlpha = prev * alpha;
  drawBox(ctx, item.entry, PAD, y);
  const kind = item.entry.view.kind;
  if (kind === "Fork") {
    drawStrip(ctx, item.entry, PAD + NODE_W + STRIP_MARGIN, y + NODE_H / 2, hitRegions, item.cellMarks);
  } else if (hitRegions && leafHits && (kind === "Leaf" || kind === "__value__")) {
    // The box stands for one key: prefix + own path for a Leaf, the Fork's
    // prefix for its value pill.
    const key = kind === "Leaf" ? item.entry.prefix.concat(nibbleStringToArray(item.entry.view.path)) : item.entry.prefix;
    hitRegions.push({ x: PAD, y, w: NODE_W, h: NODE_H, leafKey: key });
  }
  ctx.globalAlpha = prev;
  if (withMark && item.mark) drawMark(ctx, item.mark, PAD, y, alpha);
}

function setupCanvas(canvas, width, height) {
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, width * dpr);
  canvas.height = Math.max(1, height * dpr);
  canvas.style.width = width + "px";
  canvas.style.height = height + "px";
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);
  ctx.globalAlpha = 1;
  return ctx;
}

function paintLayout(canvas, layout) {
  const ctx = setupCanvas(canvas, layout.width, layout.height);
  const hitRegions = [];
  drawEdges(ctx, layout, new Map(), 1);
  for (const item of layout.items) drawItem(ctx, item, item.y, 1, hitRegions, true, !!canvas._onLeafClick);
  canvas._hitRegions = hitRegions;
}

// One frame of A -> B at eased progress t. Matched boxes slide and, if what
// they show changed, crossfade; unmatched ones fade out (only in A) or in
// (only in B). A matched box whose hash changed gets a brief grey ring: the
// rehash travelling up the path. Clicks are not served mid-transition; hit
// regions are set when the final frame is painted.
function paintTransition(canvas, A, B, t) {
  const ctx = setupCanvas(canvas, Math.max(A.width, B.width), Math.max(A.height, B.height));
  const aById = new Map(A.items.map((it) => [it.id, it]));
  const bById = new Map(B.items.map((it) => [it.id, it]));
  const pos = new Map();
  for (const b of B.items) {
    const a = aById.get(b.id);
    pos.set(b.id, a ? lerp(a.y, b.y, t) : b.y);
  }
  for (const a of A.items) if (!bById.has(a.id)) pos.set(a.id, a.y);

  drawEdges(ctx, A, pos, 1 - t);
  drawEdges(ctx, B, pos, t);
  for (const a of A.items) {
    if (!bById.has(a.id)) drawItem(ctx, a, pos.get(a.id), 1 - t, null, true);
  }
  for (const b of B.items) {
    const a = aById.get(b.id);
    const y = pos.get(b.id);
    if (!a) {
      drawItem(ctx, b, y, t, null, true);
      continue;
    }
    if (a.sig === b.sig) {
      drawItem(ctx, b, y, 1, null, false);
    } else {
      drawItem(ctx, a, y, 1 - t, null, false);
      drawItem(ctx, b, y, t, null, false);
    }
    if (b.mark) drawMark(ctx, b.mark, PAD, y, a.mark === b.mark ? 1 : t);
    else if ((a.entry.view.hash ?? "") !== (b.entry.view.hash ?? "")) drawMark(ctx, "rehashed", PAD, y, Math.sin(Math.PI * t));
  }
  canvas._hitRegions = [];
}

function reducedMotion() {
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches === true;
}

function animate(canvas, A, B, duration, onDone) {
  const start = performance.now();
  const step = (now) => {
    const t = Math.min(1, (now - start) / duration);
    paintTransition(canvas, A, B, easeInOut(t));
    if (t < 1) {
      canvas._anim = requestAnimationFrame(step);
    } else {
      canvas._anim = null;
      paintLayout(canvas, B);
      onDone?.();
    }
  };
  canvas._anim = requestAnimationFrame(step);
}

// Generic renderer: draws any NodeView-shaped JSON (from WasmTrie or
// WasmProofTrie) onto the given canvas as a single selectable spine.
// `rerender` is called (with no arguments) after a click changes the
// selection -- pass the function that will fetch fresh JSON and call this
// again, not a closure over stale `json`.
//
// `opts`, all optional:
//   focus      nibble array: make the spine follow this key, instead of
//              resetting the selection because the root hash changed
//   from       the previously shown tree's JSON: animate from it to `json`
//   marks      { nibblePrefixHex: "removed" | "collapsing" | "survivor" |
//                "unknown" | "resolved" | "rehashed" }, decorations on `json`
//   fromMarks  the same for `from`, so a mark carried over does not blink
//   duration   ms; 0 paints the final frame at once
//   onDone     called once the final frame is on the canvas
export function drawTreeJson(canvas, json, rerender, opts = {}) {
  ensureClickHandler(canvas);
  canvas._onSelect = rerender;
  if (canvas._anim) {
    cancelAnimationFrame(canvas._anim);
    canvas._anim = null;
  }

  const view = JSON.parse(json);
  if (!canvas._selection || (!opts.focus && canvas._lastRootHash !== view.hash)) {
    canvas._selection = new Map();
  }
  canvas._lastRootHash = view.hash;

  if (opts.from) {
    const fromView = JSON.parse(opts.from);
    if (opts.focus) applyFocus(fromView, canvas._selection, opts.focus);
    const A = layoutFor(fromView, canvas._selection, opts.fromMarks ?? {});
    if (opts.focus) applyFocus(view, canvas._selection, opts.focus);
    const B = layoutFor(view, canvas._selection, opts.marks ?? {});
    const duration = reducedMotion() ? 0 : (opts.duration ?? DEFAULT_DURATION);
    if (duration > 0) {
      animate(canvas, A, B, duration, opts.onDone);
      return;
    }
    paintLayout(canvas, B);
    opts.onDone?.();
    return;
  }

  if (opts.focus) applyFocus(view, canvas._selection, opts.focus);
  paintLayout(canvas, layoutFor(view, canvas._selection, opts.marks ?? {}));
  opts.onDone?.();
}
