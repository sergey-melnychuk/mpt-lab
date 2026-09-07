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
    const selectable = (n) => cells[n]?.present && !cells[n].isStub;

    let sel = selection.get(forkKey);
    if (sel === undefined || (sel !== "value" && !selectable(sel))) {
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
  ctx.fillText(view.kind === "__value__" ? "value" : view.kind, cx, y + 15);

  ctx.font = "10.5px ui-monospace, monospace";
  ctx.fillStyle = cssVar("--muted");
  let sub;
  if (view.kind === "Leaf") {
    sub = tryDecodeKey(entry.prefix.concat(nibbleStringToArray(view.path)));
  } else if (view.kind === "__value__") {
    sub = decodeHexValue(view.value);
  } else if (view.hash) {
    sub = view.hash.slice(0, 12) + "…";
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
function drawStrip(ctx, entry, stripX, centerY, hitRegions) {
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
      hitRegions.push({ x, y: rowY, w: CELL, h: CELL, forkKey: entry.forkKey, nibble: n });
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
    hitRegions.push({ x: stripX, y: vy, w, h: CELL, forkKey: entry.forkKey, nibble: "value" });
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

// Generic renderer: draws any NodeView-shaped JSON (from WasmTrie or
// WasmProofTrie) onto the given canvas as a single selectable spine.
// `rerender` is called (with no arguments) after a click changes the
// selection -- pass the function that will fetch fresh JSON and call this
// again, not a closure over stale `json`.
export function drawTreeJson(canvas, json, rerender) {
  ensureClickHandler(canvas);
  canvas._onSelect = rerender;

  const view = JSON.parse(json);
  if (canvas._lastRootHash !== view.hash) {
    canvas._selection = new Map();
    canvas._lastRootHash = view.hash;
  }

  const spine = buildSpine(view, canvas._selection);
  const hasFork = spine.some((e) => e.view.kind === "Fork");
  const stripWidth = 16 * (CELL + CELL_GAP) - CELL_GAP;

  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const width = PAD * 2 + NODE_W + (hasFork ? STRIP_MARGIN + stripWidth : 0);
  const height = PAD * 2 + spine.length * NODE_H + Math.max(0, spine.length - 1) * GAP_Y;
  canvas.width = Math.max(1, width * dpr);
  canvas.height = Math.max(1, height * dpr);
  canvas.style.width = width + "px";
  canvas.style.height = height + "px";
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);

  const boxX = PAD;
  const centerX = boxX + NODE_W / 2;
  const hitRegions = [];
  let y = PAD;

  for (let i = 0; i < spine.length; i++) {
    const entry = spine[i];

    if (i > 0) {
      ctx.strokeStyle = cssVar("--border");
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(centerX, y - GAP_Y);
      ctx.lineTo(centerX, y);
      ctx.stroke();

      const prev = spine[i - 1];
      const label =
        prev.view.kind === "Skip" ? prev.view.path : prev.view.kind === "Fork" ? (prev.selected === "value" ? "ε" : prev.selected.toString(16)) : null;
      if (label) {
        const ly = y - GAP_Y / 2;
        ctx.font = "11px ui-monospace, monospace";
        ctx.textAlign = "center";
        const w = ctx.measureText(label).width + 6;
        ctx.fillStyle = cssVar("--panel");
        ctx.fillRect(centerX - w / 2, ly - 7, w, 14);
        ctx.fillStyle = cssVar("--muted");
        ctx.fillText(label, centerX, ly + 4);
      }
    }

    drawBox(ctx, entry, boxX, y);
    if (entry.view.kind === "Fork") {
      drawStrip(ctx, entry, boxX + NODE_W + STRIP_MARGIN, y + NODE_H / 2, hitRegions);
    }

    y += NODE_H + GAP_Y;
  }

  canvas._hitRegions = hitRegions;
}
