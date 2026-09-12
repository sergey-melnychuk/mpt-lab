// The states a trie passes through when one key changes, reconstructed from
// the NodeView JSON before and after (see lib.rs's `to_view`).
//
// mpt-core mutates atomically and re-derives the canonical shape in one
// pass, so the intermediate states -- the Fork left with a single occupant,
// the survivor whose variant nobody knows yet -- never exist as a trie. They
// are what makes a delete-collapse understandable, though, so this module
// builds them by hand from the before-snapshot, one collapse rule at a time
// (NOTES.md §6.2, PLAN.md §1). Pure functions over plain JSON, no DOM.
//
// Frame notes are deliberately terse: the picture carries the explanation.

const pathNibbles = (s) => [...(s ?? "")].map((c) => parseInt(c, 16));
const hexOf = (nibbles) => nibbles.map((n) => n.toString(16)).join("");
const clone = (v) => JSON.parse(JSON.stringify(v));
const at = (prefix) => "/" + (hexOf(prefix) || "");

// Hex string -> nibble array, with the same odd-length rule as lib.rs's
// `parse_hex_bytes`: "0x1" is one byte 0x01, i.e. nibbles [0, 1].
export function hexToNibbles(hex) {
  let s = hex.trim();
  if (s.startsWith("0x") || s.startsWith("0X")) s = s.slice(2);
  if (s.length % 2 === 1) s = "0" + s;
  return [...s.toLowerCase()].map((c) => parseInt(c, 16));
}

// Walk `view` along `key` (nibble array). Returns every node on the way as
// { node, prefix } -- `prefix` being the nibbles consumed before reaching
// it -- plus how the key terminates: at a Leaf holding exactly it ("leaf"),
// in a Fork's value slot ("value"), or nowhere ("absent").
export function walkKey(view, key) {
  const chain = [];
  let node = view;
  let prefix = [];
  let i = 0;
  for (;;) {
    chain.push({ node, prefix });
    if (node.kind === "Leaf") {
      return { chain, end: hexOf(key.slice(i)) === (node.path ?? "") ? "leaf" : "absent" };
    }
    if (node.kind === "Skip") {
      const p = pathNibbles(node.path);
      if (hexOf(key.slice(i, i + p.length)) !== node.path) return { chain, end: "absent" };
      prefix = prefix.concat(p);
      i += p.length;
      node = node.child;
      continue;
    }
    if (node.kind === "Fork") {
      if (i === key.length) return { chain, end: node.value !== undefined ? "value" : "absent" };
      const c = (node.children ?? []).find((c) => c.nibble === key[i]);
      if (!c) return { chain, end: "absent" };
      prefix = prefix.concat([key[i]]);
      i += 1;
      node = c.node;
      continue;
    }
    return { chain, end: "absent" }; // Stub or Null
  }
}

// The node object sitting exactly at `prefix` (a prefix that ends on a node
// boundary, as every `walkKey` chain prefix does). Used to edit a clone.
function nodeAt(view, prefix) {
  let node = view;
  let i = 0;
  while (i < prefix.length) {
    if (node.kind === "Skip") {
      i += pathNibbles(node.path).length;
      node = node.child;
    } else if (node.kind === "Fork") {
      const c = (node.children ?? []).find((c) => c.nibble === prefix[i]);
      if (!c) return null;
      i += 1;
      node = c.node;
    } else {
      return null;
    }
  }
  return node;
}

// Every node from the root down to (and including) `prefix` gets rehashed by
// a change below it. The synthesized frames cannot know the new hashes, and
// must not show the old ones as if they still held.
function markPending(view, chain, upto) {
  for (const c of chain.slice(0, upto + 1)) {
    const n = nodeAt(view, c.prefix);
    if (n) {
      n.hash = "";
      n.pending = true;
    }
  }
}

const occupancy = (fork) => (fork.children ?? []).length + (fork.value !== undefined ? 1 : 0);

// Frames for removing `key` (nibble array): [{ view, focus, marks, note }].
// `view` is NodeView JSON to draw, `focus` the nibble path the spine should
// follow, `marks` a map of nibble-prefix -> style for the renderer to
// decorate, `note` a few words for that step. frames[0] is the before state
// with the doomed node marked; the last frame is `after` itself. Returns
// null when the key was not in `before` -- there is nothing to show.
export function removalStory(before, after, key) {
  const { chain, end } = walkKey(before, key);
  if (end === "absent") return null;

  const keyLabel = "0x" + hexOf(key);
  const term = chain[chain.length - 1];
  const frames = [];

  // The whole trie is this one leaf.
  if (end === "leaf" && chain.length === 1) {
    frames.push({ view: before, focus: key, marks: { "": "removed" }, note: `Removing ${keyLabel}` });
    frames.push({ view: after, focus: key, marks: {}, note: "Only key removed — trie empty" });
    return frames;
  }

  // The Fork that loses an occupant: the terminal itself when the key ends in
  // a value slot, otherwise the Leaf's parent (a Leaf's parent is always a
  // Fork -- a Skip's child is always a Fork, so a Leaf never hangs off one).
  const forkIdx = end === "value" ? chain.length - 1 : chain.length - 2;
  const forkP = chain[forkIdx].prefix;
  const removedNibble = end === "value" ? null : key[forkP.length];

  frames.push({
    view: before,
    focus: key,
    marks: { [hexOf(term.prefix)]: "removed" },
    note: end === "value" ? `Removing ${keyLabel} (value slot)` : `Removing ${keyLabel}`,
  });

  // Frame 1: the occupant is gone, nothing has been reshaped yet.
  const f1 = clone(before);
  const fork1 = nodeAt(f1, forkP);
  if (end === "value") delete fork1.value;
  else fork1.children = fork1.children.filter((c) => c.nibble !== removedNibble);
  markPending(f1, chain, forkIdx);
  const occ = occupancy(fork1);

  if (occ >= 2) {
    frames.push({
      view: f1,
      focus: forkP,
      marks: { [hexOf(forkP)]: "rehashed" },
      note: `Leaf gone — Fork keeps ${occ}, no collapse`,
    });
    frames.push({ view: after, focus: forkP, marks: {}, note: "Done — path re-hashed" });
    return frames;
  }

  // occ === 1: the Fork must collapse onto whatever is left.
  const survivorChild = fork1.children[0]; // undefined when only the value slot remains
  const parentIsSkip = forkIdx > 0 && chain[forkIdx - 1].node.kind === "Skip";
  const merged = parentIsSkip ? "; Skip merged" : "";

  if (!survivorChild) {
    frames.push({
      view: f1,
      focus: forkP,
      marks: { [hexOf(forkP)]: "collapsing" },
      note: "Fork down to its value slot — must collapse",
    });
    frames.push({
      view: after,
      focus: forkP,
      marks: { [hexOf(forkP)]: "survivor" },
      note: `Fork → Leaf, no lookup needed${merged}`,
    });
    return frames;
  }

  const n = survivorChild.nibble;
  const surv = survivorChild.node;
  const survP = forkP.concat([n]);
  const survKey = hexOf(survP);
  const nib = n.toString(16);

  frames.push({
    view: f1,
    focus: survP,
    marks: { [hexOf(forkP)]: "collapsing", [survKey]: "survivor" },
    note: "Fork down to one child — must collapse",
  });

  if (surv.inlined) {
    frames.push({
      view: f1,
      focus: survP,
      marks: { [hexOf(forkP)]: "collapsing", [survKey]: "resolved" },
      note: `Survivor inlined (${surv.size} B) — no lookup`,
    });
  } else {
    const unknown = clone(f1);
    const slot = nodeAt(unknown, forkP).children.find((c) => c.nibble === n);
    slot.node = { kind: "Stub", hash: surv.hash, size: surv.size, inlined: false, unknown: true };
    frames.push({
      view: unknown,
      focus: survP,
      marks: { [hexOf(forkP)]: "collapsing", [survKey]: "unknown" },
      note: `Hash only — lookup needed at ${at(survP)}`,
    });
    frames.push({
      view: f1,
      focus: survP,
      marks: { [hexOf(forkP)]: "collapsing", [survKey]: "resolved" },
      note: `Looked up: ${surv.kind}` + (surv.path !== undefined ? `, path "${surv.path}"` : ""),
    });
  }

  // Where the survivor ended up in `after`: walk its old position.
  const landed = walkKey(after, survP).chain;
  const landedP = landed[landed.length - 1].prefix;
  frames.push({
    view: after,
    focus: survP,
    marks: { [hexOf(landedP)]: "survivor" },
    note: `Collapsed — nibble ${nib} joins survivor's path${merged}`,
  });
  return frames;
}

// A few words on an insert or update of `key`, for the transition that
// animates it (no intermediate frames needed: nothing is unknown).
export function describeChange(before, after, key, kind) {
  const keyLabel = "0x" + hexOf(key);
  if (kind === "update") return `Updated ${keyLabel} — path re-hashed`;
  const { chain } = walkKey(before, key);
  switch (chain[chain.length - 1].node.kind) {
    case "Null":
      return `Inserted ${keyLabel} — first key`;
    case "Leaf":
      return `Inserted ${keyLabel} — Leaf split into a Fork`;
    case "Skip":
      return `Inserted ${keyLabel} — Skip split`;
    case "Fork":
      return `Inserted ${keyLabel} — empty Fork slot`;
    default:
      return `Inserted ${keyLabel}`;
  }
}
