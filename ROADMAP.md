# Roadmap

The core is done: insert, get, delete, byte-exact roots against all 22
`ethereum/tests` fixtures, and inclusion plus exclusion proofs with a stateless
verifier. Four directions from here, none of which depend on the others. This
file is decision material, not a plan — pick one.

Quick comparison:

| | Effort | New concepts | Risk of a dead end | What it proves |
|---|---|---|---|---|
| **Mainnet verification** | ~1 day | Low | Very low | The bit-exactness was real |
| **Visualizer** | 1–2 weeks | Medium (wasm, layout) | Medium | Understanding, and it's the artifact |
| **Incremental hashing** | 3–5 days | Medium (dirty tracking) | Low | Real client architecture |
| **Fuzzing** | ~1 day setup | Low | Low | Correctness beyond what tests reach |

---

## 1. Mainnet verification

Point the trie at real Ethereum state. Fetch a block header's `stateRoot`, call
`eth_getProof` for an account, and verify that proof against the header root
with our own `verify_proof`. Then do the storage trie nested inside it.

**Why it's worth doing.** This is the payoff for bit-exactness, and it is short.
Passing `ethereum/tests` says the encoding is right; validating a live account
balance against a root that consensus agreed on says the whole thing is right.
It is also the only follow-up that can be finished in an afternoon.

**What it needs.**
- An RPC endpoint. Any public one works for reads.
- The account trie's key is `keccak256(address)` — the secure-trie mode already
  wired up for the fixtures.
- The account *value* is `rlp([nonce, balance, storageRoot, codeHash])`. Decoding
  it is the first time the trie's values have had internal structure.
- Storage keys are `keccak256(slot)` and storage values are RLP-encoded integers
  with no leading zeros, which is its own small canonicality trap.
- `eth_getProof` returns `accountProof` and `storageProof` as hex node lists,
  which drop straight into `verify_proof`.

**Where it will be interesting.** Proofs for absent accounts. Most addresses have
never been touched, so `eth_getProof` on a random address returns an *exclusion*
proof — real-world confirmation of §7.4. Also worth checking: an account whose
`storageRoot` is the empty-trie constant, which exercises §7.5.

**Risk.** Almost none. If it fails, the failure localises to a specific node.

---

## 2. Interactive visualizer (wasm + canvas/SVG)

Compile `mpt-core` to `wasm32-unknown-unknown` and render the trie in a browser.
This was the original motivation and everything it needs now exists.

**Why it's worth doing.** The MPT's difficulty is structural, not algorithmic:
holding in your head what a leaf splitting into a fork looks like, or what a
branch collapse does on delete. Those are graph rewrites, and a picture removes
the imagining. It is also the only follow-up that produces something to show
someone.

**Architecture, decided but not yet built.**
- Workspace split: `mpt-core` (no wasm awareness, no viz awareness), `mpt-wasm`
  (the bindgen boundary), `web/`.
- Mutating operations parameterised over an `Observer` trait with a no-op ZST
  default, so instrumented and uninstrumented builds compile to the same code.
- The interesting design question is what an `Event` should carry. "Node changed"
  is useless for animation; the vocabulary wants to be the rewrites themselves —
  `PathSplit { at_nibble }`, `ForkCollapsed { into }`, `RehashedUpward { .. }`.
  Defining that vocabulary is the same problem as understanding the algorithm.
- Serialise a whole snapshot plus an event list to JSON per operation. A few
  hundred nodes is nothing; don't get clever with shared memory.

**Rendering: SVG or canvas 2D, not WebGL.** The content is dominated by text —
nibble paths, HP prefixes, truncated hashes — and text plus hit-testing is what
WebGL makes hardest and the DOM makes free. At this scale nothing is fill-rate
bound. Revisit only for a million-node real state trie, which is a different
project.

**Layout warning.** Tidy-tree layouts look terrible on 17-ary forks. Do not fan
out sixteen slots with fourteen empty. Draw a fork as a compact 16-cell
occupancy strip, with edges only from occupied slots.

**Three views worth building, in order:**
1. **Inlining.** Render sub-32-byte children physically *inside* their parent's
   box. This is the rule people get wrong most often and the reason proof length
   ≠ path depth (§5.2, §7.2). Drawn correctly it stops being a footnote.
2. **Dirty propagation on insert.** Highlight which nodes got re-hashed and which
   did not. Explains the point of Merkleization in one frame. Pairs naturally
   with follow-up 3.
3. **Proof scope.** Grey the trie out, highlight the nodes a proof actually
   contains, and mark the termination point for exclusion proofs explicitly.

**Suggested first move.** A throwaway toolchain spike: get `merkle.rs` compiling
to wasm, call `root()` from JS, draw boxes, stop. Half a day, settles the build
story (`wasm-pack` + a bundler, or `trunk`) while the surface area is trivial.

**Risk.** Medium. Layout work expands to fill available time, and the event
vocabulary may need a couple of rewrites before it feels right.

---

## 3. Incremental hashing

Replace on-demand Merkleization (§5.1) with dirty tracking, so `hash()` rehashes
only the path that changed instead of the whole trie.

**Why it's worth doing.** It is what every real client does, it is a genuine
algorithmic change rather than plumbing, and the existing test suite is a
complete safety net — the roots must not move by a single bit.

**What it needs.**
- A cached `Option<H::Out>` (or cached encoding) per node, invalidated up the
  path on mutation.
- A decision about ownership. Cached hashes plus `Box<Node>` means mutation needs
  `&mut` all the way down, which the current recursive by-value style already
  gives you. An `Rc`/arena representation would allow structural sharing between
  trie versions, which is what a client needs for reorgs — bigger change, more
  interesting.
- Node-db pruning becomes tractable at the same time (§5.3), since you would then
  know which nodes went away.

**How to validate.** Run the full fixture suite plus a proptest asserting the
incremental root always equals a from-scratch recompute after every operation.
That property is the whole test.

**Bonus.** This is the version the visualizer's dirty-propagation view wants, so
doing it first makes follow-up 2 better.

**Risk.** Low. Wrong answers show up immediately as root mismatches.

---

## 4. Differential fuzzing

`cargo-fuzz` over random operation sequences, comparing against `alloy-trie` or
`eth_trie`.

**Why it's worth doing.** The property tests explore a shallow space: short keys,
small maps, and a shuffle. A fuzzer finds the inputs nobody thought to write —
particularly around deletion, where the collapse rules have the most branches.

**What it needs.**
- A fuzz target taking arbitrary bytes, decoding them into an op sequence
  (insert/remove with keys and values from a small alphabet, to encourage
  collisions and shared prefixes), applying to both implementations, and
  comparing roots after every step.
- A second target for `verify_proof` fed arbitrary bytes as the proof, asserting
  only that it returns rather than panicking. Cheap, and it is the
  attacker-facing surface.
- A third comparing our proofs against the reference's, since a proof that
  verifies is not necessarily the *canonical* proof (§7.3).

**Where a bug is most likely.** Deletion collapse across the 32-byte inlining
boundary, and hex-prefix parity on odd-length paths at depth.

**Risk.** Low, and the least interesting to write. Highest chance of finding
something real per hour spent.

---

## Also open

Small items, each an hour or two, recorded so they aren't lost:

- **The three `> OPEN:` blocks in NOTES.md.** `size` provenance in the binary
  tree, RLP recursion depth limiting, and whether `Hasher` genericity earns its
  keep now that `ProofError` hardcodes `[u8; 32]`.
- **Iteration.** Ordered traversal yielding key/value pairs. Needed by anything
  that wants to diff two tries.
- **Range proofs.** Prove a contiguous span of keys with one witness. This is how
  snap sync works, and it builds directly on §7.
- **Trie diffing.** Given two roots and a shared node db, enumerate what changed.
  Falls out of structural sharing if follow-up 3 goes the `Rc` route.

---

## A suggestion, not a decision

If forced to order them: **mainnet first** (one day, closes the loop, and
validating a real account balance is a good moment), then **incremental
hashing** (sets up the dirty-node view), then the **visualizer** with real state
flowing through it. **Fuzzing** slots in anywhere and is worth doing before
anything gets called finished.

But the visualizer was the original motivation, and motivation is worth more than
sequencing.
