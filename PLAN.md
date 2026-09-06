# PLAN.md — Phase B: on-demand node resolution

Implementation brief. Self-contained: everything needed to start is here, with
pointers to `NOTES.md` and `PTRIE.md` for background.

**Goal:** make `insert` and `remove` work on a partial trie by fetching missing
nodes from a store, instead of panicking when traversal reaches a `Stub`.

**Current state:** Phase A is done and verified against mainnet. A trie
reconstructed from proofs re-derives real state roots, and value updates
propagate correctly through both the storage and account tries. What does not
work is the one case a proof cannot cover — see §1.

---

## 0. Orientation

### Repository layout

```
crates/mpt-core/          no_std + alloc, no dependencies beyond sha3/rlp/hex
  src/hasher.rs           Hasher trait, Keccak256
  src/merkle.rs           binary Merkle tree — a contrast case, NOT used by the MPT
  src/path.rs             nibble expansion, hex-prefix (compact) codec
  src/trie.rs             Node, Trie, insert/get/remove, encode_node, proofs,
                          decode_node / build_partial / node_root / count_stubs
  tests/                  fixtures.rs (ethereum/tests), trie.rs, remove.rs, proof.rs

crates/mpt-reth/          std, depends on reth v2.5.1 via git tag
  src/bin/live.rs         two-level mainnet verification + mutation
  src/bin/collapse.rs     path-directed fetch of a node no proof contains
```

`mpt-reth` is excluded from the workspace default members; `cargo test` at the
root must not build reth.

### The node model

```rust
pub enum Node<H: Hasher> {
    Null,                                                   // empty trie only
    Leaf { path: Vec<u8>, value: Vec<u8> },                 // yellow paper: leaf
    Skip { path: Vec<u8>, child: Box<Node<H>> },            // yellow paper: EXTENSION
    Fork { children: [Option<Box<Node<H>>>; 16],            // yellow paper: branch
           value: Option<Vec<u8>> },
    Stub(H::Out),                                           // unloaded subtree
}
```

`path` fields hold nibbles, one per `u8`, values `0x0..=0xf`.

Structural invariants, asserted by `Node::debug_check`:

- a `Skip`'s path is never empty
- a `Skip`'s child is always a `Fork` (never a Leaf, never another Skip — those
  merge)
- a `Fork` has at least two occupants, counting children and its value slot
- `Null` appears only as the whole trie's root

`Stub` is always a node whose RLP is ≥ 32 bytes: anything smaller was inlined
into its parent and therefore arrived in the witness for free.

### Reading order

- `PTRIE.md` §3 — what a witness must contain, and the one thing it cannot
- `PTRIE.md` §4 — design decisions already made; do not relitigate without cause
- `PTRIE.md` §6 — the Phase B sketch this plan implements
- `PTRIE.md` §8 — reth integration, verified
- `NOTES.md` §6.2 — the deletion collapse rules in the non-partial case

---

## 1. The problem, precisely

Removing a key can drop a `Fork` to a single occupant, at which point
`normalize` collapses it and `prepend(nibble, sibling)` must produce:

- sibling is a `Leaf` → `Leaf { path: [n] ++ path, value }`
- sibling is a `Skip` → `Skip { path: [n] ++ path, child }`
- sibling is a `Fork` → `Skip { path: [n], child: fork }`

Three different results. A `Stub` tells you which one applies: nothing. The hash
does not encode the variant.

And the sibling hangs off a *different nibble* of that Fork, so it was never on
the deleted key's path and the inclusion proof never contained it. The Fork
holds only its 32-byte reference.

**This is the only place a sideways, non-path resolution is needed.** Inserts,
updates and non-collapsing removes are all satisfied by the path the traversal
is already walking.

In Ethereum terms it is routine, not exotic: `SSTORE(slot, 0)` **is** a
deletion. There is no "slot present with value zero".

Resolution is one level deep. Once the sibling is loaded, its own children stay
`Stub`, because `prepend` changes the sibling's path, not its children's
references.

---

## 2. Step 0 — measure first (30 minutes, do this before anything else)

`collapse.rs` already computes the deepest `Fork` on a key's path and reports
its occupancy. Extend it to loop over many slots and print a histogram.

Sample: a few hundred slots across contracts with different storage shapes —
USDC (dense), an NFT contract, something with sparse storage. For each, report
whether removing it would collapse a Fork (occupancy == 2) and whether the
surviving sibling is a `Stub` or arrived inlined.

**Why this gates the rest.** With 16-way branching over uniformly distributed
secure-trie keys, most Forks near the top have many occupants. If the collapse
fires on 30% of removals, Phase B is core infrastructure and steps 1–4 are all
worth doing properly. If it fires on 0.5%, the honest design may be "return
`MissingNode` and let the caller fetch and retry" — far less work than threading
a provider through every traversal.

Record the number in `PTRIE.md` §10, which currently lists this as the first
open question.

---

## 3. Step 1 — `TrieError` and `Result`-ify traversal

The bulk of the remaining work. Entirely mechanical, no design decisions. Do it
in one commit, with no provider anywhere.

### 3.1 The error type

New file `crates/mpt-core/src/error.rs`:

```rust
/// Reasons a traversal over a partial trie can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrieError<H: Hasher> {
    /// Traversal reached a subtree we do not have.
    ///
    /// `path` is the nibble prefix at which the stub sits. Both fields are
    /// load-bearing: the path steers a fetch (PTRIE.md §8.1), the hash
    /// verifies the result.
    MissingNode { hash: H::Out, path: Vec<u8> },
    /// A store returned bytes that do not hash to the stub's reference.
    HashMismatch { expected: H::Out, got: H::Out },
    /// Bytes that are not a valid 2- or 17-item RLP node.
    MalformedNode,
}
```

Deriving on a generic enum adds an `H: Clone + PartialEq` bound that a marker
type cannot satisfy — write the impls by hand, or bound on `H::Out` only. See
`PTRIE.md` §4.2; the same problem was hit adding `Stub`.

`Display` + `core::error::Error` impls: needed, and `ProofError` already has
them for reference. Note `core::error::Error` requires `Display`.

### 3.2 Signature changes

```rust
fn insert_at<H>(node: Node<H>, suffix: &[u8], value: Vec<u8>) -> Node<H>
// becomes
fn insert_at<H>(node: Node<H>, suffix: &[u8], value: Vec<u8>) -> Result<Node<H>, TrieError<H>>
```

Same for `remove_at` (currently `(Node, bool)` → `Result<(Node, bool), _>`),
`normalize`, `prepend`, and `get_at`. Public `Trie::insert` / `remove` / `get`
follow.

Each currently has a `Stub` arm that panics. Replace with:

```rust
Node::Stub(h) => return Err(TrieError::MissingNode { hash: h, path: path_so_far.to_vec() }),
```

### 3.3 Threading the path

`MissingNode.path` requires knowing which nibbles were consumed to reach the
node. The recursion does not currently track this — add a `path_so_far: &[u8]`
parameter, or reconstruct it from the original key minus the remaining suffix.
The latter is less invasive: `&key_nibbles[..key_nibbles.len() - suffix.len()]`.

**Careful with `normalize`.** Its sibling is at `fork_path ++ [sibling_nibble]`,
which is *not* on the key's path, so the subtraction trick does not apply there.
`normalize` needs the fork's own path passed in explicitly.

### 3.4 Test impact

Existing tests never construct a `Stub`, so they stay green. Expect churn from
`?` and `.unwrap()` in test bodies. `tests/fixtures.rs`, `tests/trie.rs`,
`tests/remove.rs` and both `mpt-reth` binaries will all need touching.

### 3.5 Acceptance

- Full existing suite green, including all 22 `ethereum/tests` fixtures.
- `cargo build -p mpt-core --target wasm32-unknown-unknown` still passes.
- New test: build a partial trie from proofs, remove a key whose collapse needs
  an absent sibling, assert `Err(MissingNode { .. })` with the **correct path
  and hash**. Verify by looking the hash up in the parent Fork's RLP.

That last test is the point of the whole step: it turns "which nodes does this
need?" from analysis into observation.

---

## 4. Step 2 — `NodeProvider` and `MapProvider`

### 4.1 The trait

New file `crates/mpt-core/src/partial.rs`:

```rust
/// Resolves a `Stub` to the node it stands for.
///
/// Implementations may key on EITHER argument: a witness map keys on `hash`,
/// reth keys on `path_nibbles` (PTRIE.md §8.1). The caller ALWAYS verifies the
/// returned bytes against `hash`, so a provider is never trusted — the same
/// discipline `verify` applies to every proof node.
pub trait NodeProvider<H: Hasher> {
    /// Return the RLP encoding of the node at `path_nibbles` whose hash is
    /// `hash`, or `None` if this store cannot supply it.
    fn get(&self, path_nibbles: &[u8], hash: &H::Out) -> Option<Vec<u8>>;
}
```

Keep `mpt-core` `no_std` — the trait adds no dependencies.

### 4.2 Provider-aware traversal

```rust
impl<H: Hasher> Trie<H> {
    pub fn insert_with<P: NodeProvider<H>>(&mut self, p: &P, key: &[u8], value: Vec<u8>)
        -> Result<(), TrieError<H>>;
    pub fn remove_with<P: NodeProvider<H>>(&mut self, p: &P, key: &[u8])
        -> Result<bool, TrieError<H>>;
    pub fn get_with<P: NodeProvider<H>>(&self, p: &P, key: &[u8])
        -> Result<Option<&[u8]>, TrieError<H>>;
}
```

Keep the non-`_with` versions as thin wrappers over a never-resolving provider,
so existing call sites are unchanged.

On reaching `Stub(h)`:

```rust
let bytes = p.get(path_so_far, &h)
    .ok_or(TrieError::MissingNode { hash: h, path: path_so_far.to_vec() })?;
let got = H::hash_all(&[&bytes]);
if got != h {
    return Err(TrieError::HashMismatch { expected: h, got });
}
let node = decode_node::<H>(&BTreeMap::new(), &bytes);
// replace in place, then continue into `node`
```

Two things to get right:

- **`decode_node` with an empty map** yields a node whose children are all
  `Stub`, which is exactly right. Resolving one node must not speculatively pull
  its subtree.
- **Replace in place.** Rehashing walks back up the same path and `normalize`
  may revisit nodes, so an in-place swap makes the second visit free. See
  `PTRIE.md` §4.5.

### 4.3 Providers

```rust
/// Offline, from proofs. Ignores the path; fails on anything absent.
pub struct WitnessProvider<H: Hasher>(pub BTreeMap<H::Out, Vec<u8>>);

/// A complete node map, so nothing ever misses. Isolates traversal bugs from
/// witness-construction bugs — use this as the test oracle.
pub struct MapProvider<H: Hasher>(pub BTreeMap<H::Out, Vec<u8>>);

/// Instrumented wrapper recording every (path, hash) requested. This IS the
/// witness builder: run a workload against a complete store, collect what was
/// touched, and that is the minimal witness for that workload.
pub struct RecordingProvider<H: Hasher, P> {
    inner: P,
    seen: RefCell<Vec<(Vec<u8>, H::Out)>>,
}
```

`WitnessProvider` and `MapProvider` are the same code; keep them distinct so
call sites document intent. `RecordingProvider` needs `core::cell::RefCell`,
which is `no_std`-fine.

### 4.4 Acceptance

Build a synthetic full trie and use it as the oracle:

```rust
// 1. Full trie, ~1000 keys. Snapshot every node into a BTreeMap.
// 2. Proofs for a few keys -> a partial trie.
// 3. Apply the same op sequence to both, driving the partial one through
//    MapProvider.
// 4. Assert the roots match after every op.
```

Add a proptest over random maps, random touched subsets, and random interleaved
insert/remove sequences. `tests/remove.rs` already has
`agrees_with_btreemap_under_interleaved_ops` as a template.

---

## 5. Step 3 — the delete-collapse test

The test that actually proves Phase B. Everything above is scaffolding for it.

Construct a trie where a `Fork` has **exactly two** occupants and the sibling is
**not** on the target key's path, so no proof for that key can contain it.

```rust
#[test]
fn delete_collapse_resolves_a_leaf_sibling() {
    // Two keys sharing a long prefix, diverging at one nibble, and nothing
    // else under that Fork. Proof for key A cannot contain key B's leaf.
    // Removing A must resolve B through the provider, prepend the nibble onto
    // B's path, and produce the same root as removing A from the full trie.
}

#[test]
fn delete_collapse_resolves_a_fork_sibling() {
    // Same, but the sibling subtree is large enough to be a Fork, so prepend
    // wraps it in a fresh `Skip { path: [n] }` rather than extending a path.
}
```

Both must assert:

1. removal **without** a provider returns `Err(MissingNode { .. })` naming the
   sibling's hash and path;
2. removal **with** the provider succeeds and yields a root byte-identical to
   the full trie's after the same removal;
3. re-inserting the removed key restores the original root **exactly**.

Assertion 3 is the one that catches non-canonical repair. A trie holding the
right data in the wrong shape answers `get` correctly and hashes wrong — see
`NOTES.md` §6.3.

Also test the value-slot case: a `Fork` whose only remaining occupant is its own
value slot collapses to `Leaf { path: [], value }` and needs no sibling at all.

### Open question to settle here

Resolving a sibling may expose new stubs one level down. Does a single
`normalize` pass still suffice, as it did in the non-partial case
(`NOTES.md` §6.2)? Construct a chain of collapses across several levels and find
out. Record the answer in `PTRIE.md` §10.

---

## 6. Step 4 — `RethProvider`

Ten lines. The mechanism is verified — see `PTRIE.md` §8.2 for a real run.

```rust
impl NodeProvider<Keccak256> for RethProvider {
    fn get(&self, path_nibbles: &[u8], hash: &[u8; 32]) -> Option<Vec<u8>> {
        let probe = key_with_prefix(path_nibbles);   // pack nibbles into a B256
        let mp = self.state.multiproof(
            Default::default(),
            MultiProofTargets::account_with_slots(self.hashed_address, [probe]),
        ).ok()?;
        let sub = mp.storages.get(&self.hashed_address)?;
        sub.subtree.values()
            .map(|b| b.to_vec())
            .find(|n| H::hash_all(&[n]) == *hash)
    }
}
```

`key_with_prefix` already exists in `collapse.rs` — move it somewhere shared.

**Add a cache.** A multiproof returns a complete walk (8 nodes in the verified
run, only one of them requested), so later stubs along the same path should cost
nothing. A `RefCell<BTreeMap<H::Out, Vec<u8>>>` populated from every response is
enough.

The account trie works identically via `MultiProofTargets::accounts` with a
synthesised hashed address, reading `mp.account_subtree`.

### Acceptance

Rerun the step 3 tests against mainnet: find a real slot whose removal collapses
a Fork (step 0's measurement will have identified candidates), remove it, and
assert the new `storageRoot` — then re-insert and assert the original returns
byte-exactly.

---

## 7. Constraints and pitfalls

- **`mpt-core` stays `no_std` + `alloc`.** The wasm build is the canary:
  `cargo build -p mpt-core --target wasm32-unknown-unknown` must stay green.
- **Never trust a provider.** Every resolved node is hash-checked before use.
  This is what makes reading from an untrusted database as sound as reading from
  a verified proof.
- **`--release` for anything touching reth.** Its provider stack is unusably
  slow in a debug build.
- **reth keeps the empty-trie sentinel** that `eth_getProof` strips: an empty
  trie is `[0x80]`, not `[]`. Filter it. See `PTRIE.md` §8.5.
- **Do not add reth to the workspace default members.**
- **Canonicality is the correctness bar.** A partial trie that returns the right
  values but the wrong root is broken. Assert on roots, not on `get`.

---

## 8. Definition of done

- [ ] Step 0 measurement recorded in `PTRIE.md` §10
- [ ] `TrieError` exists; all traversal returns `Result`; existing suite green
- [ ] `NodeProvider` + `MapProvider` + `WitnessProvider` + `RecordingProvider`
- [ ] Partial trie driven by `MapProvider` matches a full trie under random
      interleaved insert/remove sequences (proptest)
- [ ] Delete-collapse resolves both a Leaf sibling and a Fork sibling, with the
      revert assertion passing
- [ ] `RethProvider` with caching; the same test green against mainnet
- [ ] `PTRIE.md` status line updated to "Phase B: done"

