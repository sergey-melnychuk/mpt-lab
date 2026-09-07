# Partial tries: stateless state-root recomputation

**Phase A: done, verified against mainnet.**
**Phase B: done, verified against mainnet.** All five steps complete:
`TrieError` + `Result`-ified traversal, `NodeProvider`/`MapProvider`/
`WitnessProvider`/`RecordingProvider`, the delete-collapse tests against a
synthetic oracle, the step-0 occupancy measurement, and `RethProvider` —
verified live against a real USDC balance slot (`examples/phase_b.rs`).

Prerequisites: stages 1–7 (insert, get, remove, byte-exact roots, proofs).

---

## 1. What this is

Given a Merkle Patricia Trie we do **not** hold — Ethereum mainnet state — plus
proofs for a handful of key/value pairs, reconstruct enough of the trie to apply
modifications and compute the new root hash. Without ever materialising the full
trie.

This is variously called a **block witness**, a **trie witness**, or **stateless
execution**. It underpins stateless clients, zkEVM state transitions, and fraud
provers.

### Why it works

A proof is not just evidence — it is a **sub-trie**. Every node in a proof is a
real node holding real child references. Splice a set of proofs together and you
get a trie complete along the paths you care about and stubbed out everywhere
else. Because a node's encoding depends only on its own path/value plus its
children's *references* — never their contents — a stubbed trie re-encodes to
exactly the same root as the full one.

Measured on mainnet at block 25914162: **8 storage nodes with 87 stubs**
reproduce USDC's `storageHash`, and **9 account nodes with 104 stubs** reproduce
the block's `stateRoot`.

### Where the unloaded subtrees' hashes come from

The crux, and it falls out of the node layout. A Fork encodes as a 17-item RLP
list: **all sixteen child references plus the value slot**. So a Fork in a proof
hands you the hashes of every child, including the fifteen you did not descend
into.

Real proof, keys `0x1111 / 0x1122 / 0x1133 / 0x99`, proving `0x1111`:

```
root = 1e1491a6…2733

[0] keccak=1e1491a6…2733   17 items   FORK
    item[ 1] = 6291b27b…89df    ← descend (first nibble is 1)
    item[ 9] = add779e8…9732    ← NOT visited — hash known for free

[1] keccak=6291b27b…89df    2 items   SKIP, hp(0x11) = ext, path [1]
    item[ 0] = 11
    item[ 1] = f1cafe53…411e    ← descend

[2] keccak=f1cafe53…411e   17 items   FORK
    item[ 1] = 7c0481ed…8782    ← descend
    item[ 2] = b9f0acb3…04e2    ← NOT visited — hash known for free
    item[ 3] = 12b4291d…d312    ← NOT visited — hash known for free

[3] keccak=7c0481ed…8782    2 items   LEAF, hp(0x31) = leaf, path [1]
    item[ 0] = 31
    item[ 1] = aaaa…aaaa        ← the value
```

The chain of custody is unbroken: `[0]` verified against the root, `[0]` gave
`[1]`'s hash, `[1]` gave `[2]`'s hash, `[2]` handed over two off-path hashes.
Those are as trustworthy as the root itself. They become **stubs**.

---

## 2. Goals

**Phase A — offline, witness-only.** Rebuild a partial trie from proofs, apply
value updates, and derive the new root. Done: `crates/mpt-reth/src/bin/live.rs`
runs it against mainnet over RPC and over a local reth database.

**Phase B — on-demand node lookup.** Inserts and removes may need nodes the
witness does not contain. A `NodeProvider` resolves them when traversal hits a
stub. The fetching mechanism is verified (§8); the traversal plumbing is not
written.

Non-goals: EVM execution, transaction replay.

---

## 3. What the witness must contain

**The rule:** every node whose *encoding changes*, plus every node needed to
compute those encodings.

A node's encoding depends on its own path/value and its children's references,
so a change propagates strictly **upward along one path** — which the proof
already is. There is exactly one exception.

| Operation | Witness sufficient? | Why |
|---|---|---|
| Update an existing key's value | **Yes** | Only the root-to-leaf path re-encodes, and the proof is that path |
| Insert where the exclusion proof ends at an empty Fork slot | **Yes** | The new leaf drops into the slot; nothing else moves |
| Insert where the exclusion proof ends on a diverging Leaf/Skip | **Yes** | The split needs that node's full contents, and `prove` pushes the node it terminated on |
| **Remove that collapses a Fork to one occupant** | **No** — see §8.3 | `normalize` calls `prepend(n, sibling)`, which needs the sibling's *variant and path*. The sibling hangs off a different nibble, so it was never on the deleted key's path; the Fork holds only its 32-byte reference |
| Value size crossing the 32-byte inlining boundary | Yes, but | The node flips between inlined and hashed, changing the parent's length. Worth a test |

Two things soften the collapse case in practice: it only fires when the Fork
drops to **exactly one** occupant, and with 16-way branching over uniformly
distributed secure-trie keys most Forks near the top have many occupants. But
"usually fine" is not a design.

Note that **setting an Ethereum storage slot to zero is a deletion** — there is
no "present with value zero". The collapse case is routine.

### The access set cannot be known in advance

For re-execution with modified inputs — a different balance, a different gas
price — the touched-key set is a *function of execution*. A changed balance can
change a branch, which changes which `SLOAD`s happen, which changes which slots
are written. You cannot build the witness up front because you do not know the
trace until you run it.

This is why Phase B is not optional. Batch witnesses work when someone already
produced the block and shipped the witness with it; they do not work for "what
if this had been slightly different".

---

## 4. Design decisions

### 4.1 A fifth node variant: `Stub`

```rust
/// A subtree we have not loaded, identified by its node hash.
///
/// Encodes as a 32-byte reference and nothing else, so a trie containing
/// Stubs still produces the correct root. Always a hashed node: anything
/// under 32 bytes was inlined into its parent and therefore came along in
/// the witness for free.
Stub(H::Out),
```

`Null / Leaf / Skip / Fork / Stub`.

**Why it carries the hash, not just a prefix.** Two hard requirements:

1. `encode_node` on the parent needs each child's *reference* to build its RLP.
   For a stub that reference **is** the hash. Without it you cannot encode the
   parent and therefore cannot compute any root above the stub — the entire
   point of the exercise.
2. It is the soundness check. When a store returns bytes you verify
   `keccak256(bytes) == stub_hash` before use. That is what makes reading from
   an untrusted database exactly as trustworthy as reading from a verified
   proof.

**Why the prefix is not stored.** The traversal already knows which nibbles it
consumed to reach the stub, so the prefix is context, not state. Storing it
would duplicate information that `normalize` rewrites during collapse.

### 4.2 `Node<H>` stayed generic

Adding `Stub` propagates `H` through `insert_at`, `remove_at`, `normalize`,
`prepend`, `skip_or`, `encode_node` and every test — and `#[derive(Clone)]` on a
generic enum adds an `H: Clone` bound a marker type cannot satisfy, so the
derives need care. A concrete `H256` alias would have been smaller.

Kept generic anyway. `ProofError::HashMismatch` still hardcodes `[u8; 32]`, so
the codebase is mixed. Revisit if the parameter keeps costing.

When building an `H::Out` from proof bytes, use the trait's own bounds rather
than assuming 32:

```rust
if d.len() != H::LENGTH { return Err(...); }
let mut h = H::Out::default();
h.as_mut().copy_from_slice(d);
```

### 4.3 Traversal returns `Result`

Every traversal can now fail by hitting a stub. `Node -> Node` becomes
`Node -> Result<Node, TrieError>`.

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrieError {
    /// Traversal reached a subtree we do not have. `path` is the nibble prefix
    /// at which the stub sits — enough to fetch it (§8.1).
    MissingNode { hash: H256, path: Vec<u8> },
    /// A store returned bytes that do not hash to the stub's reference.
    HashMismatch { expected: H256, got: H256 },
    /// Bytes that are not a valid node.
    MalformedNode,
}
```

`MissingNode` carries **both** hash and path deliberately: the path steers the
fetch, the hash verifies the result.

### 4.4 `NodeProvider`: one mechanism, several backings

There is one mechanism — resolve on demand from a store — and the trait is the
seam letting the store be a `BTreeMap`, a reth database, or an RPC.

```rust
/// Resolves a `Stub` to the node it stands for.
///
/// Implementations may key on EITHER argument: a witness map keys on `hash`,
/// reth keys on `path_nibbles` (§8.1). The caller ALWAYS verifies the returned
/// bytes against `hash`, so a provider is never trusted — the same discipline
/// `verify` applies to every proof node.
pub trait NodeProvider {
    /// Return the RLP encoding of the node at `path_nibbles` whose keccak256
    /// is `hash`, or `None` if this store cannot supply it.
    fn get(&self, path_nibbles: &[u8], hash: &H256) -> Option<Vec<u8>>;
}
```

**Rejected — a hash-only provider.** Cleaner, but reth is not content-addressed
(§8.4); its proof API is path-directed. The path argument is what makes the
reth implementation possible at all.

**Rejected — fetch-and-restart.** Run until `MissingNode`, fetch, restart from
scratch. Avoids threading the provider through traversal, but costs one full
re-execution per missing node and does not compose with EVM execution later.

### 4.5 Resolve in place

When a stub resolves, replace it in the tree rather than caching to the side.
Rehashing walks back up the same path and `normalize` may revisit nodes, so
in-place means the second visit is free.

### 4.6 `mpt-core` stays `no_std` and pure

`NodeProvider` is a trait, so `mpt-core` gains `Stub`, `TrieError` and the trait
without gaining dependencies. `mpt-reth` holds the database implementation and
its `std` baggage. The `wasm32-unknown-unknown` build stays green as the canary.

---

## 5. Phase A — done

### 5.1 What exists

```rust
/// Decode one node's RLP into a `Node`. Child references resolve against
/// `nodes` when present and become `Stub` when not; inlined children (a nested
/// RLP list rather than a 32-byte string) decode in place and are never stubs.
pub fn decode_node<H: Hasher>(nodes: &BTreeMap<H::Out, Vec<u8>>, bytes: &[u8]) -> Node<H>;

/// Rebuild a partial trie rooted at `root`. A root we do not have becomes a
/// bare `Stub`.
pub fn build_partial<H: Hasher>(nodes: &BTreeMap<H::Out, Vec<u8>>, root: &H::Out) -> Node<H>;

/// keccak256(rlp(node)).
pub fn node_root<H: Hasher>(node: &Node<H>) -> H::Out;

/// How much of the trie we do not have. Diagnostics only.
pub fn count_stubs<H: Hasher>(node: &Node<H>) -> usize;

impl<H: Hasher> Trie<H> {
    pub fn from_node(root: Node<H>) -> Self;
}
```

`decode_node` is the mirror image of `encode_node`. Reading them side by side
and checking they agree is worth five minutes.

### 5.2 Verified on mainnet

`crates/mpt-reth/src/bin/live.rs`, both over RPC and against a local reth
datadir. For one account and one slot it:

1. reconstructs the **storage** trie from `storageProof`, confirms it re-derives
   `storageHash`;
2. rebuilds the account tuple as `rlp([nonce, balance, storageRoot, codeHash])`
   using the storage root **it just derived**, not the one the RPC reported;
3. reconstructs the **account** trie from `accountProof`, confirms it re-derives
   the block header's `stateRoot`;
4. changes the slot value, re-derives `storageRoot'`, splices it into the
   account tuple, re-derives `stateRoot'`;
5. reverts both and asserts the original roots return **byte-exactly**.

Step 5 is the important one. It is the mainnet analogue of
`delete_restores_the_exact_root`: if any node on the path re-encodes differently
coming back than it did going in, the root will not match. Passing means the
reconstruction is canonical, not merely plausible.

Nothing is trusted except one 32-byte number in the block header. Lie about the
slot value and the storage root breaks; lie about the storage root and the
account RLP breaks; lie about the account and the state root breaks.

### 5.3 Gotchas found the hard way

- **JSON-RPC quantities are minimal-width.** A nonce of 1 arrives as `"0x1"` —
  odd-length hex, which `hex::decode` rejects outright. Pad it.
- **Zero balance.** `"0x0"` decodes to `[0x00]`, strips to empty, and `rlp("")`
  is `0x80` — correct, but only if you strip leading zeros.
- **Storage values are RLP-encoded.** The trie holds `rlp(value)`, not the raw
  32-byte word. Slot 0 holding an address is `0x94fcb1…`, not `0x000…fcb1…`.
- **Secure tries have no extension nodes in practice.** Keys are
  `keccak256(x)`, uniformly distributed, so prefixes worth compressing
  essentially never occur. Real proofs are all Forks and one Leaf.

### 5.4 Still worth adding

- Freeze a mainnet run as a test with hardcoded roots, so a refactor cannot
  silently break it.
- A synthetic proptest: random maps, random touched subsets, value updates only,
  partial root always equal to full root.
- Assert the stub count is nonzero, or a witness that accidentally contains
  everything would make the test vacuous.
- Tamper a witness node and confirm reconstruction fails.

---

## 6. Phase B — the plan

### 6.1 Traversal with a provider

```rust
impl<H: Hasher> Trie<H> {
    pub fn insert_with<P: NodeProvider>(&mut self, p: &P, key: &[u8], value: Vec<u8>)
        -> Result<(), TrieError>;
    pub fn remove_with<P: NodeProvider>(&mut self, p: &P, key: &[u8])
        -> Result<bool, TrieError>;
    pub fn get_with<P: NodeProvider>(&self, p: &P, key: &[u8])
        -> Result<Option<&[u8]>, TrieError>;
}
```

The recursion carries `&P` and the nibble prefix consumed so far. On reaching
`Stub(h)`:

```rust
let bytes = p.get(path_so_far, &h)
    .ok_or(TrieError::MissingNode { hash: h, path: path_so_far.to_vec() })?;
let got = H::hash_all(&[&bytes]);
if got != h { return Err(TrieError::HashMismatch { expected: h, got }); }
let node = decode_node(&Default::default(), &bytes);  // children become Stubs
// replace in place, then continue into `node`
```

Note `decode_node` with an empty map yields a node whose children are all stubs,
which is exactly right — resolving one node should not speculatively pull its
subtree.

### 6.2 `normalize` is where stubs bite

`prepend(n, sibling)` must know whether `sibling` is a Leaf (extend path), a
Skip (extend path), or a Fork (wrap in a new `Skip { path: [n] }`). A `Stub`
answers none of these, and the hash will not tell you.

If the sibling were always a Fork you could wrap it blind without loading it.
It is not — in a secure trie it is usually a Leaf.

This is the **only** place a sideways, non-path resolution is needed, and it is
the reason Phase B exists. Only one level deep: once the sibling is resolved,
its own children stay stubs, because `prepend` changes the sibling's path, not
its children's references.

Dedicated test:

```rust
#[test]
fn delete_collapse_resolves_the_sibling_stub() {
    // A Fork with exactly two occupants where the sibling is NOT on the
    // deleted key's path, so the witness cannot contain it. Deleting one
    // occupant must resolve the sibling through the provider and produce the
    // same root as the full trie.
}
```

Two sub-cases: sibling is a Leaf (path extends, value moves up) and sibling is a
Fork (gets wrapped in a fresh `Skip`).

### 6.3 Providers

```rust
/// Offline, from proofs. Ignores the path, fails on anything absent.
pub struct WitnessProvider(pub BTreeMap<H256, Vec<u8>>);

/// A complete node map, so nothing ever misses. Isolates traversal bugs from
/// witness-construction bugs.
pub struct MapProvider(pub BTreeMap<H256, Vec<u8>>);

/// Instrumented wrapper recording every (path, hash) requested. This IS the
/// witness builder: run a workload against a complete store, collect what was
/// touched, and that is the minimal witness for that workload.
pub struct RecordingProvider<P> { inner: P, seen: RefCell<Vec<(Vec<u8>, H256)>> }

/// Backed by a reth database. See §8.3.
pub struct RethProvider { /* … */ }
```

`RecordingProvider` is worth building early. It turns "which nodes does this
workload need?" from an analysis problem into an observation.

### 6.4 Fetch characteristics

- **Volume is low.** Only collapsing removes need a sideways fetch. Inserts,
  updates and non-collapsing removes are satisfied by the path already being
  walked. Load is roughly proportional to slots hitting zero, not to op count.
- **Serial, not batchable.** You do not know you need the sibling until the
  collapse fires, and you do not know that until the preceding ops are applied.
  No batching within a transaction. Across a block you could pre-warm from the
  access list, but that is speculative.
- **Not IO-bound with a local database.** A fetch is a local read. Do not build
  async machinery for this.
- **Fetches overfetch usefully.** A reth multiproof returns a whole path (§8.2),
  so cache it — later stubs along the same path are free.

---

## 7. Nesting: account trie over storage trie

1. Build a partial **storage** trie from `storageProof`; verify against the
   account's `storageRoot`.
2. Apply slot updates; recompute → `storageRoot'`.
3. Decode the account value `rlp([nonce, balance, storageRoot, codeHash])`, swap
   in `storageRoot'`, re-encode.
4. Build a partial **state** trie from `accountProof`; verify against the
   block's `stateRoot`.
5. Insert the updated account at `keccak256(address)`; recompute →
   `stateRoot'`.

`eth_getProof(address, [slots…])` returns both proofs in one call — this is
exactly what it is for. Verified end to end in `live.rs`.

Storage keys are `keccak256(slot)`; storage values are RLP integers with no
leading zeros.

**Empty trie:** `prove` on a `Null` root returns an **empty** proof, and
`verify_proof` special-cases it — empty proof against `keccak256(0x80)` is
`Ok(None)`, against any other root it is `Err(Truncated)`. The naive
alternative, emitting `rlp(Null) = [0x80]`, passes the hash check and then fails
to decode, since `0x80` is a string rather than a 2- or 17-item list. reth hit
the same edge case and resolved it identically — see §8.5.

---

## 8. reth integration

**Status: verified against reth v2.5.1 source and a live mainnet node.**

### 8.1 The mechanism: path-directed node fetching

`StateProofProvider::multiproof` is the whole answer:

```rust
fn multiproof(&self, input: TrieInput, targets: MultiProofTargets)
    -> ProviderResult<MultiProof>;
```

Two properties make it work where `eth_getProof` cannot:

1. **`MultiProofTargets` takes already-hashed keys.** It is
   `hashed_address -> {hashed_slot}`, not address and raw slot. So we choose the
   trie key directly, with no keccak preimage needed.
2. **The result is path-keyed.** `MultiProof.account_subtree` and
   `StorageMultiProof.subtree` are `ProofNodes`, which derefs to
   `HashMap<Nibbles, Bytes>` — nibble path to RLP node.

To fetch the node at nibble path `P`: pack `P` into a `B256`, pad right with
zeros, request a multiproof for it. Any key with that prefix walks through the
node, so the response contains it. The probe key almost certainly maps to
nothing, which is irrelevant — an exclusion proof holds the same nodes on the
way down.

`eth_getProof` structurally cannot do this: it takes the **raw** slot and hashes
it for you, so steering to a chosen path would require inverting keccak. **This
is the reason to be on the database rather than an endpoint.**

### 8.2 Verified on mainnet

Fetching an off-path child of the storage root — a node the inclusion proof
could not contain, known only by its hash:

```
  our nibble    2  (on the proof's path)
  target path   /0
  target hash   451af683…2653ecd6
  in witness?   no — the proof never descended there
  probe key     0000…0000
  multiproof returned 8 node(s), keyed by path:
    len 0    532b  f598556d…e57c8147
    len 1    532b  451af683…2653ecd6   <-- the one we wanted
    len 2    532b  66cc57ef…00d8e1c0
    ...
    len 7     35b  12de53e1…cff52232
  hash check    OK  (532 bytes, Fork)
```

- The response is a **complete walk** for the probe key, path lengths 0..7.
  Off-target nodes are not pruned.
- Seven unrequested nodes arrive. That overfetch is free — they all go into the
  witness. Not worth optimising at ~500 bytes each.
- The account trie works the same way: `MultiProofTargets::accounts` with a
  synthesised hashed address, reading `mp.account_subtree`.

### 8.3 `NodeProvider` implementation

§4.4's two-argument signature turns out to be exactly right: **path to steer,
hash to verify.**

```rust
impl NodeProvider for RethProvider {
    fn get(&self, path_nibbles: &[u8], hash: &H256) -> Option<Vec<u8>> {
        let probe = key_with_prefix(path_nibbles);   // pack nibbles into a B256
        let mp = self.state.multiproof(
            Default::default(),
            MultiProofTargets::account_with_slots(self.hashed_address, [probe]),
        ).ok()?;
        let sub = mp.storages.get(&self.hashed_address)?;
        sub.subtree.values()
            .map(|b| b.to_vec())
            .find(|n| keccak(n) == *hash)
    }
}
```

Ten lines. The hash check keeps it sound whatever reth returns, so the provider
is never trusted. Add a cache keyed by path prefix: a multiproof returns a whole
walk, so subsequent stubs along it cost nothing.

### 8.4 What this replaces

An earlier draft planned to read `AccountsTrie` / `StoragesTrie` directly and
reconstruct nodes from `BranchNodeCompact`, falling back to prefix scans over
`HashedAccounts` / `HashedStorages`. **None of that is necessary.** Recorded
because the constraints are real and would resurface if the proof API became
unavailable:

- reth is **not content-addressed**. There is no `hash -> node` table, unlike
  geth's old flat scheme. Lookups are by path.
- `AccountsTrie` maps `StoredNibbles(path) -> BranchNodeCompact`
  `{ state_mask, tree_mask, hash_mask, hashes, root_hash }` — **not RLP**, so it
  cannot be hashed or spliced into a parent.
- `hashes` holds only the children flagged in `hash_mask`, a subset of those in
  `state_mask`. The rest must be computed from underlying state.
- **Only branch nodes are stored, and not all of them.** No leaves, no
  extensions. `tree_mask` marks which children are also in the database, so the
  tables are a sparse index over the trie, not the trie.
- reth 2.0's storage v2 dropped the plain state tables; only hashed state
  remains on MDBX. `HashedAccounts` / `HashedStorages` survive, keyed by
  `keccak256(addr)` / `keccak256(slot)`, which is the trie key.
- The schema churns between releases — `StoredNibblesSubKey` was repacked from
  65 to 33 bytes recently. The proof API avoids that dependency entirely.

### 8.5 Practical notes

- **`--release` is mandatory.** reth's provider stack is unusably slow in a
  debug build.
- **Keep `mpt-reth` out of the workspace default members**, or `cargo test` at
  the root builds all of reth. Use `exclude`, or a separate workspace. Put
  `[profile.release]` at the workspace root — profiles in non-root packages are
  ignored.
- **reth does not strip the empty-trie sentinel.** An empty trie comes back as a
  single `0x80` node rather than an empty list; that normalisation happens only
  at the EIP-1186 response boundary. Filter it — our `verify` expects the empty
  list (§7).
- **A minimal node prunes historical state**, so `history_by_block_number` fails
  below the pruning horizon. `latest()` always works.
- reth is not usefully published to crates.io (the `reth-*` crates there are
  0.0.0 placeholders). Pin the git tag:
  `reth-ethereum = { git = "…", tag = "v2.5.1", features = ["node"] }`.
- Open read-only with `EthereumNode::provider_factory_builder()
  .open_read_only(spec, ReadOnlyConfig::from_datadir(dir), runtime)` — safe
  against a running node's datadir.
- **Follow-up, not yet done: batch the witness bootstrap into one
  `multiproof()` call instead of one `state.proof()` per touched account.**
  `examples/block.rs` (the yevm block-replay experiment) calls
  `state.proof(addr, &slots)` separately for every touched account to build
  the initial witness — measured on a real 552-account block: **5.44s of a
  9.6s total run**, i.e. 552 independent trie walks from the root, each
  paying its own MDBX round-trips. `StateProofProvider::multiproof()`
  (§8.1/§9) already accepts a `MultiProofTargets` map keyed by *many*
  hashed addresses at once (see `crates/rpc/rpc-eth-api/src/helpers/state.rs`'s
  `get_multi_proof` in reth itself for the exact usage pattern: build one
  `MultiProofTargets`, one call, then split `multiproof.account_proof(addr,
  &slots)` back out per account) — one round trip instead of N. The tradeoff:
  `proof()` conveniently hands back a decoded `AccountProof` (nonce, balance,
  storageRoot, codeHash already parsed); `multiproof()` returns raw
  `account_subtree`/`storages[addr].subtree` nodes only, so switching means
  decoding each touched account's `TrieAccount` leaf ourselves from the
  reconstructed `Node<Keccak256>` (`build_partial` + a leaf lookup) instead
  of trusting `.info`. Expected payoff: this is the single largest cost in
  the whole block-replay run by a wide margin (bigger than yevm execution
  itself), so batching it should cut total run time roughly in half.

### 8.6 Worth reading first

reth already contains this design. `RevealedSparseNode` — "carries all
information needed by a sparse trie to reveal a particular node" — is our `Stub`
resolution, behind a `SparseTrieInterface` with a `ParallelSparseTrie`
implementation. v1.11.0 made the sparse trie persist across payload validations;
2.0 added partial proofs that fetch only what is not already cached.

Phase B is a solved problem at production scale inside reth, and
`reth-trie-sparse` may be usable directly. An hour reading it is worth it either
way.

Also relevant: `StateProofProvider::witness(input, target, mode)` returns
`Vec<Bytes>` — reth's own witness generation, for when the access set *is* known
ahead of time.

---

## 9. Entry points

| File | Contents |
|---|---|
| `crates/mpt-core/src/trie.rs` | `Stub` variant, `decode_node`, `build_partial`, `node_root`, `count_stubs`, `Trie::from_node`, `Result`-ified traversal (`insert_at`/`remove_at`/`get_at`/`normalize`/`prepend`), `insert_with`/`remove_with`/`get_with` — **done** |
| `crates/mpt-core/src/error.rs` | `TrieError` — **done** |
| `crates/mpt-core/src/partial.rs` | `NodeProvider`, `NoProvider`, `WitnessProvider`, `MapProvider`, `RecordingProvider` — **done** |
| `crates/mpt-core/tests/partial.rs` | Synthetic round-trip (fixed sweep + proptest) against `MapProvider`, plus `WitnessProvider`/`RecordingProvider` coverage — **done** |
| `crates/mpt-core/tests/provider.rs` | Delete-collapse: Leaf sibling, Fork sibling, value-slot (no provider needed), a repeated-collapse session — **done** |
| `crates/mpt-core/examples/live.rs` | Two-level mainnet verification and mutation — **done** |
| `crates/mpt-reth/examples/collapse.rs` | Path-directed fetch of a missing node, walked through by hand — **done** |
| `crates/mpt-reth/examples/sweep.rs` | Step 0: Fork-occupancy histogram across real slots — **done** |
| `crates/mpt-reth/src/lib.rs` (`RethProvider`) | Step 4: caching `NodeProvider` impl — **done** |
| `crates/mpt-reth/examples/phase_b.rs` | `RethProvider` acceptance test, live against mainnet — **done** |

### Remaining order

All five steps are done:

1. ~~`TrieError`; `Result`-ify traversal.~~ Done.
2. ~~`NodeProvider` + `MapProvider`; thread it through traversal.~~ Done.
3. ~~`normalize` sibling resolution; the delete-collapse test against a synthetic
   full trie used as the oracle.~~ Done — see `tests/provider.rs`.
4. ~~`RethProvider` (§8.3, ten lines) and the same test against mainnet.~~ Done
   — see `crates/mpt-reth/src/lib.rs` and `examples/phase_b.rs`.
5. ~~`RecordingProvider`; measure how often the collapse case fires on real
   workloads.~~ Done via `examples/sweep.rs` (a lighter-weight measurement that
   doesn't need a full `RecordingProvider` session) — see §10.

Steps 1–3 turned out to need no design changes beyond what §4 and §6 already
specified, with one exception: `get_with`/`get` take `&mut self`, not `&self`
as originally sketched — see §10.

---

## 10. Open questions

- **How often does the collapse case actually fire? Answered: 13.7%** (41/300)
  in `examples/sweep.rs`'s measurement — 150 pseudo-random storage slots each
  on USDC and WETH, real mainnet data, block ~25920774. Occupancy-2 Forks
  (where removal collapses) ranged from 9% (USDC) to a higher share on WETH;
  in **every** occupancy-2 case found (41/41), the surviving sibling was a
  genuine `Stub`, never already inlined in the proof. This settles PLAN.md
  §2's decision: at ~14%, Phase B is core infrastructure, not a rare edge
  case — threading a provider through traversal is worth it. (Slots were
  pseudo-random rather than known-populated ones; see the sweep's own doc
  comment for why that's still a fair sample of Fork occupancy.) Verified
  live end-to-end on a genuinely populated slot too: `examples/phase_b.rs`
  removes a real USDC holder's balance slot (occupancy 2), through
  `RethProvider`, and reverts it back to the exact original `storageRoot`.
- **Does one `normalize` pass suffice** when resolving may itself expose new
  stubs a level down, as it did for the non-partial case (NOTES.md §6.2)?
  **Answered: yes, and provably so, not just empirically.** A `Fork`'s
  occupancy-≥2 invariant (`Node::debug_check`) means a single `remove` can
  collapse **at most one** Fork: an ancestor Fork's occupancy only changes if
  one of its own children disappears entirely, which only happens if that
  child was itself a bare `Leaf` holding the removed key — never a `Fork`
  (a Fork can't hold just one key, by the same invariant). So the chain a
  removal triggers is Fork-collapse (at most once) followed by zero or more
  `Skip`-path merges on the way back up, and merging paths never needs a
  provider. `tests/provider.rs::repeated_collapses_against_one_provider`
  exercises many *separate* removals against one provider instead, each
  independently resolving its own sibling.
- **Should `Trie` own its provider** rather than taking it per call?
  **Answered: no — per-call, as `insert_with`/`remove_with`/`get_with` do.**
  Implemented as sketched; no reason found to revisit.
- **Should `build_partial` fail or return a bare `Stub`** when the root itself
  is missing? **Answered: bare `Stub`** — already how `build_partial` worked
  going into Phase B (`crates/mpt-core/src/trie.rs`), and
  `insert_into_a_stub_root_fails` (`tests/trie.rs`) now pins the exact error:
  `Err(MissingNode { hash: root, path: [] })`.
- **New: `get_with` takes `&mut self`, not `&self`.** The sketch in §6.1 had
  `get_with(&self, ...)`, but resolving a `Stub` mutates the tree (§4.5,
  "resolve in place") and the returned `&[u8]` borrows from that mutation, so
  it needs `&mut Node<H>` underneath. Plain `get` moved to `&mut self` too, to
  share one implementation and because it already needed a non-panicking way
  to distinguish "confirmed absent" (`Ok(None)`) from "don't know"
  (`Err(MissingNode)`) — the exact bug class flagged in PLAN.md §3.2 (a
  `Stub` silently reported as absent would make an exclusion proof over a
  partial trie a lie). No test in this repo relied on calling `get` through a
  shared `&Trie` reference, so the widening cost nothing.
- **Witness serialisation format.** A flat list of RLP nodes matches what
  `eth_getProof` returns. Worth defining if witnesses are shipped between
  processes. Still open.
- **Is `reth-trie-sparse` usable standalone?** If so, §6 is mostly redundant.
  Still open.
- **Does any publicly-hosted RPC endpoint expose a path- or hash-directed node
  lookup, making the delete-collapse gap (crates/mpt-wasm's Mainnet tab hits
  this directly) fixable without running your own node? Researched, answer:
  no, and the constraint is more fundamental than "provider hasn't gotten
  around to it."**
  - `RethProvider` (§8) was never an RPC method to begin with — `multiproof()`
    is a Rust API called against a local, embedded `open_read_only(datadir)`
    (§8.5); there's no network endpoint here to look for on a public host.
  - geth's `debug_dbGet` reads the raw KV store by its literal on-disk key,
    which — depending on the client's storage scheme (hash-keyed vs. the
    newer path-based scheme; §8.4's schema-churn point applies here too) —
    might even be a path. But commercial providers uniformly exclude it: paid
    "debug/trace" tiers expose `debug_traceTransaction` /
    `debug_traceBlockByNumber` / `debug_traceCall`, never raw `debug_dbGet` —
    unrestricted disk-key access is treated as an operational risk, not a
    product feature. Erigon's extra `debug_*`/`erigon_*` methods (e.g.
    `debug_accountRange`) don't cover single-node-by-path either.
  - `eth_getProof` (EIP-1186) remains the only standardized, universally
    available method, and PLAN.md §1 / §8.1 already cover why it can't be
    steered: it hashes the key before walking, so you can't choose a path.
  - The actual fix on the horizon is protocol-level, not an RPC addition:
    EIP-6800 (Verkle) and the newer EIP-7864 (binary tree, replacing the
    hexary Keccak MPT entirely) are both aimed at making witnesses small
    enough to travel WITH blocks, which would make ad hoc sideways fetches
    unnecessary rather than easier. As of this writing neither has shipped —
    Verkle is paused pending further review, and EIP-7864 looks like the
    likelier near-term direction — so there's nothing to build against yet.
  - Net effect: the mitigations already listed in PLAN.md §1 (run your own
    node for path-directed access, brute-force a short prefix's preimage, or
    batch enough keys into one `eth_getProof` call that the sibling arrives
    incidentally) are still the complete list. `crates/mpt-wasm`'s Mainnet
    tab surfaces the unresolved case honestly (exact hash + path in the
    error) rather than pretending it's fixable client-side.

