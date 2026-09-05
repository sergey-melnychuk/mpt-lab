# Partial tries: stateless state-root recomputation

Status: design, not yet implemented.
Prerequisites: stages 1–7 complete (insert, get, remove, byte-exact roots, proofs).

---

## 1. What this is

Given a Merkle Patricia Trie we do **not** hold — Ethereum mainnet state, say —
plus Merkle proofs for a handful of key/value pairs, reconstruct enough of the
trie's structure to apply modifications to those pairs and compute the new root
hash. Correctly, and without ever materialising the full trie.

Concretely: take a block's `stateRoot`, get proofs for the storage slots of one
account, change some slot values, and compute what the account's `storageRoot`
and hence the block's `stateRoot` *would* be.

This is variously called a **block witness**, a **trie witness**, or **stateless
execution**. It is the mechanism behind stateless clients, zkEVM state
transitions, and fraud provers.

### Why it works

A proof is not just evidence — it is a **sub-trie**. Every node in a proof is a
real node holding real child references. Splice a set of proofs together and you
have a trie that is complete along the paths you care about and stubbed out
everywhere else. Because a node's encoding depends only on its own path/value
plus its children's *references* (not their contents), a stubbed trie
re-encodes to exactly the same root as the full one.

Measured on a 1000-key trie: **proofs for 5 keys yield 16 distinct nodes.** That
is the entire working set needed to recompute the root after modifying those 5.

### Why the hashes of unloaded subtrees are known

This is the crux, and it falls out of the node layout. A Fork encodes as a
17-item RLP list: **all sixteen child references plus the value slot**. So when
a proof hands you a Fork, it hands you the hashes of every child, including the
fifteen you did not descend into.

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
`[1]`'s hash, `[1]` gave `[2]`'s hash, `[2]` gave two off-path hashes. Those
off-path hashes are as trustworthy as the root itself. They become **stubs**.

---

## 2. Goals

**Phase A — offline, witness-only.** We build a full trie ourselves, extract
proofs for a few keys, throw the trie away, reconstruct a partial trie from the
proofs, apply value updates, and assert the resulting root equals what the full
trie would have produced. No external store.

**Phase B — on-demand node lookup.** Insert, remove, and structural updates may
need nodes the witness does not contain. Introduce a `NodeProvider` the
traversal consults when it hits a stub. Back it with a `HashMap` first, then
with reth's database.

Non-goals for now: EVM execution, transaction replay, and reth schema
integration (deferred to §8).

---

## 3. What the witness must contain

**The rule:** the witness must contain every node whose *encoding changes*, plus
every node needed to compute those encodings.

A node's encoding depends on its own path/value and its children's references.
So a change propagates strictly **upward along one path** — which the proof
already covers. There is exactly one exception, and it is the whole
complication.

| Operation | Witness sufficient? | Why |
|---|---|---|
| Update value of an existing key | **Yes** | Only the root-to-leaf path re-encodes, and the proof is that path |
| Insert where the exclusion proof ends at an empty Fork slot | **Yes** | New leaf drops into the slot; nothing else moves |
| Insert where the exclusion proof ends on a diverging Leaf/Skip | **Usually** | The split needs that node's full contents — `prove` pushes the node it terminated on, so verify against `collect` |
| **Delete that collapses a Fork to one occupant** | **No** | `normalize` calls `prepend(n, sibling)`, which needs the sibling's *variant and path*. The proof holds the Fork, and the Fork holds only the sibling's 32-byte reference |
| Value size crossing the 32-byte inlining boundary | Yes, but | The node flips between inlined and hashed, changing the parent's length. Have a test |

Note that **setting an Ethereum storage slot to zero is a deletion**, so the
collapse case is routine, not exotic.

### The access set cannot be known in advance

For re-execution with modified inputs — a different balance, a different gas
price — the set of touched keys is a *function of execution*. A changed balance
can change a branch, which changes which `SLOAD`s happen, which changes which
accounts are touched. You cannot build the witness up front because you do not
know the trace until you run it.

This is precisely why Phase B is not optional, and why on-demand resolution from
a store is the only general answer. Batch witnesses work when someone else
already produced the block and shipped the witness with it; they do not work for
"what if this had been slightly different".

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
Stub(H256),
```

Node becomes `Null / Leaf / Skip / Fork / Stub`. Everything else follows.

**Why it carries the hash, not just a prefix.** Two reasons, both hard
requirements:

1. `encode_node` on the parent needs each child's *reference* to build its RLP.
   For a stub that reference **is** the hash. Without it you cannot encode the
   parent and therefore cannot compute any root above the stub — the entire
   point of the exercise.
2. It is the soundness check. When a store returns bytes you verify
   `keccak256(bytes) == stub_hash` before use. That check is what makes reading
   from an untrusted database exactly as trustworthy as reading from a verified
   proof.

**Why the prefix is not stored.** The traversal already knows which nibbles it
consumed to reach the stub, so the prefix is context, not state. Storing it
would duplicate information that `normalize` rewrites during collapse.

### 4.2 Concrete `H256`, not generic `H`

Adding `Stub(H::Out)` would turn `Node` into `Node<H>`, propagating a type
parameter through `insert_at`, `remove_at`, `normalize`, `prepend`, `skip_or`,
`encode_node`, and every test — plus the derive-bound problem, since
`#[derive(Clone)]` on a generic enum adds a `H: Clone` bound that a marker type
cannot satisfy.

**Decision:** `pub type H256 = [u8; 32];` and `Node` stays concrete.
`ProofError::HashMismatch` already hardcodes `[u8; 32]` for the same reason.
This resolves the open question in NOTES.md §C.2 as: **generic where it is real
(`merkle.rs` genuinely is hash-agnostic), concrete where it is not (the MPT spec
mandates Keccak-256).**

### 4.3 Traversal returns `Result`

Every traversal can now fail by hitting a stub. Signatures change from
`Node -> Node` to `Node -> Result<Node, TrieError>`.

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrieError {
    /// Traversal reached a subtree we do not have.
    /// `path` is the nibble prefix at which the stub sits — enough to look it
    /// up in a path-addressed store such as reth's.
    MissingNode { hash: H256, path: Vec<u8> },
    /// A store returned bytes that do not hash to the stub's reference.
    HashMismatch { expected: H256, got: H256 },
    /// Bytes that are not a valid node.
    MalformedNode,
}
```

`MissingNode` carrying **both** hash and path is deliberate: the hash for
verification and for content-addressed stores, the path for reth's
nibble-keyed tables (§8).

### 4.4 `NodeProvider`: one mechanism, several backings

There is one mechanism — resolve on demand from a store — and the trait is
simply the seam that lets the store be a `HashMap`, an RPC, or reth's MDBX.

```rust
pub trait NodeProvider {
    /// Return the RLP of the node at `path_nibbles` whose keccak256 is `hash`.
    ///
    /// Implementations may key on either argument. The caller ALWAYS verifies
    /// the returned bytes against `hash`, so a provider is never trusted.
    fn get(&self, path_nibbles: &[u8], hash: &H256) -> Option<Vec<u8>>;
}
```

A `HashMap`-backed provider ignores the path and gives you Phase A for free. A
reth-backed provider uses the path for lookup and the hash for verification.
Phase A is therefore not a throwaway prototype; it is the same code path with a
different provider.

**Alternative rejected — a hash-only provider.** Cleaner, but reth's trie tables
are path-keyed, so the adapter would have to maintain its own hash index. More
work, no benefit.

**Alternative rejected — fetch-and-restart loop.** Run until `MissingNode`,
fetch, restart from scratch. Avoids threading the provider through traversal,
but it is O(missing nodes) full re-executions and it does not compose with EVM
execution later.

### 4.5 Resolve in place

When a stub resolves, replace it in the tree rather than caching to the side.
Rehashing walks back up the same path, and `normalize` may revisit nodes, so
in-place means the second visit is free. Costs `&mut` on traversal, which the
existing by-value recursive style already provides.

### 4.6 `mpt-core` stays `no_std` and pure

The provider is a trait, so `mpt-core` gains `Stub`, `TrieError`, and
`NodeProvider` without gaining dependencies. A separate `mpt-reth` crate holds
the MDBX-backed implementation and its `std` baggage. The
`wasm32-unknown-unknown` build stays green as the canary.

---

## 5. Blueprint: Phase A

### 5.1 New module `crates/mpt-core/src/partial.rs`

```rust
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::trie::{Node, Trie};
use crate::{H256, keccak};

/// A set of nodes recovered from proofs, addressed by hash.
#[derive(Debug, Clone, Default)]
pub struct Witness {
    nodes: BTreeMap<H256, Vec<u8>>,
}

impl Witness {
    pub fn new() -> Self { Self::default() }

    /// Absorb one proof. Nodes are self-identifying, so order and overlap
    /// between proofs do not matter — duplicates collapse.
    pub fn add_proof(&mut self, proof: &[Vec<u8>]) {
        for node in proof {
            self.nodes.insert(keccak(node), node.clone());
        }
    }

    pub fn len(&self) -> usize { self.nodes.len() }
    pub fn is_empty(&self) -> bool { self.nodes.is_empty() }
    pub fn get(&self, hash: &H256) -> Option<&[u8]> {
        self.nodes.get(hash).map(Vec::as_slice)
    }

    /// Rebuild a partial trie rooted at `root`.
    ///
    /// Fails if `root` itself is absent. Anything else missing becomes a Stub.
    /// ALWAYS follow this with `trie.hash() == root` — that assertion is the
    /// entire trust boundary; everything after it is arithmetic.
    pub fn build(&self, root: &H256) -> Result<Trie, TrieError> {
        todo!("resolve(root), wrap in Trie")
    }

    /// Decode one node's RLP into a Node, turning child references into
    /// resolved subtrees when present in the witness and Stubs when not.
    ///
    /// Reference handling — the one rule that matters:
    ///   * slot holds a 32-byte RLP *string*  -> hash ref. Recurse if we have
    ///     it, else Stub(hash).
    ///   * slot holds a nested RLP *list*     -> the child was INLINED. Decode
    ///     it in place. Never a Stub: inlined nodes always came along for free.
    ///   * slot holds the empty string 0x80   -> genuinely absent child.
    fn resolve(&self, hash: &H256) -> Node {
        todo!()
    }
}
```

`resolve` is the mirror image of `encode_node`. Writing them next to each other
and checking they agree is worth the five minutes.

### 5.2 Acceptance test — the one that proves the concept

```rust
#[test]
fn partial_trie_recomputes_the_same_root() {
    // 1. Full trie, ~1000 keys.
    let ks = keys(1000);
    let mut full = Trie::new();
    for (i, k) in ks.iter().enumerate() { full.insert(k, vec![(i % 251) as u8; 40]); }
    let root = full.hash();

    // 2. Proofs for 5 keys -> witness. (Measured: 16 nodes.)
    let touched = [3usize, 17, 400, 401, 999].map(|i| ks[i].clone());
    let mut w = Witness::new();
    for k in &touched { w.add_proof(&full.prove(k)); }

    // 3. Rebuild from the witness ALONE and check it hashes to the same root.
    let mut partial = w.build(&root).unwrap();
    assert_eq!(partial.hash(), root, "partial trie must reproduce the root");

    // 4. Update the 5 values in the partial trie.
    for (j, k) in touched.iter().enumerate() {
        partial.insert(k, vec![0xf0 | j as u8; 40]).unwrap();
    }
    let partial_root = partial.hash();

    // 5. Same updates against the full trie.
    for (j, k) in touched.iter().enumerate() { full.insert(k, vec![0xf0 | j as u8; 40]); }

    // 6. The payoff.
    assert_eq!(partial_root, full.hash());
}
```

Step 3 is the trust boundary. Step 6 is the whole sub-project in one assertion.

### 5.3 Further Phase A tests

- **Stub count is nonzero.** Otherwise the witness accidentally contains
  everything and the test proves nothing. Assert the partial trie has stubs.
- **Every touched key is readable; every untouched key errors with
  `MissingNode`.** Confirms the partial trie is genuinely partial.
- **Tampered witness is rejected.** Flip a bit in one witness node; `build`
  must fail, or `hash()` must not equal `root`.
- **Inlining.** Use short values so nodes inline, and confirm a nested-list
  reference is decoded in place rather than becoming a stub.
- **Empty-trie root.** A witness for the empty trie is empty; `build` must yield
  `Null` and hash to `56e81f17…`.
- **Proptest.** Random maps, random touched subsets, value updates only. Partial
  root always equals full root.

---

## 6. Blueprint: Phase B

### 6.1 Traversal with a provider

```rust
impl Trie {
    pub fn insert_with<P: NodeProvider>(
        &mut self, p: &P, key: &[u8], value: Vec<u8>,
    ) -> Result<(), TrieError>;

    pub fn remove_with<P: NodeProvider>(
        &mut self, p: &P, key: &[u8],
    ) -> Result<bool, TrieError>;

    pub fn get_with<P: NodeProvider>(
        &self, p: &P, key: &[u8],
    ) -> Result<Option<&[u8]>, TrieError>;
}
```

The recursion carries `&P` and the nibble prefix consumed so far. On reaching a
`Stub(h)`:

```rust
let bytes = p.get(path_so_far, &h).ok_or(TrieError::MissingNode { hash: h, path: path_so_far.to_vec() })?;
let got = keccak(&bytes);
if got != h { return Err(TrieError::HashMismatch { expected: h, got }); }
let node = decode_node(&bytes)?;   // children become Stubs in turn
// replace in place, then continue into `node`
```

Note `decode_node` here is the same function `Witness::resolve` needs, minus the
witness lookup — factor it out so both use one implementation.

### 6.2 `normalize` is where stubs actually bite

`prepend(n, sibling)` must know whether `sibling` is a Leaf (extend path), a
Skip (extend path), or a Fork (wrap in a new Skip). A `Stub` answers none of
these. So `normalize` becomes fallible and must resolve the sibling first.

This is the *only* place a sideways (non-path) resolution is needed, and it is
the reason Phase B exists. Give it a dedicated test:

```rust
#[test]
fn delete_collapse_resolves_the_sibling_stub() {
    // Build a Fork with exactly two occupants where the sibling is NOT on the
    // deleted key's path, so the witness cannot contain it.
    // Deleting one occupant must resolve the sibling through the provider and
    // produce the same root as the full trie.
}
```

Two sub-cases to cover: the sibling is a Leaf (path extends, value moves up) and
the sibling is a Fork (gets wrapped in a fresh `Skip { path: [n] }`).

### 6.3 Providers

```rust
/// Phase A: offline, fails on anything the witness lacks. Path ignored.
pub struct WitnessProvider(pub Witness);

/// Development: a full node map, so nothing ever misses. Useful for isolating
/// bugs in traversal from bugs in witness construction.
pub struct MapProvider(pub BTreeMap<H256, Vec<u8>>);

/// Instrumented wrapper: records every (path, hash) requested. This IS the
/// witness builder — run the workload against a complete store, collect what
/// was touched, and you have the minimal witness for that workload.
pub struct RecordingProvider<P> { inner: P, seen: RefCell<Vec<(Vec<u8>, H256)>> }
```

`RecordingProvider` is worth building early. It turns "which nodes does this
workload need?" from an analysis problem into an observation, and it produces
minimal witnesses as a by-product.

---

## 7. Nesting: account trie over storage trie

Ethereum has two levels, and the sub-project only pays off once both work.

1. Build a partial **storage** trie from `storageProof`; verify against the
   account's `storageRoot`.
2. Apply slot updates; recompute → `storageRoot'`.
3. Decode the account value, which is `rlp([nonce, balance, storageRoot, codeHash])`,
   swap in `storageRoot'`, re-encode.
4. Build a partial **state** trie from `accountProof`; verify against the
   block's `stateRoot`.
5. Insert the updated account at `keccak256(address)`; recompute → `stateRoot'`.

`eth_getProof(address, [slots…])` returns both proofs in one call — this is
exactly what it is for. Note that storage keys are `keccak256(slot)` and storage
values are RLP integers with no leading zeros, which is its own canonicality
trap.

**Milestone worth aiming at:** take a real mainnet block, `eth_getProof` an
account it touched, apply the same changes the transaction made, and land on the
next block's `stateRoot`.

---

## 8. reth integration (deferred)

Recorded so the constraints are not rediscovered later. **Verify all of this
against the actual reth 2.5.1 source before building — the schema below is from
general knowledge, not from reading that version.**

- Trie nodes live in `AccountsTrie` (keyed by nibble path) and `StoragesTrie`
  (keyed by hashed address **plus** nibble path). **Not content-addressed** —
  hence the `path_nibbles` argument on `NodeProvider`.
- Storage tries are per-account, so a `StoragesTrie` lookup needs the account's
  `keccak256(address)`. Either two provider impls or one with an account-context
  field.
- **reth stores only branch nodes.** Leaves and extensions are reconstructed
  from `HashedAccounts` / `HashedStorages`. A prefix lookup returning nothing
  means "not a branch", not "missing". Since the sibling needed during a delete
  collapse is often a leaf, resolving it means a prefix range scan over hashed
  state and rebuilding the node — with the stub hash confirming you got it right.

**Cheaper first cut:** ignore the trie tables entirely and build every node from
`HashedAccounts` / `HashedStorages` by prefix scan. Slower, no schema
dependency, and correctness is identical because every node is verified against
its hash regardless. Get the round-trip green that way, then optimise to use
reth's branch nodes.

**Scale is not a concern.** ~7 levels deep on mainnet state, so a few dozen node
reads per account. The trie never materialises.

---

## 9. Entry points

| File | Contents |
|---|---|
| `crates/mpt-core/src/trie.rs` | Add `Stub` variant; `Result`-ify traversal; `normalize` resolves siblings |
| `crates/mpt-core/src/partial.rs` | `Witness`, `decode_node`, `NodeProvider`, `WitnessProvider`, `MapProvider`, `RecordingProvider` |
| `crates/mpt-core/src/error.rs` | `TrieError` |
| `crates/mpt-core/tests/partial.rs` | Phase A round-trip and its variants |
| `crates/mpt-core/tests/provider.rs` | Phase B, including the delete-collapse sibling case |
| `crates/mpt-reth/` | MDBX provider (new crate, `std`) |

### Suggested order

1. `H256` alias; `Stub` variant; make `encode_node` handle it. Existing tests
   stay green because no stub is ever constructed yet.
2. `TrieError`; `Result`-ify traversal. Mechanical, noisy, no behaviour change.
3. `decode_node` + `Witness`. Assert `build(&root).hash() == root`.
4. The §5.2 acceptance test with value updates only. **This is the milestone.**
5. `NodeProvider` + `MapProvider`; thread it through traversal.
6. `normalize` sibling resolution; the delete-collapse test.
7. `RecordingProvider`; use it to produce minimal witnesses.
8. Account/storage nesting (§7).
9. reth (§8).

Steps 1–4 are a weekend and prove the whole idea. Everything after is extension.

---

## 10. Open questions

- **Does `prove` always include the diverging node** for an exclusion proof that
  terminates on a Leaf or Skip? It should, since `collect` pushes the node it
  stops at — but confirm rather than assume, because insert-into-witness depends
  on it.
- **Should `Witness::build` fail or return a bare `Stub`** when the root itself
  is missing? Failing is probably right, but an all-stub trie is a legitimate
  representation of "we know the root and nothing else".
- **Ordering of `normalize`'s sibling resolution.** Resolving may itself expose
  new stubs one level down. Does one pass suffice, as it did for the non-partial
  case (NOTES.md §6.2)?
- **Should `Trie` own its provider** rather than taking it per call? Owning is
  ergonomic but makes `Trie` non-`Send` for many providers and couples the type
  to a lifetime.
- **Witness serialisation format.** A flat list of RLP nodes is the obvious
  choice and matches what `eth_getProof` returns. Worth defining if witnesses
  are ever to be shipped between processes.
