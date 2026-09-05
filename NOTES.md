# Design decisions

Rationale for choices that are not obvious from the code, plus the security
properties each one buys or costs. Written as we went; the stage numbers refer
to the build order in README.md.

---

## Stage 1 — binary Merkle tree (`merkle.rs`)

This module is a warm-up and a contrast case, not a dependency of the MPT. Only
`hasher.rs` carries forward. It exists to isolate the *Merkle* half of "Merkle
Patricia Trie" from the *Patricia* half, and to make the absence-proof gap
concrete before the MPT's design is introduced as the answer to it.

### 1.1 Leaf vs node domain separation
**Choice:** tag byte at a fixed offset. `hash_leaf = H(b"L" ‖ data)`,
`hash_node = H(b"N" ‖ l ‖ r)`.

**Why:** the tags sit at byte 0, a position the attacker does not control.
Without them, an attacker takes an honest 4-leaf tree over `a,b,c,d` and builds
a 2-leaf tree over the 64-byte strings `X = la‖lb` and `Y = lc‖ld`. Then
`H(X) = L` and `H(Y) = R` by construction, so both trees have root `H(L‖R)`.
Same root, different leaf set, no hash broken — and the attacker can produce a
valid inclusion proof for `X`, a value never in the leaf set. Second preimage
attack; RFC 6962 §2.1.

**Rejected:** separating by length ("nodes are always 2·LENGTH bytes, anything
else is a leaf"). Holds until someone submits a 64-byte leaf, at which point the
attacker chooses the discriminating property rather than us. The tag must sit
outside attacker-controlled data.

**Extra weight under promotion (§1.2):** promotion means one hash value
legitimately appears at several depths, so "value found at an unexpected depth"
is normal traffic rather than a structural anomaly we could reject. The tags are
the only thing keeping the two preimage spaces disjoint. A promoted node is a
plain copy — never re-tag it with `hash_leaf`.

### 1.2 Odd node counts: PROMOTION
**Choice:** an odd level's last element is copied unchanged into the next level.
Level widths follow `n → (n + 1) / 2`.

**Duplication** is ruled out by test, not argument: duplicating `c` in `[a,b,c]`
gives level 1 = `[N(la,lb), N(lc,lc)]`, identical to what `[a,b,c,c]` produces,
so two distinct leaf sets collide. CVE-2012-2459, caught by
`duplicated_tail_leaf_changes_the_root`.

**Padding** to `next_power_of_two` was rejected. It is what SSZ / the beacon
chain does and it is the *safer* option (see the cost below). Chosen against
because this tree has no bounded depth known in advance, and promotion supports
cheap append plus CT-style consistency proofs between two tree sizes.

**THE COST — the important entry in this file.** Promotion makes tree shape
unrecoverable from `(root, leaf, index, proof)`, so `verify` takes `size` as a
fifth argument. `size` is NOT a hint the verifier uses to rebuild shape. It is
an *unauthenticated input that selects which of several valid interpretations of
the same proof applies*. The proof does not bind it.

Concretely, `n = 3`. Level 0 = `[L0, L1, L2]`, `L2` promotes, root `R = N(A, L2)`
with `A = N(L0, L1)`. The honest proof for index 2 is `[A]`. That same proof
also verifies for `(index 1, size 2)`: one step, index odd, fold `N(A, L2) = R`.
Same root, same proof, same leaf, two different positions asserted, no hash
broken. Documented by `promotion_allows_index_remapping`.

Note also that `size` influences the fold ONLY through the promotion branch, so
traversal-equivalent sizes accept the same proof — 7 and 8 for index 3, say.
Documented by `traversal_equivalent_sizes_accept_the_same_proof`. A blanket
"wrong size is rejected" test would be asserting something false.

**Consequence:** `size` must arrive over the same authenticated channel as the
root. RFC 6962 signs `tree_size` into the Signed Tree Head for exactly this
reason.

> **OPEN: where does `size` come from in this system, and what authenticates it?**

Under padding this attack class does not exist: fixed depth means the index is
fully recovered from the direction bits plus the proof length, and no external
input selects the interpretation.

### 1.3 Empty-tree root
**Choice:** `H::Out::default()`, the all-zero hash.

**Why:** zero is outside the image of Keccak with overwhelming probability, so
no attacker can construct a non-empty tree whose root is zero. Asserted by
`empty_root_is_the_zero_hash_and_unreachable_by_hashing`.

**Cost:** `empty_root == H::Out::default()`, so "empty tree" and "zeroed /
uninitialised" share a bit pattern. Do not derive `Default` on `MerkleTree`, and
never use a zero hash as an "absent" sentinel in a struct field.

**Contrast:** the MPT uses `keccak256(rlp(""))` =
`56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421`, precisely
because a Fork's 16 child slots need "no child" and "child is an empty trie" to
be distinct values in the same position. Different constraint, different answer.

### 1.4 Proof encoding: bare sibling list
**Choice:** `Proof { siblings: Vec<H::Out> }`. Direction derived from
`index % 2` at each level; index and size passed to `verify` as arguments.

**Rejected — per-step direction bits:** these make `verify` work statelessly
under promotion with no `size` argument, but then `verify` cannot accept an
index at all, because the index is not recoverable from a variable-length path.
That is a *membership* proof, not a *position* proof, and position is what is
being committed to (§1.6).

**Rejected — bundling index and size into `Proof`:** the four inputs have three
different provenances — `leaf` is the verifier's own, `index` is the verifier's
*question*, `size` is authenticated metadata, `siblings` is the only
prover-supplied item. A struct containing all four *looks* self-contained and
authenticated and is neither. If a self-contained object is wanted, it needs a
signature over the claim, which is a different type. The accurate name for what
`Proof` holds is an audit path or witness; a proof is `(claim, witness)` and the
claim lives outside.

**Malleability closed in `verify`:** siblings are read with `.get()` (a short
proof returns false rather than panicking — `verify` is the attacker-facing
entry point), and `cursor == siblings.len()` is checked at the end so trailing
junk is rejected. Without that second check a proof is not a canonical object,
and anything downstream that hashes, caches, dedupes or signs one inherits a
malleability bug. The same question returns for RLP (§2.1) and for MPT proofs
(§7.3).

### 1.5 Storage layout
Levels of `H::Out`, level 0 = leaf hashes, folding upward. Leaf *data* is not
stored: nothing in the API returns it, `prove` emits only sibling hashes, and
`verify` takes the leaf from the caller. Matches deployment reality — the prover
holds the tree, leaf data lives elsewhere, and proofs travel without it.
Bottom-up indexing so `prove` halves the index as it walks levels in order.

### 1.6 Ordering: an ordered list, not a sorted set
No sorting, no dedup. The order *is* part of the commitment — asserted by
`distinct_leaf_sets_have_distinct_roots`. Ethereum's transaction and receipt
tries are keyed by position, and a block whose transactions execute in a
different order is a different block.

### 1.7 Proof-length invariant
Padded depth (`next_power_of_two().trailing_zeros()`) does NOT hold — that
asserts uniform leaf depth, which promotion breaks by design. For `n = 9`, leaf
8 promotes at every level and gets a 1-sibling proof while leaf 0 gets 4.

The real invariant is that `prove` and `verify` agree on step count for every
`(index, size)`. Pinned by `proof_length_matches_promotion_recurrence`, which
re-derives the recurrence independently in the test. The duplication is
deliberate: a change to promotion in `new()` must break the test rather than
silently reshape every proof.

### 1.8 Security statement
Given `root` AND an authenticated `size`, a successful
`verify(root, leaf, index, size, proof)` means: the prover has shown that the
ordered list committed to by `root` has `leaf` at position `index`.

Without an authenticated `size` the position claim is void and the statement
weakens to membership at *some* position (§1.2).

It does NOT cover: the value at any other index; whether `leaf` also appears
elsewhere; or **what is absent from the list** — that would be a claim over all
indices at once, and the format addresses exactly one.

### 1.9 Why absence is impossible here — and what fixes it
**Attempt 1, enumerate every index.** `O(n log n)` bandwidth, includes every
leaf, so it is the dataset with extra steps rather than a proof. The fatal
problem is not cost: the *prover chooses what to send*. Omit index 7 and the
verifier notices nothing — there is no authenticated count to contradict, and
paths do not bind position anyway.

**Attempt 2, sort the leaves and prove a gap between two adjacent ones.** This
is the right construction, `O(log n)`, and it is what sorted-Merkle range proofs
do. It rests on two facts the proof cannot establish:

1. **Adjacency.** Under promotion, `index` is not bound by the path (§1.2), so
   "adjacent" is whatever the prover claims.
2. **Sortedness.** Nothing about the root says the leaves are sorted. A prover
   who builds a deliberately unsorted tree can place `a` and `b` next to each
   other with `x` elsewhere, and both inclusion proofs are honest.

Proving sortedness is the `O(n)` enumeration again. **The gap is not bandwidth:
a positional Merkle tree commits to a list, and "sorted" and "adjacent" are
properties of a list that a root cannot attest to.**

**The general form: positional commitments prove membership; keyed commitments
prove non-membership.** Keying by the key's own nibbles means a key's location
is *derived* rather than claimed, the verifier recomputes it independently, and
sortedness is not an assumption because shape is a function of the key set.
That is the MPT, and §7.4 is the payoff.

---

## Stage 2 — RLP

### 2.1 Canonicality
Encoding is easy; the decoder is the work. RLP admits multiple byte sequences
that would decode to the same item, and a conformant decoder must **reject** the
non-canonical ones: non-minimal single bytes (`0x81 0x2a` where `0x2a` alone is
canonical), non-minimal length prefixes (long form for a length ≤ 55), leading
zeros in a declared length, truncated input, and trailing bytes.

The reason is the same one as §1.4: if two byte sequences decode to the same
item then `keccak256` of them differs, and any protocol that hashes, signs,
caches or compares encoded data has a malleability bug. Ethereum has had real
consensus bugs here.

The central property is `encode(decode(input)) == input` for every accepted
input, not just `decode(encode(item)) == item`. Only the first direction catches
a permissive decoder.

### 2.2 Using the `rlp` crate
`rlp` 0.6 with `default-features = false` is used for MPT node encoding.
`RlpStream::append_raw(&bytes, 1)` is the escape hatch that makes inlined child
references expressible — see §5.2.

> **OPEN: recursion depth.** `0xc1 0xc1 0xc1 …` is a one-byte-per-level stack
> overflow from a hostile peer. Real clients cap depth. Decide whether ours does.

---

## Stage 3 — nibbles and hex-prefix (`path.rs`)

### 3.1 No `Nibbles` newtype
Nibbles and bytes are both `Vec<u8>`, and the trie passes both around. A wrapper
would prevent passing bytes where a nibble path is expected — a bug that
type-checks and produces a trie returning wrong answers. Rejected anyway for
friction; mitigated by naming parameters `path_nibbles` / `key_bytes` and by
validating at the two entry points (`from_nibbles`, `hex_prefix_decode`) where
invalid values can enter. Nibble values above `0x0f` are rejected, not masked.

### 3.2 Unpacked in memory, packed on the wire
Nibbles are one per `u8` in memory. Packing them 4-bit would need a
`(bytes, start_nibble, len)` view type, because a slice starting at an odd
nibble does not start at a byte boundary — and slicing, `common_prefix_len` and
concatenation are what the trie does constantly. The memory saving is ~32 bytes
per path. Packing belongs at the serialisation boundary only, which is what HP
is.

### 3.3 Hex-prefix canonicality
Flag nibble is `2 * is_leaf + (len % 2)`, plus a `0x0` pad nibble when the path
length is even. First nibble: 0 = ext/even, 1 = ext/odd, 2 = leaf/even,
3 = leaf/odd.

The decoder rejects empty input, a first nibble above 3, and **an even-parity
declaration whose pad nibble is not zero** (`0x01 0x23`). That last one is the
canonicality rule most implementations skip, and it is the same class as §2.1.
Asserted by `accepted_input_re_encodes_identically`.

### 3.4 HP is the MPT's domain separation
§1.1 uses explicit tag bytes; the MPT does not need them. A Leaf is
`rlp([hp(path, true), value])`, a Skip is `rlp([hp(path, false), child_ref])` —
both 2-item lists, distinguished by bit 1 of the first nibble of item 0. A Fork
is a 17-item list, so it cannot be confused with either. Asserted by
`leaf_and_extension_never_collide` and `encoding_is_injective_over_small_paths`.

---

## Stage 4 — the trie, unhashed (`trie.rs`)

### 4.1 Node naming
`Null` / `Leaf` / `Skip` / `Fork`. `Skip` is the yellow paper's **extension**
node. Every fixture, reference implementation and spec document says
"extension", so the mapping is recorded in doc comments on each variant.

### 4.2 Structural invariants
Checked by `debug_check`, called after every mutation in tests. Every stage 6
deletion bug is one of these being violated:

- a `Skip`'s path is never empty
- a `Skip`'s child is always a `Fork` (never a Leaf, never another Skip — those
  merge)
- a `Fork` has at least two occupants, counting the 16 children and its own
  value slot
- `Null` appears only as the whole trie's root

`skip_or(path, child)` returns `child` unchanged when `path` is empty, which
enforces the first invariant in one place instead of four.

### 4.3 Order independence
The MPT has ONE canonical shape per key/value set, so inserting the same map in
two orders must produce structurally equal tries. Asserted at stage 4 on the
`Node` tree and at stage 5 on the root hash, which is what the
`trieanyorder.json` fixtures check.

---

## Stage 5 — Merkleization

### 5.1 On-demand hashing
`root_hash` walks and re-encodes the whole trie on every call. Real clients keep
dirty flags and rehash only the changed path. On-demand is correct and simple;
incremental is a stage 8 optimisation and is what a dirty-node visualisation
would want anyway.

### 5.2 The node-reference rule
```
ref(node) = if rlp(node).len() < 32 { rlp(node) }   // inlined verbatim
            else { keccak256(rlp(node)) }           // 32-byte hash
root_hash = keccak256(rlp(root))                    // root is ALWAYS hashed
```

The size test is on the *child's own* encoding. `< 32` is strict: a 32-byte
inline value would be indistinguishable from a hash reference when decoding.

An inlined child's bytes are already well-formed RLP and are spliced into the
parent **raw** (`RlpStream::append_raw`); a hash reference is a 32-byte *string*
and goes through `append` (emerging with the `0xa0` prefix). Getting this
backwards double-encodes and every trie with small nodes fails.

Inlining propagates upward: a small leaf inside its parent makes the parent
bigger, which may push the parent over 32 and force *it* to be hashed. This is
why a proof's node count does not match the path depth (§7.2).

### 5.3 Stale db entries
Deletion leaves orphaned entries in the node db. Harmless for `root_hash`, which
re-encodes from the root, and harmless for proofs, which only ever walk live
nodes. Real clients reference-count or prune. Noted, not fixed.

---

## Stage 6 — deletion

### 6.1 Why it is the hard part
Insert only adds structure. Delete must remove it *and repair the shape*,
because the MPT is canonical: a trie with redundant nodes holds the right data,
answers `get` correctly, and hashes wrong.

### 6.2 The collapse rules (`normalize`)
Applied to any node whose child just changed, on the way back up the recursion.

**Fork, one occupant:**
- occupant is the value slot → `Leaf { path: [], value }`
- occupant is child at nibble `n` → the fork disappears and `n` is prepended to
  the child's path: a Leaf or Skip gains `[n]` on its path, a Fork gets wrapped
  in `Skip { path: [n], child }`
- the `(1 child, None)` case requires the value slot to be empty — a fork with
  one child *and* a value has occupancy 2 and stays a fork

**Skip over Leaf / Skip over Skip:** merge the paths. This is what keeps the
"Skip child is always a Fork" invariant true, and it must run *after* the fork
collapse, since collapsing a fork is what produces a skip-over-leaf.

One `normalize` per level suffices, but only because it runs at every level on
the way up: a collapse at depth 5 produces a merge at depth 4, which produces
one at depth 3, each seeing an already-repaired child.

### 6.3 The strongest test
Insert a key, delete it, assert the root is **byte-identical** to before.
Non-canonical leftover structure is invisible to `get` and shows up only here.
`delete_restores_the_exact_root` sweeps six key shapes; the proptest
`root_depends_only_on_surviving_contents` is the general form.

---

## Stage 7 — proofs

### 7.1 Signature
```rust
verify_proof(root: &H::Out, key: &[u8], proof: &[Vec<u8>])
    -> Result<Option<Vec<u8>>, ProofError>
```
`root` is the only trusted input. `key` is the verifier's question. `proof` is
attacker-controlled. `Ok(Some(v))` = proven present, `Ok(None)` = **proven
absent**, `Err` = the proof is garbage.

There is deliberately no `KeyNotFound` error variant. Absence is a successful
result, not a failure; putting it in the error enum would throw away the ability
to distinguish "proven absent" from "your proof is broken".

### 7.2 Proof structure
Generation is a path walk collecting each traversed node's RLP. Nodes under 32
bytes were inlined into their parent and get **no entry of their own** — they
are already covered by the parent's hash. Hence proof length ≠ path depth, which
is the thing that confuses people about `eth_getProof` output. Asserted by
`inlined_children_do_not_get_their_own_proof_entry` and
`every_proof_node_hashes_into_the_chain`.

### 7.3 Verifier hardening
- every node is checked against the reference its parent held, or the root at
  step 0
- a short proof returns `Truncated`, never panics — `verify_proof` is the
  attacker-facing entry point
- `cursor != proof.len()` after the walk → `TrailingNodes`. Same canonicality
  reasoning as §1.4 and §2.1
- an inlined reference consumes no proof node; a 32-byte reference consumes one.
  This distinction is the whole of the `resolve` helper

### 7.4 Exclusion terminates three ways
Empty Fork slot; Leaf whose stored path diverges from the key; Skip whose stored
path diverges from the key. Each is a *positive* proof of absence, checked
structurally rather than claimed. Compare §1.9: nothing here is asserted by the
prover, because the path is derived from the key the verifier already holds.

### 7.5 Empty trie
`prove` on a `Null` root returns an **empty** proof, and `verify_proof`
special-cases it: empty proof against `keccak256(0x80)` is `Ok(None)`, against
any other root it is `Err(Truncated)`. The naive alternative — emitting
`rlp(Null)` = `[0x80]` — passes the hash check and then fails to decode as a
node, since `0x80` is a string rather than a 2- or 17-item list.

### 7.6 Empty values are indistinguishable from absent values
RLP encodes both an empty string and "no value" as `0x80`, so a Fork's empty
value slot reads as `None`. Ethereum sidesteps this by never storing empty
values. Inherited, not solved.

---

## Cross-cutting

### C.1 Hasher API: chunked `hash_all(&[&[u8]])`
Lets `hash_leaf` / `hash_node` prepend a tag byte with a stack slice literal
instead of building a prefixed `Vec`. Both are heap-free.

**Hazard:** chunk boundaries carry NO information.
`hash_all(&[b"ab"]) == hash_all(&[b"a", b"b"])`, and
`hash_all(&[]) == hash_all(&[b""])`. The chunk split *looks* like structure and
is not — writing `hash_leaf` as `H::hash_all(&[data])` and `hash_node` as
`H::hash_all(&[l, r])` reproduces the §1.1 attack exactly. Asserted by
`chunking_is_transparent`.

**Not taken:** exposing a streaming digest type. Strictly more general — an RLP
encoder could write directly into the digest and never materialise a buffer —
but it puts the `digest` crate's traits in `mpt-core`'s public API. In practice
the chunk API buys nothing for MPT node hashing, which is
`keccak256(rlp(node))` over one contiguous buffer.

### C.2 `no_std` + `alloc`
Costs nothing and keeps the core crate honest about what it touches. The
`wasm32-unknown-unknown` build is checked in CI as the canary: if it breaks,
something leaked in.

> **OPEN: is `Hasher` generality worth it, given the MPT hardcodes Keccak-256?**
> The trait shape (associated `Out`, const `LENGTH`, stateless `hash_all`)
> matches `hash-db` and lets a caller swap in Blake2 for a Substrate-style trie.
> `ProofError::HashMismatch` currently hardcodes `[u8; 32]` so it can carry the
> hashes; making it generic means parameterising the error enum. Decide.
