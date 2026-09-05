# Design decisions

## Stage 1 — binary Merkle tree

### 1. Leaf vs node domain separation
Choice: tag byte at a fixed offset. hash_leaf = H(b"L" ‖ data), hash_node = H(b"N" ‖ l ‖ r).
Why: the tags sit at byte 0, a position the attacker does not control. Without them, an
attacker takes an honest 4-leaf tree over a,b,c,d and builds a 2-leaf tree over the
64-byte strings X = la‖lb and Y = lc‖ld. Then H(X) = L and H(Y) = R by construction, so
both trees have root H(L‖R). Same root, different leaf set, no hash broken. The attacker
can then produce a valid inclusion proof for X (proof = [R], index 0) — a value that was
never in the leaf set. Second preimage attack; see RFC 6962 §2.1.

Rejected: separating by length ("nodes are always 2·LENGTH bytes, anything else is a
leaf"). Holds until someone submits a 64-byte leaf, at which point the attacker chooses
the discriminating property rather than us. The tag must be outside attacker-controlled
data.

Extra weight under promotion (§2): promotion means one hash value legitimately appears at
several depths, so "value found at an unexpected depth" is normal traffic rather than a
structural anomaly we could reject. The tags are the only thing keeping the leaf and node
preimage spaces disjoint. Do NOT re-tag a promoted node with hash_leaf — promotion is a
plain copy.

Note: the MPT does not use tag bytes. It gets the same disjointness from RLP structure
plus hex-prefix encoding — leaf and extension are 2-item lists distinguished by the first
nibble of the encoded path, branch is a 17-item list. Verify that reasoning covers every
node shape at stage 3.

### 2. Odd node counts: PROMOTION (not duplication, not padding)
Choice: an odd level's last element is copied unchanged into the next level. Level widths
follow n → (n + 1) / 2.

Duplication is ruled out by test, not by argument: duplicating c in [a,b,c] gives level 1 =
[N(la,lb), N(lc,lc)], identical to what [a,b,c,c] produces, so the two leaf sets collide.
That is CVE-2012-2459, caught by duplicated_tail_leaf_changes_the_root.

Padding to next_power_of_two was rejected. It is what SSZ / the beacon chain does, and it is
the *safer* option (see the cost below). Chosen against because the tree here has no
bounded depth known in advance, and promotion gives cheap append plus CT-style consistency
proofs between two tree sizes, which padding does not.

THE COST — this is the important entry in this file:
Promotion makes tree shape unrecoverable from (root, leaf, index, proof), so verify takes
`size` as a fifth argument. `size` is NOT a hint the verifier uses to rebuild shape. It is
an unauthenticated input that selects which of several valid interpretations of the same
proof applies. The proof does not bind it.

Concretely, n = 3. Level 0 = [L0, L1, L2], L2 promotes, root R = N(A, L2), A = N(L0, L1).
The honest proof for index 2 is [A]. That same proof also verifies for (index 1, size 2):
one step, index odd, fold N(A, L2) = R. Same root, same proof, same leaf, two different
positions asserted, no hash broken. An attacker who controls `size` picks which position
claim the proof supports. Documented by promotion_allows_index_remapping.

Note also that `size` influences the fold ONLY through the promotion branch, so sizes that
are traversal-equivalent for a given index accept the same proof — e.g. 7 and 8 for index 3.
Documented by traversal_equivalent_sizes_accept_the_same_proof. A "wrong size is rejected"
test asserting the general case would be asserting something false.

Consequence: `size` must arrive over the same authenticated channel as the root. RFC 6962
signs tree_size into the Signed Tree Head for exactly this reason.

>>> WHERE DOES `size` COME FROM IN THIS SYSTEM, AND WHAT AUTHENTICATES IT? <
Answer:

Under padding this class of attack does not exist: fixed depth means index is fully
recovered from the direction bits plus the proof length, and no external input selects the
interpretation.

### 3. Empty-tree root
Choice: H::Out::default(), i.e. the all-zero hash.
Why: zero is outside the image of Keccak with overwhelming probability, so no attacker can
construct a non-empty tree whose root is zero. Asserted by
empty_root_is_the_zero_hash_and_unreachable_by_hashing.
Cost: empty_root == H::Out::default(), so "empty tree" and "zeroed / uninitialized" share a
bit pattern. Consequences — do not derive Default on MerkleTree; never use a zero hash as an
"absent" sentinel in a struct field, since it cannot be told apart from "present, and it is
the empty tree."
root() currently returns zero for the empty tree by accident (levels == [[]], so
.last().last() is None and unwrap_or_default() happens to match empty_root). Make that
deliberate or the two silently diverge if §3 ever changes.
Contrast for later: Ethereum uses keccak256(rlp("")) =
56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421, precisely because a
branch node's 16 child slots need "no child" and "child is an empty trie" to be distinct
values in the same position. Different constraint, different answer. Revisit at stage 5.

### 4. Proof encoding: bare sibling list, index and size passed to verify
Choice: Proof { siblings: Vec<H::Out> }. Direction is derived from index % 2 at each level.

Rejected — per-step direction bits: these make verify work statelessly under promotion with
no `size` argument, but verify can then no longer accept an index at all, because the index
is not recoverable from a variable-length path. That yields a *membership* proof, not a
*position* proof. Position is the thing being committed to (see §6), so this is a downgrade.

Rejected — padding, which would have let index alone determine the fold. See §2.

What the chosen option costs: everything in §2. The index/size pair is attacker-chosen and
the proof does not bind either.

Malleability closed in verify: siblings are read with .get() (a short proof returns false
rather than panicking — verify is the attacker-facing entry point), and cursor ==
siblings.len() is checked at the end so trailing junk is rejected. Without that second check
a proof is not a canonical object, and anything downstream that hashes, caches, dedupes or
signs a proof inherits a malleability bug. Same question returns for non-canonical RLP at
stage 2.

### 5. Storage layout
Choice: levels of H::Out, level 0 = leaf hashes, folding upward. Leaf *data* is not stored.
Why: nothing in the API returns leaf data — prove() emits only sibling hashes and verify()
takes the leaf from the caller. Matches deployment reality: the prover holds the tree, leaf
data lives elsewhere (block body, database, the verifier's own hand), and proofs travel
without it. Also makes level 0 size independent of leaf size.
Nested Vec<Vec<H::Out>> over a flat Vec with computed offsets because promotion makes levels
ragged and this is not a hot path.
Indexing direction: bottom-up, so prove() halves the index as it walks levels in order.

### 6. Ordering: leaves are an ordered list, not a sorted set
No sorting, no dedup. The order *is* part of the commitment — asserted by
distinct_leaf_sets_have_distinct_roots. Ethereum's transaction and receipt tries are keyed by
position, and a block whose transactions execute in a different order is a different block.
Sorting would also break the positional API: index stops being meaningful to a caller who
cannot ask the tree where their leaf ended up.

### 7. Is `Hasher` generality worth it, given the MPT hardcodes Keccak-256?
Argument:

### 8. Hasher API: chunked `hash_all(&[&[u8]])` rather than `hash(&[u8])`
Why: lets hash_leaf and hash_node prepend a tag byte with a stack-allocated slice literal
instead of building a prefixed Vec. Both are heap-free.
Hazard: chunk boundaries carry NO information. hash_all(&[b"ab"]) == hash_all(&[b"a", b"b"]),
and hash_all(&[]) == hash_all(&[b""]) == hash_all(&[b"", b""]). The chunk split looks like
structure and is not — writing hash_leaf as H::hash_all(&[data]) and hash_node as
H::hash_all(&[l, r]) reproduces the attack in §1 exactly. Asserted by
chunking_is_transparent.
Trade-off not taken: exposing a streaming digest type instead (associated
Digest: sha3::digest::Digest). Strictly more general — an RLP encoder could write directly
into the digest and never materialize a buffer. Cost: puts the `digest` crate's traits in
mpt-core's public API and ties the abstraction to one hashing ecosystem.
Open for stage 2: this API buys nothing for MPT node hashing, which is keccak256(rlp(node))
over one contiguous buffer. The allocation to eliminate there belongs to the RLP encoder's
API — does encode write into a caller-supplied &mut Vec<u8> or return a fresh one? Decide
that with the streaming option above in mind.

## Security statement for stage 1
Given `root` AND an authenticated `size`, a successful verify(root, leaf, index, size, proof)
means: the prover has shown that the ordered list committed to by `root` has `leaf` at
position `index`.

Without an authenticated `size` the position claim is void, and the statement weakens to
membership at *some* position — see §2.

The verifier already holds `leaf` — it is an input, not something learned. What stays hidden
is everything else: leaves off the path entirely, and only the path siblings' hashes for
those on it. proof.siblings.len() leaks an approximate list length.

What the statement does NOT cover:
- nothing about the value at any other index
- nothing about whether `leaf` also appears at other indices
- nothing about what is absent from the list — that would be a claim over all indices at
  once, and the proof format addresses exactly one

Open characterization: enumerate all (index, size) pairs for small sizes and group them by
which proofs they accept. The size of those equivalence classes is the honest measure of what
`size` does. Worth doing now rather than after three more stages.

## Proof-length invariant
Padded depth (next_power_of_two().trailing_zeros()) does NOT hold — that asserts uniform
leaf depth, which promotion breaks by design. For n = 9, leaf 8 promotes at every level and
gets a 1-sibling proof while leaf 0 gets 4.
The real invariant is that prove() and verify() agree on step count for every (index, size).
Pinned by proof_length_matches_promotion_recurrence, which re-derives the recurrence
independently in the test. The duplication is deliberate: a change to promotion in new()
must break the test rather than silently reshape every proof.
Proptest over n in 1..200 will rarely hit n = 2^k + 1, where promotion cascades maximally.
Fixed case: promoted_tail_leaf_has_short_proof (n = 9).

## prove_absence failure analysis
Attempt 1 — unsorted list, prove "x is at no index":
Where it breaks:

Attempt 2 — sort the leaves first, prove a gap between two adjacent ones:
What this buys:
What is still missing:

The test: describe one specific lie an adversarial prover can tell that a verifier holding
only the root cannot detect.
