# mpt-lab

A Merkle Patricia Trie in Rust, written from scratch to learn how Ethereum's
state commitment actually works.

It is byte-exact: the roots it produces match the `ethereum/tests` fixtures, and
therefore match the `stateRoot` in a real block header.

```rust
let mut t = Trie::<Keccak256>::new();
t.insert(b"do",    b"verb".to_vec()).unwrap();
t.insert(b"dog",   b"puppy".to_vec()).unwrap();
t.insert(b"doge",  b"coin".to_vec()).unwrap();
t.insert(b"horse", b"stallion".to_vec()).unwrap();

assert_eq!(
    hex::encode(t.hash()),
    "5991bb8c6514148a29db676a14ac506cd2cd5775ace63c30a4fe457715e9ac84"
);

// Prove a key is present, holding only the 32-byte root.
let root  = t.hash();
let proof = t.prove(b"dog");
assert_eq!(verify_proof(&root, b"dog", &proof), Ok(Some(b"puppy".to_vec())));

// Prove a key is ABSENT. This is the thing a plain Merkle tree cannot do.
let proof = t.prove(b"cat");
assert_eq!(verify_proof(&root, b"cat", &proof), Ok(None));
```

## What's here

| Module | Contents |
|---|---|
| `hasher.rs` | `Hasher` trait, `Keccak256` |
| `merkle.rs` | Binary Merkle tree — a contrast case, not an MPT dependency |
| `path.rs` | Nibble expansion, hex-prefix (compact) codec |
| `trie.rs` | `Node` (`Null`/`Leaf`/`Skip`/`Fork`), insert, get, remove, Merkleization, proofs |

`mpt-core` is `no_std` + `alloc` and builds for `wasm32-unknown-unknown`.

## Features

- Insert, get, and delete with correct canonical collapse
- Byte-exact root hashes, including the sub-32-byte node inlining rule
- Inclusion **and exclusion** proofs, with a stateless verifier that needs only
  the root
- Secure-trie mode (keys hashed with keccak256) — no extra trie code, just the
  key transform
- Structural invariants checked after every mutation in tests

## Testing

```bash
cargo test
cargo test -- --nocapture     # fixture case names
cargo build --target wasm32-unknown-unknown
```

**Fixtures.** All 22 cases from
[`ethereum/tests/TrieTests`](https://github.com/ethereum/tests/tree/develop/TrieTests):
7 `trieanyorder`, 7 `trieanyorder_secureTrie`, 5 `trietest`, 3
`trietest_secureTrie`. Insert-only cases are additionally replayed in three
shuffled orders to check that the root depends on contents and not on insertion
sequence.

Refresh them with:

```bash
for f in trietest trieanyorder trietest_secureTrie trieanyorder_secureTrie; do
  curl -sS -o "crates/mpt-core/tests/fixtures/$f.json" \
    "https://raw.githubusercontent.com/ethereum/tests/develop/TrieTests/$f.json"
done
```

**Property tests.** Differential against `BTreeMap` under interleaved
insert/remove; root independence from insertion and deletion order; insert-then-
remove is an exact identity on the root hash; every proof verifies and no
tampered proof does; the verifier never panics on arbitrary bytes.

## Notes for readers

Three things surprise most people reading MPT code for the first time:

**Nodes under 32 bytes are inlined.** A child whose RLP is shorter than 32 bytes
is embedded verbatim in its parent rather than referenced by hash. It changes
the bytes, so it changes every hash above it — and it means a proof's node count
is *less* than the path depth, because inlined nodes never appear as separate
proof entries.

**Deletion is the hard part.** The MPT has one canonical shape per key/value
set, so removing a key means repairing the structure: forks with a single
remaining occupant collapse, and the extension nodes above them absorb the
result. A trie with redundant nodes returns correct `get` results and the wrong
root hash.

**Exclusion proofs are why the trie is keyed by path.** A binary Merkle tree can
prove a leaf is at a position; it cannot prove a value is absent, even with
sorted leaves, because "sorted" and "adjacent" are properties of a list that a
root cannot attest to. Keying by the key's own nibbles makes a key's location
*derived* rather than claimed, so the verifier recomputes it independently and
absence becomes structurally checkable. `NOTES.md` §1.9 works through why the
obvious constructions fail.

## Build order

Written stage by stage, each gated on the previous being green. Useful if you
want to follow the same path.

1. **Binary Merkle tree** — inclusion proofs, domain separation, and the
   discovery that exclusion proofs are impossible here
2. **RLP** — encode/decode with strict canonicality
3. **Nibbles and hex-prefix** — the compact codec, leaf/extension tagging
4. **Radix-16 trie** — node model, insert, get, no hashing at all
5. **Merkleization** — node references, inlining, node db, first real roots
6. **Deletion** — branch collapsing and extension merging
7. **Proofs** — generation plus a stateless verifier

`NOTES.md` records the design decisions and the security property each one buys
or costs, roughly in that order.

## Not done

- Incremental hashing. `hash()` re-encodes the whole trie; real clients keep
  dirty flags and rehash only the changed path.
- Node-db pruning. Deletion orphans entries; nothing reference-counts them.
- Iteration over key/value pairs.
- Fuzzing against a reference implementation such as `alloy-trie`.
- Verifying a proof against real mainnet state via `eth_getProof`.

## References

- Ethereum Yellow Paper, appendix C (hex-prefix) and appendix D (RLP)
- [Merkle Patricia Trie spec](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/)
- RFC 6962 (Certificate Transparency) — for the binary tree's audit paths and
  the `tree_size` authentication problem
- CVE-2012-2459 — why duplicating an odd tail node is unsafe
