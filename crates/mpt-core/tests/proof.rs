//! Inclusion and exclusion proofs.
//!
//! The verifier holds ONE trusted input: the 32-byte root. Everything else is
//! attacker-controlled bytes. `Ok(Some(v))` proves the key maps to `v`,
//! `Ok(None)` proves the key is absent, `Err` means the proof is garbage.
//!
//! Contrast with the binary Merkle tree in merkle.rs, which cannot express
//! `Ok(None)` at any cost: a positional commitment can't attest to a property
//! of all positions at once. Keying by path is what buys exclusion proofs.

use mpt_core::Keccak256 as K;
use mpt_core::trie::{ProofError, Trie, verify};
use proptest::prelude::*;
use std::collections::BTreeMap;

fn build(pairs: &[(&[u8], &[u8])]) -> Trie<K> {
    let mut t = Trie::<K>::new();
    for (k, v) in pairs {
        t.insert(k, v.to_vec());
    }
    t
}

const CLASSIC: &[(&[u8], &[u8])] = &[
    (b"do", b"verb"),
    (b"dog", b"puppy"),
    (b"doge", b"coin"),
    (b"horse", b"stallion"),
];

/// Keys that force deep paths, inlined children, and wide forks all at once.
fn mixed() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut v: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b"".to_vec(), b"empty-key".to_vec()),
        (b"a".to_vec(), b"s".to_vec()),   // 1-byte value: inlined
        (b"ab".to_vec(), vec![0xcd; 64]), // long value: hashed
        (b"abc".to_vec(), b"x".to_vec()), // terminates in a fork slot
        (b"prefix_shared_aaaa".to_vec(), vec![0x01; 40]), // deep skip
        (b"prefix_shared_bbbb".to_vec(), vec![0x02; 40]),
    ];
    for i in 0u8..16 {
        v.push((vec![i << 4], vec![i; 33])); // 16-wide fork
    }
    v
}

// ---------- inclusion ----------

#[test]
fn every_present_key_is_provable() {
    let mut t = build(CLASSIC);
    let root = t.hash();
    for (k, v) in CLASSIC {
        let proof = t.prove(k);
        assert_eq!(
            verify(&root, k, &proof),
            Ok(Some(v.to_vec())),
            "key {:?}",
            core::str::from_utf8(k)
        );
    }
}

#[test]
fn inclusion_across_shapes() {
    let pairs = mixed();
    let mut t = Trie::<K>::new();
    for (k, v) in &pairs {
        t.insert(k, v.clone());
    }
    let root = t.hash();
    for (k, v) in &pairs {
        assert_eq!(
            verify(&root, k, &t.prove(k)),
            Ok(Some(v.clone())),
            "key {k:?}"
        );
    }
}

#[test]
fn empty_key_is_provable() {
    let mut t = build(&[(b"", b"at-root"), (b"a", b"other")]);
    let root = t.hash();
    assert_eq!(
        verify(&root, b"", &t.prove(b"")),
        Ok(Some(b"at-root".to_vec()))
    );
}

// ---------- exclusion: the whole point ----------

#[test]
fn absent_keys_are_provably_absent() {
    let mut t = build(CLASSIC);
    let root = t.hash();
    for k in [
        &b"cat"[..], // diverges at the very first nibble
        b"d",        // strict prefix, no value there
        b"dogecoin", // extends past an existing leaf
        b"hors",     // strict prefix of "horse"
        b"",         // empty key, absent
        b"doge\x00", // one byte past a leaf
        b"x",        // empty slot in the top fork
        b"dogg",     // diverges at the last nibble
    ] {
        assert_eq!(verify(&root, k, &t.prove(k)), Ok(None), "key {k:?}");
    }
}

#[test]
fn exclusion_termination_shapes() {
    // The three ways an exclusion proof can terminate, each isolated:
    //   1. fork reached, next nibble's slot empty
    //   2. leaf reached, stored path diverges from the key
    //   3. skip reached, stored path diverges from the key
    let mut t = build(&[
        (b"\x11\x11\x11\x11", &vec![0xaa; 40]),
        (b"\x11\x11\x11\x12", &vec![0xbb; 40]),
        (b"\x99", &vec![0xcc; 40]),
    ]);
    let root = t.hash();

    // 1: top fork has nothing under nibble 5
    assert_eq!(verify(&root, b"\x55", &t.prove(b"\x55")), Ok(None));
    // 2: walks to the "\x11\x11\x11\x11" leaf, path diverges
    assert_eq!(
        verify(
            &root,
            b"\x11\x11\x11\x11\x99",
            &t.prove(b"\x11\x11\x11\x11\x99")
        ),
        Ok(None)
    );
    // 3: enters the shared "\x11\x11\x11" skip then diverges within it
    assert_eq!(
        verify(&root, b"\x11\x11\x99", &t.prove(b"\x11\x11\x99")),
        Ok(None)
    );
}

#[test]
fn exclusion_after_deletion() {
    // A deleted key must be provably absent, and the proof must reflect the
    // collapsed shape rather than any stale structure.
    let mut t = build(CLASSIC);
    t.remove(b"dog");
    let root = t.hash();
    assert_eq!(verify(&root, b"dog", &t.prove(b"dog")), Ok(None));
    assert_eq!(
        verify(&root, b"doge", &t.prove(b"doge")),
        Ok(Some(b"coin".to_vec()))
    );
}

#[test]
fn empty_trie_proves_everything_absent() {
    let mut t = Trie::<K>::new();
    let root = t.hash();
    for k in [&b""[..], b"anything", b"\x00"] {
        assert_eq!(verify(&root, k, &t.prove(k)), Ok(None), "key {k:?}");
    }
}

// ---------- soundness: forged proofs must be rejected ----------

#[test]
fn proof_does_not_verify_against_a_different_root() {
    let mut t = build(CLASSIC);
    let other = build(&[(b"do", b"verb"), (b"dog", b"DIFFERENT")]).hash();
    let proof = t.prove(b"dog");
    assert!(
        matches!(
            verify(&other, b"dog", &proof),
            Err(ProofError::HashMismatch { .. })
        ),
        "a proof from one trie must not verify under another root"
    );
}

#[test]
fn tampering_with_any_node_is_detected() {
    let pairs = mixed();
    let mut t = Trie::<K>::new();
    for (k, v) in &pairs {
        t.insert(k, v.clone());
    }
    let root = t.hash();
    let key = b"prefix_shared_aaaa";
    let proof = t.prove(key);
    assert!(
        proof.len() >= 2,
        "need a multi-node proof, got {}",
        proof.len()
    );

    for i in 0..proof.len() {
        for bit in [0usize, 3, 7] {
            let mut bad = proof.clone();
            let last = bad[i].len() - 1;
            bad[i][last] ^= 1 << bit;
            assert!(
                verify(&root, key, &bad).is_err(),
                "flipping bit {bit} of node {i} was not detected"
            );
        }
    }
}

#[test]
fn truncated_proof_is_rejected() {
    let pairs = mixed();
    let mut t = Trie::<K>::new();
    for (k, v) in &pairs {
        t.insert(k, v.clone());
    }
    let root = t.hash();
    let key = b"prefix_shared_bbbb";
    let full = t.prove(key);
    assert!(full.len() >= 2);

    for cut in 0..full.len() {
        let short = &full[..cut];
        assert!(
            verify(&root, key, short).is_err(),
            "truncating to {cut} of {} nodes was accepted",
            full.len()
        );
    }
}

#[test]
fn trailing_nodes_are_rejected() {
    // Canonicality: a proof must be exactly what the prover should have sent.
    // Same reasoning as the cursor check in merkle.rs — anything that hashes,
    // caches, dedupes or signs a proof inherits a malleability bug otherwise.
    let mut t = build(CLASSIC);
    let root = t.hash();
    let mut proof = t.prove(b"dog");
    proof.push(vec![0x80]);
    assert_eq!(
        verify(&root, b"dog", &proof),
        Err(ProofError::TrailingNodes(1))
    );
}

#[test]
fn reordered_proof_is_rejected() {
    let pairs = mixed();
    let mut t = Trie::<K>::new();
    for (k, v) in &pairs {
        t.insert(k, v.clone());
    }
    let root = t.hash();
    let key = b"prefix_shared_aaaa";
    let mut proof = t.prove(key);
    assert!(proof.len() >= 2);
    let last = proof.len() - 1;
    proof.swap(0, last);
    assert!(verify(&root, key, &proof).is_err());
}

#[test]
fn garbage_nodes_are_rejected_not_panicked_on() {
    // verify is the attacker-facing entry point. Malformed input must
    // return Err, never unwind.
    let root = build(CLASSIC).hash();
    for junk in [
        vec![],
        vec![vec![]],
        vec![vec![0xff]],
        vec![vec![0xc0]],                   // empty RLP list: 0 items, not 2 or 17
        vec![vec![0xc3, 0x01, 0x02, 0x03]], // 3-item list
        vec![vec![0x80]],                   // empty string, not a list
        vec![vec![0xff; 40]],
    ] {
        let r = verify(&root, b"dog", &junk);
        assert!(r.is_err(), "junk {junk:?} was accepted as {r:?}");
    }
}

#[test]
fn a_proof_for_one_key_does_not_prove_another() {
    let mut t = build(CLASSIC);
    let root = t.hash();
    let proof = t.prove(b"dog");
    // Using "dog"'s proof to ask about "horse" must not yield horse's value.
    // It may legitimately fail in several ways; what it must never do is
    // return Ok(Some(stallion)).
    assert_ne!(
        verify(&root, b"horse", &proof),
        Ok(Some(b"stallion".to_vec()))
    );
}

// ---------- structure of the proof itself ----------

#[test]
fn inlined_children_do_not_get_their_own_proof_entry() {
    // Sub-32-byte nodes live inside their parent's RLP, so they are already
    // covered by the parent's hash and must not appear as separate entries.
    // This is why proof length does not equal path depth.
    let mut t = build(&[(b"\x01", b"a"), (b"\x81", b"b")]);
    let root = t.hash();
    let proof = t.prove(b"\x01");
    assert_eq!(proof.len(), 1, "root fork only; the leaf is inlined");
    assert_eq!(verify(&root, b"\x01", &proof), Ok(Some(b"a".to_vec())));
}

#[test]
fn every_proof_node_hashes_into_the_chain() {
    // Each node after the first must be referenced by its predecessor, and the
    // first must hash to the root.
    let pairs = mixed();
    let mut t = Trie::<K>::new();
    for (k, v) in &pairs {
        t.insert(k, v.clone());
    }
    let root = t.hash();
    for (k, _) in &pairs {
        let proof = t.prove(k);
        assert!(!proof.is_empty(), "key {k:?} produced an empty proof");
        assert_eq!(
            <K as mpt_core::Hasher>::hash_all(&[&proof[0]]),
            root,
            "first proof node must hash to the root"
        );
        for node in &proof {
            assert!(
                node.len() >= 32,
                "sub-32-byte node in a proof: it should have been inlined"
            );
        }
    }
}

// ---------- properties ----------

fn kv_map() -> impl Strategy<Value = BTreeMap<Vec<u8>, Vec<u8>>> {
    prop::collection::btree_map(
        prop::collection::vec(any::<u8>(), 0..5),
        prop::collection::vec(any::<u8>(), 1..40),
        1..40,
    )
}

proptest! {
    #[test]
    fn present_and_absent_keys_both_verify(
        map in kv_map(),
        probes in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..5), 1..20),
    ) {
        let mut t = Trie::<K>::new();
        for (k, v) in &map { t.insert(k, v.clone()); }
        let root = t.hash();

        for (k, v) in &map {
            prop_assert_eq!(verify(&root, k, &t.prove(k)), Ok(Some(v.clone())));
        }
        for p in &probes {
            let want = map.get(p).cloned();
            prop_assert_eq!(verify(&root, p, &t.prove(p)), Ok(want), "probe {:?}", p);
        }
    }

    #[test]
    fn no_proof_survives_mutation(map in kv_map(), idx in any::<prop::sample::Index>()) {
        let keys: Vec<_> = map.keys().cloned().collect();
        let key = idx.get(&keys).clone();

        let mut t = Trie::<K>::new();
        for (k, v) in &map { t.insert(k, v.clone()); }
        let root = t.hash();
        let proof = t.prove(&key);

        for i in 0..proof.len() {
            for pos in [0usize, proof[i].len() / 2, proof[i].len() - 1] {
                let mut bad = proof.clone();
                bad[i][pos] ^= 0x01;
                prop_assert!(
                    verify(&root, &key, &bad).is_err(),
                    "byte {pos} of node {i} tampered undetected"
                );
            }
        }
    }

    #[test]
    fn verifier_never_panics(
        map in kv_map(),
        junk in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..40), 0..6),
        key in prop::collection::vec(any::<u8>(), 0..5),
    ) {
        let mut t = Trie::<K>::new();
        for (k, v) in &map { t.insert(k, v.clone()); }
        let root = t.hash();
        // Random bytes are almost never a valid proof; the contract is that
        // the verifier returns rather than unwinding, whatever it is handed.
        let _ = verify(&root, &key, &junk);
    }
}
