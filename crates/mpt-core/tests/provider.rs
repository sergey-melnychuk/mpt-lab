//! PLAN.md Phase B, step 3: the delete-collapse test.
//!
//! Removing a key can drop a Fork to a single occupant. `normalize` then must
//! `prepend` the surviving nibble onto the SIBLING — and the sibling hangs off
//! a different nibble of that Fork, so it was never on the deleted key's path
//! and no inclusion proof for that key can contain it (PLAN.md §1). This is
//! the one case a `NodeProvider` earns its keep for: without one, removal must
//! fail with `Err(MissingNode)`; with one, it must succeed and reproduce
//! exactly what removing the key from the full trie would have produced.

use std::collections::BTreeMap;

use mpt_core::Keccak256 as K;
use mpt_core::error::TrieError;
use mpt_core::hasher::keccak;
use mpt_core::partial::MapProvider;
use mpt_core::trie::{Node, Trie, build_partial, count_stubs, node_root};

type Witness = BTreeMap<[u8; 32], Vec<u8>>;

fn build(pairs: &[(&[u8], &[u8])]) -> Trie<K> {
    let mut t = Trie::<K>::new();
    for (k, v) in pairs {
        t.insert(k, v.to_vec()).unwrap();
    }
    t
}

/// Every node the full trie contains, keyed by hash. `MapProvider` is the test
/// oracle: it can resolve anything, so it isolates traversal bugs from
/// witness-construction bugs (PLAN.md §4.3).
fn full_map(t: &mut Trie<K>, all_keys: &[&[u8]]) -> Witness {
    let mut map = Witness::new();
    for k in all_keys {
        for n in t.prove(k) {
            map.insert(keccak(&n), n);
        }
    }
    map
}

/// The proof for exactly `probe` — everything an inclusion proof for that key
/// carries, and nothing else. Used to build the partial trie under test.
fn probe_witness(t: &mut Trie<K>, probe: &[u8]) -> Witness {
    let mut w = Witness::new();
    for n in t.prove(probe) {
        w.insert(keccak(&n), n);
    }
    w
}

#[test]
fn delete_collapse_resolves_a_leaf_sibling() {
    // Two keys sharing an 8-nibble prefix, diverging at the next nibble, and
    // nothing else under that Fork:
    //   a  = 0,1,0,2,0,3,1,0
    //   b  = 0,1,0,2,0,3,2,0
    // 40-byte values so nothing inlines: b's Leaf is a real hashed node, so
    // its reference in the Fork is a 32-byte hash, not inlined bytes.
    let a: &[u8] = &[0x01, 0x02, 0x03, 0x10];
    let b: &[u8] = &[0x01, 0x02, 0x03, 0x20];
    let pairs: &[(&[u8], &[u8])] = &[(a, &[0xaa; 40]), (b, &[0xbb; 40])];

    let mut full = build(pairs);
    let root = full.hash();
    let all_map = full_map(&mut full, &[a, b]);

    let w = probe_witness(&mut full, a);
    let partial: Node<K> = build_partial(&w, &root);
    assert_eq!(node_root(&partial), root);
    assert!(
        count_stubs(&partial) > 0,
        "b's leaf must be a Stub, or this test is vacuous"
    );

    // Without a provider: MissingNode, naming b's own hash and path.
    let mut without = Trie::<K>::from_node(partial.clone());
    match without.remove(a) {
        Err(TrieError::MissingNode { hash, path }) => {
            // Verify against the parent Fork's RLP: that hash really is what
            // the Fork holds at b's nibble.
            let fork = match &partial {
                Node::Skip { child, .. } => &**child,
                other => other,
            };
            let Node::Fork { children, .. } = fork else {
                panic!("expected a Fork, got {fork:?}")
            };
            let b_nibble = path.last().copied().expect("sibling path is non-empty") as usize;
            match children[b_nibble].as_deref() {
                Some(Node::Stub(h)) => assert_eq!(*h, hash, "path names the wrong sibling"),
                other => panic!("expected the sibling to still be a Stub, got {other:?}"),
            }
        }
        other => panic!("expected Err(MissingNode {{ .. }}), got {other:?}"),
    }

    // With a provider that has everything: succeeds, and matches the full
    // trie's root after the same removal.
    let mut with = Trie::<K>::from_node(partial);
    let provider = MapProvider::<K>(all_map);
    assert!(with.remove_with(&provider, a).unwrap());
    with.root().debug_check();

    let mut reference = build(pairs);
    assert!(reference.remove(a).unwrap());
    assert_eq!(with.hash(), reference.hash());

    // Re-inserting restores the original root byte-exactly — the
    // canonicality check. A trie holding the right data in the wrong shape
    // answers `get` correctly and hashes wrong (NOTES.md §6.3).
    with.insert_with(&provider, a, [0xaa; 40].to_vec()).unwrap();
    assert_eq!(with.hash(), root);
}

#[test]
fn delete_collapse_resolves_a_fork_sibling() {
    // Same shared 6-nibble prefix, but the sibling itself branches further:
    //   a  = 0,1,0,2,0,3, 1,0
    //   b1 = 0,1,0,2,0,3, 2,0
    //   b2 = 0,1,0,2,0,3, 2,1
    // Removing a collapses the Fork at nibble 6 down to its nibble-2 child —
    // which is itself a Fork (b1 vs b2 at nibble 7), so `prepend` must wrap it
    // in a fresh `Skip { path: [2] }` rather than extending a path.
    let a: &[u8] = &[0x01, 0x02, 0x03, 0x10];
    let b1: &[u8] = &[0x01, 0x02, 0x03, 0x20];
    let b2: &[u8] = &[0x01, 0x02, 0x03, 0x21];
    let pairs: &[(&[u8], &[u8])] = &[(a, &[0xaa; 40]), (b1, &[0xb1; 40]), (b2, &[0xb2; 40])];

    let mut full = build(pairs);
    let root = full.hash();
    let all_map = full_map(&mut full, &[a, b1, b2]);

    let w = probe_witness(&mut full, a);
    let partial: Node<K> = build_partial(&w, &root);
    assert_eq!(node_root(&partial), root);
    assert!(count_stubs(&partial) > 0, "vacuous: the sibling subtree wasn't stubbed");

    let mut without = Trie::<K>::from_node(partial.clone());
    assert!(matches!(without.remove(a), Err(TrieError::MissingNode { .. })));

    let mut with = Trie::<K>::from_node(partial);
    let provider = MapProvider::<K>(all_map);
    assert!(with.remove_with(&provider, a).unwrap());
    with.root().debug_check();
    // The collapsed shape really is Skip{[2], Fork} at the root, not merged
    // into a Leaf — confirms the Fork-sibling branch of `prepend` ran.
    assert!(
        matches!(with.root(), Node::Skip { path, child } if path.ends_with(&[2]) && matches!(**child, Node::Fork { .. })),
        "expected the collapsed sibling Fork to survive under a Skip, got {:?}",
        with.root()
    );

    let mut reference = build(pairs);
    assert!(reference.remove(a).unwrap());
    assert_eq!(with.hash(), reference.hash());

    with.insert_with(&provider, a, [0xaa; 40].to_vec()).unwrap();
    assert_eq!(with.hash(), root);
}

#[test]
fn value_slot_collapse_needs_no_sibling() {
    // A Fork whose only remaining occupant after removal is its own value
    // slot collapses to Leaf{path: [], value} — no sibling, no provider
    // needed even on a partial trie built from nothing but the target key's
    // own proof.
    let a: &[u8] = &[0x01, 0x02];
    let long: &[u8] = &[0x01, 0x02, 0x03];
    let pairs: &[(&[u8], &[u8])] = &[(a, &[0xaa; 40]), (long, &[0xcc; 40])];

    let mut full = build(pairs);
    let root = full.hash();
    let w = probe_witness(&mut full, long);
    let partial: Node<K> = build_partial(&w, &root);
    assert_eq!(node_root(&partial), root);

    let mut t = Trie::<K>::from_node(partial);
    assert!(t.remove(a).unwrap(), "no provider needed for this collapse");
    t.root().debug_check();

    let mut reference = build(pairs);
    assert!(reference.remove(a).unwrap());
    assert_eq!(t.hash(), reference.hash());
}

/// A longer session: several removals against ONE partial trie, most needing
/// a Fork-collapse sibling from the provider, none reusing a node already
/// resolved from the last one (each removal touches a disjoint prefix).
/// Exercises resolution repeatedly rather than once, and confirms canonical
/// shape survives re-inserting everything back in a different order.
#[test]
fn repeated_collapses_against_one_provider() {
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0u16..64)
        .map(|i| (keccak(&i.to_be_bytes())[..4].to_vec(), vec![i as u8; 40]))
        .collect();
    let refs: Vec<(&[u8], &[u8])> = pairs
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();

    let mut full = build(&refs);
    let root = full.hash();
    let all_keys: Vec<&[u8]> = refs.iter().map(|(k, _)| *k).collect();
    let all_map = full_map(&mut full, &all_keys);
    let provider = MapProvider::<K>(all_map);

    // Proof for one key only: everything else the removals below need must
    // come from the provider.
    let w = probe_witness(&mut full, refs[0].0);
    let partial: Node<K> = build_partial(&w, &root);
    let mut t = Trie::<K>::from_node(partial);

    let mut reference = build(&refs);
    for (k, _) in refs.iter().take(20) {
        assert!(t.remove_with(&provider, k).unwrap());
        assert!(reference.remove(k).unwrap());
        t.root().debug_check();
        assert_eq!(t.hash(), reference.hash(), "diverged removing {k:?}");
    }

    // Put them all back, in reverse order, through the same provider.
    for (k, v) in refs.iter().take(20).rev() {
        t.insert_with(&provider, k, v.to_vec()).unwrap();
        reference.insert(k, v.to_vec()).unwrap();
    }
    assert_eq!(t.hash(), root, "root did not come back after full revert");
    assert_eq!(t.hash(), reference.hash());
}
