//! PLAN.md Phase B, step 2 acceptance: a partial trie driven by a
//! `NodeProvider` must behave exactly like a full trie, under both a fixed
//! sweep and randomised interleaved insert/remove sequences.

use std::collections::BTreeMap;

use mpt_core::Keccak256 as K;
use mpt_core::hasher::keccak;
use mpt_core::partial::{MapProvider, RecordingProvider, WitnessProvider};
use mpt_core::trie::{Trie, build_partial};
use proptest::prelude::*;

type Map = BTreeMap<[u8; 32], Vec<u8>>;

fn full_map(t: &mut Trie<K>, all_keys: &[&[u8]]) -> Map {
    let mut map = Map::new();
    for k in all_keys {
        for n in t.prove(k) {
            map.insert(keccak(&n), n);
        }
    }
    map
}

/// Full trie, snapshot every node, then a proof for a handful of keys builds
/// a partial trie. Apply the same op sequence to both, the partial one
/// through a `MapProvider`. Roots must match after every op — including ops
/// that touch keys the initial proof never mentioned, since the provider can
/// resolve anything the traversal needs along the way.
#[test]
fn map_provider_matches_full_trie_across_a_fixed_sweep() {
    const N: u16 = 300;
    let keys: Vec<Vec<u8>> = (0..N)
        .map(|i| keccak(&i.to_be_bytes())[..6].to_vec())
        .collect();
    let pairs: Vec<(&[u8], Vec<u8>)> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (k.as_slice(), vec![(i % 251) as u8; 40]))
        .collect();

    let mut full = Trie::<K>::new();
    for (k, v) in &pairs {
        full.insert(k, v.clone()).unwrap();
    }
    let root = full.hash();

    let all_refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
    let all_map = full_map(&mut full, &all_refs);
    let provider = MapProvider::<K>(all_map);

    // A proof for a handful of keys only. Everything else the sweep below
    // touches must come from the provider.
    let mut w = Map::new();
    for k in &keys[..5] {
        for n in full.prove(k) {
            w.insert(keccak(&n), n);
        }
    }
    let partial_root = build_partial(&w, &root);
    let mut partial = Trie::<K>::from_node(partial_root);

    let mut reference = Trie::<K>::new();
    for (k, v) in &pairs {
        reference.insert(k, v.clone()).unwrap();
    }

    // Update every 7th key, remove every 11th, insert some fresh ones.
    for (i, k) in keys.iter().enumerate() {
        if i % 11 == 0 {
            assert_eq!(
                partial.remove_with(&provider, k).unwrap(),
                reference.remove(k).unwrap(),
                "remove({i}) return value diverged"
            );
        } else if i % 7 == 0 {
            let v = vec![0xee; 40];
            partial.insert_with(&provider, k, v.clone()).unwrap();
            reference.insert(k, v).unwrap();
        }
        assert_eq!(
            partial.hash(),
            reference.hash(),
            "roots diverged after touching key {i}"
        );
    }
    for i in 9000u16..9010 {
        let k = keccak(&i.to_be_bytes())[..6].to_vec();
        let v = vec![0xd0 + (i % 16) as u8; 40];
        partial.insert_with(&provider, &k, v.clone()).unwrap();
        reference.insert(&k, v).unwrap();
        assert_eq!(
            partial.hash(),
            reference.hash(),
            "diverged inserting fresh key {i}"
        );
    }
}

/// `WitnessProvider` is the offline counterpart: same resolution logic, used
/// to document that a proof-shaped map (not a full store) also works as a
/// provider when it happens to have what's needed.
#[test]
fn witness_provider_resolves_from_a_proof_shaped_map() {
    let pairs: &[(&[u8], &[u8])] = &[
        (b"do", b"verb"),
        (b"dog", b"puppy"),
        (b"doge", b"coin"),
        (b"horse", b"stallion"),
    ];
    let mut full = Trie::<K>::new();
    for (k, v) in pairs {
        full.insert(k, v.to_vec()).unwrap();
    }
    let root = full.hash();

    let mut w = Map::new();
    for (k, _) in pairs {
        for n in full.prove(k) {
            w.insert(keccak(&n), n);
        }
    }
    let mut t = Trie::<K>::from_node(build_partial(&w, &root));
    let provider = WitnessProvider::<K>(w);

    // Value updates only touch nodes each key's own proof already carries, so
    // this never actually needs the provider to supply anything — but it must
    // not error just because one is present.
    for (k, v) in pairs {
        t.insert_with(&provider, k, v.to_vec()).unwrap();
    }
    assert_eq!(t.hash(), root);
}

/// `RecordingProvider` is the witness builder: whatever it resolves while
/// backing a workload IS the minimal witness for that workload.
#[test]
fn recording_provider_captures_exactly_what_was_resolved() {
    let a: &[u8] = &[0x01, 0x02, 0x03, 0x10];
    let b: &[u8] = &[0x01, 0x02, 0x03, 0x20];
    let mut full = Trie::<K>::new();
    full.insert(a, vec![0xaa; 40]).unwrap();
    full.insert(b, vec![0xbb; 40]).unwrap();
    let root = full.hash();

    let all_map = full_map(&mut full, &[a, b]);

    let mut w = Map::new();
    for n in full.prove(a) {
        w.insert(keccak(&n), n);
    }
    let mut t = Trie::<K>::from_node(build_partial(&w, &root));

    let recording = RecordingProvider::new(MapProvider::<K>(all_map));
    assert!(t.remove_with(&recording, a).unwrap());

    let seen = recording.seen();
    assert_eq!(
        seen.len(),
        1,
        "removing a needs exactly one extra node: b's leaf"
    );
    assert_eq!(
        seen[0].0,
        [0, 1, 0, 2, 0, 3, 2],
        "resolved at the wrong path"
    );
}

proptest! {
    /// Random map, random touched subset for the initial proof, random
    /// interleaved insert/remove sequence — driven through `MapProvider`,
    /// checked against a plain `Trie` on the same operations.
    #[test]
    fn map_provider_agrees_with_a_full_trie_under_random_ops(
        seed_pairs in prop::collection::vec((prop::collection::vec(any::<u8>(), 1..6), prop::collection::vec(any::<u8>(), 1..40)), 1..60),
        probe_count in 1usize..10,
        ops in prop::collection::vec((any::<u8>(), prop::collection::vec(any::<u8>(), 1..6), prop::collection::vec(any::<u8>(), 1..40)), 1..40),
    ) {
        let mut m: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        for (k, v) in &seed_pairs {
            m.insert(k.clone(), v.clone());
        }
        let mut full = Trie::<K>::new();
        for (k, v) in &m {
            full.insert(k, v.clone()).unwrap();
        }
        let root = full.hash();

        let all_keys: Vec<&[u8]> = m.keys().map(Vec::as_slice).collect();
        let all_map = full_map(&mut full, &all_keys);
        let provider = MapProvider::<K>(all_map);

        let mut w = Map::new();
        for k in all_keys.iter().take(probe_count.min(all_keys.len())) {
            for n in full.prove(k) {
                w.insert(keccak(&n), n);
            }
        }
        let mut partial = Trie::<K>::from_node(build_partial(&w, &root));
        let mut reference = Trie::<K>::new();
        for (k, v) in &m {
            reference.insert(k, v.clone()).unwrap();
        }

        for (tag, k, v) in &ops {
            if tag % 3 == 0 && !m.is_empty() {
                let idx = (*k.first().unwrap_or(&0) as usize) % m.len();
                let key = m.keys().nth(idx).unwrap().clone();
                let got = partial.remove_with(&provider, &key).unwrap();
                let want = reference.remove(&key).unwrap();
                m.remove(&key);
                prop_assert_eq!(got, want);
            } else {
                partial.insert_with(&provider, k, v.clone()).unwrap();
                reference.insert(k, v.clone()).unwrap();
                m.insert(k.clone(), v.clone());
            }
            prop_assert_eq!(partial.hash(), reference.hash());
        }
    }
}
