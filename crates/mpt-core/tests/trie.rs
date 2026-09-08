use mpt_core::Keccak256 as K;
use mpt_core::error::TrieError;
use mpt_core::trie::{Node, Trie};
use proptest::prelude::*;
use std::collections::BTreeMap;

fn root_of(pairs: &[(&[u8], &[u8])]) -> [u8; 32] {
    built(pairs).hash()
}

fn built(pairs: &[(&[u8], &[u8])]) -> Trie<K> {
    let mut t = Trie::new();
    for (k, v) in pairs {
        t.insert(k, v.to_vec()).unwrap();
        t.root().debug_check();
    }
    t
}

const CLASSIC: &[(&[u8], &[u8])] = &[
    (b"do", b"verb"),
    (b"dog", b"puppy"),
    (b"doge", b"coin"),
    (b"horse", b"stallion"),
];

#[test]
fn classic_four_lookups() {
    let mut t = built(CLASSIC);
    for (k, v) in CLASSIC {
        assert_eq!(
            t.get(k).unwrap(),
            Some(*v),
            "key={:?}",
            core::str::from_utf8(k)
        );
    }
    assert_eq!(t.get(b"d").unwrap(), None);
    assert_eq!(t.get(b"dogez").unwrap(), None);
    assert_eq!(t.get(b"hors").unwrap(), None);
    assert_eq!(t.get(b"").unwrap(), None);
}

#[test]
fn insertion_order_does_not_matter() {
    let fwd = built(CLASSIC);
    let mut rev: Vec<_> = CLASSIC.to_vec();
    rev.reverse();
    let bwd = built(&rev);
    // Structural equality, not just lookup equality. This is the property
    // stage 5 turns into "the root hash is order-independent".
    assert_eq!(fwd, bwd);
}

#[test]
fn classic_four_shape() {
    // "do"=[6,4,6,f] "dog"=[6,4,6,f,6,7] "doge"=[6,4,6,f,6,7,6,5]
    // "horse"=[6,8,6,f,7,2,7,3,6,5]
    // All four share nibble [6], then diverge at 4 vs 8.
    let t = built(CLASSIC);
    let Node::Skip { path, child } = t.root() else {
        panic!(
            "root should be a Skip over the shared nibble, got {:?}",
            t.root()
        );
    };
    assert_eq!(path, &vec![6]);
    let Node::Fork { children, value } = &**child else {
        panic!("Skip child must be a Fork");
    };
    assert!(value.is_none(), "no key terminates at nibble [6]");
    assert!(children[4].is_some(), "the 'do*' subtree");
    assert!(children[8].is_some(), "the 'horse' leaf");
    assert_eq!(t.root().fork_occupancy(), 0, "root is a Skip, not a Fork");
    // TODO: assert the rest yourself. Walk children[4] down and check where
    // "verb" and "puppy" land (value slots, not leaves) and what shape the
    // "doge" tail takes.
}

#[test]
fn value_replacement() {
    let mut t = built(CLASSIC);
    t.insert(b"dog", b"hound".to_vec()).unwrap();
    t.root().debug_check();
    assert_eq!(t.get(b"dog").unwrap(), Some(&b"hound"[..]));
    assert_eq!(t.get(b"doge").unwrap(), Some(&b"coin"[..]));
}

#[test]
fn empty_key() {
    let mut t = Trie::<K>::new();
    t.insert(b"", b"root-value".to_vec()).unwrap();
    t.root().debug_check();
    assert_eq!(t.get(b"").unwrap(), Some(&b"root-value"[..]));
    t.insert(b"a", b"other".to_vec()).unwrap();
    t.root().debug_check();
    assert_eq!(t.get(b"").unwrap(), Some(&b"root-value"[..]));
    assert_eq!(t.get(b"a").unwrap(), Some(&b"other"[..]));
}

#[test]
fn diverge_at_first_nibble() {
    let mut t = built(&[(b"\x01", b"one"), (b"\x81", b"two")]);
    assert!(matches!(t.root(), Node::Fork { .. }), "no shared prefix");
    assert_eq!(t.get(b"\x01").unwrap(), Some(&b"one"[..]));
    assert_eq!(t.get(b"\x81").unwrap(), Some(&b"two"[..]));
}

#[test]
fn wide_forks() {
    let mut t = Trie::<K>::new();
    for i in 0u16..256 {
        t.insert(&i.to_be_bytes(), i.to_string().into_bytes())
            .unwrap();
    }
    t.root().debug_check();
    for i in 0u16..256 {
        assert_eq!(
            t.get(&i.to_be_bytes()).unwrap(),
            Some(i.to_string().as_bytes())
        );
    }
}

#[test]
fn one_nibble_remainder() {
    // Exercises the Skip-split subtlety: the remainder after the fork index is
    // a single nibble, so no wrapping Skip is created.
    let mut t = built(&[(b"\x12\x34", b"a"), (b"\x12\x35", b"b"), (b"\x12", b"c")]);
    assert_eq!(t.get(b"\x12\x34").unwrap(), Some(&b"a"[..]));
    assert_eq!(t.get(b"\x12\x35").unwrap(), Some(&b"b"[..]));
    assert_eq!(t.get(b"\x12").unwrap(), Some(&b"c"[..]));
}

#[test]
fn delete_restores_the_exact_root() {
    // Non-canonical leftover structure is invisible to `get` but changes the
    // root. Adding then removing a key must land byte-for-byte back where it
    // started, for every shape of key: deeper, shallower, sibling, prefix,
    // empty, and disjoint.
    let base = root_of(CLASSIC);
    for extra in [
        &b"dogecoin"[..], // extends an existing leaf
        b"dogg",          // splits at the last nibble
        b"d",             // strict prefix of everything in the "do" subtree
        b"horsey",        // extends the other branch
        b"x",             // entirely disjoint, new top-level fork slot
        b"",              // empty key, lands in a value slot
        b"do",            // NOTE: overwrites an existing key, see below
    ] {
        let mut t = built(CLASSIC);
        let existed = t.get(extra).unwrap().is_some();
        t.insert(extra, b"temporary".to_vec()).unwrap();
        t.root().debug_check();
        assert!(
            t.remove(extra).unwrap(),
            "remove({extra:?}) reported not-present"
        );
        t.root().debug_check();

        if existed {
            // "do" was already there; removing it leaves a smaller trie.
            assert_ne!(t.hash(), base);
        } else {
            assert_eq!(
                hex::encode(t.hash()),
                hex::encode(base),
                "insert+remove of {extra:?} did not restore the root"
            );
        }
    }
}

#[test]
fn delete_everything_gives_the_empty_root() {
    let empty = Trie::<K>::new().hash();
    let mut t = built(CLASSIC);
    for (k, _) in CLASSIC {
        assert!(t.remove(k).unwrap());
        t.root().debug_check();
    }
    assert_eq!(hex::encode(t.hash()), hex::encode(empty));
}

#[test]
fn order_of_deletion_does_not_matter() {
    // Same surviving key set, three different deletion orders, one root.
    let all: &[(&[u8], &[u8])] = &[
        (b"do", b"verb"),
        (b"dog", b"puppy"),
        (b"doge", b"coin"),
        (b"horse", b"stallion"),
        (b"house", b"home"),
        (b"h", b"aitch"),
    ];
    let survivors: &[(&[u8], &[u8])] = &[(b"do", b"verb"), (b"horse", b"stallion")];
    let want = root_of(survivors);

    for order in [
        [&b"dog"[..], b"doge", b"house", b"h"],
        [&b"h"[..], b"house", b"doge", b"dog"],
        [&b"house"[..], b"dog", b"h", b"doge"],
    ] {
        let mut t = built(all);
        for k in order {
            assert!(t.remove(k).unwrap(), "remove({k:?})");
            t.root().debug_check();
        }
        assert_eq!(hex::encode(t.hash()), hex::encode(want), "order {order:?}");
    }
}

#[test]
fn fork_collapses_to_leaf_when_one_child_remains() {
    // Two keys diverging at the first nibble make a bare Fork at the root.
    // Deleting one must leave a Leaf, not a Fork with a single occupant.
    let mut t = built(&[(b"\x01", b"a"), (b"\x81", b"b")]);
    assert!(t.remove(b"\x81").unwrap());
    t.root().debug_check();
    assert_eq!(
        hex::encode(t.hash()),
        hex::encode(root_of(&[(b"\x01", b"a")]))
    );
}

#[test]
fn fork_collapses_to_leaf_when_only_the_value_slot_remains() {
    // "ab" terminates inside the fork created by "ab"/"abc": its value lives in
    // the fork's value slot. Removing "abc" leaves only that slot, which must
    // become a Leaf with an empty remaining path.
    let mut t = built(&[(b"ab", b"short"), (b"abc", b"long")]);
    assert!(t.remove(b"abc").unwrap());
    t.root().debug_check();
    assert_eq!(
        hex::encode(t.hash()),
        hex::encode(root_of(&[(b"ab", b"short")]))
    );
}

#[test]
fn skip_absorbs_a_collapsed_child() {
    // A deep shared prefix produces Skip -> Fork. Collapsing the fork must be
    // absorbed into the skip's path, producing ONE leaf, not Skip -> Leaf.
    let mut t = built(&[(b"aaaaaaaa1", b"x"), (b"aaaaaaaa2", b"y")]);
    assert!(t.remove(b"aaaaaaaa2").unwrap());
    t.root().debug_check();
    assert_eq!(
        hex::encode(t.hash()),
        hex::encode(root_of(&[(b"aaaaaaaa1", b"x")]))
    );
}

#[test]
fn skip_merges_with_skip() {
    // Three keys built Skip -> Fork -> (Skip -> Fork, Leaf). Deleting the right
    // key collapses the inner fork and forces a skip-over-skip merge.
    let pairs: &[(&[u8], &[u8])] = &[
        (b"prefix_aaa_1", b"1"),
        (b"prefix_aaa_2", b"2"),
        (b"prefix_bbb_3", b"3"),
    ];
    let mut t = built(pairs);
    assert!(t.remove(b"prefix_bbb_3").unwrap());
    t.root().debug_check();
    assert_eq!(
        hex::encode(t.hash()),
        hex::encode(root_of(&[(b"prefix_aaa_1", b"1"), (b"prefix_aaa_2", b"2")]))
    );
}

#[test]
fn multi_level_collapse_propagates_upward() {
    // Removing one key at depth must collapse a fork, merge the parent skip,
    // merge that into ITS parent, and so on. One-pass-per-level normalisation
    // has to handle the whole chain.
    let pairs: &[(&[u8], &[u8])] = &[
        (b"\x11\x11\x11\x11", b"deep"),
        (b"\x11\x11\x11\x12", b"sibling"),
        (b"\x99", b"far"),
    ];
    let mut t = built(pairs);
    assert!(t.remove(b"\x11\x11\x11\x12").unwrap());
    t.root().debug_check();
    assert_eq!(
        hex::encode(t.hash()),
        hex::encode(root_of(&[
            (b"\x11\x11\x11\x11", b"deep"),
            (b"\x99", b"far")
        ]))
    );
}

#[test]
fn collapse_across_the_inlining_boundary() {
    // Small nodes are inlined in their parent; large ones are  into the
    // db. A collapse that changes a node's size can flip it across that
    // boundary, which changes the parent's encoding too.
    let big = vec![0xabu8; 64];
    let mut t = Trie::<K>::new();
    t.insert(b"k1", big.clone()).unwrap();
    t.insert(b"k2", b"s".to_vec()).unwrap();
    t.insert(b"k3", b"s".to_vec()).unwrap();
    t.remove(b"k1").unwrap();
    t.root().debug_check();

    let mut want = Trie::<K>::new();
    want.insert(b"k2", b"s".to_vec()).unwrap();
    want.insert(b"k3", b"s".to_vec()).unwrap();
    assert_eq!(hex::encode(t.hash()), hex::encode(want.hash()));
}

#[test]
fn removing_absent_keys_is_a_no_op() {
    let base = root_of(CLASSIC);
    for absent in [
        &b"cat"[..], // diverges immediately
        b"d",        // prefix, no value there
        b"dogecoin", // extends past an existing leaf
        b"hors",     // prefix of "horse"
        b"",         // empty key, absent
        b"doge\x00", // one nibble past a leaf
    ] {
        let mut t = built(CLASSIC);
        assert!(
            !t.remove(absent).unwrap(),
            "remove({absent:?}) claimed success"
        );
        t.root().debug_check();
        assert_eq!(
            hex::encode(t.hash()),
            hex::encode(base),
            "failed removal of {absent:?} still mutated the trie"
        );
    }
}

#[test]
fn remove_from_empty_trie() {
    let mut t = Trie::<K>::new();
    assert!(!t.remove(b"anything").unwrap());
    assert!(!t.remove(b"").unwrap());
    assert_eq!(hex::encode(t.hash()), hex::encode(Trie::<K>::new().hash()));
}

#[test]
fn double_remove() {
    let mut t = built(CLASSIC);
    assert!(t.remove(b"dog").unwrap());
    assert!(
        !t.remove(b"dog").unwrap(),
        "second removal should report absent"
    );
    t.root().debug_check();
    assert_eq!(t.get(b"dog").unwrap(), None);
    assert_eq!(t.get(b"doge").unwrap(), Some(&b"coin"[..]));
}

#[test]
fn empty_key_removal() {
    let mut t = Trie::<K>::new();
    t.insert(b"", b"at-root".to_vec()).unwrap();
    t.insert(b"a", b"other".to_vec()).unwrap();
    t.root().debug_check();
    assert!(t.remove(b"").unwrap());
    t.root().debug_check();
    assert_eq!(t.get(b"").unwrap(), None);
    assert_eq!(t.get(b"a").unwrap(), Some(&b"other"[..]));
    assert_eq!(
        hex::encode(t.hash()),
        hex::encode(root_of(&[(b"a", b"other")]))
    );
}

fn kv_map() -> impl Strategy<Value = BTreeMap<Vec<u8>, Vec<u8>>> {
    prop::collection::btree_map(
        prop::collection::vec(any::<u8>(), 0..6),
        prop::collection::vec(any::<u8>(), 1..8),
        0..40,
    )
}

proptest! {
    #[test]
    fn agrees_with_btreemap(map in kv_map(), probes in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..6), 0..20)) {
        let mut t = Trie::<K>::new();
        for (k, v) in &map {
            t.insert(k, v.clone()).unwrap();
            t.root().debug_check();
        }
        for (k, v) in &map {
            prop_assert_eq!(t.get(k).unwrap(), Some(v.as_slice()));
        }
        for p in &probes {
            prop_assert_eq!(t.get(p).unwrap(), map.get(p).map(|v| v.as_slice()));
        }
    }

    #[test]
    fn structure_is_insertion_order_independent(map in kv_map(), seed in any::<u64>()) {
        let mut a = Trie::<K>::new();
        for (k, v) in &map {
            a.insert(k, v.clone()).unwrap();
        }

        let mut shuffled: Vec<_> = map.iter().collect();
        // cheap deterministic shuffle
        let mut s = seed | 1;
        for i in (1..shuffled.len()).rev() {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            shuffled.swap(i, (s >> 33) as usize % (i + 1));
        }
        let mut b = Trie::new();
        for (k, v) in shuffled {
            b.insert(k, v.clone()).unwrap();
        }

        prop_assert_eq!(a, b);
    }

    #[test]
    fn root_depends_only_on_surviving_contents(
        map in kv_map(),
        cut in prop::collection::vec(any::<bool>(), 30),
    ) {
        // built the full map then delete a subset, versus inserting only the
        // survivors. Both must produce the same root, because the MPT's shape
        // is a function of its contents and nothing else.
        let keys: Vec<_> = map.keys().cloned().collect();
        let doomed: Vec<_> = keys.iter().zip(&cut).filter(|&(_, &c)| c).map(|(k, _)| k.clone()).collect();

        let mut deleted = Trie::<K>::new();
        for (k, v) in &map { deleted.insert(k, v.clone()).unwrap(); }
        for k in &doomed {
            prop_assert!(deleted.remove(k).unwrap());
            deleted.root().debug_check();
        }

        let mut direct = Trie::<K>::new();
        for (k, v) in &map {
            if !doomed.contains(k) { direct.insert(k, v.clone()).unwrap(); }
        }

        prop_assert_eq!(hex::encode(deleted.hash()), hex::encode(direct.hash()));
    }

    #[test]
    fn agrees_with_btreemap_under_interleaved_ops(
        ops in prop::collection::vec(
            (prop::collection::vec(any::<u8>(), 0..4),
             prop::option::of(prop::collection::vec(any::<u8>(), 1..20))),
            1..60,
        ),
    ) {
        let mut t = Trie::<K>::new();
        let mut m: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();

        for (k, v) in &ops {
            match v {
                Some(v) => { t.insert(k, v.clone()).unwrap(); m.insert(k.clone(), v.clone()); }
                None => {
                    let expected = m.remove(k).is_some();
                    prop_assert_eq!(t.remove(k).unwrap(), expected, "remove({:?}) return value", k);
                }
            }
            t.root().debug_check();
        }

        for (k, v) in &m { prop_assert_eq!(t.get(k).unwrap(), Some(v.as_slice())); }
        for (k, _) in &ops { if !m.contains_key(k) { prop_assert_eq!(t.get(k).unwrap(), None); } }
    }

    #[test]
    fn insert_then_remove_is_identity(map in kv_map(), extra in prop::collection::vec(any::<u8>(), 0..5)) {
        prop_assume!(!map.contains_key(&extra));
        let mut t = Trie::<K>::new();
        for (k, v) in &map { t.insert(k, v.clone()).unwrap(); }
        let before = t.hash();

        t.insert(&extra, b"scratch".to_vec()).unwrap();
        prop_assert!(t.remove(&extra).unwrap());
        t.root().debug_check();

        prop_assert_eq!(hex::encode(t.hash()), hex::encode(before));
    }
}

// Insertion into a partial trie needs no nodes beyond its own exclusion proof.
//
// The counterpart to the delete-collapse case (PTRIE.md §3, §6.2). Removal can
// need a node no proof contains, because `normalize` reads a SIBLING's
// contents to prepend a nibble onto it. Insertion never calls `normalize`, and
// nothing else in the trie reaches sideways: a node's encoding depends on its
// own path/value plus its children's *references*, never their contents. So an
// insert changes only nodes on the new key's path — and the exclusion proof
// IS that path.
//
// An exclusion proof terminates in exactly three shapes, and all three are
// covered here:
//
//   EmptySlot      a Fork whose slot for the next nibble is empty. The new
//                  leaf drops in; sibling stubs are never read.
//   DivergingLeaf  a Leaf whose stored path diverges. The split needs that
//                  node's full path and value — which we have, because `prove`
//                  pushes the node it terminated on.
//   DivergingSkip  a Skip whose stored path diverges. Same, plus its child
//                  reference is copied verbatim into the rebuilt structure.
//
// Measured on a 400-key trie with 400 distinct absent keys: 261 EmptySlot,
// 132 DivergingLeaf, 7 DivergingSkip. Every insert produced a root identical
// to the full trie's.

use mpt_core::hasher::keccak;
use mpt_core::path::to_nibbles;
use mpt_core::trie::{build_partial, count_stubs, node_rlp, node_root};

#[test]
fn node_rlp_hashes_to_node_root() {
    let t = built(CLASSIC);
    // Walk down to a non-Stub, non-root node so this isn't just re-testing
    // `hash()` on the root. CLASSIC's root is a Skip over the shared [6]
    // nibble (see classic_four_shape); its child Fork has the real nodes.
    let Node::Skip { child, .. } = t.root() else {
        panic!("CLASSIC's root should be a Skip")
    };
    let Node::Fork { children, .. } = &**child else {
        panic!("Skip child must be a Fork")
    };
    let grandchild = children
        .iter()
        .flatten()
        .next()
        .expect("CLASSIC's Fork has at least one child");
    assert_eq!(keccak(&node_rlp(grandchild)), node_root(grandchild));
}

/// Where an exclusion proof stopped.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Hash)]
enum Termination {
    EmptySlot,
    DivergingLeaf,
    DivergingSkip,
    /// The key resolved to a value after all — not an exclusion proof.
    Present,
}

fn classify(node: &Node<K>, suffix: &[u8]) -> Termination {
    match node {
        Node::Fork { children, value } => match suffix.split_first() {
            None => {
                if value.is_some() {
                    Termination::Present
                } else {
                    Termination::EmptySlot
                }
            }
            Some((&n, rest)) => match &children[n as usize] {
                Some(c) => classify(c, rest),
                None => Termination::EmptySlot,
            },
        },
        Node::Skip { path, child } => {
            if suffix.starts_with(path) {
                classify(child, &suffix[path.len()..])
            } else {
                Termination::DivergingSkip
            }
        }
        Node::Leaf { path, .. } => {
            if path == suffix {
                Termination::Present
            } else {
                Termination::DivergingLeaf
            }
        }
        // A stub means the proof was insufficient, which is exactly what this
        // test asserts never happens for insertion.
        Node::Stub(_) => panic!("classify walked into a Stub"),
        Node::Null => Termination::EmptySlot,
    }
}

/// Keys are keccak-derived so they distribute like a real secure trie: no
/// shared prefixes, wide Forks, mostly Leaf terminations near the bottom.
fn key(i: u16) -> Vec<u8> {
    keccak(&i.to_be_bytes())[..6].to_vec()
}

fn full_trie(n: u16) -> Trie<K> {
    let mut t = Trie::<K>::new();
    for i in 0..n {
        // 40-byte values so nothing inlines: every node is a real hashed node
        // and off-path children genuinely become Stubs.
        t.insert(&key(i), vec![(i % 251) as u8; 40]).unwrap();
    }
    t
}

#[test]
fn insertion_never_needs_a_node_outside_its_proof() {
    const PRESENT: u16 = 400;
    let mut full = full_trie(PRESENT);
    let root = full.hash();

    let mut seen: BTreeMap<Termination, usize> = BTreeMap::new();
    let mut min_stubs = usize::MAX;

    for i in 1000u16..1400 {
        let k = key(i);
        assert!(
            full.get(&k).unwrap().is_none(),
            "test key {i} collided with a present key"
        );

        // The exclusion proof, and nothing else.
        let proof = full.prove(&k);
        let mut witness: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
        for n in &proof {
            witness.insert(keccak(n), n.clone());
        }

        let partial: Node<K> = build_partial(&witness, &root);
        assert_eq!(
            node_root(&partial),
            root,
            "partial trie must reproduce the root"
        );

        let stubs = count_stubs(&partial);
        assert!(
            stubs > 0,
            "witness accidentally contained everything — test is vacuous"
        );
        min_stubs = min_stubs.min(stubs);

        let termination = classify(&partial, &to_nibbles(&k));
        assert_ne!(termination, Termination::Present, "key {i} is not absent");
        *seen.entry(termination).or_default() += 1;

        // The assertion. If insertion needed anything the proof did not carry,
        // this walks into a Stub — which either panics or silently produces a
        // different root. Both fail here.
        let mut partial_trie = Trie::<K>::from_node(partial);
        partial_trie.insert(&k, vec![0xee; 40]).unwrap();
        let partial_root = partial_trie.hash();

        let mut reference = full_trie(PRESENT);
        reference.insert(&k, vec![0xee; 40]).unwrap();

        assert_eq!(
            hex::encode(partial_root),
            hex::encode(reference.hash()),
            "insert of key {i} ({termination:?}, {stubs} stubs) diverged from the full trie"
        );
    }

    // All three exclusion shapes must actually occur, or the test only proves
    // whichever one happened to come up.
    for shape in [
        Termination::EmptySlot,
        Termination::DivergingLeaf,
        Termination::DivergingSkip,
    ] {
        assert!(
            seen.get(&shape).copied().unwrap_or(0) > 0,
            "termination shape {shape:?} was never exercised; seen = {seen:?}"
        );
    }

    eprintln!("terminations: {seen:?}, min stubs {min_stubs}");
}

#[test]
fn insertion_into_an_empty_partial_trie() {
    // Degenerate case: the empty trie. `prove` returns an empty proof and
    // `build_partial` must yield Null, not a Stub. See PTRIE.md §7.
    let mut empty = Trie::<K>::new();
    let root = empty.hash();

    let witness: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    let partial: Node<K> = build_partial(&witness, &root);
    assert_eq!(node_root(&partial), root);
    assert_eq!(
        count_stubs(&partial),
        0,
        "the empty trie has nothing to stub"
    );

    let mut t = Trie::<K>::from_node(partial);
    t.insert(b"anything", b"value".to_vec()).unwrap();

    let mut reference = Trie::<K>::new();
    reference.insert(b"anything", b"value".to_vec()).unwrap();
    assert_eq!(t.hash(), reference.hash());
}

#[test]
fn repeated_inserts_into_one_partial_trie() {
    // Several inserts against a single witness. Each one only needs its own
    // path, and paths accumulate — so a witness covering N keys supports
    // inserting all N without any further nodes.
    const PRESENT: u16 = 200;
    let mut full = full_trie(PRESENT);
    let root = full.hash();

    let new_keys: Vec<Vec<u8>> = (2000u16..2010).map(key).collect();

    let mut witness: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    for k in &new_keys {
        for n in full.prove(k) {
            witness.insert(keccak(&n), n);
        }
    }

    let mut partial = Trie::<K>::from_node(build_partial(&witness, &root));
    assert_eq!(partial.hash(), root);

    let mut reference = full_trie(PRESENT);
    for (j, k) in new_keys.iter().enumerate() {
        partial.insert(k, vec![j as u8; 40]).unwrap();
        reference.insert(k, vec![j as u8; 40]).unwrap();
        assert_eq!(
            hex::encode(partial.hash()),
            hex::encode(reference.hash()),
            "diverged after inserting key {j}"
        );
    }
}

#[test]
fn value_update_needs_nothing_extra() {
    // The baseline case, for contrast with the delete-collapse test: updating
    // an existing key touches only its own path.
    const PRESENT: u16 = 200;
    let mut full = full_trie(PRESENT);
    let root = full.hash();
    let k = key(77);

    let mut witness: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    for n in full.prove(&k) {
        witness.insert(keccak(&n), n);
    }

    let mut partial = Trie::<K>::from_node(build_partial(&witness, &root));
    partial.insert(&k, vec![0x42; 40]).unwrap();

    let mut reference = full_trie(PRESENT);
    reference.insert(&k, vec![0x42; 40]).unwrap();
    assert_eq!(hex::encode(partial.hash()), hex::encode(reference.hash()));

    // And reverting restores the root byte-exactly — the canonicality check.
    partial.insert(&k, vec![(77 % 251) as u8; 40]).unwrap();
    assert_eq!(hex::encode(partial.hash()), hex::encode(root));
}

// Coverage for partial-trie insertion beyond the main sweep.
//
// The sweep in `insertion_never_needs_a_node_outside_its_proof` establishes
// the *property*: an exclusion proof always carries the nodes an insert needs.
// These tests check the *implementation* handles every shape those nodes can
// take — a separate claim, and the one that actually breaks.
//
// The sweep uses keccak-derived keys and 40-byte values, which is the easiest
// possible case: nothing inlines, no key is a prefix of another, and every
// node is a separate proof entry. These cover what that misses.

type Witness = BTreeMap<[u8; 32], Vec<u8>>;

fn build(pairs: &[(&[u8], &[u8])]) -> Trie<K> {
    let mut t = Trie::<K>::new();
    for (k, v) in pairs {
        t.insert(k, v.to_vec()).unwrap();
    }
    t
}

fn witness(t: &mut Trie<K>, keys: &[&[u8]]) -> Witness {
    let mut w = Witness::new();
    for k in keys {
        for n in t.prove(k) {
            w.insert(keccak(&n), n);
        }
    }
    w
}

/// Build a partial trie from proofs for `probe`, apply `ops` to it and to a
/// fresh full trie, and assert the roots agree at the end. Returns the stub
/// count so callers can assert the test was not vacuous.
fn check(name: &str, pairs: &[(&[u8], &[u8])], probe: &[&[u8]], ops: &[(&[u8], &[u8])]) -> usize {
    let mut full = build(pairs);
    let root = full.hash();

    let w = witness(&mut full, probe);
    let partial: Node<K> = build_partial(&w, &root);
    assert_eq!(
        node_root(&partial),
        root,
        "{name}: partial trie must reproduce the root"
    );

    let stubs = count_stubs(&partial);

    let mut partial_trie = Trie::<K>::from_node(partial);
    let mut reference = build(pairs);
    for (k, v) in ops {
        partial_trie.insert(k, v.to_vec()).unwrap();
        reference.insert(k, v.to_vec()).unwrap();
    }

    assert_eq!(
        hex::encode(partial_trie.hash()),
        hex::encode(reference.hash()),
        "{name}: partial trie diverged from the full trie ({stubs} stubs)"
    );
    stubs
}

// ---------------------------------------------------------------------------
// 1. inlined nodes
// ---------------------------------------------------------------------------

#[test]
fn split_an_inlined_leaf() {
    // 1-byte values make leaves encode under 32 bytes, so they live INSIDE
    // their parent's RLP as nested lists rather than as 32-byte hash
    // references. `decode_node` must take its `!item.is_data()` branch and
    // decode in place; treating a nested list as a hash reference would fail
    // here and nowhere in the main sweep.
    //
    // Note the stub count is zero: a trie this small inlines entirely into its
    // root, so the proof carries everything. The decoder branch is still
    // exercised, which is the point. `inlined_children_with_real_stubs` below
    // covers inlining where stubs genuinely occur.
    let pairs: &[(&[u8], &[u8])] = &[(b"\x01", b"a"), (b"\x02", b"b"), (b"\x81", b"c")];
    check("split inlined leaf", pairs, &[b"\x03"], &[(b"\x03", b"e")]);
    check(
        "insert beside inlined",
        pairs,
        &[b"\x90"],
        &[(b"\x90", b"f")],
    );
}

#[test]
fn inlined_children_with_real_stubs() {
    // Wide enough that the root Fork exceeds 32 bytes and its children become
    // hash references, while the leaves under each child stay small enough to
    // inline. Now BOTH reference kinds appear in one proof and stubs are real.
    let owned: Vec<(Vec<u8>, Vec<u8>)> = (0u8..48)
        .map(|i| (vec![i, i.wrapping_mul(7)], vec![i]))
        .collect();
    let pairs: Vec<(&[u8], &[u8])> = owned
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();

    let stubs = check(
        "inlined + stubs",
        &pairs,
        &[&[0x05, 0x99]],
        &[(&[0x05, 0x99], b"z")],
    );
    assert!(
        stubs > 0,
        "expected real stubs; witness covered the whole trie"
    );
}

// ---------------------------------------------------------------------------
// 2. crossing the 32-byte inlining boundary
// ---------------------------------------------------------------------------

#[test]
fn overwrite_crosses_the_inlining_boundary() {
    // A short value inlines; a long one is hashed. Overwriting one with the
    // other flips the node between the two forms, which changes the PARENT's
    // encoding by more than swapping a hash — the parent's length changes too.
    // PTRIE.md §3 flags this as needing a test.
    let pairs: &[(&[u8], &[u8])] = &[(b"aa", b"x"), (b"ab", b"y"), (b"zz", b"q")];
    let long = vec![0xcd; 64];

    check("short -> long", pairs, &[b"aa"], &[(b"aa", &long)]);

    // And the other direction: a hashed node shrinking back to inlined.
    let big: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b"aa".to_vec(), vec![0xcd; 64]),
        (b"ab".to_vec(), vec![0xef; 64]),
        (b"zz".to_vec(), vec![0x11; 64]),
    ];
    let refs: Vec<(&[u8], &[u8])> = big
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();
    check("long -> short", &refs, &[b"aa"], &[(b"aa", b"x")]);
}

// ---------------------------------------------------------------------------
// 3. the empty key
// ---------------------------------------------------------------------------

#[test]
fn insert_the_empty_key() {
    // hp([], true) is 0x20 — a leaf with an empty path. Depending on the trie's
    // shape this becomes either that leaf at the root or a value in the root
    // Fork's slot 16. A fourth termination shape the main sweep never produces.
    check(
        "empty key",
        &[(b"a", b"1"), (b"b", b"2")],
        &[b""],
        &[(b"", b"root")],
    );

    // And into a trie that already has a value at the empty key.
    check(
        "overwrite empty key",
        &[(b"", b"old"), (b"a", b"1")],
        &[b""],
        &[(b"", b"new")],
    );
}

// ---------------------------------------------------------------------------
// 4. prefix relationships
// ---------------------------------------------------------------------------

#[test]
fn prefix_keys_use_the_fork_value_slot() {
    // When one key is a strict prefix of another, the split leaves one path
    // exhausted, so its value goes in the Fork's value slot rather than into a
    // child. That branch of `insert_at` is exercised in tests/trie.rs on full
    // tries, but never with stubs present — keccak-derived keys are all the
    // same length and share no prefixes.
    let long = vec![1u8; 40];
    let other = vec![2u8; 40];
    let fresh = vec![3u8; 40];
    let pairs: &[(&[u8], &[u8])] = &[(b"key", &long), (b"other", &other)];

    // New key is a strict prefix of an existing one.
    let s = check("new key is a prefix", pairs, &[b"ke"], &[(b"ke", &fresh)]);
    assert!(
        s > 0,
        "expected a stub — the 'other' subtree should not be in the witness"
    );

    // Existing key is a strict prefix of the new one.
    let s = check(
        "existing is a prefix",
        pairs,
        &[b"keyy"],
        &[(b"keyy", &fresh)],
    );
    assert!(s > 0);

    // Same, with values short enough to inline: both special cases at once.
    check(
        "prefix + inlined",
        &[(b"key", b"1"), (b"other", b"2")],
        &[b"ke"],
        &[(b"ke", b"3")],
    );
}

// ---------------------------------------------------------------------------
// 5. many ops against one witness
// ---------------------------------------------------------------------------

#[test]
fn interleaved_inserts_and_updates() {
    // A witness covering N keys supports operating on all N. Paths accumulate
    // in the partial trie rather than interfering, and an update to an existing
    // key mixed in with inserts must not disturb either.
    let owned: Vec<(Vec<u8>, Vec<u8>)> = (0u16..60)
        .map(|i| {
            (
                keccak(&i.to_be_bytes())[..4].to_vec(),
                vec![(i % 251) as u8; 40],
            )
        })
        .collect();
    let pairs: Vec<(&[u8], &[u8])> = owned
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();

    let new_keys: Vec<Vec<u8>> = (500u16..505)
        .map(|i| keccak(&i.to_be_bytes())[..4].to_vec())
        .collect();

    let mut probe: Vec<&[u8]> = new_keys.iter().map(Vec::as_slice).collect();
    probe.extend(pairs.iter().take(3).map(|(k, _)| *k));

    let mut ops: Vec<(&[u8], &[u8])> = new_keys
        .iter()
        .map(|k| (k.as_slice(), &b"inserted"[..]))
        .collect();
    ops.extend(pairs.iter().take(3).map(|(k, _)| (*k, &b"updated"[..])));

    let stubs = check("interleaved", &pairs, &probe, &ops);
    assert!(
        stubs > 10,
        "expected a genuinely partial trie, got {stubs} stubs"
    );
}

// ---------------------------------------------------------------------------
// 6. the root itself is unknown
// ---------------------------------------------------------------------------

#[test]
fn empty_witness_gives_a_stub_root() {
    // An empty witness with a NON-empty root is the honest "we know the root
    // and nothing else". It must be a Stub, and it must still re-derive that
    // root, since a Stub encodes as exactly its hash reference.
    //
    // Contrast `insertion_into_an_empty_partial_trie`: the EMPTY-trie root is
    // fully determined (rlp(Null) is 0x80), so build_partial special-cases it
    // to Null rather than an unresolvable Stub.
    let owned: Vec<(Vec<u8>, Vec<u8>)> = (0u16..40)
        .map(|i| (keccak(&i.to_be_bytes())[..4].to_vec(), vec![i as u8; 40]))
        .collect();
    let pairs: Vec<(&[u8], &[u8])> = owned
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();

    let root = build(&pairs).hash();
    let partial: Node<K> = build_partial(&Witness::new(), &root);

    assert!(
        matches!(partial, Node::Stub(_)),
        "expected a Stub root, got {partial:?}"
    );
    assert_eq!(count_stubs(&partial), 1);
    assert_eq!(
        node_root(&partial),
        root,
        "a Stub root must still re-derive its hash"
    );
}

#[test]
fn insert_into_a_stub_root_fails() {
    // Traversal cannot proceed past an unresolvable Stub: it must return
    // Err(TrieError::MissingNode { hash, path: [] }) rather than panic or
    // silently produce a wrong root.
    let owned: Vec<(Vec<u8>, Vec<u8>)> = (0u16..40)
        .map(|i| (keccak(&i.to_be_bytes())[..4].to_vec(), vec![i as u8; 40]))
        .collect();
    let pairs: Vec<(&[u8], &[u8])> = owned
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();

    let mut full = build(&pairs);
    let root = full.hash();
    let mut t = Trie::<K>::from_node(build_partial(&Witness::new(), &root));
    match t.insert(b"anything", vec![0xaa; 40]) {
        Err(TrieError::MissingNode { hash, path }) => {
            assert_eq!(hash, root, "the stub root's own hash");
            assert!(path.is_empty(), "the root sits at the empty path");
        }
        other => panic!("expected Err(MissingNode {{ hash: root, path: [] }}), got {other:?}"),
    }
}
