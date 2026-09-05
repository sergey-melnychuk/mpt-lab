use mpt_core::Keccak256 as K;
use mpt_core::trie::{Node, Trie};
use proptest::prelude::*;
use std::collections::BTreeMap;

fn root_of(pairs: &[(&[u8], &[u8])]) -> [u8; 32] {
    built(pairs).hash()
}

fn built(pairs: &[(&[u8], &[u8])]) -> Trie<K> {
    let mut t = Trie::new();
    for (k, v) in pairs {
        t.insert(k, v.to_vec());
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
    let t = built(CLASSIC);
    for (k, v) in CLASSIC {
        assert_eq!(t.get(k), Some(*v), "key={:?}", core::str::from_utf8(k));
    }
    assert_eq!(t.get(b"d"), None);
    assert_eq!(t.get(b"dogez"), None);
    assert_eq!(t.get(b"hors"), None);
    assert_eq!(t.get(b""), None);
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
    t.insert(b"dog", b"hound".to_vec());
    t.root().debug_check();
    assert_eq!(t.get(b"dog"), Some(&b"hound"[..]));
    assert_eq!(t.get(b"doge"), Some(&b"coin"[..]));
}

#[test]
fn empty_key() {
    let mut t = Trie::<K>::new();
    t.insert(b"", b"root-value".to_vec());
    t.root().debug_check();
    assert_eq!(t.get(b""), Some(&b"root-value"[..]));
    t.insert(b"a", b"other".to_vec());
    t.root().debug_check();
    assert_eq!(t.get(b""), Some(&b"root-value"[..]));
    assert_eq!(t.get(b"a"), Some(&b"other"[..]));
}

#[test]
fn diverge_at_first_nibble() {
    let t = built(&[(b"\x01", b"one"), (b"\x81", b"two")]);
    assert!(matches!(t.root(), Node::Fork { .. }), "no shared prefix");
    assert_eq!(t.get(b"\x01"), Some(&b"one"[..]));
    assert_eq!(t.get(b"\x81"), Some(&b"two"[..]));
}

#[test]
fn wide_forks() {
    let mut t = Trie::<K>::new();
    for i in 0u16..256 {
        t.insert(&i.to_be_bytes(), i.to_string().into_bytes());
    }
    t.root().debug_check();
    for i in 0u16..256 {
        assert_eq!(t.get(&i.to_be_bytes()), Some(i.to_string().as_bytes()));
    }
}

#[test]
fn one_nibble_remainder() {
    // Exercises the Skip-split subtlety: the remainder after the fork index is
    // a single nibble, so no wrapping Skip is created.
    let t = built(&[(b"\x12\x34", b"a"), (b"\x12\x35", b"b"), (b"\x12", b"c")]);
    assert_eq!(t.get(b"\x12\x34"), Some(&b"a"[..]));
    assert_eq!(t.get(b"\x12\x35"), Some(&b"b"[..]));
    assert_eq!(t.get(b"\x12"), Some(&b"c"[..]));
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
        let existed = t.get(extra).is_some();
        t.insert(extra, b"temporary".to_vec());
        t.root().debug_check();
        assert!(t.remove(extra), "remove({extra:?}) reported not-present");
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
        assert!(t.remove(k));
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
            assert!(t.remove(k), "remove({k:?})");
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
    assert!(t.remove(b"\x81"));
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
    assert!(t.remove(b"abc"));
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
    assert!(t.remove(b"aaaaaaaa2"));
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
    assert!(t.remove(b"prefix_bbb_3"));
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
    assert!(t.remove(b"\x11\x11\x11\x12"));
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
    t.insert(b"k1", big.clone());
    t.insert(b"k2", b"s".to_vec());
    t.insert(b"k3", b"s".to_vec());
    t.remove(b"k1");
    t.root().debug_check();

    let mut want = Trie::<K>::new();
    want.insert(b"k2", b"s".to_vec());
    want.insert(b"k3", b"s".to_vec());
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
        assert!(!t.remove(absent), "remove({absent:?}) claimed success");
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
    assert!(!t.remove(b"anything"));
    assert!(!t.remove(b""));
    assert_eq!(hex::encode(t.hash()), hex::encode(Trie::<K>::new().hash()));
}

#[test]
fn double_remove() {
    let mut t = built(CLASSIC);
    assert!(t.remove(b"dog"));
    assert!(!t.remove(b"dog"), "second removal should report absent");
    t.root().debug_check();
    assert_eq!(t.get(b"dog"), None);
    assert_eq!(t.get(b"doge"), Some(&b"coin"[..]));
}

#[test]
fn empty_key_removal() {
    let mut t = Trie::<K>::new();
    t.insert(b"", b"at-root".to_vec());
    t.insert(b"a", b"other".to_vec());
    t.root().debug_check();
    assert!(t.remove(b""));
    t.root().debug_check();
    assert_eq!(t.get(b""), None);
    assert_eq!(t.get(b"a"), Some(&b"other"[..]));
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
            t.insert(k, v.clone());
            t.root().debug_check();
        }
        for (k, v) in &map {
            prop_assert_eq!(t.get(k), Some(v.as_slice()));
        }
        for p in &probes {
            prop_assert_eq!(t.get(p), map.get(p).map(|v| v.as_slice()));
        }
    }

    #[test]
    fn structure_is_insertion_order_independent(map in kv_map(), seed in any::<u64>()) {
        let mut a = Trie::<K>::new();
        for (k, v) in &map {
            a.insert(k, v.clone());
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
            b.insert(k, v.clone());
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
        for (k, v) in &map { deleted.insert(k, v.clone()); }
        for k in &doomed {
            prop_assert!(deleted.remove(k));
            deleted.root().debug_check();
        }

        let mut direct = Trie::<K>::new();
        for (k, v) in &map {
            if !doomed.contains(k) { direct.insert(k, v.clone()); }
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
                Some(v) => { t.insert(k, v.clone()); m.insert(k.clone(), v.clone()); }
                None => {
                    let expected = m.remove(k).is_some();
                    prop_assert_eq!(t.remove(k), expected, "remove({:?}) return value", k);
                }
            }
            t.root().debug_check();
        }

        for (k, v) in &m { prop_assert_eq!(t.get(k), Some(v.as_slice())); }
        for (k, _) in &ops { if !m.contains_key(k) { prop_assert_eq!(t.get(k), None); } }
    }

    #[test]
    fn insert_then_remove_is_identity(map in kv_map(), extra in prop::collection::vec(any::<u8>(), 0..5)) {
        prop_assume!(!map.contains_key(&extra));
        let mut t = Trie::<K>::new();
        for (k, v) in &map { t.insert(k, v.clone()); }
        let before = t.hash();

        t.insert(&extra, b"scratch".to_vec());
        prop_assert!(t.remove(&extra));
        t.root().debug_check();

        prop_assert_eq!(hex::encode(t.hash()), hex::encode(before));
    }
}
