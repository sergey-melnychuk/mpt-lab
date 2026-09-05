use mpt_core::trie::{Node, Trie};

fn built(pairs: &[(&[u8], &[u8])]) -> Trie {
    let mut t = Trie::new();
    for (k, v) in pairs {
        t.insert(k, v.to_vec());
        t.root_node().debug_check();
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
    let Node::Skip { path, child } = t.root_node() else {
        panic!(
            "root should be a Skip over the shared nibble, got {:?}",
            t.root_node()
        );
    };
    assert_eq!(path, &vec![6]);
    let Node::Fork { children, value } = &**child else {
        panic!("Skip child must be a Fork");
    };
    assert!(value.is_none(), "no key terminates at nibble [6]");
    assert!(children[4].is_some(), "the 'do*' subtree");
    assert!(children[8].is_some(), "the 'horse' leaf");
    assert_eq!(
        t.root_node().fork_occupancy(),
        0,
        "root is a Skip, not a Fork"
    );
    // TODO: assert the rest yourself. Walk children[4] down and check where
    // "verb" and "puppy" land (value slots, not leaves) and what shape the
    // "doge" tail takes.
}

#[test]
fn value_replacement() {
    let mut t = built(CLASSIC);
    t.insert(b"dog", b"hound".to_vec());
    t.root_node().debug_check();
    assert_eq!(t.get(b"dog"), Some(&b"hound"[..]));
    assert_eq!(t.get(b"doge"), Some(&b"coin"[..]));
}

#[test]
fn empty_key() {
    let mut t = Trie::new();
    t.insert(b"", b"root-value".to_vec());
    t.root_node().debug_check();
    assert_eq!(t.get(b""), Some(&b"root-value"[..]));
    t.insert(b"a", b"other".to_vec());
    t.root_node().debug_check();
    assert_eq!(t.get(b""), Some(&b"root-value"[..]));
    assert_eq!(t.get(b"a"), Some(&b"other"[..]));
}

#[test]
fn diverge_at_first_nibble() {
    let t = built(&[(b"\x01", b"one"), (b"\x81", b"two")]);
    assert!(
        matches!(t.root_node(), Node::Fork { .. }),
        "no shared prefix"
    );
    assert_eq!(t.get(b"\x01"), Some(&b"one"[..]));
    assert_eq!(t.get(b"\x81"), Some(&b"two"[..]));
}

#[test]
fn wide_forks() {
    let mut t = Trie::new();
    for i in 0u16..256 {
        t.insert(&i.to_be_bytes(), i.to_string().into_bytes());
    }
    t.root_node().debug_check();
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
