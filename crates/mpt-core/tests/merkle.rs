use mpt_core::Keccak256 as K;
use mpt_core::merkle::{self, MerkleTree};

#[test]
fn leaf_and_node_preimage_spaces_are_disjoint() {
    let la = merkle::hash_leaf::<K>(b"alpha");
    let lb = merkle::hash_leaf::<K>(b"beta");

    let mut concat = Vec::new();
    concat.extend_from_slice(la.as_ref());
    concat.extend_from_slice(lb.as_ref());

    // The forged leaf whose bytes are an internal node's preimage.
    assert_ne!(
        merkle::hash_leaf::<K>(&concat),
        merkle::hash_node::<K>(&la, &lb)
    );
}

#[test]
fn empty_root_is_the_zero_hash_and_unreachable_by_hashing() {
    let z = merkle::empty_root::<K>();
    assert_eq!(z.as_ref(), [0u8; 32]);
    // No leaf and no internal combination should ever land on it.
    assert_ne!(merkle::hash_leaf::<K>(b""), z);
    assert_ne!(merkle::hash_node::<K>(&z, &z), z);
}

fn leaves(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect()
}

#[test]
fn empty_tree_root_is_documented_constant() {
    let t = MerkleTree::<K>::new(&[]);
    assert!(t.is_empty());
    assert_eq!(t.root(), merkle::empty_root::<K>());
}

#[test]
fn roundtrip_all_indices_up_to_nine_leaves() {
    for n in 1..=9 {
        let ls = leaves(n);
        let t = MerkleTree::<K>::new(&ls);
        let root = t.root();
        #[allow(clippy::needless_range_loop)]
        for i in 0..n {
            let p = t.prove(i).expect("index in range");
            assert!(
                merkle::verify::<K>(&root, &ls[i], i, t.len(), &p),
                "n={n} i={i} failed to verify"
            );
        }
        assert!(t.prove(n).is_none(), "n={n}: out-of-range index proved");
    }
}

#[test]
fn proof_does_not_verify_for_wrong_index() {
    let ls = leaves(7);
    let t = MerkleTree::<K>::new(&ls);
    let root = t.root();
    for i in 0..7 {
        let p = t.prove(i).unwrap();
        for j in 0..7 {
            if i == j {
                continue;
            }
            assert!(!merkle::verify::<K>(&root, &ls[j], j, t.len(), &p));
            assert!(!merkle::verify::<K>(&root, &ls[i], j, t.len(), &p));
        }
    }
}

#[test]
fn bitflipped_sibling_is_rejected() {
    let ls = leaves(8);
    let t = MerkleTree::<K>::new(&ls);
    let root = t.root();
    for k in 0..t.prove(3).unwrap().siblings.len() {
        let mut p = t.prove(3).unwrap();
        p.siblings[k].as_mut()[0] ^= 0x01;
        assert!(
            !merkle::verify::<K>(&root, &ls[3], 3, t.len(), &p),
            "sibling {k}"
        );
    }
}

#[test]
fn leaf_and_node_domains_are_separated() {
    // A 2-leaf tree's root is hash_node(hash_leaf(a), hash_leaf(b)).
    // A 1-leaf tree whose leaf bytes are that same concatenated preimage must
    // NOT collide with it, or an attacker can pass an node off as data.
    let a = b"alpha".to_vec();
    let b = b"beta".to_vec();
    let two = MerkleTree::<K>::new(&[a.clone(), b.clone()]);

    let mut preimage = Vec::new();
    preimage.extend_from_slice(merkle::hash_leaf::<K>(&a).as_ref());
    preimage.extend_from_slice(merkle::hash_leaf::<K>(&b).as_ref());
    let one = MerkleTree::<K>::new(&[preimage]);

    assert_ne!(two.root(), one.root());
}

#[test]
fn duplicated_tail_leaf_changes_the_root() {
    // CVE-2012-2459 shape: [a,b,c] and [a,b,c,c] must be distinguishable.
    let a = b"a".to_vec();
    let b = b"b".to_vec();
    let c = b"c".to_vec();
    let three = MerkleTree::<K>::new(&[a.clone(), b.clone(), c.clone()]);
    let four = MerkleTree::<K>::new(&[a, b, c.clone(), c]);
    assert_ne!(three.root(), four.root());
}

#[test]
fn distinct_leaf_sets_have_distinct_roots() {
    let x = MerkleTree::<K>::new(&leaves(5)).root();
    let mut ls = leaves(5);
    ls.swap(1, 3);
    let y = MerkleTree::<K>::new(&ls).root();
    assert_ne!(x, y, "tree must be order-sensitive");
}

#[test]
fn traversal_equivalent_sizes_accept_the_same_proof() {
    // size influences the fold ONLY through the promotion branch, so for an
    // index that is never a tail, 7 and 8 are indistinguishable.
    let ls = leaves(7);
    let t = MerkleTree::<K>::new(&ls);
    let (root, p) = (t.root(), t.prove(3).unwrap());
    assert!(merkle::verify::<K>(&root, &ls[3], 3, 7, &p));
    assert!(merkle::verify::<K>(&root, &ls[3], 3, 8, &p));
}

#[test]
fn promotion_allows_index_remapping() {
    // Documents a real limitation: `size` is unauthenticated and selects
    // which position claim the proof supports. See NOTES.md decision 2.
    let ls = leaves(3);
    let t = MerkleTree::<K>::new(&ls);
    let (root, p) = (t.root(), t.prove(2).unwrap());
    assert!(merkle::verify::<K>(&root, &ls[2], 2, 3, &p));
    assert!(
        merkle::verify::<K>(&root, &ls[2], 1, 2, &p),
        "known remapping"
    );
}

#[test]
fn size_lies_that_change_traversal_are_rejected() {
    let ls = leaves(7);
    let t = MerkleTree::<K>::new(&ls);
    let root = t.root();
    let p = t.prove(6).unwrap(); // tail: promotes, 2 siblings
    assert_eq!(p.siblings.len(), 2);
    for bad in [8usize, 9, 100] {
        assert!(
            !merkle::verify::<K>(&root, &ls[6], 6, bad, &p),
            "size={bad}"
        );
    }
}
