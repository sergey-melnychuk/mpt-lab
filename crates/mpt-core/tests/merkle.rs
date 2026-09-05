use mpt_core::Keccak256 as K;
use mpt_core::merkle::{self, MerkleTree};

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
        for i in 0..n {
            let p = t.prove(i).expect("index in range");
            assert!(
                merkle::verify::<K>(&root, &ls[i], i, &p),
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
            assert!(!merkle::verify::<K>(&root, &ls[j], j, &p));
            assert!(!merkle::verify::<K>(&root, &ls[i], j, &p));
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
        assert!(!merkle::verify::<K>(&root, &ls[3], 3, &p), "sibling {k}");
    }
}

#[test]
fn leaf_and_internal_domains_are_separated() {
    // A 2-leaf tree's root is hash_internal(hash_leaf(a), hash_leaf(b)).
    // A 1-leaf tree whose leaf bytes are that same concatenated preimage must
    // NOT collide with it, or an attacker can pass an internal node off as data.
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
