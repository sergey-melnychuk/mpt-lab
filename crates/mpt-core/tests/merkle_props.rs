use mpt_core::Keccak256 as K;
use mpt_core::merkle::{self, MerkleTree};
use proptest::prelude::*;

proptest! {
    #[test]
    fn every_proof_verifies(
        ls in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 0..40),
            1..64,
        ),
    ) {
        let t = MerkleTree::<K>::new(&ls);
        let root = t.root();
        for (i, leaf) in ls.iter().enumerate() {
            prop_assert!(merkle::verify::<K>(&root, leaf, i, &t.prove(i).unwrap()));
        }
    }

    #[test]
    fn proof_length_matches_depth_invariant(n in 1usize..200) {
        let ls: Vec<Vec<u8>> = (0..n).map(|i| vec![i as u8]).collect();
        let t = MerkleTree::<K>::new(&ls);
        let expected = n.next_power_of_two().trailing_zeros() as usize;
        for i in 0..n {
            // If your odd-count strategy makes this false, the invariant is
            // different, not absent. Replace it with yours and justify it.
            prop_assert_eq!(t.prove(i).unwrap().siblings.len(), expected);
        }
    }

    #[test]
    fn foreign_leaf_never_verifies(
        ls in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..20), 1..32),
        outsider in prop::collection::vec(any::<u8>(), 1..20),
    ) {
        prop_assume!(!ls.contains(&outsider));
        let t = MerkleTree::<K>::new(&ls);
        let root = t.root();
        for i in 0..ls.len() {
            let p = t.prove(i).unwrap();
            prop_assert!(!merkle::verify::<K>(&root, &outsider, i, &p));
        }
    }
}
