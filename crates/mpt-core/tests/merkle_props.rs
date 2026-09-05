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
            prop_assert!(merkle::verify::<K>(&root, leaf, i, t.len(), &t.prove(i).unwrap()));
        }
    }

    #[test]
    fn proof_length_matches_depth_invariant(n in 1usize..200) {
        fn expected_len(mut index: usize, mut size: usize) -> usize {
            let mut count = 0;
            while size > 1 {
                if !(index == size - 1 && size % 2 == 1) {
                    count += 1;
                }
                index /= 2;
                size = size.div_ceil(2);
            }
            count
        }
        let ls: Vec<Vec<u8>> = (0..n).map(|i| vec![i as u8]).collect();
        let t = MerkleTree::<K>::new(&ls);
        for i in 0..n {
            let len = expected_len(i, n);
            prop_assert!(len <= (usize::BITS - (n - 1).leading_zeros()) as usize);
            prop_assert_eq!(t.prove(i).unwrap().siblings.len(), len);
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
            prop_assert!(!merkle::verify::<K>(&root, &outsider, i, t.len(), &p));
        }
    }
}
