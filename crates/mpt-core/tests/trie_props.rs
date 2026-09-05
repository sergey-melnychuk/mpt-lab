use mpt_core::trie::Trie;
use proptest::prelude::*;
use std::collections::BTreeMap;

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
        let mut t = Trie::new();
        for (k, v) in &map {
            t.insert(k, v.clone());
            t.root_node().debug_check();
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
        let mut a = Trie::new();
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
}
