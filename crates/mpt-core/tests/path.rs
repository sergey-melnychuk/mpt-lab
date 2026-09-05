//! Hex-prefix (compact) encoding, yellow paper appendix C.
//!
//! First nibble: 0 = ext/even, 1 = ext/odd, 2 = leaf/even, 3 = leaf/odd.

use mpt_core::path::{self, Error};
use proptest::prelude::*;

#[test]
fn nibble_expansion() {
    assert_eq!(path::to_nibbles(b"do"), vec![6, 4, 6, 15]);
    assert_eq!(path::to_nibbles(b""), Vec::<u8>::new());
    assert_eq!(path::to_nibbles(&[0x00, 0xff]), vec![0, 0, 15, 15]);
}

#[test]
fn packing_rejects_bad_input() {
    assert_eq!(path::from_nibbles(&[1, 2, 3]), Err(Error::OddNibbleLength));
    assert_eq!(path::from_nibbles(&[1, 0x10]), Err(Error::InvalidNibble));
}

#[test]
fn common_prefixes() {
    assert_eq!(path::common_prefix_len(&[1, 2, 3], &[1, 2, 9]), 2);
    assert_eq!(path::common_prefix_len(&[1, 2], &[1, 2, 3]), 2);
    assert_eq!(path::common_prefix_len(&[], &[1]), 0);
}

const EXT: bool = false;
const LEAF: bool = true;

/// (path nibbles, is_leaf, encoded bytes)
const VECTORS: &[(&[u8], bool, &[u8])] = &[
    // Empty paths. Both are legal and both occur: 0x20 is the leaf storing the
    // empty key, 0x00 is an extension with nothing to skip.
    (&[], EXT, &[0x00]),
    (&[], LEAF, &[0x20]),
    // Odd length: flag nibble is followed directly by the path.
    (&[1, 2, 3, 4, 5], EXT, &[0x11, 0x23, 0x45]),
    (&[0x0f, 1, 0x0c, 0x0b, 8], LEAF, &[0x3f, 0x1c, 0xb8]),
    // Even length: flag nibble, then a zero pad nibble, then the path.
    (&[0, 1, 2, 3, 4, 5], EXT, &[0x00, 0x01, 0x23, 0x45]),
    (
        &[0, 0x0f, 1, 0x0c, 0x0b, 8],
        LEAF,
        &[0x20, 0x0f, 0x1c, 0xb8],
    ),
    // Single nibble, both flavours: shortest odd case.
    (&[0], EXT, &[0x10]),
    (&[0x0f], LEAF, &[0x3f]),
    // Leading-zero path must survive: [0,0] is not the same as [].
    (&[0, 0], LEAF, &[0x20, 0x00]),
];

#[test]
fn encode_vectors() {
    for (path, is_leaf, want) in VECTORS {
        let got = path::hex_prefix_encode(path, *is_leaf);
        assert_eq!(
            got,
            want.to_vec(),
            "encode({path:?}, leaf={is_leaf}) = {}, want {}",
            hex::encode(&got),
            hex::encode(want)
        );
    }
}

#[test]
fn decode_vectors() {
    for (path, is_leaf, encoded) in VECTORS {
        let got = path::hex_prefix_decode(encoded);
        assert_eq!(
            got,
            Ok((path.to_vec(), *is_leaf)),
            "decode({}) mismatch",
            hex::encode(encoded)
        );
    }
}

#[test]
fn flag_nibble_encodes_both_dimensions() {
    // The four legal first nibbles, one per (is_leaf, parity) combination.
    assert_eq!(path::hex_prefix_encode(&[1, 2], EXT)[0] >> 4, 0);
    assert_eq!(path::hex_prefix_encode(&[1], EXT)[0] >> 4, 1);
    assert_eq!(path::hex_prefix_encode(&[1, 2], LEAF)[0] >> 4, 2);
    assert_eq!(path::hex_prefix_encode(&[1], LEAF)[0] >> 4, 3);
}

#[test]
fn leaf_and_extension_never_collide() {
    // The property standing in for the b"L"/b"N" tags in merkle.rs: no leaf's
    // HP encoding equals any extension's, for any pair of paths. Bit 1 of the
    // first nibble differs, and the first nibble is at a fixed offset.
    for a in 0..6usize {
        for b in 0..6usize {
            let pa: Vec<u8> = (0..a).map(|i| (i % 16) as u8).collect();
            let pb: Vec<u8> = (0..b).map(|i| (i % 16) as u8).collect();
            assert_ne!(
                path::hex_prefix_encode(&pa, LEAF),
                path::hex_prefix_encode(&pb, EXT),
                "leaf({pa:?}) collided with ext({pb:?})"
            );
        }
    }
}

#[test]
fn encoding_is_injective_over_small_paths() {
    // No two (path, is_leaf) pairs share an encoding. If this fails, two
    // distinct nodes can produce identical RLP and therefore identical hashes.
    use std::collections::HashMap;
    let mut seen: HashMap<Vec<u8>, (Vec<u8>, bool)> = HashMap::new();
    for len in 0..5usize {
        for bits in 0..(1u32 << (4 * len.min(3))) {
            let p: Vec<u8> = (0..len).map(|i| ((bits >> (4 * i)) & 0xf) as u8).collect();
            for is_leaf in [false, true] {
                let enc = path::hex_prefix_encode(&p, is_leaf);
                if let Some(prev) = seen.insert(enc.clone(), (p.clone(), is_leaf)) {
                    panic!(
                        "collision on {}: {prev:?} and {:?}",
                        hex::encode(&enc),
                        (p.clone(), is_leaf)
                    );
                }
            }
        }
    }
}

// ---------- decoder rejections ----------

#[test]
fn rejects_empty_input() {
    // There is always at least a flag nibble.
    assert_eq!(path::hex_prefix_decode(&[]), Err(Error::EmptyHexPrefix));
}

#[test]
fn rejects_flag_above_three() {
    for first in 4u8..16 {
        let enc = [first << 4, 0x23];
        assert_eq!(
            path::hex_prefix_decode(&enc),
            Err(Error::InvalidHexPrefixFlag),
            "first nibble {first:#x} should be rejected"
        );
    }
}

#[test]
fn rejects_nonzero_pad_nibble() {
    // Canonicality: an even-parity declaration must pad with 0x0. Accepting
    // anything else means two byte strings decode to the same path, which is
    // the same malleability class as non-minimal RLP length prefixes.
    for pad in 1u8..16 {
        for flag in [0u8, 2] {
            let enc = [(flag << 4) | pad, 0x23];
            assert_eq!(
                path::hex_prefix_decode(&enc),
                Err(Error::NonZeroHexPrefixPad),
                "flag={flag} pad={pad:#x} should be rejected"
            );
        }
    }
}

#[test]
fn even_declaration_needs_a_pad_nibble_at_all() {
    // 0x00 is the shortest legal even encoding (flag + pad, empty path).
    // A bare flag nibble cannot exist since input is whole bytes, but check
    // the boundary explicitly.
    assert_eq!(path::hex_prefix_decode(&[0x00]), Ok((vec![], EXT)));
    assert_eq!(path::hex_prefix_decode(&[0x20]), Ok((vec![], LEAF)));
}

// ---------- round trip ----------

proptest! {
    #[test]
    fn round_trip(
        path in prop::collection::vec(0u8..16, 0..40),
        is_leaf in any::<bool>(),
    ) {
        let enc = path::hex_prefix_encode(&path, is_leaf);
        prop_assert_eq!(path::hex_prefix_decode(&enc), Ok((path, is_leaf)));
    }

    #[test]
    fn encoded_length_follows_parity(
        path in prop::collection::vec(0u8..16, 0..40),
        is_leaf in any::<bool>(),
    ) {
        // One flag nibble, plus a pad nibble iff even, packed two per byte.
        let expected = (path.len() + if path.len() % 2 == 0 { 2 } else { 1 }) / 2;
        prop_assert_eq!(path::hex_prefix_encode(&path, is_leaf).len(), expected);
    }

    #[test]
    fn accepted_input_re_encodes_identically(bytes in prop::collection::vec(any::<u8>(), 0..24)) {
        // Canonicality in the other direction: anything the decoder accepts
        // must be exactly what the encoder would have produced. This is the
        // check that catches a missing pad-nibble validation.
        if let Ok((p, is_leaf)) = path::hex_prefix_decode(&bytes) {
            prop_assert_eq!(path::hex_prefix_encode(&p, is_leaf), bytes);
        }
    }

    #[test]
    fn leaf_flag_survives_round_trip(path in prop::collection::vec(0u8..16, 0..20)) {
        let l = path::hex_prefix_decode(&path::hex_prefix_encode(&path, LEAF)).unwrap();
        let e = path::hex_prefix_decode(&path::hex_prefix_encode(&path, EXT)).unwrap();
        prop_assert_eq!(l.1, LEAF);
        prop_assert_eq!(e.1, EXT);
        prop_assert_eq!(l.0, e.0);
    }
}
