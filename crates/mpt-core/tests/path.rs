use mpt_core::path::{self, Error};

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
