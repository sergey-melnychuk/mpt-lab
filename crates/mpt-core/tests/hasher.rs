use mpt_core::{Hasher, Keccak256};

#[test]
fn keccak256_empty_input() {
    const EMPTY: &str = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
    assert_eq!(hex::encode(Keccak256::hash_one(b"")), EMPTY);
    assert_eq!(hex::encode(Keccak256::hash_all(&[])), EMPTY);
    assert_eq!(hex::encode(Keccak256::hash_all(&[b"", b""])), EMPTY);
}

#[test]
fn chunking_is_transparent() {
    assert_eq!(
        Keccak256::hash_all(&[b"hello world"]),
        Keccak256::hash_all(&[b"hello", b" ", b"world"])
    );
}
#[test]
fn hasher_is_keccak_not_sha3() {
    // NIST SHA3-256("") — if this ever matches, you imported sha3::Sha3_256
    // instead of sha3::Keccak256 and every root you produce will be wrong.
    assert_ne!(
        hex::encode(Keccak256::hash_one(b"")),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
}
