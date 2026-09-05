/// Cryptographic hash used to build node references.
pub trait Hasher {
    type Out: AsRef<[u8]>
        + AsMut<[u8]>
        + Default
        + Copy
        + Eq
        + Ord
        + core::hash::Hash
        + core::fmt::Debug;

    const LENGTH: usize;

    fn hash_one(chunks: &[u8]) -> Self::Out;

    fn hash_all(chunks: &[&[u8]]) -> Self::Out;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keccak256;

impl Hasher for Keccak256 {
    type Out = [u8; 32];
    const LENGTH: usize = 32;

    fn hash_one(chunk: &[u8]) -> [u8; 32] {
        use sha3::Digest;
        sha3::Keccak256::digest(chunk).into()
    }

    fn hash_all(chunks: &[&[u8]]) -> [u8; 32] {
        use sha3::Digest;
        let mut h = sha3::Keccak256::new();
        for chunk in chunks {
            h.update(chunk);
        }
        h.finalize().into()
    }
}

pub fn keccak(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    sha3::Keccak256::digest(data).into()
}
