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

    fn hash(data: &[u8]) -> Self::Out;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keccak256;

impl Hasher for Keccak256 {
    type Out = [u8; 32];
    const LENGTH: usize = 32;

    fn hash(data: &[u8]) -> [u8; 32] {
        use sha3::Digest;
        sha3::Keccak256::digest(data).into()
    }
}
