use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    OddNibbleLength,
    InvalidNibble,
}

/// Expand bytes to nibbles, high nibble first.
pub fn to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(b >> 4);
        out.push(b & 0x0f);
    }
    out
}

/// Pack nibbles back into bytes. Rejects odd length and values above 0x0f.
pub fn from_nibbles(nibbles: &[u8]) -> Result<Vec<u8>, Error> {
    if nibbles.len() % 2 != 0 {
        return Err(Error::OddNibbleLength);
    }
    if nibbles.iter().any(|&n| n > 0x0f) {
        return Err(Error::InvalidNibble);
    }
    Ok(nibbles
        .chunks_exact(2)
        .map(|p| (p[0] << 4) | p[1])
        .collect())
}

pub fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}
