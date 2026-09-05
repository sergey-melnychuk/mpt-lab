use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    OddNibbleLength,
    InvalidNibble,
    EmptyHexPrefix,
    InvalidHexPrefixFlag,
    NonZeroHexPrefixPad,
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
    if !nibbles.len().is_multiple_of(2) {
        return Err(Error::OddNibbleLength);
    }
    if nibbles.iter().any(|&n| n > 0x0f) {
        return Err(Error::InvalidNibble);
    }
    Ok(nibbles
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| (p[0] << 4) | p[1])
        .collect())
}

pub fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

/// Compact ("hex-prefix") encoding, yellow paper appendix C.
///
/// Prepends a flag nibble encoding leaf-vs-extension and path parity, then a
/// zero pad nibble when the path length is even, so the total nibble count is
/// always even and packs into whole bytes.
///
/// First nibble: 0 = ext/even, 1 = ext/odd, 2 = leaf/even, 3 = leaf/odd.
pub fn hex_prefix_encode(path_nibbles: &[u8], is_leaf: bool) -> Vec<u8> {
    let odd = path_nibbles.len() % 2 == 1;
    let flag = 2 * (is_leaf as u8) + (odd as u8);

    let mut nibbles = Vec::with_capacity(path_nibbles.len() + 2);
    nibbles.push(flag);
    if !odd {
        nibbles.push(0);
    }
    nibbles.extend_from_slice(path_nibbles);

    from_nibbles(&nibbles).expect("even length by construction; nibbles pre-validated")
}

pub fn hex_prefix_decode(encoded: &[u8]) -> Result<(Vec<u8>, bool), Error> {
    let nibbles = to_nibbles(encoded);
    let (&flag, rest) = nibbles.split_first().ok_or(Error::EmptyHexPrefix)?;
    if flag > 3 {
        return Err(Error::InvalidHexPrefixFlag);
    }
    let is_leaf = flag & 2 != 0;
    let odd = flag & 1 != 0;
    if odd {
        Ok((rest.to_vec(), is_leaf))
    } else {
        match rest.split_first() {
            Some((0, tail)) => Ok((tail.to_vec(), is_leaf)),
            _ => Err(Error::NonZeroHexPrefixPad),
        }
    }
}
