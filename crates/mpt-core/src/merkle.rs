use alloc::vec::Vec;

use crate::hasher::Hasher;

/// Inclusion proof for a single leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof<H: Hasher> {
    /// Sibling hashes, leaf level first.
    pub siblings: Vec<H::Out>,
}

/// Fixed-arity binary Merkle tree over an ordered list of leaves.
#[derive(Debug, Clone)]
pub struct MerkleTree<H: Hasher> {
    levels: Vec<Vec<H::Out>>,
}

impl<H: Hasher> MerkleTree<H> {
    pub fn new(leaves: &[Vec<u8>]) -> Self {
        let leaves = leaves
            .iter()
            .map(|leaf| hash_leaf::<H>(leaf))
            .collect::<Vec<_>>();
        let log2 = (usize::BITS - leaves.len().leading_zeros()) as usize;
        let mut levels = Vec::with_capacity(log2.max(1));
        levels.push(leaves);

        loop {
            let last = levels.last().cloned().unwrap_or_default();
            if last.len() <= 1 {
                break;
            }
            let rem = last.len() % 2;
            let len = last.len() / 2;
            let mut level = Vec::with_capacity(len + rem);
            for i in 0..len {
                let lhs = last[i * 2];
                let rhs = last[i * 2 + 1];
                level.push(hash_node::<H>(&lhs, &rhs));
            }
            if rem > 0 {
                level.push(last[last.len() - 1]);
            }
            levels.push(level);
        }
        Self { levels }
    }

    pub fn root(&self) -> H::Out {
        self.levels
            .last()
            .and_then(|level| level.last())
            .cloned()
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.levels
            .first()
            .map(|level| level.len())
            .unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn prove(&self, mut index: usize) -> Option<Proof<H>> {
        if index >= self.len() {
            return None;
        }
        let mut siblings = Vec::with_capacity(self.levels.len());
        for level in self.levels.iter() {
            if level.len() == 1 {
                break;
            }

            let is_last = index == level.len() - 1;
            let is_even = level.len().is_multiple_of(2);
            if is_last && !is_even {
                index /= 2;
                continue;
            }

            let sibling_index = if index.is_multiple_of(2) {
                index + 1
            } else {
                index - 1
            };
            siblings.push(level[sibling_index]);
            index /= 2;
        }
        Some(Proof { siblings })
    }
}

/// Hash of a leaf's contents. Domain-separated from [`hash_node`].
pub fn hash_leaf<H: Hasher>(data: &[u8]) -> H::Out {
    H::hash_all(&[b"L", data])
}

/// Hash of two child references. Domain-separated from [`hash_leaf`].
pub fn hash_node<H: Hasher>(lhs: &H::Out, rhs: &H::Out) -> H::Out {
    H::hash_all(&[b"N", lhs.as_ref(), rhs.as_ref()])
}

/// Root of the empty tree. DECISION: document your choice in NOTES.md.
pub fn empty_root<H: Hasher>() -> H::Out {
    H::Out::default()
}

/// Stateless verification. Must not allocate.
pub fn verify<H: Hasher>(
    root: &H::Out,
    leaf: &[u8],
    mut index: usize,
    mut size: usize,
    proof: &Proof<H>,
) -> bool {
    if index >= size {
        return false;
    }

    let mut acc = hash_leaf::<H>(leaf);
    let mut cursor = 0;
    while size > 1 {
        let is_last = index == size - 1;
        let is_even = size.is_multiple_of(2);
        if is_last && !is_even {
            size = size.div_ceil(2);
            index /= 2;
            continue;
        }

        let Some(sibling) = proof.siblings.get(cursor) else {
            return false;
        };
        if index.is_multiple_of(2) {
            acc = hash_node::<H>(&acc, sibling);
        } else {
            acc = hash_node::<H>(sibling, &acc);
        };

        cursor += 1;
        index /= 2;
        size = size.div_ceil(2);
    }

    &acc == root && cursor == proof.siblings.len()
}
