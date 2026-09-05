use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::hasher::Hasher;

/// Inclusion proof for a single leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof<H: Hasher> {
    /// Sibling hashes, leaf level first.
    pub siblings: Vec<H::Out>,
    // DECISION: does the verifier take the index as a separate argument, or
    // does each step carry its own direction bit? Pick one, delete the other,
    // and record in NOTES.md what a malicious prover gains from the loser.
}

/// Fixed-arity binary Merkle tree over an ordered list of leaves.
#[derive(Debug, Clone)]
pub struct MerkleTree<H: Hasher> {
    // TODO: your storage. A flat level-by-level Vec<H::Out> is the obvious
    // choice; if you pick something else, justify it in NOTES.md.
    _marker: PhantomData<H>,
}

impl<H: Hasher> MerkleTree<H> {
    pub fn new(leaves: &[Vec<u8>]) -> Self {
        todo!()
    }

    pub fn root(&self) -> H::Out {
        todo!()
    }

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn prove(&self, index: usize) -> Option<Proof<H>> {
        todo!()
    }
}

/// Hash of a leaf's contents. Domain-separated from [`hash_internal`].
pub fn hash_leaf<H: Hasher>(data: &[u8]) -> H::Out {
    todo!()
}

/// Hash of two child references. Domain-separated from [`hash_leaf`].
pub fn hash_internal<H: Hasher>(left: &H::Out, right: &H::Out) -> H::Out {
    todo!()
}

/// Root of the empty tree. DECISION: document your choice in NOTES.md.
pub fn empty_root<H: Hasher>() -> H::Out {
    todo!()
}

/// Stateless verification. Must not allocate.
pub fn verify<H: Hasher>(root: &H::Out, leaf: &[u8], index: usize, proof: &Proof<H>) -> bool {
    todo!()
}
