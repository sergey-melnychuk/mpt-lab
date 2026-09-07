//! Fetching the nodes a partial trie is missing.
//!
//! `Trie::insert`/`remove`/`get` walk a trie that may contain `Stub`s (PTRIE.md
//! §4.1). Reaching one without a way to resolve it is an error
//! ([`crate::error::TrieError::MissingNode`]); the `_with` methods take a
//! [`NodeProvider`] that can supply the missing bytes instead.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::Hasher;

/// Resolves a `Stub` to the node it stands for.
///
/// Implementations may key on EITHER argument: a witness map keys on `hash`,
/// reth keys on `path_nibbles` (PTRIE.md §8.1). The caller ALWAYS verifies the
/// returned bytes against `hash`, so a provider is never trusted — the same
/// discipline `verify` applies to every proof node.
pub trait NodeProvider<H: Hasher> {
    /// Return the RLP encoding of the node at `path_nibbles` whose hash is
    /// `hash`, or `None` if this store cannot supply it.
    fn get(&self, path_nibbles: &[u8], hash: &H::Out) -> Option<Vec<u8>>;
}

/// Resolves nothing. Backs the plain (non-`_with`) `Trie` methods: on a trie
/// that never actually contains a `Stub` on the touched path, this is never
/// asked to supply anything, so it behaves exactly as if there were no
/// provider at all.
pub struct NoProvider;

impl<H: Hasher> NodeProvider<H> for NoProvider {
    fn get(&self, _path_nibbles: &[u8], _hash: &H::Out) -> Option<Vec<u8>> {
        None
    }
}

/// Offline, from proofs. Ignores the path; fails on anything absent.
pub struct WitnessProvider<H: Hasher>(pub BTreeMap<H::Out, Vec<u8>>);

impl<H: Hasher> NodeProvider<H> for WitnessProvider<H> {
    fn get(&self, _path_nibbles: &[u8], hash: &H::Out) -> Option<Vec<u8>> {
        self.0.get(hash).cloned()
    }
}

/// A complete node map, so nothing ever misses. Isolates traversal bugs from
/// witness-construction bugs — use this as the test oracle.
pub struct MapProvider<H: Hasher>(pub BTreeMap<H::Out, Vec<u8>>);

impl<H: Hasher> NodeProvider<H> for MapProvider<H> {
    fn get(&self, _path_nibbles: &[u8], hash: &H::Out) -> Option<Vec<u8>> {
        self.0.get(hash).cloned()
    }
}

/// Instrumented wrapper recording every `(path, hash)` requested. This IS the
/// witness builder: run a workload against a complete store, collect what was
/// touched, and that is the minimal witness for that workload.
pub struct RecordingProvider<H: Hasher, P> {
    inner: P,
    seen: RefCell<Vec<(Vec<u8>, H::Out)>>,
}

impl<H: Hasher, P: NodeProvider<H>> RecordingProvider<H, P> {
    pub fn new(inner: P) -> Self {
        Self {
            inner,
            seen: RefCell::new(Vec::new()),
        }
    }

    /// Every `(path, hash)` this provider actually resolved, in request order.
    pub fn seen(&self) -> Vec<(Vec<u8>, H::Out)> {
        self.seen.borrow().clone()
    }
}

impl<H: Hasher, P: NodeProvider<H>> NodeProvider<H> for RecordingProvider<H, P> {
    fn get(&self, path_nibbles: &[u8], hash: &H::Out) -> Option<Vec<u8>> {
        let bytes = self.inner.get(path_nibbles, hash);
        if bytes.is_some() {
            self.seen.borrow_mut().push((path_nibbles.to_vec(), *hash));
        }
        bytes
    }
}
