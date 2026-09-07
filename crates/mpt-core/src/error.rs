use alloc::vec::Vec;

use crate::Hasher;

/// Reasons a traversal over a partial trie can fail.
///
/// Hand-written `Debug`/`Clone`/`PartialEq`/`Eq` rather than `#[derive(..)]`:
/// deriving on a generic enum adds an `H: Debug + Clone + ...` bound even
/// though only `H::Out` is ever stored, and `Hasher::Out` already carries
/// those bounds itself (PLAN.md §3.1, PTRIE.md §4.2 — the same problem `Stub`
/// hit).
pub enum TrieError<H: Hasher> {
    /// Traversal reached a subtree we do not have.
    ///
    /// `path` is the nibble prefix at which the stub sits. Both fields are
    /// load-bearing: the path steers a fetch (PTRIE.md §8.1), the hash
    /// verifies the result.
    MissingNode { hash: H::Out, path: Vec<u8> },
    /// A store returned bytes that do not hash to the stub's reference.
    HashMismatch { expected: H::Out, got: H::Out },
    /// Bytes that are not a valid 2- or 17-item RLP node.
    MalformedNode,
}

impl<H: Hasher> core::fmt::Debug for TrieError<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TrieError::MissingNode { hash, path } => f
                .debug_struct("MissingNode")
                .field("hash", hash)
                .field("path", path)
                .finish(),
            TrieError::HashMismatch { expected, got } => f
                .debug_struct("HashMismatch")
                .field("expected", expected)
                .field("got", got)
                .finish(),
            TrieError::MalformedNode => f.write_str("MalformedNode"),
        }
    }
}

impl<H: Hasher> Clone for TrieError<H> {
    fn clone(&self) -> Self {
        match self {
            TrieError::MissingNode { hash, path } => TrieError::MissingNode {
                hash: *hash,
                path: path.clone(),
            },
            TrieError::HashMismatch { expected, got } => TrieError::HashMismatch {
                expected: *expected,
                got: *got,
            },
            TrieError::MalformedNode => TrieError::MalformedNode,
        }
    }
}

impl<H: Hasher> PartialEq for TrieError<H> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                TrieError::MissingNode { hash: h1, path: p1 },
                TrieError::MissingNode { hash: h2, path: p2 },
            ) => h1 == h2 && p1 == p2,
            (
                TrieError::HashMismatch {
                    expected: e1,
                    got: g1,
                },
                TrieError::HashMismatch {
                    expected: e2,
                    got: g2,
                },
            ) => e1 == e2 && g1 == g2,
            (TrieError::MalformedNode, TrieError::MalformedNode) => true,
            _ => false,
        }
    }
}

impl<H: Hasher> Eq for TrieError<H> {}

impl<H: Hasher> core::fmt::Display for TrieError<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<H: Hasher> core::error::Error for TrieError<H> {}
