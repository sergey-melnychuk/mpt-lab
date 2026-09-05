use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::path::{common_prefix_len, to_nibbles};

/// Radix-16 trie with path compression. No hashing at this stage — children are
/// owned pointers, not hash references. Stage 5 replaces Box<Node> with a
/// reference type and adds Merkleization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// Yellow paper: the empty node. RLP-encoded as the empty string.
    Null,
    /// Yellow paper: leaf node. `rlp([hp(path, true), value])`.
    /// `path` is the remaining key suffix at this point.
    Leaf { path: Vec<u8>, value: Vec<u8> },
    /// Yellow paper: **extension** node. `rlp([hp(path, false), child_ref])`.
    /// INVARIANT: `path` is never empty, and `child` is always a `Fork`.
    Skip { path: Vec<u8>, child: Box<Node> },
    /// Yellow paper: branch node. 17-item RLP list.
    /// `value` is set when a key terminates exactly here.
    Fork {
        children: [Option<Box<Node>>; 16],
        value: Option<Vec<u8>>,
    },
}

impl Default for Node {
    fn default() -> Self {
        Node::Null
    }
}

impl Node {
    pub fn empty_fork() -> Self {
        Node::Fork {
            children: core::array::from_fn(|_| None),
            value: None,
        }
    }

    /// Number of occupants: children present plus the value slot.
    pub fn fork_occupancy(&self) -> usize {
        match self {
            Node::Fork { children, value } => {
                children.iter().filter(|c| c.is_some()).count() + value.is_some() as usize
            }
            _ => 0,
        }
    }

    /// Assert the four structural invariants. Panics on violation.
    /// Call after every mutation in tests — every stage-6 deletion bug is one
    /// of these being violated.
    pub fn debug_check(&self) {
        self.check_inner(true)
    }

    fn check_inner(&self, is_root: bool) {
        match self {
            Node::Null => {
                assert!(is_root, "Null may only appear as the whole trie's root");
            }
            Node::Leaf { .. } => {}
            Node::Skip { path, child } => {
                assert!(!path.is_empty(), "Skip path must be non-empty");
                assert!(
                    matches!(**child, Node::Fork { .. }),
                    "Skip child must be a Fork, got {child:?}"
                );
                child.check_inner(false);
            }
            Node::Fork { children, .. } => {
                assert!(
                    self.fork_occupancy() >= 2,
                    "Fork must have >= 2 occupants, got {}",
                    self.fork_occupancy()
                );
                for c in children.iter().flatten() {
                    c.check_inner(false);
                }
            }
        }
    }
}

/// In-memory trie over byte keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trie {
    root: Node,
}

impl Trie {
    pub fn new() -> Self {
        Self { root: Node::Null }
    }

    pub fn root_node(&self) -> &Node {
        &self.root
    }

    pub fn insert(&mut self, key: &[u8], value: Vec<u8>) {
        let suffix = to_nibbles(key);
        let root = core::mem::replace(&mut self.root, Node::Null);
        self.root = insert_at(root, &suffix, value);
    }

    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        get_at(&self.root, &to_nibbles(key))
    }
}

/// Insert `value` at `suffix_nibbles` under `node`, returning the new node.
///
/// Five cases. Work them in this order:
///   Null  -> becomes Leaf { path: suffix, value }
///   Leaf  -> identical path: replace value.
///            else: split on common prefix into a Fork (wrapped in a Skip if
///            the common prefix is non-empty). A path exhausted at the split
///            point puts its value in the Fork's value slot, not a child.
///   Skip  -> full prefix match: recurse into child with shortened suffix.
///            partial match: split into shorter Skip + new Fork + remainders.
///            SUBTLETY: a remainder of exactly one nibble attaches its subtree
///            directly to the Fork with no wrapping Skip (Skip paths are never
///            empty, and a 1-nibble remainder is entirely consumed by the Fork
///            index).
///   Fork  -> empty suffix: set the value slot.
///            else: recurse into children[suffix[0]] with suffix[1..].
fn insert_at(node: Node, suffix_nibbles: &[u8], value: Vec<u8>) -> Node {
    let _ = (&node, suffix_nibbles, &value, common_prefix_len);
    todo!("stage 4")
}

fn get_at<'a>(node: &'a Node, suffix_nibbles: &[u8]) -> Option<&'a [u8]> {
    todo!("stage 4")
}
