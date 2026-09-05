use alloc::{boxed::Box, collections::BTreeMap};
use alloc::vec::Vec;
use rlp::RlpStream;

use crate::path::hex_prefix_encode;
use crate::{Hasher, path::{common_prefix_len, to_nibbles}};

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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trie<H: Hasher> {
    root: Node,
    db: BTreeMap<H::Out, Vec<u8>>, // hash -> rlp(node), for nodes >= 32 bytes
}

impl<H: Hasher> Trie<H> {
    pub fn new() -> Self {
        Self { root: Node::Null, db: Default::default() }
    }

    pub fn root(&self) -> &Node {
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

    pub fn remove(&mut self, key: &[u8]) -> bool {
        let suffix = to_nibbles(key);
        let root = core::mem::replace(&mut self.root, Node::Null);
        let (root, removed) = remove_at(root, &suffix);
        self.root = root;
        removed
    }

    pub fn hash(&mut self) -> H::Out {
        H::hash_one(&encode_node::<H>(&self.root, &mut self.db))
    }
}

/*
Returns the node's RLP. Four arms:

Null → vec![0x80]
Leaf { path, value } → rlp([hp(path, true), value])
Skip { path, child } → rlp([hp(path, false), node_ref(child)])
Fork { children, value } → 17-item list: each child slot is node_ref(child) 
    or the empty string "" when None, then the value or "" when None

The important detail: a child slot holds either a 32-byte hash
string or the child's RLP inlined as a nested structure.
In RLP terms, a hash ref is Item::Bytes(&hash) which encodes with the 0xa0 prefix, 
while an inlined child is the child's already-encoded bytes spliced in raw.
If your RLP API only takes Item, you may need a "pre-encoded raw" escape hatch.
Decide how to express that before you write this function;
it's the one place your stage 2 API design gets tested.
*/
fn encode_node<H: Hasher>(node: &Node, db: &mut BTreeMap<H::Out, Vec<u8>>) -> Vec<u8> {
    match node {
        Node::Null => {
            let mut s = RlpStream::new();
            s.append_empty_data();
            s.out().to_vec()
        }
        Node::Leaf { path, value } => {
            let mut s = RlpStream::new_list(2);
            s.append(&hex_prefix_encode(path, true));
            s.append(&value.as_slice());
            s.out().to_vec()
        }
        Node::Skip { path, child } => {
            let mut s = RlpStream::new_list(2);
            s.append(&hex_prefix_encode(path, false));
            append_ref::<H>(&mut s, child, db);
            s.out().to_vec()
        }
        Node::Fork { children, value } => {
            let mut s = RlpStream::new_list(17);
            for c in children {
                match c {
                    Some(c) => append_ref::<H>(&mut s, c, db),
                    None => { s.append_empty_data(); }
                }
            }
            match value {
                Some(v) => { s.append(&v.as_slice()); }
                None => { s.append_empty_data(); }
            }
            s.out().to_vec()
        }
    }
}

fn append_ref<H: Hasher>(s: &mut RlpStream, node: &Node, db: &mut BTreeMap<H::Out, Vec<u8>>) {
    let enc = encode_node::<H>(node, db);
    if enc.len() < 32 {
        s.append_raw(&enc, 1);          // already RLP, splice verbatim
    } else {
        let h = H::hash_one(&enc);
        db.insert(h, enc);
        s.append(&h.as_ref());          // 32-byte string, gets the 0xa0 prefix
    }
}

fn insert_at(node: Node, suffix_nibbles: &[u8], value: Vec<u8>) -> Node {
    match node {
        Node::Null => Node::Leaf { path: suffix_nibbles.to_vec(), value },
        Node::Leaf { path, value: old } => {
            if &path == suffix_nibbles {
                return Node::Leaf { path, value };
            }

            let common = common_prefix_len(&path, suffix_nibbles);
            let new_rest = &suffix_nibbles[common..];
            let old_rest = &path[common..];

            let mut children: [Option<Box<Node>>; 16] = core::array::from_fn(|_| None);
            let mut slot = None;

            if let Some((&n, rest)) = new_rest.split_first() {
                children[n as usize] = Some(Box::new(Node::Leaf { path: rest.to_vec(), value }));
            } else {
                slot = Some(value);
            }

            if let Some((&n, rest)) = old_rest.split_first() {
                children[n as usize] = Some(Box::new(Node::Leaf { path: rest.to_vec(), value: old }));
            } else {
                slot = Some(old);
            }

            skip_or(path[..common].to_vec(), Node::Fork { children, value: slot })
        }
        Node::Skip { path, child } if suffix_nibbles.starts_with(&path) => {
            let child = insert_at(*child, &suffix_nibbles[path.len()..], value);
            Node::Skip { path, child: Box::new(child) }
        }
        Node::Skip { path, child } => {
            let common = common_prefix_len(&path, suffix_nibbles);
            let new_rest = &suffix_nibbles[common..];
            let old_rest = &path[common..];

            let mut children: [Option<Box<Node>>; 16] = core::array::from_fn(|_| None);
            let mut slot = None;

            // !suffix_nibbles.starts_with(&path), hence common < path.len(), hence old_rest is non-empty
            children[old_rest[0] as usize] = Some(Box::new(skip_or(old_rest[1..].to_vec(), *child)));

            if let Some((&n, rest)) = new_rest.split_first() {
                children[n as usize] = Some(Box::new(Node::Leaf { path: rest.to_vec(), value }));
            } else {
                slot = Some(value);
            }

            skip_or(path[..common].to_vec(), Node::Fork { children, value: slot })
        }
        Node::Fork { mut children, value: current } => {
            if suffix_nibbles.is_empty() {
                return Node::Fork { children, value: Some(value) };
            }
            let index = suffix_nibbles[0] as usize;
            let child = if let Some(child) = children[index].take() {
                insert_at(*child, &suffix_nibbles[1..], value)
            } else {
                Node::Leaf { path: suffix_nibbles[1..].to_vec(), value }
            };
            children[index] = Some(Box::new(child));
            Node::Fork {
                children,
                value: current,
            }
        }
    }
}

fn skip_or(path: Vec<u8>, child: Node) -> Node {
    if path.is_empty() { child } else { Node::Skip { path, child: Box::new(child) } }
}

fn get_at<'a>(node: &'a Node, suffix_nibbles: &[u8]) -> Option<&'a [u8]> {
    match node {
        Node::Leaf { path, value } if path == suffix_nibbles => 
            Some(value.as_slice()),
        Node::Skip { path, child } if suffix_nibbles.starts_with(path) => 
            get_at(child, &suffix_nibbles[path.len()..]),
        Node::Fork { value, .. } if suffix_nibbles.is_empty() =>
            value.as_deref(),
        Node::Fork { children, .. } =>
            children[suffix_nibbles[0] as usize].as_ref()
                .and_then(|c| get_at(c, &suffix_nibbles[1..])),
        _ => None
    }
}

fn remove_at(node: Node, suffix_nibbles: &[u8]) -> (Node, bool) {
    match node {
        Node::Leaf { ref path, .. } if path == suffix_nibbles => 
            (Node::Null, true),
        Node::Skip { path, child } if suffix_nibbles.starts_with(&path) => {
            let (child, removed) = remove_at(*child, &suffix_nibbles[path.len()..]);
            if !removed {
                return (Node::Skip { path, child: Box::new(child) }, false);
            }
            (normalize(Node::Skip { path, child: Box::new(child) }), true)
        }
        Node::Fork { children, value } if suffix_nibbles.is_empty() => {
            let removed = value.is_some();
            if !removed {
                return (Node::Fork { children, value }, false);
            }
            (normalize(Node::Fork { children, value: None }), true)
        }
        Node::Fork { mut children, value } => {
            let i = suffix_nibbles[0] as usize;
            let Some(child) = children[i].take() else {
                return (Node::Fork { children, value }, false);
            };
            let (child, removed) = remove_at(*child, &suffix_nibbles[1..]);
            children[i] = match child {
                Node::Null => None,
                c => Some(Box::new(c)),
            };
            if !removed {
                return (Node::Fork { children, value }, false);
            }
            (normalize(Node::Fork { children, value }), true)
        }
        other => (other, false),
    }
}

/// Restore canonical shape after a child changed. Only meaningful on a node
/// whose subtree was just modified.
fn normalize(node: Node) -> Node {
    match node {
        Node::Fork { mut children, value } => {
            let occupied: Vec<usize> = (0..16).filter(|&i| children[i].is_some()).collect();
            match (occupied.len(), &value) {
                // Only the value slot survives: a leaf with an empty path.
                (0, Some(_)) => Node::Leaf { path: Vec::new(), value: value.unwrap() },
                (0, None) => Node::Null,
                // Exactly one child and no value: the fork disappears and its
                // nibble index becomes a path prefix on the child.
                (1, None) => {
                    let n = occupied[0];
                    prepend(n as u8, *children[n].take().unwrap())
                }
                _ => Node::Fork { children, value },
            }
        }
        Node::Skip { path, child } => match *child {
            // Skip over Leaf / Skip: merge paths. This is what keeps the
            // "Skip child is always a Fork" invariant true.
            Node::Leaf { path: cp, value } => {
                let mut p = path;
                p.extend_from_slice(&cp);
                Node::Leaf { path: p, value }
            }
            Node::Skip { path: cp, child: gc } => {
                let mut p = path;
                p.extend_from_slice(&cp);
                Node::Skip { path: p, child: gc }
            }
            Node::Null => Node::Null,
            c => Node::Skip { path, child: Box::new(c) },
        },
        other => other,
    }
}

/// Push nibble `n` onto the front of `node`'s path, wrapping in a Skip when
/// the node has no path of its own.
fn prepend(n: u8, node: Node) -> Node {
    match node {
        Node::Leaf { path, value } => {
            let mut p = [n].to_vec();
            p.extend_from_slice(&path);
            Node::Leaf { path: p, value }
        }
        Node::Skip { path, child } => {
            let mut p = [n].to_vec();
            p.extend_from_slice(&path);
            Node::Skip { path: p, child }
        }
        f @ Node::Fork { .. } => Node::Skip { path: [n].to_vec(), child: Box::new(f) },
        Node::Null => Node::Null,
    }
}
