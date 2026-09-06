use alloc::vec::Vec;
use alloc::{boxed::Box, collections::BTreeMap};
use rlp::RlpStream;
use thiserror::Error;

use crate::hasher::keccak;
use crate::path::{hex_prefix_decode, hex_prefix_encode};
use crate::{
    Hasher,
    path::{common_prefix_len, to_nibbles},
};

/// Radix-16 trie with path compression. No hashing at this stage — children are
/// owned pointers, not hash references. Stage 5 replaces Box<Node> with a
/// reference type and adds Merkleization.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Node<H: Hasher> {
    /// Yellow paper: the empty node. RLP-encoded as the empty string.
    #[default]
    Null,
    /// Yellow paper: leaf node. `rlp([hp(path, true), value])`.
    /// `path` is the remaining key suffix at this point.
    Leaf {
        path: Vec<u8>,
        value: Vec<u8>,
    },
    /// Yellow paper: **extension** node. `rlp([hp(path, false), child_ref])`.
    /// INVARIANT: `path` is never empty, and `child` is always a `Fork`.
    Skip {
        path: Vec<u8>,
        child: Box<Node<H>>,
    },
    /// Yellow paper: branch node. 17-item RLP list.
    /// `value` is set when a key terminates exactly here.
    Fork {
        children: [Option<Box<Node<H>>>; 16],
        value: Option<Vec<u8>>,
    },
    Stub(H::Out),
}

impl<H: Hasher + core::fmt::Debug> Node<H> {
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
            Node::Leaf { .. } | Node::Stub(_) => {}
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
    root: Node<H>,
    db: BTreeMap<H::Out, Vec<u8>>, // hash -> rlp(node), for nodes >= 32 bytes
}

impl<H: Hasher> Trie<H> {
    pub fn new() -> Self {
        Self {
            root: Node::Null,
            db: Default::default(),
        }
    }

    pub fn from_node(root: Node<H>) -> Self {
        Self {
            root,
            db: Default::default(),
        }
    }

    pub fn root(&self) -> &Node<H> {
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

    pub fn prove(&mut self, key: &[u8]) -> Vec<Vec<u8>> {
        if matches!(self.root, Node::Null) {
            return Vec::new();
        }
        let mut ret = Vec::new();
        collect::<H>(&self.root, &to_nibbles(key), &mut ret, &mut self.db, true);
        ret
    }
}

fn collect<H: Hasher>(
    node: &Node<H>,
    suffix: &[u8],
    out: &mut Vec<Vec<u8>>,
    db: &mut BTreeMap<H::Out, Vec<u8>>,
    is_root: bool,
) {
    let enc = encode_node::<H>(node, db);
    if is_root || enc.len() >= 32 {
        out.push(enc);
    }
    match node {
        Node::Null | Node::Leaf { .. } | Node::Stub(_) => {}
        Node::Skip { path, child } => {
            if suffix.starts_with(path) {
                collect::<H>(child, &suffix[path.len()..], out, db, false);
            }
        }
        Node::Fork { children, .. } => {
            if let Some((&n, rest)) = suffix.split_first()
                && let Some(c) = &children[n as usize]
            {
                collect::<H>(c, rest, out, db, false);
            }
        }
    }
}

/// Resolve a child reference. Returns the referenced node's bytes, advancing
/// `cursor` only when the reference is a 32-byte hash — an inlined child is
/// already covered by its parent's hash and consumes no proof node.
fn resolve(
    item: rlp::Rlp<'_>,
    proof: &[Vec<u8>],
    cursor: &mut usize,
) -> Result<Vec<u8>, ProofError> {
    if !item.is_data() {
        return Ok(item.as_raw().to_vec());
    }
    let d = item.data().map_err(|_| ProofError::MalformedNode)?;
    if d.len() != 32 {
        return Err(ProofError::BadNodeRef);
    }
    let n = proof.get(*cursor).ok_or(ProofError::Truncated)?;
    *cursor += 1;
    let have = keccak(n);
    if have.as_slice() != d {
        let mut want = [0u8; 32];
        want.copy_from_slice(d);
        return Err(ProofError::HashMismatch { want, have });
    }
    Ok(n.clone())
}

fn rlp_bytes(r: &rlp::Rlp<'_>, i: usize) -> Result<Vec<u8>, ProofError> {
    r.at(i)
        .and_then(|x| x.data().map(<[u8]>::to_vec))
        .map_err(|_| ProofError::MalformedNode)
}

pub fn verify(
    root: &[u8; 32],
    key: &[u8],
    proof: &[Vec<u8>],
) -> Result<Option<Vec<u8>>, ProofError> {
    if proof.is_empty() {
        return if *root == keccak(&[0x80]) {
            Ok(None)
        } else {
            Err(ProofError::Truncated)
        };
    }

    let nibbles = to_nibbles(key);
    let mut suffix = &nibbles[..];
    let mut cursor = 0usize;

    let first = proof.get(cursor).ok_or(ProofError::Truncated)?;
    cursor += 1;
    let have = keccak(first);
    if have != *root {
        return Err(ProofError::HashMismatch { want: *root, have });
    }
    let mut current = first.clone();

    let result = loop {
        let r = rlp::Rlp::new(&current);
        let count = r.item_count().map_err(|_| ProofError::MalformedNode)?;

        if count == 17 {
            // Fork.
            let Some((&n, rest)) = suffix.split_first() else {
                // Key consumed: the answer is the value slot.
                let v = rlp_bytes(&r, 16)?;
                break if v.is_empty() { None } else { Some(v) };
            };
            suffix = rest;

            let item = r.at(n as usize).map_err(|_| ProofError::MalformedNode)?;
            // Empty slot proves absence.
            if item.is_data()
                && item
                    .data()
                    .map_err(|_| ProofError::MalformedNode)?
                    .is_empty()
            {
                break None;
            }
            current = resolve(item, proof, &mut cursor)?;
        } else if count == 2 {
            // Leaf or Skip, distinguished by the hex-prefix flag.
            let encoded_path = rlp_bytes(&r, 0)?;
            let (path, is_leaf) =
                hex_prefix_decode(&encoded_path).map_err(|_| ProofError::MalformedNode)?;

            if is_leaf {
                break if suffix == &path[..] {
                    Some(rlp_bytes(&r, 1)?)
                } else {
                    // Diverging leaf path proves absence.
                    None
                };
            }

            if !suffix.starts_with(&path) {
                // Diverging skip path proves absence.
                break None;
            }
            suffix = &suffix[path.len()..];

            let item = r.at(1).map_err(|_| ProofError::MalformedNode)?;
            current = resolve(item, proof, &mut cursor)?;
        } else {
            return Err(ProofError::MalformedNode);
        }
    };

    // Canonicality: the proof must contain exactly the nodes the walk needed.
    if cursor != proof.len() {
        return Err(ProofError::TrailingNodes(proof.len() - cursor));
    }
    Ok(result)
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    /// A node's keccak256 didn't match the reference its parent held (or the
    /// root, at step 0). This is the core soundness check.
    HashMismatch { want: [u8; 32], have: [u8; 32] },
    /// The walk needed another node and the proof ran out.
    Truncated,
    /// Nodes left over after the walk terminated. Same canonicality reasoning
    /// as `cursor == siblings.len()` in stage 1: a proof must be a canonical
    /// object or anything that hashes or caches it inherits a malleability bug.
    TrailingNodes(usize),
    /// RLP that isn't a valid node: wrong item count, non-canonical encoding,
    /// bad hex-prefix.
    MalformedNode,
    /// A child reference that is neither a 32-byte hash nor valid inline RLP.
    BadNodeRef,
}

impl core::fmt::Display for ProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
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
fn encode_node<H: Hasher>(node: &Node<H>, db: &mut BTreeMap<H::Out, Vec<u8>>) -> Vec<u8> {
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
                    None => {
                        s.append_empty_data();
                    }
                }
            }
            match value {
                Some(v) => {
                    s.append(&v.as_slice());
                }
                None => {
                    s.append_empty_data();
                }
            }
            s.out().to_vec()
        }
        Node::Stub(hash) => hash.as_ref().to_vec(),
    }
}

fn append_ref<H: Hasher>(s: &mut RlpStream, node: &Node<H>, db: &mut BTreeMap<H::Out, Vec<u8>>) {
    if let Node::Stub(h) = node {
        s.append(&h.as_ref());
        return;
    }
    let enc = encode_node::<H>(node, db);
    if enc.len() < 32 {
        s.append_raw(&enc, 1); // already RLP, splice verbatim
    } else {
        let h = H::hash_one(&enc);
        db.insert(h, enc);
        s.append(&h.as_ref()); // 32-byte string, gets the 0xa0 prefix
    }
}

fn insert_at<H: Hasher>(node: Node<H>, suffix_nibbles: &[u8], value: Vec<u8>) -> Node<H> {
    match node {
        Node::Null => Node::Leaf {
            path: suffix_nibbles.to_vec(),
            value,
        },
        Node::Leaf { path, value: old } => {
            if path == suffix_nibbles {
                return Node::Leaf { path, value };
            }

            let common = common_prefix_len(&path, suffix_nibbles);
            let new_rest = &suffix_nibbles[common..];
            let old_rest = &path[common..];

            let mut children: [Option<Box<Node<H>>>; 16] = core::array::from_fn(|_| None);
            let mut slot = None;

            if let Some((&n, rest)) = new_rest.split_first() {
                children[n as usize] = Some(Box::new(Node::Leaf {
                    path: rest.to_vec(),
                    value,
                }));
            } else {
                slot = Some(value);
            }

            if let Some((&n, rest)) = old_rest.split_first() {
                children[n as usize] = Some(Box::new(Node::Leaf {
                    path: rest.to_vec(),
                    value: old,
                }));
            } else {
                slot = Some(old);
            }

            skip_or(
                path[..common].to_vec(),
                Node::Fork {
                    children,
                    value: slot,
                },
            )
        }
        Node::Skip { path, child } if suffix_nibbles.starts_with(&path) => {
            let child = insert_at(*child, &suffix_nibbles[path.len()..], value);
            Node::Skip {
                path,
                child: Box::new(child),
            }
        }
        Node::Skip { path, child } => {
            let common = common_prefix_len(&path, suffix_nibbles);
            let new_rest = &suffix_nibbles[common..];
            let old_rest = &path[common..];

            let mut children: [Option<Box<Node<H>>>; 16] = core::array::from_fn(|_| None);
            let mut slot = None;

            // !suffix_nibbles.starts_with(&path), hence common < path.len(), hence old_rest is non-empty
            children[old_rest[0] as usize] =
                Some(Box::new(skip_or(old_rest[1..].to_vec(), *child)));

            if let Some((&n, rest)) = new_rest.split_first() {
                children[n as usize] = Some(Box::new(Node::Leaf {
                    path: rest.to_vec(),
                    value,
                }));
            } else {
                slot = Some(value);
            }

            skip_or(
                path[..common].to_vec(),
                Node::Fork {
                    children,
                    value: slot,
                },
            )
        }
        Node::Fork {
            mut children,
            value: current,
        } => {
            if suffix_nibbles.is_empty() {
                return Node::Fork {
                    children,
                    value: Some(value),
                };
            }
            let index = suffix_nibbles[0] as usize;
            let child = if let Some(child) = children[index].take() {
                insert_at(*child, &suffix_nibbles[1..], value)
            } else {
                Node::Leaf {
                    path: suffix_nibbles[1..].to_vec(),
                    value,
                }
            };
            children[index] = Some(Box::new(child));
            Node::Fork {
                children,
                value: current,
            }
        }
        Node::Stub(h) => {
            panic!("insert reached Stub({})", hex::encode(h))
        }
    }
}

fn skip_or<H: Hasher>(path: Vec<u8>, child: Node<H>) -> Node<H> {
    if path.is_empty() {
        child
    } else {
        Node::Skip {
            path,
            child: Box::new(child),
        }
    }
}

fn get_at<'a, H: Hasher>(node: &'a Node<H>, suffix_nibbles: &[u8]) -> Option<&'a [u8]> {
    match node {
        Node::Leaf { path, value } if path == suffix_nibbles => Some(value.as_slice()),
        Node::Skip { path, child } if suffix_nibbles.starts_with(path) => {
            get_at(child, &suffix_nibbles[path.len()..])
        }
        Node::Fork { value, .. } if suffix_nibbles.is_empty() => value.as_deref(),
        Node::Fork { children, .. } => children[suffix_nibbles[0] as usize]
            .as_ref()
            .and_then(|c| get_at(c, &suffix_nibbles[1..])),
        _ => None,
    }
}

fn remove_at<H: Hasher>(node: Node<H>, suffix_nibbles: &[u8]) -> (Node<H>, bool) {
    match node {
        Node::Leaf { ref path, .. } if path == suffix_nibbles => (Node::Null, true),
        Node::Skip { path, child } if suffix_nibbles.starts_with(&path) => {
            let (child, removed) = remove_at(*child, &suffix_nibbles[path.len()..]);
            if !removed {
                return (
                    Node::Skip {
                        path,
                        child: Box::new(child),
                    },
                    false,
                );
            }
            (
                normalize(Node::Skip {
                    path,
                    child: Box::new(child),
                }),
                true,
            )
        }
        Node::Fork { children, value } if suffix_nibbles.is_empty() => {
            let removed = value.is_some();
            if !removed {
                return (Node::Fork { children, value }, false);
            }
            (
                normalize(Node::Fork {
                    children,
                    value: None,
                }),
                true,
            )
        }
        Node::Fork {
            mut children,
            value,
        } => {
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
        Node::Stub(h) => {
            panic!("remove reached Stub({})", hex::encode(h))
        }
        node => (node, false),
    }
}

/// Restore canonical shape after a child changed. Only meaningful on a node
/// whose subtree was just modified.
fn normalize<H: Hasher>(node: Node<H>) -> Node<H> {
    match node {
        Node::Fork {
            mut children,
            value,
        } => {
            let occupied: Vec<usize> = (0..16).filter(|&i| children[i].is_some()).collect();
            match (occupied.len(), &value) {
                // Only the value slot survives: a leaf with an empty path.
                (0, Some(_)) => Node::Leaf {
                    path: Vec::new(),
                    value: value.unwrap(),
                },
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
            Node::Skip {
                path: cp,
                child: gc,
            } => {
                let mut p = path;
                p.extend_from_slice(&cp);
                Node::Skip { path: p, child: gc }
            }
            Node::Null => Node::Null,
            c => Node::Skip {
                path,
                child: Box::new(c),
            },
        },
        Node::Stub(h) => {
            panic!("normalize reached Stub({})", hex::encode(h))
        }
        node => node,
    }
}

/// Push nibble `n` onto the front of `node`'s path, wrapping in a Skip when
/// the node has no path of its own.
fn prepend<H: Hasher>(n: u8, node: Node<H>) -> Node<H> {
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
        f @ Node::Fork { .. } => Node::Skip {
            path: [n].to_vec(),
            child: Box::new(f),
        },
        Node::Null => Node::Null,
        Node::Stub(h) => {
            panic!("prepend reached Stub({})", hex::encode(h))
        }
    }
}

/// Decode one node's RLP into a `Node`.
///
/// Child references resolve against `nodes` when present and become `Stub`
/// when not. Inlined children (a nested RLP list rather than a 32-byte string)
/// are decoded in place and are never stubs — they came along inside their
/// parent's bytes for free.
pub fn decode_node<H: Hasher>(nodes: &BTreeMap<H::Out, Vec<u8>>, bytes: &[u8]) -> Node<H> {
    let r = rlp::Rlp::new(bytes);
    let count = r.item_count().expect("node must be an RLP list");

    if count == 17 {
        let mut children: [Option<Box<Node<H>>>; 16] = core::array::from_fn(|_| None);
        #[allow(clippy::needless_range_loop)]
        for i in 0..16 {
            let item = r.at(i).unwrap();
            if item.is_data() {
                let d = item.data().unwrap();
                if d.is_empty() {
                    continue; // genuinely absent child
                }
                if d.len() != H::LENGTH {
                    panic!(
                        "child reference is {} bytes, expected {}",
                        d.len(),
                        H::LENGTH
                    );
                }
                let mut h = H::Out::default();
                h.as_mut().copy_from_slice(d);
                children[i] = Some(Box::new(build_partial(nodes, &h)));
            } else {
                children[i] = Some(Box::new(decode_node(nodes, item.as_raw())));
            }
        }
        let v = r.at(16).unwrap().data().unwrap().to_vec();
        Node::Fork {
            children,
            value: if v.is_empty() { None } else { Some(v) },
        }
    } else if count == 2 {
        let encoded_path = r.at(0).unwrap().data().unwrap().to_vec();
        let (path, is_leaf) = hex_prefix_decode(&encoded_path).expect("bad hex-prefix");
        if is_leaf {
            Node::Leaf {
                path,
                value: r.at(1).unwrap().data().unwrap().to_vec(),
            }
        } else {
            let item = r.at(1).unwrap();
            let child = if item.is_data() {
                let d = item.data().unwrap();
                if d.len() != H::LENGTH {
                    panic!(
                        "child reference is {} bytes, expected {}",
                        d.len(),
                        H::LENGTH
                    );
                }
                let mut h = H::Out::default();
                h.as_mut().copy_from_slice(d);
                build_partial(nodes, &h)
            } else {
                decode_node(nodes, item.as_raw())
            };
            Node::Skip {
                path,
                child: Box::new(child),
            }
        }
    } else {
        panic!("node has {count} items, expected 2 or 17")
    }
}

/// Rebuild a partial trie rooted at `root` from a hash-indexed node set.
/// A root we don't have becomes a bare `Stub`.
pub fn build_partial<H: Hasher>(nodes: &BTreeMap<H::Out, Vec<u8>>, root: &H::Out) -> Node<H> {
    // The empty trie is fully determined by its root: rlp(Null) is 0x80, whose
    // keccak IS the empty-trie constant. A witness never carries it, and a Stub
    // here would be unresolvable — there is no node to fetch.
    if *root == H::hash_all(&[&[0x80]]) {
        return Node::Null;
    }
    match nodes.get(root) {
        Some(bytes) => decode_node(nodes, bytes),
        None => Node::Stub(*root),
    }
}

/// keccak256(rlp(node)) — the root hash of a trie rooted at this node.
pub fn node_root<H: Hasher>(node: &Node<H>) -> H::Out {
    // A Stub already IS its own root hash: there is no RLP to encode, only the
    // reference its parent held.
    if let Node::Stub(h) = node {
        return *h;
    }
    let mut db = BTreeMap::new();
    H::hash_all(&[&encode_node::<H>(node, &mut db)])
}

/// How much of the trie we don't have. Diagnostics only.
pub fn count_stubs<H: Hasher>(node: &Node<H>) -> usize {
    match node {
        Node::Stub(_) => 1,
        Node::Skip { child, .. } => count_stubs(child),
        Node::Fork { children, .. } => children.iter().flatten().map(|c| count_stubs(c)).sum(),
        Node::Null | Node::Leaf { .. } => 0,
    }
}
