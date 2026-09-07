//! wasm-bindgen bindings around `mpt-core`, for `www/index.html`.
//!
//! Keys and values are typed as UTF-8 text (matching the fixtures used
//! throughout mpt-core's own tests, e.g. `b"dog"` -> `b"puppy"`) rather than
//! hex, since this is meant to be typed into a form field. Every method that
//! hands a tree back to JS returns it as a JSON `NodeView` (see below), not
//! the `Node` itself — wasm-bindgen can't cross the boundary with an enum
//! that owns recursive `Box`es, and JSON keeps the JS side a plain object
//! tree instead of needing bindgen-generated accessor methods per field.

use std::collections::BTreeMap;

use mpt_core::{
    Keccak256,
    error::TrieError,
    hasher::keccak,
    partial::WitnessProvider,
    trie::{Node, Trie, build_partial, count_stubs, decode_node, node_rlp, node_root},
};
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Decode a short RLP-encoded byte string back to raw bytes — the inverse of
/// `rlp_trimmed_string_hex`. What `WasmProofTrie::get` returns for a storage
/// slot is the raw trie leaf value, which for a real Ethereum storage trie is
/// itself RLP-encoded; this is how the JS side turns that back into the
/// plain hex a user would recognize (matching what `eth_getProof` reports).
#[wasm_bindgen]
pub fn rlp_decode_string_hex(rlp_hex: &str) -> Result<String, JsValue> {
    let bytes = parse_hex(rlp_hex)?;
    let r = rlp::Rlp::new(&bytes);
    let data = r
        .data()
        .map_err(|e| JsValue::from_str(&format!("not an RLP string: {e}")))?;
    Ok(hex::encode(data))
}

/// RLP-encode a byte string, trimming leading zero bytes first — the
/// encoding both a storage-trie leaf value and an RLP integer field use.
/// `0x00` trims to the empty string, which RLP encodes as `0x80` (Ethereum's
/// "zero" convention: there is no all-zero-byte encoding of zero).
#[wasm_bindgen]
pub fn rlp_trimmed_string_hex(value_hex: &str) -> Result<String, JsValue> {
    let mut bytes = parse_hex(value_hex)?;
    while bytes.first() == Some(&0) {
        bytes.remove(0);
    }
    let mut s = rlp::RlpStream::new();
    s.append(&bytes.as_slice());
    Ok(hex::encode(s.out()))
}

/// RLP-encode an account leaf: `[nonce, balance, storageRoot, codeHash]`.
/// `storageRoot`/`codeHash` are fixed 32-byte strings; `nonce`/`balance` are
/// RLP integers (leading zeros trimmed, zero -> empty string).
#[wasm_bindgen]
pub fn rlp_account_hex(
    nonce_hex: &str,
    balance_hex: &str,
    storage_root_hex: &str,
    code_hash_hex: &str,
) -> Result<String, JsValue> {
    fn trimmed(hex_in: &str) -> Result<Vec<u8>, JsValue> {
        let mut bytes = parse_hex(hex_in)?;
        while bytes.first() == Some(&0) {
            bytes.remove(0);
        }
        Ok(bytes)
    }
    let nonce = trimmed(nonce_hex)?;
    let balance = trimmed(balance_hex)?;
    let storage_root = parse_hex(storage_root_hex)?;
    let code_hash = parse_hex(code_hash_hex)?;
    let mut s = rlp::RlpStream::new_list(4);
    s.append(&nonce.as_slice());
    s.append(&balance.as_slice());
    s.append(&storage_root.as_slice());
    s.append(&code_hash.as_slice());
    Ok(hex::encode(s.out()))
}

/// keccak256, exposed so the JS side never needs its own hash implementation
/// (or a third-party library) just to compute a secure-trie key —
/// `keccak256(address)` / `keccak256(slot)` — before calling `get`/`insert`/
/// `remove` on a `WasmProofTrie`.
#[wasm_bindgen]
pub fn keccak256_hex(hex_in: &str) -> Result<String, JsValue> {
    let bytes = parse_hex(hex_in)?;
    Ok(hex::encode(keccak(&bytes)))
}

/// Decode hex, tolerating an odd digit count by left-padding a zero nibble —
/// Ethereum JSON-RPC "quantity" encoding drops leading zeros and never pads
/// to a whole byte (`nonce: "0x1"`, not `"0x01"`), unlike "data" fields
/// (hashes, addresses), which are always whole bytes already.
///
/// A `JsValue`-free core: real `JsValue` construction (not just mentioning
/// the type) calls into a wasm-only FFI import that aborts the process on a
/// native target, so this is what the test module below calls instead of
/// `parse_hex` — a bad-hex test case would otherwise abort the whole test
/// binary rather than failing one test.
fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let padded;
    let s = if s.len() % 2 == 1 {
        padded = format!("0{s}");
        &padded
    } else {
        s
    };
    hex::decode(s).map_err(|e| format!("bad hex {s:?}: {e}"))
}

fn parse_hex(s: &str) -> Result<Vec<u8>, JsValue> {
    parse_hex_bytes(s).map_err(|e| JsValue::from_str(&e))
}

fn parse_hash32(s: &str) -> Result<[u8; 32], JsValue> {
    let bytes = parse_hex(s)?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| JsValue::from_str(&format!("expected 32 bytes, got {}", v.len())))
}

type WitnessEntries = Vec<([u8; 32], Vec<u8>)>;

/// Decode a JSON array of hex RLP-node strings into `(hash, bytes)` pairs,
/// skipping the empty-trie sentinel `0x80` some clients include verbatim.
fn parse_witness_nodes(nodes_hex_json: &str) -> Result<WitnessEntries, JsValue> {
    let nodes: Vec<String> =
        serde_json::from_str(nodes_hex_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    nodes
        .iter()
        .map(|h| parse_hex(h))
        .filter(|b| b.as_deref() != Ok([0x80].as_slice()))
        .map(|b| b.map(|bytes| (keccak(&bytes), bytes)))
        .collect()
}

/// `TrieError` as a small JSON object rather than Rust `Debug` output — the
/// UI needs the hash/path as hex to show "this is the exact node a public
/// RPC's `eth_getProof` cannot supply" (PLAN.md §1, PTRIE.md §8.1).
fn describe_error(e: &TrieError<Keccak256>) -> JsValue {
    let json = match e {
        TrieError::MissingNode { hash, path } => serde_json::json!({
            "kind": "MissingNode",
            "hash": hex::encode(hash),
            "path": nibbles_to_hex(path),
        }),
        TrieError::HashMismatch { expected, got } => serde_json::json!({
            "kind": "HashMismatch",
            "expected": hex::encode(expected),
            "got": hex::encode(got),
        }),
        TrieError::MalformedNode => serde_json::json!({ "kind": "MalformedNode" }),
    };
    JsValue::from_str(&json.to_string())
}

/// One nibble per hex digit — not byte-aligned, so this is *not*
/// `hex::encode`: a 3-nibble path prints as 3 hex characters, not 4.
fn nibbles_to_hex(path: &[u8]) -> String {
    path.iter().map(|n| char::from_digit(*n as u32, 16).unwrap()).collect()
}

#[derive(Serialize)]
struct ChildView {
    nibble: u8,
    node: NodeView,
}

/// A `Node<Keccak256>`, flattened for JSON. Every variant carries `hash` (its
/// `node_root`) and `size`/`inlined` (from `node_rlp`) so the UI can show
/// exactly what a proof would carry: nodes with `size >= 32` get their own
/// proof entry, smaller ones ride along inlined inside their parent.
#[derive(Serialize)]
struct NodeView {
    kind: &'static str,
    hash: String,
    size: usize,
    inlined: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    child: Option<Box<NodeView>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    children: Option<Vec<ChildView>>,
}

fn to_view(node: &Node<Keccak256>) -> NodeView {
    let hash = hex::encode(node_root(node));
    let rlp_len = node_rlp(node).len();
    let inlined = rlp_len < 32 && !matches!(node, Node::Stub(_));
    let base = NodeView {
        kind: "Null",
        hash,
        size: rlp_len,
        inlined,
        path: None,
        value: None,
        child: None,
        children: None,
    };
    match node {
        Node::Null => base,
        Node::Leaf { path, value } => NodeView {
            kind: "Leaf",
            path: Some(nibbles_to_hex(path)),
            value: Some(hex::encode(value)),
            ..base
        },
        Node::Skip { path, child } => NodeView {
            kind: "Skip",
            path: Some(nibbles_to_hex(path)),
            child: Some(Box::new(to_view(child))),
            ..base
        },
        Node::Fork { children, value } => NodeView {
            kind: "Fork",
            value: value.as_ref().map(hex::encode),
            children: Some(
                children
                    .iter()
                    .enumerate()
                    .filter_map(|(i, c)| {
                        c.as_deref().map(|c| ChildView {
                            nibble: i as u8,
                            node: to_view(c),
                        })
                    })
                    .collect(),
            ),
            ..base
        },
        Node::Stub(_) => NodeView { kind: "Stub", ..base },
    }
}

/// Walk `node` and replace every `Stub` whose hash is in `witness` with the
/// decoded node it stands for, recursing into what that decode exposes.
/// A `Stub` neither present in `witness` nor reachable is left alone — this
/// only ever adds resolution, never removes or rebuilds anything, which is
/// what makes it safe to call after `insert`/`remove` have already mutated
/// parts of the tree.
fn resolve_stubs(node: &mut Node<Keccak256>, witness: &BTreeMap<[u8; 32], Vec<u8>>) {
    if let Node::Stub(h) = node {
        match witness.get(h) {
            Some(bytes) => *node = decode_node::<Keccak256>(&BTreeMap::new(), bytes),
            None => return,
        }
    }
    match node {
        Node::Skip { child, .. } => resolve_stubs(child, witness),
        Node::Fork { children, .. } => {
            for c in children.iter_mut().flatten() {
                resolve_stubs(c, witness);
            }
        }
        Node::Leaf { .. } | Node::Null | Node::Stub(_) => {}
    }
}

/// A plain, always-full trie built directly from hex key/value pairs — no
/// witness, no `Stub`s. Backs `www/build.html`'s "build a trie from scratch"
/// page: the JS side hashes each key with `keccak256_hex` and RLP-encodes
/// each value with `rlp_trimmed_string_hex` before calling `insert`, the same
/// transforms a real Ethereum secure trie applies, so a hand-built trie here
/// has the same shape a real account/storage trie would.
#[wasm_bindgen]
pub struct WasmTrie {
    inner: Trie<Keccak256>,
}

#[wasm_bindgen]
impl WasmTrie {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmTrie {
        console_error_panic_hook::set_once();
        WasmTrie { inner: Trie::new() }
    }

    /// Insert `key_hex` -> `value_hex` (both hex). This trie is never
    /// partial, so a `Stub` can never be hit — the `Result` here only ever
    /// carries a malformed-hex error from `parse_hex`.
    pub fn insert(&mut self, key_hex: &str, value_hex: &str) -> Result<(), JsValue> {
        let key = parse_hex(key_hex)?;
        let value = parse_hex(value_hex)?;
        self.inner
            .insert(&key, value)
            .map_err(|e| JsValue::from_str(&format!("{e:?}")))
    }

    /// Returns whether `key_hex` was present. `Ok(false)` is a normal result,
    /// not an error — removing an absent key is a no-op.
    pub fn remove(&mut self, key_hex: &str) -> Result<bool, JsValue> {
        let key = parse_hex(key_hex)?;
        self.inner
            .remove(&key)
            .map_err(|e| JsValue::from_str(&format!("{e:?}")))
    }

    /// The value at `key_hex`, hex-encoded, or `undefined` if absent.
    pub fn get(&mut self, key_hex: &str) -> Result<Option<String>, JsValue> {
        let key = parse_hex(key_hex)?;
        Ok(self.inner.get(&key).ok().flatten().map(hex::encode))
    }

    pub fn hash(&mut self) -> String {
        hex::encode(self.inner.hash())
    }

    /// The whole trie, as JSON (see `NodeView`).
    pub fn to_json(&self) -> String {
        serde_json::to_string(&to_view(self.inner.root())).unwrap_or_default()
    }
}

impl Default for WasmTrie {
    fn default() -> Self {
        Self::new()
    }
}

/// A trie reconstructed from a REAL witness — an `eth_getProof` response's
/// `accountProof`, or the union of its `storageProof[i].proof` arrays — with
/// raw hex keys/values rather than `WasmTrie`'s UTF-8 text ones, since real
/// account/slot keys are 20/32-byte hashes, not readable strings.
///
/// Every mutation resolves `Stub`s from the witness this trie was built
/// with (plus anything added via `add_witness`), NEVER by reaching out to a
/// network itself — fetching more proof data is the JS side's job. Hitting a
/// `Stub` this witness doesn't cover returns `Err` describing exactly which
/// node (hash + path) is missing: PTRIE.md §8.1's constraint made visible,
/// not hidden.
#[wasm_bindgen]
pub struct WasmProofTrie {
    inner: Trie<Keccak256>,
    witness: BTreeMap<[u8; 32], Vec<u8>>,
}

#[wasm_bindgen]
impl WasmProofTrie {
    /// `nodes_hex_json` is a JSON array of hex RLP-node strings — an
    /// `accountProof`, or a single account's `storageProof[i].proof`
    /// (concatenate several to cover several slots at once).
    pub fn from_witness(root_hex: &str, nodes_hex_json: &str) -> Result<WasmProofTrie, JsValue> {
        console_error_panic_hook::set_once();
        let root = parse_hash32(root_hex)?;
        let witness: BTreeMap<[u8; 32], Vec<u8>> = parse_witness_nodes(nodes_hex_json)?.into_iter().collect();
        let inner = Trie::from_node(build_partial::<Keccak256>(&witness, &root));
        Ok(WasmProofTrie { inner, witness })
    }

    /// Merge more RLP proof nodes into this trie's witness — e.g. after
    /// fetching another slot's proof — and resolve whatever `Stub`s that
    /// newly covers, IN PLACE on the current tree. "In place" is the whole
    /// point: this walks the tree exactly as it stands now, so any patch
    /// already applied via `insert`/`remove` survives; it is NOT rebuilt from
    /// the original root via `build_partial`, which would throw those away.
    pub fn add_witness(&mut self, nodes_hex_json: &str) -> Result<(), JsValue> {
        self.witness.extend(parse_witness_nodes(nodes_hex_json)?);
        let mut root = self.inner.root().clone();
        resolve_stubs(&mut root, &self.witness);
        self.inner = Trie::from_node(root);
        Ok(())
    }

    fn provider(&self) -> WitnessProvider<Keccak256> {
        WitnessProvider(self.witness.clone())
    }

    /// Insert `key` -> `value` (both hex). On `Err`, the JS side gets a JSON
    /// string (see `describe_error`), not a Rust `Debug` dump.
    pub fn insert(&mut self, key_hex: &str, value_hex: &str) -> Result<(), JsValue> {
        let key = parse_hex(key_hex)?;
        let value = parse_hex(value_hex)?;
        let provider = self.provider();
        self.inner
            .insert_with(&provider, &key, value)
            .map_err(|e| describe_error(&e))
    }

    /// `SSTORE(slot, 0)` — Ethereum deletes a zeroed slot rather than storing
    /// it, so this is what applying a "set to zero" diff means (PLAN.md §1).
    pub fn remove(&mut self, key_hex: &str) -> Result<bool, JsValue> {
        let key = parse_hex(key_hex)?;
        let provider = self.provider();
        self.inner
            .remove_with(&provider, &key)
            .map_err(|e| describe_error(&e))
    }

    pub fn get(&mut self, key_hex: &str) -> Result<Option<String>, JsValue> {
        let key = parse_hex(key_hex)?;
        let provider = self.provider();
        self.inner
            .get_with(&provider, &key)
            .map(|v| v.map(hex::encode))
            .map_err(|e| describe_error(&e))
    }

    pub fn hash(&mut self) -> String {
        hex::encode(self.inner.hash())
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&to_view(self.inner.root())).unwrap_or_default()
    }

    pub fn count_stubs(&self) -> usize {
        count_stubs(self.inner.root())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_bytes_strips_prefix_and_pads_odd_length() {
        assert_eq!(parse_hex_bytes("0x1234").unwrap(), vec![0x12, 0x34]);
        assert_eq!(parse_hex_bytes("1234").unwrap(), vec![0x12, 0x34]);
        // Ethereum JSON-RPC "quantity" encoding: odd digit count, left-padded
        // with a zero nibble rather than rejected.
        assert_eq!(parse_hex_bytes("0x1").unwrap(), vec![0x01]);
        assert_eq!(parse_hex_bytes("1").unwrap(), vec![0x01]);
        assert_eq!(parse_hex_bytes("").unwrap(), Vec::<u8>::new());
        assert!(parse_hex_bytes("0xzz").is_err());
    }

    #[test]
    fn rlp_trimmed_string_hex_trims_leading_zeros() {
        // All-zero trims to the empty string, which RLP encodes as 0x80 --
        // Ethereum's "zero" convention, not an all-zero byte string.
        assert_eq!(rlp_trimmed_string_hex("0x00").unwrap(), "80");
        assert_eq!(rlp_trimmed_string_hex("").unwrap(), "80");
        // Leading zero bytes trimmed, remaining single byte < 0x80 encodes
        // as itself with no RLP length prefix.
        assert_eq!(rlp_trimmed_string_hex("0x0000002a").unwrap(), "2a");
        // A remaining byte >= 0x80 needs the length-prefixed form, since RLP
        // reserves single-byte encodings for values < 0x80.
        assert_eq!(rlp_trimmed_string_hex("0x00ff").unwrap(), "81ff");
    }

    #[test]
    fn rlp_account_hex_encodes_a_four_item_list() {
        let storage_root = format!("0x{}", "11".repeat(32));
        let code_hash = format!("0x{}", "22".repeat(32));
        let encoded = rlp_account_hex("0x07", "0x2a", &storage_root, &code_hash).unwrap();

        let bytes = hex::decode(&encoded).unwrap();
        let r = rlp::Rlp::new(&bytes);
        assert_eq!(r.item_count().unwrap(), 4);
        assert_eq!(r.at(0).unwrap().data().unwrap(), &[0x07][..]);
        assert_eq!(r.at(1).unwrap().data().unwrap(), &[0x2a][..]);
        assert_eq!(r.at(2).unwrap().data().unwrap(), hex::decode("11".repeat(32)).unwrap());
        assert_eq!(r.at(3).unwrap().data().unwrap(), hex::decode("22".repeat(32)).unwrap());
    }

    #[test]
    fn rlp_account_hex_trims_zero_nonce_and_balance_to_empty() {
        let zero32 = format!("0x{}", "00".repeat(32));
        let encoded = rlp_account_hex("0x00", "0x00", &zero32, &zero32).unwrap();

        let bytes = hex::decode(&encoded).unwrap();
        let r = rlp::Rlp::new(&bytes);
        assert_eq!(r.at(0).unwrap().data().unwrap(), &[] as &[u8]);
        assert_eq!(r.at(1).unwrap().data().unwrap(), &[] as &[u8]);
    }

    #[test]
    fn resolve_stubs_replaces_only_stubs_present_in_witness() {
        let leaf = Node::<Keccak256>::Leaf {
            path: vec![1, 2, 3],
            value: vec![0xab, 0xcd],
        };
        let leaf_hash = node_root(&leaf);
        let unknown_hash = [0xffu8; 32];

        let mut witness = BTreeMap::new();
        witness.insert(leaf_hash, node_rlp(&leaf));

        let mut tree = Node::empty_fork();
        if let Node::Fork { children, .. } = &mut tree {
            children[0] = Some(Box::new(Node::Stub(leaf_hash)));
            children[1] = Some(Box::new(Node::Stub(unknown_hash)));
        }

        resolve_stubs(&mut tree, &witness);

        let Node::Fork { children, .. } = &tree else {
            panic!("root should still be a Fork, got {tree:?}");
        };
        // In the witness: resolved to the actual decoded node.
        assert_eq!(children[0].as_deref(), Some(&leaf));
        // Not in the witness: left alone, not an error.
        assert_eq!(children[1].as_deref(), Some(&Node::Stub(unknown_hash)));
    }
}
