//! HTTP twins of `mpt-reth`'s providers: resolve a partial trie's `Stub`s
//! through the `silt_multiproof` endpoint (silt PLAN D8) instead of a
//! local reth database. Same mechanism as PTRIE.md §8 — path-directed
//! multiproofs over **pre-hashed** keys — but the keys travel over
//! JSON-RPC, so the resolver needs the node's RPC URL, not its datadir.
//!
//! Soundness is unchanged (PTRIE.md §4.4): every node a response carries
//! is cached keyed by its keccak, and the caller looks up by expected
//! hash — the endpoint is never trusted.
//!
//! [`multiproof`] is the raw batched call (many targets, one request —
//! the §8.5 bootstrap pattern, over the wire); [`StorageProvider`] and
//! [`AccountProvider`] wrap it one probe at a time behind `mpt-core`'s
//! `NodeProvider`.

use std::cell::RefCell;
use std::collections::BTreeMap;

use mpt_core::{Keccak256, hasher::keccak, partial::NodeProvider};

/// Pack a nibble prefix into a 32-byte probe key, zero-padded on the
/// right (mirror of `mpt-reth`'s `key_with_prefix`). Any key with this
/// prefix walks through the node at that path, so the multiproof for it
/// necessarily contains that node (PTRIE.md §8.1).
pub fn key_with_prefix(prefix: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, n) in prefix.iter().enumerate() {
        if i / 2 >= 32 {
            break;
        }
        if i % 2 == 0 {
            out[i / 2] |= n << 4;
        } else {
            out[i / 2] |= n & 0x0f;
        }
    }
    out
}

/// Storage-trie slice of a [`Multiproof`]: the account's storage root at
/// the pinned block, plus every RLP node of the returned walks keyed by
/// keccak — the later lookup by *expected* hash is the verification.
#[derive(Debug)]
pub struct StorageNodes {
    pub root: [u8; 32],
    pub nodes: BTreeMap<[u8; 32], Vec<u8>>,
}

/// Parsed result of one `silt_multiproof` call.
#[derive(Debug)]
pub struct Multiproof {
    /// Account (state) trie walk, keccak -> RLP node.
    pub account_nodes: BTreeMap<[u8; 32], Vec<u8>>,
    /// Per **hashed** address: its storage root and storage trie walk.
    pub storages: BTreeMap<[u8; 32], StorageNodes>,
}

/// One `silt_multiproof` call. `targets` pairs a **hashed** address with
/// **hashed** storage keys (empty list = account trie only); `block`
/// pins the state by block hash (`None` = latest). `None` on any
/// transport/shape problem — a miss, never an error (the caller falls
/// back or fails the resolve, same as `mpt-reth`'s `.ok()?` discipline).
pub fn multiproof(
    url: &str,
    targets: &[([u8; 32], Vec<[u8; 32]>)],
    block: Option<&[u8; 32]>,
) -> Option<Multiproof> {
    let targets_json = {
        let mut parts = Vec::with_capacity(targets.len());
        for (addr, keys) in targets {
            let keys = keys
                .iter()
                .map(|k| format!("\"{}\"", hex32(k)))
                .collect::<Vec<_>>()
                .join(",");
            parts.push(format!("[\"{}\",[{keys}]]", hex32(addr)));
        }
        format!("[{}]", parts.join(","))
    };

    let block = block.map_or_else(|| "null".to_string(), |b| format!("\"{}\"", hex32(b)));
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"silt_multiproof","params":[{targets_json},{block}]}}"#
    );
    let text = ureq::post(url)
        .set("content-type", "application/json")
        .send_string(&body)
        .ok()?
        .into_string()
        .ok()?;
    let mut parsed: serde_json::Value = serde_json::from_str(&text).ok()?;
    let result = parsed.get_mut("result")?.take();
    parse(&result)
}

fn parse(result: &serde_json::Value) -> Option<Multiproof> {
    let mut account_nodes = BTreeMap::new();
    absorb(&mut account_nodes, result.get("accountSubtree")?);

    let mut storages = BTreeMap::new();
    for (addr_hex, entry) in result.get("storages")?.as_object()? {
        let addr = parse32(addr_hex)?;
        let root = parse32(entry.get("root")?.as_str()?)?;
        let mut nodes = BTreeMap::new();
        absorb(&mut nodes, entry.get("subtree")?);
        storages.insert(addr, StorageNodes { root, nodes });
    }
    Some(Multiproof {
        account_nodes,
        storages,
    })
}

/// Absorb every RLP node of a path->hex `subtree` map, keyed by keccak.
fn absorb(nodes: &mut BTreeMap<[u8; 32], Vec<u8>>, subtree: &serde_json::Value) {
    let Some(map) = subtree.as_object() else {
        return;
    };
    for rlp_hex in map.values() {
        let Some(s) = rlp_hex.as_str() else { continue };
        let Ok(bytes) = hex::decode(s.trim_start_matches("0x")) else {
            continue;
        };
        nodes.insert(keccak(&bytes), bytes);
    }
}

fn parse32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s.trim_start_matches("0x")).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

fn hex32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Resolves `Stub`s in one account's **storage** trie via
/// `silt_multiproof` (counterpart of `mpt-reth`'s `RethProvider`).
pub struct StorageProvider {
    url: String,
    hashed_address: [u8; 32],
    /// Block hash pinning the state; `None` = latest (fine on a quiet
    /// chain, racy on a live one — pin when you can).
    block: Option<[u8; 32]>,
    cache: RefCell<BTreeMap<[u8; 32], Vec<u8>>>,
}

impl StorageProvider {
    pub fn new(url: impl Into<String>, address: &[u8; 20], block: Option<[u8; 32]>) -> Self {
        Self::with_hashed_address(url, keccak(address), block)
    }

    /// For callers that already hold the hashed (trie) key.
    pub fn with_hashed_address(
        url: impl Into<String>,
        hashed_address: [u8; 32],
        block: Option<[u8; 32]>,
    ) -> Self {
        Self {
            url: url.into(),
            hashed_address,
            block,
            cache: RefCell::new(BTreeMap::new()),
        }
    }
}

impl NodeProvider<Keccak256> for StorageProvider {
    fn get(&self, path_nibbles: &[u8], hash: &[u8; 32]) -> Option<Vec<u8>> {
        if let Some(bytes) = self.cache.borrow().get(hash) {
            return Some(bytes.clone());
        }

        let probe = key_with_prefix(path_nibbles);
        let mp = multiproof(
            &self.url,
            &[(self.hashed_address, vec![probe])],
            self.block.as_ref(),
        )?;
        let walk = mp.storages.get(&self.hashed_address)?;

        let mut cache = self.cache.borrow_mut();
        cache.extend(walk.nodes.iter().map(|(k, v)| (*k, v.clone())));
        cache.get(hash).cloned()
    }
}

/// Resolves `Stub`s in the top-level **account** (state) trie via
/// `silt_multiproof` (counterpart of `mpt-reth`'s `AccountTrieProvider`).
pub struct AccountProvider {
    url: String,
    block: Option<[u8; 32]>,
    cache: RefCell<BTreeMap<[u8; 32], Vec<u8>>>,
}

impl AccountProvider {
    pub fn new(url: impl Into<String>, block: Option<[u8; 32]>) -> Self {
        Self {
            url: url.into(),
            block,
            cache: RefCell::new(BTreeMap::new()),
        }
    }
}

impl NodeProvider<Keccak256> for AccountProvider {
    fn get(&self, path_nibbles: &[u8], hash: &[u8; 32]) -> Option<Vec<u8>> {
        if let Some(bytes) = self.cache.borrow().get(hash) {
            return Some(bytes.clone());
        }

        let probe = key_with_prefix(path_nibbles);
        let mp = multiproof(&self.url, &[(probe, Vec::new())], self.block.as_ref())?;

        let mut cache = self.cache.borrow_mut();
        cache.extend(mp.account_nodes);
        cache.get(hash).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_with_prefix_packs_high_nibble_first() {
        assert_eq!(key_with_prefix(&[]), [0u8; 32]);
        let k = key_with_prefix(&[0xa]);
        assert_eq!(k[0], 0xa0);
        let k = key_with_prefix(&[0x1, 0x2, 0x3]);
        assert_eq!(&k[..2], &[0x12, 0x30]);
        assert_eq!(&k[2..], &[0u8; 30]);
    }

    #[test]
    fn parse_keys_nodes_by_keccak() {
        let zero = format!("0x{}", "0".repeat(64));
        let result = serde_json::json!({
            "accountSubtree": { "": "0x80", "0": "0xc0" },
            "storages": { &zero: { "root": &zero, "subtree": { "": "0x80" } } },
        });
        let mp = parse(&result).unwrap();
        assert_eq!(mp.account_nodes.get(&keccak(&[0x80])).unwrap(), &vec![0x80]);
        assert_eq!(mp.account_nodes.get(&keccak(&[0xc0])).unwrap(), &vec![0xc0]);
        assert_eq!(mp.account_nodes.len(), 2);
        let walk = mp.storages.get(&[0u8; 32]).unwrap();
        assert_eq!(walk.root, [0u8; 32]);
        assert_eq!(walk.nodes.get(&keccak(&[0x80])).unwrap(), &vec![0x80]);
    }
}
