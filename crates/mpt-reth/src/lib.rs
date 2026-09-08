//! `RethProvider`: resolves a partial trie's `Stub`s by path-directed
//! `multiproof` fetches against a local reth database. See PTRIE.md §8 for
//! the mechanism and PLAN.md §6 for why this is only ten lines.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use alloy_primitives::{Address, B256, keccak256};
use reth_ethereum::provider::{StateProofProvider, StateProviderBox};
use reth_ethereum::trie::MultiProofTargets;

use mpt_core::{Keccak256, hasher::keccak, partial::NodeProvider};

/// Pack a nibble prefix into a 32-byte key, zero-padded on the right.
///
/// Any key with this prefix walks through the node at that path, so the
/// multiproof for it necessarily contains that node. `eth_getProof` cannot do
/// this — it hashes the raw slot for you — which is why `RethProvider` needs
/// the database rather than an RPC endpoint (PTRIE.md §8.1).
pub fn key_with_prefix(prefix: &[u8]) -> B256 {
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
    B256::from(out)
}

/// Resolves `Stub`s in one account's storage trie by path-directed
/// `multiproof` fetches against a local reth database.
///
/// A multiproof response is a complete walk to the probed path (PTRIE.md
/// §8.2: 8 nodes returned for 1 requested in the verified run), so every node
/// a response carries is cached, not just the one asked for — later stubs on
/// the same path usually cost nothing.
pub struct RethProvider {
    state: Rc<StateProviderBox>,
    hashed_address: B256,
    cache: RefCell<BTreeMap<[u8; 32], Vec<u8>>>,
}

impl RethProvider {
    /// Takes a shared `Rc<StateProviderBox>` (not an owned one) so a single,
    /// potentially expensive-to-reconstruct historical `StateProviderBox`
    /// (e.g. `factory.history_by_block_number()` far behind the chain tip)
    /// can be minted ONCE and reused across many `RethProvider` instances
    /// (one per touched account) instead of re-minting it per account.
    pub fn new(state: Rc<StateProviderBox>, address: Address) -> Self {
        Self {
            state,
            hashed_address: keccak256(address),
            cache: RefCell::new(BTreeMap::new()),
        }
    }
}

impl NodeProvider<Keccak256> for RethProvider {
    fn get(&self, path_nibbles: &[u8], hash: &[u8; 32]) -> Option<Vec<u8>> {
        if let Some(bytes) = self.cache.borrow().get(hash) {
            return Some(bytes.clone());
        }

        let probe = key_with_prefix(path_nibbles);
        let mp = self
            .state
            .multiproof(
                Default::default(),
                MultiProofTargets::account_with_slots(self.hashed_address, [probe]),
            )
            .ok()?;
        let sub = mp.storages.get(&self.hashed_address)?;

        let mut cache = self.cache.borrow_mut();
        for bytes in sub.subtree.values() {
            let n = bytes.to_vec();
            cache.insert(keccak(&n), n);
        }
        cache.get(hash).cloned()
    }
}

/// Resolves `Stub`s in the top-level *account* (state) trie by path-directed
/// `multiproof` fetches, mirroring `RethProvider` but reading
/// `MultiProof::account_subtree` instead of a per-account storage subtree.
///
/// Needed only as an on-demand fallback for a delete-collapse landing on an
/// off-path sibling the account's own inclusion proof didn't carry (the same
/// gap Phase B fixes for storage tries) — most accounts touched by a normal
/// block are fully resolved by their own `state.proof(..)` witness already.
pub struct AccountTrieProvider {
    state: Rc<StateProviderBox>,
    cache: RefCell<BTreeMap<[u8; 32], Vec<u8>>>,
}

impl AccountTrieProvider {
    pub fn new(state: Rc<StateProviderBox>) -> Self {
        Self {
            state,
            cache: RefCell::new(BTreeMap::new()),
        }
    }
}

impl NodeProvider<Keccak256> for AccountTrieProvider {
    fn get(&self, path_nibbles: &[u8], hash: &[u8; 32]) -> Option<Vec<u8>> {
        if let Some(bytes) = self.cache.borrow().get(hash) {
            return Some(bytes.clone());
        }

        let probe = key_with_prefix(path_nibbles);
        let mp = self
            .state
            .multiproof(Default::default(), MultiProofTargets::accounts([probe]))
            .ok()?;

        let mut cache = self.cache.borrow_mut();
        for bytes in mp.account_subtree.values() {
            let n = bytes.to_vec();
            cache.insert(keccak(&n), n);
        }
        cache.get(hash).cloned()
    }
}
