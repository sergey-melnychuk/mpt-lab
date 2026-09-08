//! PLAN.md §2, step 0: measure before building anything.
//!
//! For each of several accounts, probe many storage slots, build the
//! inclusion witness for each, and report the occupancy of the deepest Fork
//! on that slot's path. Removing a key collapses its nearest Fork only when
//! that Fork's occupancy is exactly 2 — this is the number that decides
//! whether Phase B is core infrastructure or a rare edge case (PLAN.md §2).
//!
//! Slots are pseudo-random 32-byte values, not necessarily populated. That's
//! fine for this measurement: Fork occupancy near a point in key-space is a
//! property of the REAL trie's shape at that point, and keccak-derived
//! secure-trie keys are uniformly distributed regardless of whether the
//! specific probed key happens to hold a value — so a large random sample
//! gives an unbiased read on "if a random present key were removed, would its
//! nearest Fork collapse", without needing to know which slots are populated.
//!
//!     RETH_DATADIR=/path/to/reth/datadir cargo run -p mpt-reth --release --example sweep

use std::collections::BTreeMap;

use alloy_primitives::{Address, B256};
use reth_ethereum::{
    chainspec::ChainSpecBuilder,
    node::EthereumNode,
    provider::{StateProofProvider, providers::ReadOnlyConfig},
    storage::BlockNumReader,
};

use mpt_core::{
    Keccak256,
    hasher::keccak,
    trie::{Node, build_partial},
};

/// Well-known, long-lived, heavily-used contracts. Not a claim about their
/// storage *shape* diversity — just addresses confident enough to hardcode.
const ADDRESSES: &[(&str, &str)] = &[
    ("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
    ("WETH", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
];

const SLOTS_PER_ADDRESS: u32 = 150;

/// Cheap deterministic PRNG (splitmix64), so no `rand` dependency — same
/// rationale as `tests/hash.rs`'s shuffle.
fn next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

fn random_slot(state: &mut u64) -> B256 {
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        chunk.copy_from_slice(&next(state).to_be_bytes());
    }
    B256::from(out)
}

/// Deepest Fork on `key`'s path: its occupancy, and — when occupancy is
/// exactly 2 — whether the nibble the key does NOT take is already resolved
/// in this proof or is a `Stub`. Mirrors `collapse.rs::deepest_fork`.
fn deepest_fork_info(node: &Node<Keccak256>, key: &[u8]) -> Option<(usize, Option<bool>)> {
    fn walk(node: &Node<Keccak256>, suffix: &[u8], best: &mut Option<(usize, Option<bool>)>) {
        match node {
            Node::Fork { children, value } => {
                let occupied: Vec<(usize, bool)> = children
                    .iter()
                    .enumerate()
                    .filter_map(|(i, c)| c.as_deref().map(|c| (i, matches!(c, Node::Stub(_)))))
                    .collect();
                let occupancy = occupied.len() + value.is_some() as usize;
                let sibling_is_stub = if occupancy == 2 {
                    match suffix.split_first() {
                        Some((&n, _)) => occupied
                            .iter()
                            .find(|(i, _)| *i != n as usize)
                            .map(|(_, is_stub)| *is_stub),
                        // Key terminates here: the value slot is the other
                        // occupant, no sibling node at all.
                        None => None,
                    }
                } else {
                    None
                };
                *best = Some((occupancy, sibling_is_stub));

                if let Some((&n, rest)) = suffix.split_first()
                    && let Some(c) = &children[n as usize]
                {
                    walk(c, rest, best);
                }
            }
            Node::Skip { path: sp, child } if suffix.starts_with(sp) => {
                walk(child, &suffix[sp.len()..], best);
            }
            _ => {}
        }
    }
    let mut best = None;
    walk(node, key, &mut best);
    best
}

fn to_nibbles(b: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(b.len() * 2);
    for x in b {
        o.push(x >> 4);
        o.push(x & 0x0f);
    }
    o
}

fn main() -> eyre::Result<()> {
    let datadir = std::env::var("RETH_DATADIR").map_err(|_| eyre::eyre!("set RETH_DATADIR"))?;
    let spec = ChainSpecBuilder::mainnet().build();
    let runtime = reth_ethereum::tasks::Runtime::test();
    let factory = EthereumNode::provider_factory_builder().open_read_only(
        spec.into(),
        ReadOnlyConfig::from_datadir(datadir),
        runtime,
    )?;
    let headers = factory.provider()?;
    let number = headers.best_block_number()?;
    let state = factory.latest()?;
    println!("block {number}\n");

    let mut rng: u64 = 0x5EED;
    let mut histogram: BTreeMap<usize, u32> = BTreeMap::new();
    let mut sibling_stub = 0u32;
    let mut sibling_inlined = 0u32;
    let mut total = 0u32;
    let mut no_fork = 0u32;

    for (name, addr_hex) in ADDRESSES {
        let address: Address = addr_hex.parse()?;
        let mut per_addr: BTreeMap<usize, u32> = BTreeMap::new();

        for _ in 0..SLOTS_PER_ADDRESS {
            let slot = random_slot(&mut rng);
            let proof = state.proof(Default::default(), address, &[slot])?;
            let storage_root: [u8; 32] = proof.storage_root.0;
            let Some(sp) = proof.storage_proofs.first() else {
                continue; // account has no storage at all
            };

            let mut witness: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
            for b in &sp.proof {
                let n = b.to_vec();
                if n.as_slice() != [0x80] {
                    witness.insert(keccak(&n), n);
                }
            }
            if witness.is_empty() {
                continue; // empty storage trie
            }

            let partial: Node<Keccak256> = build_partial(&witness, &storage_root);
            let skey_nibbles = to_nibbles(&keccak(slot.as_slice()));

            let Some((occupancy, sibling_is_stub)) = deepest_fork_info(&partial, &skey_nibbles)
            else {
                no_fork += 1;
                continue;
            };

            total += 1;
            *histogram.entry(occupancy).or_default() += 1;
            *per_addr.entry(occupancy).or_default() += 1;

            match sibling_is_stub {
                Some(true) => {
                    sibling_stub += 1;
                    if sibling_stub <= 3 {
                        println!(
                            "  example collapsing slot: {name} {}",
                            hex::encode(slot.as_slice())
                        );
                    }
                }
                Some(false) => sibling_inlined += 1,
                None => {}
            }
        }

        println!("{name} ({addr_hex}): {per_addr:?}");
    }

    println!("\n=== overall (n={total}, no-fork-on-path={no_fork}) ===");
    println!("occupancy histogram: {histogram:?}");
    let collapsing = *histogram.get(&2).unwrap_or(&0);
    println!(
        "occupancy == 2 (removal would collapse this Fork): {collapsing}/{total} ({:.1}%)",
        100.0 * collapsing as f64 / total.max(1) as f64
    );
    println!(
        "  of those, sibling already in proof: {sibling_inlined}, sibling is a Stub (needs a provider): {sibling_stub}"
    );

    Ok(())
}
