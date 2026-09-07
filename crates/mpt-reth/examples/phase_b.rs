//! PLAN.md §6 acceptance: the general `RethProvider` mechanism, not the
//! one-off manual fetch `collapse.rs` walks through by hand.
//!
//! Finds a real storage slot whose removal collapses a Fork (one located by
//! `examples/sweep.rs`'s measurement — see PTRIE.md §10), removes it through
//! `Trie::remove_with(&RethProvider::new(..), ..)`, and asserts:
//!
//! 1. the SAME removal through the plain (no-provider) `remove` fails with
//!    `Err(MissingNode)` — the proof genuinely does not carry what's needed;
//! 2. `remove_with` succeeds and produces *some* new storageRoot;
//! 3. re-inserting the original value through the same provider restores the
//!    original storageRoot byte-for-byte — the canonicality check
//!    (NOTES.md §6.3): a trie holding the right data in the wrong shape
//!    answers `get` correctly and hashes wrong.
//!
//!     RETH_DATADIR=/path/to/reth/datadir cargo run -p mpt-reth --release --example phase_b

use std::collections::BTreeMap;

use alloy_primitives::{Address, B256};
use mpt_reth::RethProvider;
use reth_ethereum::{
    chainspec::ChainSpecBuilder,
    node::EthereumNode,
    provider::{StateProofProvider, providers::ReadOnlyConfig},
    storage::BlockNumReader,
};

use mpt_core::error::TrieError;
use mpt_core::{
    Keccak256,
    hasher::keccak,
    trie::{Node, Trie, build_partial, count_stubs, node_root},
};

// USDC's balanceOf mapping (slot 9) for a real long-time holder: a genuinely
// populated slot whose removal collapses a 2-occupant Fork with a stubbed
// sibling. `examples/sweep.rs` found 41/300 random probes collapse a Fork
// this way (PTRIE.md §10); this one is a real, non-zero balance rather than
// a probe into likely-empty storage, so it's an honest "SSTORE(slot, 0)".
const DEFAULT_ADDR: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const DEFAULT_SLOT: &str = "0xb47819dbb2d5e5b541bfa5fb020cad7be8f7e145ac60296fedb74a78826b7375";

fn rlp_bytes(v: &[u8]) -> Vec<u8> {
    let mut s = rlp::RlpStream::new();
    s.append(&v);
    s.out().to_vec()
}

fn main() -> eyre::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let address: Address = args
        .first()
        .map(String::as_str)
        .unwrap_or(DEFAULT_ADDR)
        .parse()?;
    let slot: B256 = args
        .get(1)
        .map(String::as_str)
        .unwrap_or(DEFAULT_SLOT)
        .parse()?;

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

    println!("block    {number}");
    println!("address  {address}");
    println!("slot     {slot}\n");

    // The ordinary inclusion proof — exactly what an `eth_getProof` client
    // would build a partial trie from.
    let account_proof = state.proof(Default::default(), address, &[slot])?;
    let storage_root: [u8; 32] = account_proof.storage_root.0;
    let sp = account_proof
        .storage_proofs
        .first()
        .ok_or_else(|| eyre::eyre!("no storage proof"))?;
    eyre::ensure!(
        !sp.value.is_zero(),
        "slot is already zero — pick one with a value (see examples/sweep.rs)"
    );
    let value = sp.value.to_be_bytes_trimmed_vec();

    let mut witness: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    for b in &sp.proof {
        let n = b.to_vec();
        if n.as_slice() != [0x80] {
            witness.insert(keccak(&n), n);
        }
    }
    let partial: Node<Keccak256> = build_partial(&witness, &storage_root);
    eyre::ensure!(node_root(&partial) == storage_root, "reconstruction failed");
    println!(
        "storage witness: {} node(s), {} stub(s), root OK\n",
        witness.len(),
        count_stubs(&partial)
    );

    let skey: [u8; 32] = keccak(slot.as_slice());

    // 1. Without a provider: the proof alone cannot resolve the sibling.
    let mut without = Trie::<Keccak256>::from_node(partial.clone());
    match without.remove(&skey) {
        Err(TrieError::MissingNode { hash, path }) => {
            println!(
                "no provider: Err(MissingNode {{ hash: {}, path: /{} }}) — as expected",
                hex::encode(hash),
                hex::encode(&path)
            );
        }
        other => {
            return Err(eyre::eyre!(
                "expected Err(MissingNode {{ .. }}) — pick a different slot \
                 (this one's Fork didn't collapse, or the sibling was already \
                 inlined); got {other:?}"
            ));
        }
    }

    // 2. With RethProvider: resolves whatever the collapse needs, by path,
    // straight from the database.
    let provider = RethProvider::new(std::rc::Rc::new(state), address);
    let mut trie = Trie::<Keccak256>::from_node(partial);
    eyre::ensure!(
        trie.remove_with(&provider, &skey)
            .map_err(|e| eyre::eyre!("{e:?}"))?,
        "remove reported the key absent"
    );
    let after = trie.hash();
    println!(
        "remove_with: storageRoot {} -> {}",
        hex::encode(storage_root),
        hex::encode(after)
    );
    eyre::ensure!(after != storage_root, "root did not change after removal");

    // 3. Revert through the same provider: canonicality.
    trie.insert_with(&provider, &skey, rlp_bytes(&value))
        .map_err(|e| eyre::eyre!("{e:?}"))?;
    eyre::ensure!(
        trie.hash() == storage_root,
        "re-inserting did not restore the root — collapse/prepend is not canonical"
    );
    println!("revert:      root restored exactly\n");

    println!("OK — Trie::remove_with/insert_with resolved a Stub through RethProvider");
    Ok(())
}
