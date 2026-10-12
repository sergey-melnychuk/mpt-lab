//! Execute block N against block N-1's state with `yevm`, apply the
//! resulting diff onto a **partial** trie built for block N-1, and check
//! the recomputed root against block N's real header `stateRoot` — the
//! datadir-free port of `mpt-reth/examples/block.rs` (PTRIE.md §8.7).
//!
//! The replay itself is unchanged: yevm's `pre_block` + `Executor::run`
//! per tx + `post_block` produce the diff (including the EIP-4788/2935
//! system writes and EIP-4895/7002/7251 block-end effects). What changed
//! is where the bytes come from — everything arrives over RPC:
//!
//!   - execution pre-state through `yevm_core::rpc::Rpc` pinned at block
//!     N-1's hash (plain `eth_*` reads instead of `yevm-reth`'s MDBX);
//!   - the block N-1 trie witness from ONE batched `silt_multiproof`
//!     call (§8.5's bootstrap, over the wire — also not subject to
//!     `eth_getProof`'s proof-window limit);
//!   - Phase B stub resolution through `mpt_silt`'s providers, same pin.
//!
//! reth appears only as the node on the other end of the URL, running
//! the silt-exex wrapper.
//!
//!     cargo run -p mpt-silt --release --example block -- [url] [N]
//!
//! `url` defaults to `http://127.0.0.1:8545`; `N` to the RPC tip. Any
//! older `N` works while N-1 is within the node's retained history.

use std::collections::{BTreeMap, BTreeSet};

use mpt_core::{
    Keccak256,
    hasher::keccak,
    partial::RecordingProvider,
    trie::{Trie, build_partial, node_root},
};
use mpt_silt::{AccountProvider, StorageProvider, multiproof};

use yevm_base::{Acc, Int};
use yevm_core::{
    cache::Cache,
    chain::Chain,
    exe::{Executor, post_block, pre_block},
    rpc::Rpc,
    state::State as _,
    trace::{Event, Target, Trace},
};

fn a20(acc: &Acc) -> [u8; 20] {
    <[u8; 20]>::try_from(acc.as_ref()).expect("Acc is 20 bytes")
}

fn b32(int: &Int) -> [u8; 32] {
    <[u8; 32]>::try_from(int.as_ref()).expect("Int is 32 bytes")
}

/// Minimal big-endian bytes — the RLP integer form (`[]` for zero).
fn trim(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().skip_while(|&&b| b == 0).copied().collect()
}

/// One raw header read; `Head` deliberately doesn't carry `stateRoot`
/// (yevm never needs it), so fetch it directly.
fn header_b32(url: &str, number: u64, field: &str) -> eyre::Result<[u8; 32]> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x{number:x}",false]}}"#
    );
    let text = ureq::post(url)
        .set("content-type", "application/json")
        .send_string(&body)?
        .into_string()?;
    let v: serde_json::Value = serde_json::from_str(&text)?;
    let s = v["result"][field]
        .as_str()
        .ok_or_else(|| eyre::eyre!("block {number}: no {field}"))?;
    let bytes = hex::decode(s.trim_start_matches("0x")).map_err(|e| eyre::eyre!("{e:?}"))?;
    Ok(<[u8; 32]>::try_from(bytes.as_slice())?)
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:8545".into());
    let n_arg: Option<u64> = std::env::args().nth(2).map(|s| s.parse()).transpose()?;

    let tip = Rpc::latest(url.clone()).await?.block_number;
    let n = n_arg.unwrap_or(tip);
    eyre::ensure!(n >= 1, "need a parent block to replay against");
    println!("rpc tip: {tip}, replaying block {n}\n");

    // All execution reads pinned at block N-1's hash — the RPC stand-in
    // for the original's `RethDb` + `history_by_block_number(n - 1)`.
    let chain = Rpc::number(url.clone(), n - 1).await?;
    let hash_p = b32(&chain.block_hash);
    let root_p = header_b32(&url, n - 1, "stateRoot")?;
    let root_n = header_b32(&url, n, "stateRoot")?;

    let head = chain.head(n).await?;
    let block = chain.block(n).await?;
    println!("block {n}: {} tx(s)", block.txs.len());

    // 1. Execute block n against block (n-1) state via yevm.
    let mut cache = Cache::new();
    cache.set_chain_id(chain.chain_id().await?);
    pre_block(&head, &mut cache, &chain).await?;

    // Snapshot pre_block's own writes (EIP-4788 beacon root, etc.) BEFORE
    // the loop's first `cache.reset()` wipes `cache.events`.
    let mut all_events: Vec<Trace> = cache.events.clone();
    for tx in &block.txs {
        cache.reset(); // clears cache.events, NOT cache.accounts
        Executor::new(tx.call.clone().into())
            .run(&tx.tx, &head, &mut cache, &chain)
            .await?;
        all_events.extend(cache.events.clone());
    }

    cache.reset();
    post_block(&block.withdrawals, &mut cache, &chain).await?;
    all_events.extend(cache.events.clone());

    // 2. Extract the diff from the accumulated events (reverted events'
    // effects never happened — see the original example).
    let mut touched_accounts: BTreeSet<[u8; 20]> = BTreeSet::new();
    let mut touched_slots: BTreeMap<[u8; 20], BTreeSet<[u8; 32]>> = BTreeMap::new();
    let mut destroyed: BTreeSet<[u8; 20]> = BTreeSet::new();

    for event in all_events.iter().filter(|e| !e.reverted) {
        match &event.event {
            Event::Put(Target::Nonce { acc, .. }, _)
            | Event::Put(Target::Value { acc, .. }, _)
            | Event::Put(Target::Code { acc, .. }, _)
            | Event::Create(acc) => {
                touched_accounts.insert(a20(acc));
            }
            Event::Delete(acc) => {
                destroyed.insert(a20(acc));
            }
            Event::Move(a, b, _) => {
                touched_accounts.insert(a20(a));
                touched_accounts.insert(a20(b));
            }
            Event::Fee(sender, coinbase, ..) => {
                touched_accounts.insert(a20(sender));
                touched_accounts.insert(a20(coinbase));
            }
            Event::Put(Target::Store { acc, key, .. }, _) => {
                let addr = a20(acc);
                touched_accounts.insert(addr);
                touched_slots.entry(addr).or_default().insert(b32(key));
            }
            _ => {}
        }
    }

    println!("withdrawals: {}", block.withdrawals.len());
    println!(
        "touched accounts: {}, touched slots: {}, destroyed: {}\n",
        touched_accounts.len(),
        touched_slots.values().map(|s| s.len()).sum::<usize>(),
        destroyed.len(),
    );

    // 3. Bootstrap the partial tries for block (n-1) from ONE batched
    // `silt_multiproof` call covering every touched account and slot
    // (PTRIE.md §8.5's bootstrap, over the wire). Nodes arrive keyed by
    // keccak — exactly the witness map `build_partial` wants.
    let targets: Vec<([u8; 32], Vec<[u8; 32]>)> = touched_accounts
        .iter()
        .chain(destroyed.iter())
        .map(|addr| {
            let slots = touched_slots
                .get(addr)
                .map(|s| s.iter().map(|slot| keccak(slot)).collect())
                .unwrap_or_default();
            (keccak(addr), slots)
        })
        .collect();
    let mp = multiproof(&url, &targets, Some(&hash_p))
        .ok_or_else(|| eyre::eyre!("silt_multiproof bootstrap failed"))?;

    let empty_root = keccak(&[0x80]); // keccak(rlp("")), the empty-trie root

    let account_witness: BTreeMap<[u8; 32], Vec<u8>> = mp
        .account_nodes
        .into_iter()
        .filter(|(_, rlp)| rlp.as_slice() != [0x80])
        .collect();
    let account_partial = build_partial::<Keccak256>(&account_witness, &root_p);
    eyre::ensure!(
        node_root(&account_partial) == root_p,
        "account trie reconstruction failed"
    );
    let mut account_trie = Trie::<Keccak256>::from_node(account_partial);

    // N-1 leaves, read back from the partial trie itself (the witness
    // proves presence AND absence): existence + the carried storageRoot.
    let mut storage_root_p: BTreeMap<[u8; 20], Option<[u8; 32]>> = BTreeMap::new();
    for addr in touched_accounts.iter().chain(destroyed.iter()) {
        let leaf = account_trie
            .get(&keccak(addr))
            .map_err(|e| eyre::eyre!("leaf lookup for 0x{}: {e:?}", hex::encode(addr)))?
            .map(<[u8]>::to_vec);
        let root = match leaf {
            Some(leaf) => {
                let decoded: Vec<u8> = rlp::Rlp::new(&leaf)
                    .val_at(2)
                    .map_err(|e| eyre::eyre!("leaf decode: {e}"))?;
                Some(<[u8; 32]>::try_from(decoded.as_slice())?)
            }
            None => None,
        };
        storage_root_p.insert(*addr, root);
    }

    let mut storage_tries: BTreeMap<[u8; 20], Trie<Keccak256>> = BTreeMap::new();
    for addr in touched_slots.keys() {
        let root = storage_root_p
            .get(addr)
            .copied()
            .flatten()
            .unwrap_or(empty_root);
        let trie = if root == empty_root {
            Trie::new()
        } else {
            let walk = mp
                .storages
                .get(&keccak(addr))
                .ok_or_else(|| eyre::eyre!("no storage walk for 0x{}", hex::encode(addr)))?;
            let witness: BTreeMap<[u8; 32], Vec<u8>> = walk
                .nodes
                .iter()
                .filter(|(_, rlp)| rlp.as_slice() != [0x80])
                .map(|(k, v)| (*k, v.clone()))
                .collect();
            let partial = build_partial::<Keccak256>(&witness, &root);
            eyre::ensure!(
                node_root(&partial) == root,
                "storage reconstruction failed for 0x{}",
                hex::encode(addr)
            );
            Trie::from_node(partial)
        };
        storage_tries.insert(*addr, trie);
    }

    // 4. Apply the diff, every mutation going through the on-demand HTTP
    // providers (Phase B collapse-resolution kicks in automatically when
    // a removal needs a node the bootstrap didn't carry), pinned at the
    // same N-1 hash as the bootstrap.
    let account_provider = RecordingProvider::new(AccountProvider::new(&url, Some(hash_p)));
    let mut stubs_resolved = 0usize;

    for addr in destroyed.iter() {
        account_trie
            .remove_with(&account_provider, &keccak(addr))
            .map_err(|e| eyre::eyre!("removing 0x{}: {e:?}", hex::encode(addr)))?;
    }

    for (addr, slots) in touched_slots.iter() {
        if destroyed.contains(addr) {
            continue;
        }
        let acc = Acc::from(addr.as_slice());
        let trie = storage_tries.get_mut(addr).expect("built above");
        let provider = RecordingProvider::new(StorageProvider::new(&url, addr, Some(hash_p)));
        for slot in slots.iter() {
            let key = Int::from(slot.as_slice());
            let value = cache.storage(&acc, &key).unwrap_or_default();
            let hashed_slot = keccak(slot);
            if value.is_zero() {
                trie.remove_with(&provider, &hashed_slot)
                    .map_err(|e| eyre::eyre!("removing slot: {e:?}"))?;
            } else {
                let encoded = rlp::encode(&trim(value.as_ref())).to_vec();
                trie.insert_with(&provider, &hashed_slot, encoded)
                    .map_err(|e| eyre::eyre!("inserting slot: {e:?}"))?;
            }
        }
        stubs_resolved += provider.seen().len();
    }

    // 5. Re-encode every touched account's leaf from yevm's post-state.
    for addr in touched_accounts.iter() {
        if destroyed.contains(addr) {
            continue;
        }
        let acc = Acc::from(addr.as_slice());
        let account = cache
            .account(&acc)
            .cloned()
            .ok_or_else(|| eyre::eyre!("no final state for 0x{}", hex::encode(addr)))?;

        let storage_root = match storage_tries.get_mut(addr) {
            Some(trie) => trie.hash(),
            None => storage_root_p
                .get(addr)
                .copied()
                .flatten()
                .unwrap_or(empty_root),
        };

        let code = &account.code.0.0;
        let nonce = account.nonce.as_u64();
        let balance = trim(account.value.as_ref());

        // EIP-161: a touched-but-empty account that wasn't in the trie
        // must not be created (the zero-fee coinbase case on dev chains).
        if storage_root_p.get(addr) == Some(&None)
            && nonce == 0
            && balance.is_empty()
            && code.is_empty()
        {
            continue;
        }

        let mut leaf = rlp::RlpStream::new_list(4);
        leaf.append(&nonce);
        leaf.append(&balance);
        leaf.append(&storage_root.to_vec());
        leaf.append(&keccak(code).to_vec());

        account_trie
            .insert_with(&account_provider, &keccak(addr), leaf.out().to_vec())
            .map_err(|e| eyre::eyre!("inserting 0x{}: {e:?}", hex::encode(addr)))?;
    }

    stubs_resolved += account_provider.seen().len();
    println!("{stubs_resolved} stubs resolved over HTTP\n");

    // 6. Compare.
    let got = account_trie.hash();
    println!("expected stateRoot: 0x{}", hex::encode(root_n));
    println!("computed stateRoot: 0x{}", hex::encode(got));
    if got == root_n {
        println!("\nMATCH");
        Ok(())
    } else {
        // Diagnostics: cross-check yevm's post-state against the node's,
        // scalar reads pinned at block N — separates "yevm diverged" from
        // "trie math diverged".
        let check = Rpc::number(url.clone(), n).await?;
        let mut diverged = 0;
        for addr in touched_accounts.iter().take(50) {
            let acc = Acc::from(addr.as_slice());
            if let Some(account) = cache.account(&acc) {
                let nonce = check.nonce(&acc).await?;
                let balance = check.balance(&acc).await?;
                if nonce != account.nonce.as_u64() || balance != account.value {
                    diverged += 1;
                    eprintln!(
                        "yevm mismatch 0x{}: nonce {} vs {}, balance {} vs {}",
                        hex::encode(addr),
                        account.nonce.as_u64(),
                        nonce,
                        account.value,
                        balance
                    );
                }
            }
        }
        for (addr, slots) in touched_slots.iter() {
            let acc = Acc::from(addr.as_slice());
            for slot in slots.iter() {
                let key = Int::from(slot.as_slice());
                let ours = cache.storage(&acc, &key).unwrap_or_default();
                let theirs = check.get(&acc, &key).await?;
                if ours != theirs {
                    diverged += 1;
                    eprintln!(
                        "yevm slot mismatch 0x{}/{key}: {ours} vs {theirs}",
                        hex::encode(addr)
                    );
                }
            }
        }
        eyre::bail!("state root MISMATCH ({diverged} yevm-vs-node divergences among touched keys)");
    }
}
