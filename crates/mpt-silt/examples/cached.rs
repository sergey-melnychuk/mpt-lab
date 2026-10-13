//! Validate the silt diff feed by state-root recomputation — `block.rs`
//! with the replay removed: instead of executing block N with yevm, pick
//! the post-state straight off the feed that fills the cache, apply it
//! onto a partial trie built for the span's parent, and compare the
//! recomputed root against the canonical header.
//!
//! This certifies BOTH halves at once, continuously:
//!   - the stream (PLAN M3's equivalence, strengthened): a dropped write,
//!     a wrong value, a bad span fold, a mishandled destroy — any of them
//!     moves the recomputed root off the header's. The planned per-key
//!     RPC sweep can't see omissions; a root comparison can.
//!   - the MPT (again): every span is a fresh witness bootstrap via ONE
//!     batched `silt_multiproof` pinned at `diff.parent_hash`, plus live
//!     Phase B stub resolution through the HTTP providers.
//!
//! Folded spans validate at the span tip (the fold is cumulative — that
//! is exactly what it promises). Reorgs are fine: each span pins to its
//! own `parent_hash`, so the new side validates independently.
//!
//!     cargo run -p mpt-silt --release --example cached -- [feed] [url]
//!
//! `feed` defaults to `127.0.0.1:8585`, `url` to `http://127.0.0.1:8545`.
//! Runs until interrupted; prints one line per validated span.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use mpt_core::{
    Keccak256,
    hasher::keccak,
    partial::RecordingProvider,
    trie::{Trie, build_partial, node_root},
};
use mpt_silt::{AccountProvider, StorageProvider, multiproof};

use silt_wire::{BlockDiff, Frame, read_frame, write_frame};
use tokio::net::TcpStream;

/// Minimal big-endian bytes — the RLP integer form (`[]` for zero).
fn trim(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().skip_while(|&&b| b == 0).copied().collect()
}

/// `eth_getBlockByHash` -> one 32-byte header field.
fn header_b32(url: &str, hash: &[u8; 32], field: &str) -> eyre::Result<[u8; 32]> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByHash","params":["0x{}",false]}}"#,
        hex::encode(hash)
    );
    // Right at the tip the just-committed header can transiently 404
    // (the ExEx fires on commit; RPC views lag by a beat) — retry briefly.
    for attempt in 0..10 {
        let text = ureq::post(url)
            .set("content-type", "application/json")
            .send_string(&body)?
            .into_string()?;
        let v: serde_json::Value = serde_json::from_str(&text)?;
        if let Some(s) = v["result"][field].as_str() {
            let bytes =
                hex::decode(s.trim_start_matches("0x")).map_err(|e| eyre::eyre!("{e:?}"))?;
            return Ok(<[u8; 32]>::try_from(bytes.as_slice())?);
        }
        if attempt == 9 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    eyre::bail!("block 0x{}: no {field}", hex::encode(hash))
}

/// The four fields of an account leaf at the parent block.
struct LeafP {
    nonce: u64,
    balance: Vec<u8>,
    storage_root: [u8; 32],
    code_hash: [u8; 32],
}

fn decode_leaf(leaf: &[u8]) -> eyre::Result<LeafP> {
    let r = rlp::Rlp::new(leaf);
    let balance: Vec<u8> = r.val_at(1).map_err(|e| eyre::eyre!("leaf: {e}"))?;
    let storage_root: Vec<u8> = r.val_at(2).map_err(|e| eyre::eyre!("leaf: {e}"))?;
    let code_hash: Vec<u8> = r.val_at(3).map_err(|e| eyre::eyre!("leaf: {e}"))?;
    Ok(LeafP {
        nonce: r.val_at(0).map_err(|e| eyre::eyre!("leaf: {e}"))?,
        balance,
        storage_root: <[u8; 32]>::try_from(storage_root.as_slice())?,
        code_hash: <[u8; 32]>::try_from(code_hash.as_slice())?,
    })
}

/// Validate one span: witness at `diff.parent_hash`, apply the diff,
/// compare roots. Returns (matched, stubs_resolved).
fn validate(url: &str, diff: &BlockDiff) -> eyre::Result<(bool, usize)> {
    let parent_root = header_b32(url, &diff.parent_hash, "stateRoot")?;
    let expected = header_b32(url, &diff.hash, "stateRoot")?;

    // The touched set IS the diff; if the feed dropped a key, the witness
    // won't cover it and the recomputed root will say so.
    let destroyed: BTreeSet<[u8; 20]> = diff
        .accounts
        .iter()
        .filter(|(_, change)| change.is_none())
        .map(|(addr, _)| *addr)
        .collect();
    let mut slots: BTreeMap<[u8; 20], BTreeMap<[u8; 32], [u8; 32]>> = BTreeMap::new();
    for (addr, slot, value) in &diff.storage {
        slots.entry(*addr).or_default().insert(*slot, *value);
    }
    let mut touched: BTreeSet<[u8; 20]> = diff.accounts.iter().map(|(a, _)| *a).collect();
    touched.extend(slots.keys().copied());

    let started = Instant::now();
    let targets: Vec<([u8; 32], Vec<[u8; 32]>)> = touched
        .iter()
        .map(|addr| {
            let probes = slots
                .get(addr)
                .map(|s| s.keys().map(|slot| keccak(slot)).collect())
                .unwrap_or_default();
            (keccak(addr), probes)
        })
        .collect();
    let mp = multiproof(url, &targets, Some(&diff.parent_hash))
        .ok_or_else(|| eyre::eyre!("silt_multiproof bootstrap failed"))?;

    let empty_root = keccak(&[0x80]);
    let witness: BTreeMap<[u8; 32], Vec<u8>> = mp
        .account_nodes
        .into_iter()
        .filter(|(_, rlp)| rlp.as_slice() != [0x80])
        .collect();
    let partial = build_partial::<Keccak256>(&witness, &parent_root);
    eyre::ensure!(
        node_root(&partial) == parent_root,
        "account trie reconstruction failed at parent"
    );
    let mut trie = Trie::<Keccak256>::from_node(partial);

    let mut leaves_p: BTreeMap<[u8; 20], Option<LeafP>> = BTreeMap::new();
    for addr in touched.iter() {
        let leaf = trie
            .get(&keccak(addr))
            .map_err(|e| eyre::eyre!("leaf lookup: {e:?}"))?
            .map(<[u8]>::to_vec);
        leaves_p.insert(*addr, leaf.as_deref().map(decode_leaf).transpose()?);
    }

    let account_provider =
        RecordingProvider::new(AccountProvider::new(url, Some(diff.parent_hash)));
    let mut stubs = 0usize;

    for addr in destroyed.iter() {
        trie.remove_with(&account_provider, &keccak(addr))
            .map_err(|e| eyre::eyre!("removing 0x{}: {e:?}", hex::encode(addr)))?;
    }

    // Storage first (leaves need the new roots).
    let mut storage_roots: BTreeMap<[u8; 20], [u8; 32]> = BTreeMap::new();
    for (addr, writes) in slots.iter() {
        if destroyed.contains(addr) {
            continue;
        }
        let root_p = leaves_p
            .get(addr)
            .and_then(|l| l.as_ref().map(|l| l.storage_root))
            .unwrap_or(empty_root);
        let mut storage = if root_p == empty_root {
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
            let partial = build_partial::<Keccak256>(&witness, &root_p);
            eyre::ensure!(
                node_root(&partial) == root_p,
                "storage reconstruction failed for 0x{}",
                hex::encode(addr)
            );
            Trie::from_node(partial)
        };
        let provider =
            RecordingProvider::new(StorageProvider::new(url, addr, Some(diff.parent_hash)));
        for (slot, value) in writes.iter() {
            let hashed_slot = keccak(slot);
            let value = trim(value);
            if value.is_empty() {
                storage
                    .remove_with(&provider, &hashed_slot)
                    .map_err(|e| eyre::eyre!("removing slot: {e:?}"))?;
            } else {
                storage
                    .insert_with(&provider, &hashed_slot, rlp::encode(&value).to_vec())
                    .map_err(|e| eyre::eyre!("inserting slot: {e:?}"))?;
            }
        }
        stubs += provider.seen().len();
        storage_roots.insert(*addr, storage.hash());
    }

    // Account leaves: diff-carried changes, plus storage-only accounts
    // whose nonce/balance/code are unchanged (read from the parent leaf).
    for addr in touched.iter() {
        if destroyed.contains(addr) {
            continue;
        }
        let change = diff
            .accounts
            .iter()
            .find(|(a, _)| a == addr)
            .and_then(|(_, c)| c.as_ref());
        let leaf_p = leaves_p.get(addr).and_then(Option::as_ref);
        let (nonce, balance, code_hash) = match (change, leaf_p) {
            (Some(c), _) => (c.nonce, trim(&c.balance), c.code_hash),
            (None, Some(l)) => (l.nonce, l.balance.clone(), l.code_hash),
            // Storage write on an account the feed claims untouched and
            // the parent trie never held: a feed bug the root will flag.
            (None, None) => (0, Vec::new(), keccak(&[])),
        };
        let storage_root = storage_roots
            .get(addr)
            .copied()
            .or_else(|| leaf_p.map(|l| l.storage_root))
            .unwrap_or(empty_root);

        // EIP-161: never create an empty account.
        if leaf_p.is_none() && nonce == 0 && balance.is_empty() && code_hash == keccak(&[]) {
            continue;
        }

        let mut leaf = rlp::RlpStream::new_list(4);
        leaf.append(&nonce);
        leaf.append(&balance);
        leaf.append(&storage_root.to_vec());
        leaf.append(&code_hash.to_vec());
        trie.insert_with(&account_provider, &keccak(addr), leaf.out().to_vec())
            .map_err(|e| eyre::eyre!("inserting 0x{}: {e:?}", hex::encode(addr)))?;
    }
    stubs += account_provider.seen().len();

    let got = trie.hash();
    let matched = got == expected;
    println!(
        "span {}..{}: accounts {} slots {} stubs {} | {} ({} ms)",
        diff.span_start,
        diff.number,
        diff.accounts.len(),
        diff.storage.len(),
        stubs,
        if matched { "MATCH" } else { "MISMATCH" },
        started.elapsed().as_millis()
    );
    if !matched {
        eprintln!(
            "  expected 0x{}\n  computed 0x{}",
            hex::encode(expected),
            hex::encode(got)
        );
    }
    Ok((matched, stubs))
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let feed = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8585".into());
    let url = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "http://127.0.0.1:8545".into());

    let mut stream = TcpStream::connect(&feed).await?;

    // Handshake: server speaks first; echo its identity, subscribe at tip.
    let hello = read_frame(&mut stream)
        .await?
        .ok_or_else(|| eyre::eyre!("eof before Hello"))?;
    let Frame::Hello {
        chain_id,
        genesis_hash,
        tip,
        ..
    } = hello
    else {
        eyre::bail!("expected server Hello");
    };
    println!("feed {feed}: chain_id={chain_id} tip={tip}, validating from tip\n");
    write_frame(&mut stream, &silt_wire::hello(chain_id, genesis_hash, 0)).await?;
    write_frame(&mut stream, &Frame::Subscribe { from: None }).await?;

    let (mut spans, mut matched, mut total_stubs) = (0u64, 0u64, 0usize);
    loop {
        let Some(frame) = read_frame(&mut stream).await? else {
            println!("feed closed: spans {spans}, matched {matched}, stubs {total_stubs}");
            return if matched == spans {
                Ok(())
            } else {
                eyre::bail!("{} span(s) MISMATCHED", spans - matched)
            };
        };
        match frame {
            Frame::Diff(diff) => {
                let url = url.clone();
                // The validator is sync (ureq + trie math) — keep it off
                // the reactor thread that owns the feed socket.
                let (ok, stubs) =
                    tokio::task::spawn_blocking(move || validate(&url, &diff)).await??;
                spans += 1;
                matched += u64::from(ok);
                total_stubs += stubs;
            }
            Frame::Reorg { new_tip_number, .. } => {
                println!("REORG -> {new_tip_number} (spans keep validating per parent_hash)")
            }
            Frame::Heartbeat { .. } => {}
            Frame::GapTooOld { oldest_available } => {
                println!("gap: spool starts at {oldest_available}")
            }
            Frame::Refused { reason } => eyre::bail!("refused: {reason}"),
            Frame::Hello { .. } | Frame::Subscribe { .. } => {}
        }
    }
}
