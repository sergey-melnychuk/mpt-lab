//! Verify a real Ethereum account and one of its storage slots, chaining from
//! a block's `stateRoot` down, using nothing but this crate plus `rlp` and
//! `hex`. `reqwest` is the transport, `serde_json` parses the JSON-RPC
//! envelope and `eyre` carries errors.
//!
//!     cargo run --example live
//!     cargo run --example live -- <address> <slot> [block]
//!
//! Ethereum's state is two nested tries:
//!
//!   storage trie   keccak256(slot) -> rlp(value)          root = storageHash
//!   account trie   keccak256(addr) -> rlp([nonce, balance, storageRoot, codeHash])
//!                                                          root = block.stateRoot
//!
//! At each level two independent checks run against the same root:
//!
//!   1. `verify` walks the proof top-down, checking each node against the
//!      reference its parent held, and returns the stored value.
//!   2. The proof nodes are reassembled into a partial `Node` tree — every
//!      off-path child becomes `Stub(hash)` — and re-encoded bottom-up. The
//!      resulting keccak must equal the root the node reported.
//!
//! Check 2 is the interesting one: it exercises hex-prefix encoding, RLP node
//! layout, the sub-32-byte inlining rule, and stubs-as-references, all against
//! state that mainnet consensus agreed on.
//!
//! Nothing is trusted except one 32-byte number in the block header. The
//! account's `storageRoot` is not read from the RPC and believed — it is the
//! value check 2 derives at the storage level, which then goes into field 2 of
//! the account tuple we build ourselves, whose RLP check 1 confirms against the
//! state trie, which check 2 reconstructs to the header's `stateRoot`.

use std::collections::BTreeMap;

use eyre::{ContextCompat, Result};
use mpt_core::{
    Keccak256,
    hasher::keccak,
    trie::{Node, Trie, build_partial, count_stubs, node_root, verify},
};

/// Archive-capable and CORS-enabled, tried in order. Public endpoints
/// rate-limit and go down; several failed during testing for unrelated
/// reasons, so the fallback list is not paranoia.
const RPCS: &[&str] = &[
    "https://eth.drpc.org",
    "https://eth-mainnet.public.blastapi.io",
    "https://rpc.mevblocker.io",
    "https://ethereum-rpc.publicnode.com", // no archive state
];

/// USDC. Slot 0 of the proxy holds an address, so the value is short enough to
/// eyeball. Pinned to a fixed block so runs are reproducible.
const DEFAULT_ADDR: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const DEFAULT_SLOT: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
const DEFAULT_BLOCK: &str = "0x1400000";

/// JSON-RPC *quantities* are minimal-width, so a nonce of 1 arrives as "0x1" —
/// odd-length hex, which `hex::decode` rejects outright. Pad it.
fn unhex(s: &str) -> Result<Vec<u8>> {
    let h = s.trim_start_matches("0x");
    Ok(if h.len() % 2 == 1 {
        hex::decode(format!("0{h}"))?
    } else {
        hex::decode(h)?
    })
}

fn h32(s: &str) -> Result<[u8; 32]> {
    let v = unhex(s)?;
    eyre::ensure!(v.len() == 32, "expected 32 bytes, got {}", v.len());
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

/// RLP integers carry no leading zeros.
/// A zero balance becomes the empty string, which encodes as 0x80 — exactly right.
fn strip_zeros(v: Vec<u8>) -> Vec<u8> {
    let i = v.iter().position(|&b| b != 0).unwrap_or(v.len());
    v[i..].to_vec()
}

fn rlp_bytes(v: &[u8]) -> Vec<u8> {
    let mut s = rlp::RlpStream::new();
    s.append(&v);
    s.out().to_vec()
}

async fn rpc(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
    });
    let resp: serde_json::Value = client.post(url).json(&body).send().await?.json().await?;
    // println!(">>>\n{}", serde_json::to_string_pretty(&body).unwrap());
    // println!("<<<\n{}", serde_json::to_string_pretty(&resp).unwrap());
    if let Some(e) = resp.get("error") {
        eyre::bail!("{method}: {e}");
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| eyre::eyre!("{method}: no result"))
}

/// One line per proof node. Leaf and Skip are both 2-item RLP lists;
/// only the hex-prefix flag nibble in item 0 tells them apart.
fn dump(proof: &[Vec<u8>]) {
    for (i, n) in proof.iter().enumerate() {
        let r = rlp::Rlp::new(n);
        let kind = match r.item_count() {
            Ok(17) => "Fork",
            Ok(2) => {
                let p = r
                    .at(0)
                    .and_then(|x| x.data().map(<[u8]>::to_vec))
                    .unwrap_or_default();
                if p.first().map(|b| b >> 4).is_some_and(|f| f & 2 != 0) {
                    "Leaf"
                } else {
                    "Skip"
                }
            }
            _ => "?",
        };
        println!(
            "  {:<3} {:<5} {:>5}b  {}",
            i,
            kind,
            n.len(),
            hex::encode(keccak(n))
        );
    }
}

/// Rebuild a trie from proof nodes alone and confirm it re-derives `root`.
/// Returns the stub count: how much of the trie we do NOT have.
fn reconstruct(label: &str, proof: &[Vec<u8>], root: &[u8; 32]) -> Result<usize> {
    let mut nodes: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    for n in proof {
        nodes.insert(keccak(n), n.clone());
    }

    let partial: Node<Keccak256> = build_partial(&nodes, root);
    let recomputed = node_root(&partial);
    let stubs = count_stubs(&partial);

    println!(
        "  reconstruct  {}  {} node(s), {} stub(s)",
        if recomputed == *root { "OK " } else { "FAIL" },
        nodes.len(),
        stubs
    );

    eyre::ensure!(
        recomputed == *root,
        "{label}: reconstruction gave {} but the root is {}",
        hex::encode(recomputed),
        hex::encode(root)
    );
    Ok(stubs)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let addr_hex = args.first().map(String::as_str).unwrap_or(DEFAULT_ADDR);
    let slot_hex = args.get(1).map(String::as_str).unwrap_or(DEFAULT_SLOT);
    let block = args.get(2).map(String::as_str).unwrap_or(DEFAULT_BLOCK);

    let client = reqwest::Client::new();

    // Try endpoints until one serves both the header and the proof.
    // Endpoints without archive state will fail on a pinned historical block.
    let mut last: Option<eyre::Report> = None;
    let (url, header, proof) = 'found: {
        for url in RPCS {
            let attempt = async {
                let header = rpc(
                    &client,
                    url,
                    "eth_getBlockByNumber",
                    serde_json::json!([block, false]),
                )
                .await?;
                let proof = rpc(
                    &client,
                    url,
                    "eth_getProof",
                    serde_json::json!([addr_hex, [slot_hex], block]),
                )
                .await?;
                Ok::<_, eyre::Report>((header, proof))
            };
            match attempt.await {
                Ok((h, p)) => break 'found (*url, h, p),
                Err(e) => {
                    eprintln!("  {url}: {e}");
                    last = Some(e);
                }
            }
        }
        return Err(last.unwrap_or_else(|| eyre::eyre!("no endpoints configured")));
    };

    println!("proof: {}", serde_json::to_string_pretty(&proof).unwrap());
    // println!("block: {}", serde_json::to_string_pretty(&header).unwrap());

    let state_root = h32(header["stateRoot"].as_str().context("no stateRoot")?)?;
    let addr = unhex(proof["address"].as_str().context("no address")?)?;

    println!("rpc      {url}");
    println!("block    {block}");
    println!("address  {addr_hex}");
    println!("slot     {slot_hex}");
    println!("\nstateRoot  {}\n", hex::encode(state_root));

    // ------------------------------------------------------------------
    // storage trie
    // ------------------------------------------------------------------

    let storage_root = h32(proof["storageHash"].as_str().context("no storageHash")?)?;
    let sp = &proof["storageProof"][0];
    let slot = unhex(sp["key"].as_str().context("no slot key")?)?;
    let value = unhex(sp["value"].as_str().context("no slot value")?)?;
    let mut storage_proof: Vec<Vec<u8>> = sp["proof"]
        .as_array()
        .context("no storage proof")?
        .iter()
        .map(|n| unhex(n.as_str().unwrap_or_default()))
        .collect::<Result<_>>()?;
    // Some clients hand back the empty trie as a lone 0x80 node — rlp(Null) —
    // rather than no nodes at all. `verify` expects the latter, and 0x80 can
    // never be a real proof node: every node is a 2- or 17-item list.
    storage_proof.retain(|n| n.as_slice() != [0x80]);

    println!("STORAGE TRIE   root {}", hex::encode(storage_root));
    // Storage tries are "secure": the key is keccak256(slot), not the slot.
    let skey = keccak(&slot);
    if storage_proof.is_empty() {
        // An account with no storage has storageRoot == keccak256(rlp("")) and
        // the proof carries no nodes. That is no reason to skip: the root fully
        // determines the trie, so we can still reconstruct it and prove the
        // slot absent. See PTRIE.md §7.
        eyre::ensure!(
            storage_root == keccak(&[0x80]),
            "empty proof but storageRoot is {} — expected the empty-trie constant",
            hex::encode(storage_root)
        );
        println!("  (no storage — root is the empty-trie constant)");

        // build_partial special-cases this root to Null rather than an
        // unresolvable Stub: rlp(Null) is 0x80, a byte we already have.
        let partial: Node<Keccak256> = build_partial(&BTreeMap::new(), &storage_root);
        eyre::ensure!(
            matches!(partial, Node::Null),
            "empty root did not rebuild as Null"
        );
        eyre::ensure!(
            node_root(&partial) == storage_root,
            "Null did not re-derive the root"
        );
        println!("  reconstruct  OK   0 node(s), 0 stub(s)");

        // An empty trie proves EVERY key absent — the exclusion case from
        // stage 7, arriving on real state.
        match verify(&storage_root, &skey, &storage_proof)? {
            None => println!("  verify       OK  slot provably absent"),
            Some(v) => eyre::bail!("empty trie returned a value: 0x{}", hex::encode(v)),
        }
        eyre::ensure!(
            value.is_empty() || value == [0],
            "RPC reported a value for an empty trie"
        );
    } else {
        println!("  key   keccak(slot) {}", hex::encode(skey));
        println!("  value 0x{}", hex::encode(&value));
        dump(&storage_proof);

        // The trie holds rlp(value), not the raw 32-byte word.
        match verify(&storage_root, &skey, &storage_proof)? {
            Some(v) if v == rlp_bytes(&value) => println!("  verify       OK  value matches"),
            Some(v) => eyre::bail!("storage value mismatch: 0x{}", hex::encode(v)),
            None => eyre::bail!("storage proof says absent, but a value was reported"),
        }
        reconstruct("storage", &storage_proof, &storage_root)?;
    }

    // ------------------------------------------------------------------
    // account trie
    // ------------------------------------------------------------------

    let account_proof: Vec<Vec<u8>> = proof["accountProof"]
        .as_array()
        .context("no account proof")?
        .iter()
        .map(|n| unhex(n.as_str().unwrap_or_default()))
        .collect::<Result<_>>()?;

    // Rebuild the account value ourselves rather than trusting the RPC's
    // fields. `storage_root` here is the value reconstruct() just re-derived,
    // which is what links the two levels.
    let nonce = strip_zeros(unhex(proof["nonce"].as_str().context("no nonce")?)?);
    let balance = strip_zeros(unhex(proof["balance"].as_str().context("no balance")?)?);
    let code_hash = h32(proof["codeHash"].as_str().context("no codeHash")?)?;

    let account_rlp = {
        let mut s = rlp::RlpStream::new_list(4);
        s.append(&nonce.as_slice());
        s.append(&balance.as_slice());
        s.append(&storage_root.as_slice());
        s.append(&code_hash.as_slice());
        s.out().to_vec()
    };

    let akey = keccak(&addr);
    println!("\nACCOUNT TRIE   root {}", hex::encode(state_root));
    println!("  key   keccak(addr) {}", hex::encode(akey));
    println!(
        "  nonce 0x{}  balance 0x{}",
        hex::encode(&nonce),
        hex::encode(&balance)
    );
    println!("  rlp   {}", hex::encode(&account_rlp));
    dump(&account_proof);

    match verify(&state_root, &akey, &account_proof)? {
        Some(v) if v == account_rlp => println!("  verify       OK  account tuple matches"),
        Some(v) => eyre::bail!(
            "account mismatch\n    ours   {}\n    proof  {}",
            hex::encode(&account_rlp),
            hex::encode(v)
        ),
        None => eyre::bail!("account proof says the account is absent"),
    }
    let stubs = reconstruct("account", &account_proof, &state_root)?;

    println!(
        "\nOK — {} storage + {} account node(s) chained from the block's stateRoot",
        storage_proof.len(),
        account_proof.len()
    );
    println!(
        "     the account trie alone has {stubs} stub(s): almost all of mainnet state is\n\
         \x20    missing, and it still hashes correctly, because a parent needs only its\n\
         \x20    children's references — never their contents."
    );

    // ------------------------------------------------------------------
    // mutate
    // ------------------------------------------------------------------
    //
    // Change the slot value and re-derive both roots without ever holding the
    // full trie. Every node whose encoding changes lies on the path from the
    // root to the modified leaf, and the proof IS that path — so this needs no
    // NodeProvider. See PTRIE.md §7.
    //
    // Note the nesting: the new storageRoot is not just printed, it goes into
    // field 2 of the account tuple, which changes the account's leaf, which
    // changes the stateRoot. One slot write moves the number in the block
    // header.

    let mut new_value = value.clone();
    if new_value.is_empty() {
        new_value = vec![1];
    } else {
        new_value[0] ^= 0xff;
    }

    println!("\nMUTATE");
    println!("  old value 0x{}", hex::encode(&value));
    println!("  new value 0x{}", hex::encode(&new_value));

    // storage level
    let mut snodes: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    for n in &storage_proof {
        snodes.insert(keccak(n), n.clone());
    }
    let mut storage_trie = Trie::<Keccak256>::from_node(build_partial(&snodes, &storage_root));
    storage_trie.insert(&skey, rlp_bytes(&new_value));
    let storage_root2 = storage_trie.hash();
    println!(
        "  storageRoot  {}\n            -> {}",
        hex::encode(storage_root),
        hex::encode(storage_root2)
    );

    // account level: the new storageRoot goes into field 2 of the tuple
    let account_rlp2 = {
        let mut s = rlp::RlpStream::new_list(4);
        s.append(&nonce.as_slice());
        s.append(&balance.as_slice());
        s.append(&storage_root2.as_slice());
        s.append(&code_hash.as_slice());
        s.out().to_vec()
    };

    let mut anodes: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    for n in &account_proof {
        anodes.insert(keccak(n), n.clone());
    }
    let mut account_trie = Trie::<Keccak256>::from_node(build_partial(&anodes, &state_root));
    account_trie.insert(&akey, account_rlp2);
    let state_root2 = account_trie.hash();
    println!(
        "  stateRoot    {}\n            -> {}",
        hex::encode(state_root),
        hex::encode(state_root2)
    );

    // Put both back. A partial trie is canonical or it is nothing: restoring
    // the original values must restore the original roots byte-for-byte, or
    // some node re-encoded differently than it did on the way in. A zero slot
    // is not stored — Ethereum deletes it — so "back" for an absent slot means
    // removing the key, not writing rlp(0).
    if value.iter().any(|&b| b != 0) {
        storage_trie.insert(&skey, rlp_bytes(&value));
    } else {
        storage_trie.remove(&skey);
    }
    eyre::ensure!(
        storage_trie.hash() == storage_root,
        "reverting the slot did not restore the storage root"
    );
    account_trie.insert(&akey, account_rlp);
    eyre::ensure!(
        account_trie.hash() == state_root,
        "reverting the account did not restore the state root"
    );
    println!("  revert       OK  both roots restored exactly");

    Ok(())
}
