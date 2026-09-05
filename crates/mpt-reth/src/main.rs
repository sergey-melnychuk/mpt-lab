//! Same verification as `examples/live.rs`, but reading proofs straight out of
//! a local reth 2.5.1 database instead of over JSON-RPC.
//!
//!     RETH_DATADIR=/path/to/reth/datadir cargo run -p mpt-reth --release
//!     RETH_DATADIR=/path/to/reth/datadir cargo run -p mpt-reth --release -- <address> <slot> [block]
//!
//! Note `--release`: reth's provider stack is unusably slow in a debug build.
//!
//! What changes versus the RPC version: `eth_getProof` hashes the slot for you,
//! so you cannot steer the walk to a particular node. reth's `proof()` takes
//! the same shape here, but the crate exposes lower-level machinery
//! (`MultiProof`, path-targeted proofs) that RPC has no equivalent for. That's
//! the reason PTRIE.md §8 wants the database rather than an endpoint.
//!
//! Everything after the fetch is unchanged: the same `verify` and the same
//! `build_partial` reconstruction from `mpt-core`.

use std::collections::BTreeMap;

use alloy_primitives::{Address, B256, keccak256};
use reth_ethereum::{
    chainspec::ChainSpecBuilder,
    node::EthereumNode,
    primitives::AlloyBlockHeader,
    provider::{
        BlockNumReader, HeaderProvider, StateProofProvider, StateProvider,
        providers::ReadOnlyConfig,
    },
};

use mpt_core::{
    Keccak256,
    hasher::keccak,
    trie::{Node, build_partial, count_stubs, node_root, verify},
};

const DEFAULT_ADDR: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"; // USDC
const DEFAULT_SLOT: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

fn rlp_bytes(v: &[u8]) -> Vec<u8> {
    let mut s = rlp::RlpStream::new();
    s.append(&v);
    s.out().to_vec()
}

/// One line per proof node. Leaf and Skip are both 2-item RLP lists; only the
/// hex-prefix flag nibble in item 0 tells them apart.
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
fn reconstruct(label: &str, proof: &[Vec<u8>], root: &[u8; 32]) -> eyre::Result<usize> {
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
    let block: Option<u64> = args.get(2).map(|s| s.parse()).transpose()?;

    let datadir = std::env::var("RETH_DATADIR")
        .map_err(|_| eyre::eyre!("set RETH_DATADIR, e.g. ~/.local/share/reth/mainnet"))?;

    // Read-only: safe to run against a live node's datadir.
    let spec = ChainSpecBuilder::mainnet().build();
    let runtime = reth_ethereum::tasks::Runtime::test();
    let factory = EthereumNode::provider_factory_builder().open_read_only(
        spec.into(),
        ReadOnlyConfig::from_datadir(datadir),
        runtime,
    )?;

    let headers = factory.provider()?;

    // A *minimal* node prunes historical state, so `history_by_block_number`
    // will fail for anything below the pruning horizon. `latest()` always works.
    let (number, state): (u64, Box<dyn StateProvider>) = match block {
        Some(n) => (n, factory.history_by_block_number(n)?),
        None => {
            let n = headers.best_block_number()?;
            (n, factory.latest()?)
        }
    };

    let header = headers
        .header_by_number(number)?
        .ok_or_else(|| eyre::eyre!("no header for block {number}"))?;
    let state_root: [u8; 32] = header.state_root().0;

    println!("datadir  {}", std::env::var("RETH_DATADIR").unwrap());
    println!("block    {number}");
    println!("address  {address}");
    println!("slot     {slot}");
    println!("\nstateRoot  {}\n", hex::encode(state_root));

    // The whole fetch. `Default::default()` is an empty `TrieInput`, i.e. no
    // in-memory overlay on top of what is committed to the database.
    let account_proof = state.proof(Default::default(), address, &[slot])?;

    // reth's own check, for comparison. Ours below is independent of it.
    account_proof.verify(header.state_root())?;
    println!("reth's AccountProof::verify  OK\n");

    let storage_root: [u8; 32] = account_proof.storage_root.0;
    let sp = account_proof
        .storage_proofs
        .first()
        .ok_or_else(|| eyre::eyre!("no storage proof returned"))?;

    // ------------------------------------------------------------------
    // storage trie
    // ------------------------------------------------------------------

    // NOTE: unlike eth_getProof, reth does NOT strip the empty-trie sentinel
    // here — an account with no storage yields a single 0x80 node rather than
    // an empty list. That normalisation happens only at the EIP-1186 response
    // boundary. See PTRIE.md §7.5: our `verify` expects the empty list.
    let storage_proof: Vec<Vec<u8>> = sp
        .proof
        .iter()
        .map(|b| b.to_vec())
        .filter(|n| n.as_slice() != [0x80])
        .collect();

    let value = sp.value.to_be_bytes_trimmed_vec();

    println!("STORAGE TRIE   root {}", hex::encode(storage_root));
    if storage_proof.is_empty() {
        println!("  (empty — this account has no storage)");
    } else {
        // Storage tries are "secure": the key is keccak256(slot).
        let skey: [u8; 32] = keccak256(slot).0;
        println!("  key   keccak(slot) {}", hex::encode(skey));
        println!("  value 0x{}", hex::encode(&value));
        dump(&storage_proof);

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

    let nodes: Vec<Vec<u8>> = account_proof
        .proof
        .iter()
        .map(|b| b.to_vec())
        .filter(|n| n.as_slice() != [0x80])
        .collect();

    // Rebuild the account tuple ourselves: rlp([nonce, balance, storageRoot,
    // codeHash]). `storage_root` here is the value reconstruct() re-derived
    // above, which is what chains the two levels together.
    let info = account_proof
        .info
        .ok_or_else(|| eyre::eyre!("account does not exist at this block"))?;

    let nonce = {
        let b = info.nonce.to_be_bytes();
        let i = b.iter().position(|&x| x != 0).unwrap_or(b.len());
        b[i..].to_vec()
    };
    let balance = info.balance.to_be_bytes_trimmed_vec();
    let code_hash: [u8; 32] = info.get_bytecode_hash().0;

    let account_rlp = {
        let mut s = rlp::RlpStream::new_list(4);
        s.append(&nonce.as_slice());
        s.append(&balance.as_slice());
        s.append(&storage_root.as_slice());
        s.append(&code_hash.as_slice());
        s.out().to_vec()
    };

    let akey: [u8; 32] = keccak256(address).0;
    println!("\nACCOUNT TRIE   root {}", hex::encode(state_root));
    println!("  key   keccak(addr) {}", hex::encode(akey));
    println!("  nonce {}  balance {}", info.nonce, info.balance);
    println!("  rlp   {}", hex::encode(&account_rlp));
    dump(&nodes);

    match verify(&state_root, &akey, &nodes)? {
        Some(v) if v == account_rlp => println!("  verify       OK  account tuple matches"),
        Some(v) => eyre::bail!(
            "account mismatch\n    ours   {}\n    proof  {}",
            hex::encode(&account_rlp),
            hex::encode(v)
        ),
        None => eyre::bail!("account proof says the account is absent"),
    }
    let stubs = reconstruct("account", &nodes, &state_root)?;

    println!(
        "\nOK — {} storage + {} account node(s) chained from the block's stateRoot",
        storage_proof.len(),
        nodes.len()
    );
    println!("     account trie alone has {stubs} stub(s)");

    {
        // ------------------------------------------------------------------
        // pull a node the proof does NOT contain, by path
        // ------------------------------------------------------------------
        //
        // Every Fork in a proof hands us the hashes of all sixteen children,
        // including the fifteen we did not descend into. Those become Stubs. This
        // picks one and fetches it.
        //
        // The mechanism: `MultiProofTargets` is keyed by *hashed* address and
        // *hashed* slot, and `StorageMultiProof.subtree` is a path -> RLP-node map.
        // So we can synthesise a B256 whose leading nibbles are the target path,
        // pad the rest, and ask — the walk passes through the node we want. The key
        // almost certainly does not exist, which is fine: an exclusion proof
        // contains the same nodes on the way down.
        //
        // eth_getProof cannot do this. It takes the RAW slot and hashes it for you,
        // so steering the walk to a chosen path would need a keccak preimage. This
        // is the reason to be on the database rather than an endpoint, and it is
        // what makes the delete-collapse sibling case solvable (PTRIE.md §6.2).

        use alloy_primitives::Bytes;
        use reth_ethereum::trie::{MultiProofTargets, Nibbles};

        if !storage_proof.is_empty() {
            println!("\nPULL BY PATH");

            // Take the root Fork and pick any occupied slot that is NOT the one on
            // our key's path. That child is a Stub: we know its hash, nothing else.
            let root_node = rlp::Rlp::new(&storage_proof[0]);
            eyre::ensure!(
                root_node.item_count()? == 17,
                "root of the storage proof is not a Fork"
            );

            let ours = keccak256(slot).0[0] >> 4; // first nibble of the hashed key
            let mut target: Option<(u8, [u8; 32])> = None;
            for n in 0..16u8 {
                if n == ours {
                    continue;
                }
                let item = root_node.at(n as usize)?;
                if !item.is_data() {
                    continue; // inlined child: already inside the parent's bytes
                }
                let d = item.data()?;
                if d.len() == 32 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(d);
                    target = Some((n, h));
                    break;
                }
            }

            let Some((nibble, want)) = target else {
                println!("  root Fork has no hashed off-path child — nothing to pull");
                return Ok(());
            };

            println!("  our nibble    {ours:x}  (on the proof's path)");
            println!("  target path   /{nibble:x}");
            println!("  target hash   {}", hex::encode(want));
            println!("  in witness?   no — the proof never descended there");

            // Pack the nibble prefix into a 32-byte probe key, zero-padded right.
            let probe = {
                let mut out = [0u8; 32];
                out[0] = nibble << 4;
                B256::from(out)
            };
            println!("  probe key     {}", hex::encode(probe.0));

            let mp = state.multiproof(
                Default::default(),
                MultiProofTargets::account_with_slots(keccak256(address), [probe]),
            )?;

            let sub = mp
                .storages
                .get(&keccak256(address))
                .ok_or_else(|| eyre::eyre!("multiproof returned no storage subtree"))?;

            let mut nodes: Vec<(Nibbles, Bytes)> =
                sub.subtree.iter().map(|(p, b)| (*p, b.clone())).collect();
            nodes.sort_by_key(|(p, _)| p.len());

            println!(
                "  multiproof returned {} node(s), keyed by path:",
                nodes.len()
            );
            let mut found: Option<Vec<u8>> = None;
            for (p, b) in &nodes {
                let h = keccak(b);
                let hit = h == want;
                println!(
                    "    len {:<2} {:>5}b  {}{}",
                    p.len(),
                    b.len(),
                    hex::encode(h),
                    if hit { "  <-- the one we wanted" } else { "" }
                );
                if hit {
                    found = Some(b.to_vec());
                }
            }

            match found {
                Some(node) => {
                    // Never trust the store. The stub's hash is the checksum, and
                    // this is the same check verify() makes on every proof node.
                    eyre::ensure!(
                        keccak(&node) == want,
                        "fetched node does not hash to the stub"
                    );
                    let kind = match rlp::Rlp::new(&node).item_count() {
                        Ok(17) => "Fork",
                        Ok(2) => "Leaf or Skip",
                        _ => "?",
                    };
                    println!("  hash check    OK  ({} bytes, {kind})", node.len());
                    println!("\n  Pulled a node the proof could not contain. This is what makes");
                    println!("  the delete-collapse sibling resolvable — see PTRIE.md §6.2.");
                }
                None => {
                    println!("\n  NOT FOUND — the probe did not return the node at /{nibble:x}.");
                    println!("  Either the multiproof prunes off-target nodes, or the probe key");
                    println!("  needs a longer prefix. Check what paths came back above.");
                }
            }
        }
    }

    Ok(())
}
