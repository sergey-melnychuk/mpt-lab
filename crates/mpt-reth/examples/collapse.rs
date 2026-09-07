//! Phase B against a real reth 2.5.1 database: remove a storage slot, hit the
//! node the proof does not contain, and fetch it by path.
//!
//!     RETH_DATADIR=/path/to/reth/datadir cargo run -p mpt-reth --release --example collapse -- <address> <slot>
//!
//! Removing a key can drop a Fork to a single occupant, at which point
//! `normalize` must `prepend` a nibble onto the SURVIVING SIBLING — and that
//! needs the sibling's variant and path, not just its hash. The sibling hangs
//! off a different nibble of the Fork, so it was never on the deleted key's
//! path and the inclusion proof never contained it. That is the one case
//! PTRIE.md §6.2 says a witness cannot cover.
//!
//! In Ethereum terms this is routine, not exotic: `SSTORE(slot, 0)` IS a
//! deletion. There is no "slot present with value zero".
//!
//! THE USEFUL FINDING: reth's `multiproof()` takes *hashed* keys
//! (`MultiProofTargets` is `hashed_address -> {hashed_slot}`) and returns
//! `ProofNodes`, a path -> RLP-node map. So a node at nibble path P is
//! reachable: build a B256 whose leading nibbles are P, pad the rest with
//! anything, and ask. This is exactly what `eth_getProof` cannot do — it takes
//! the RAW slot and hashes it for you, so steering the walk would need a keccak
//! preimage. Path-directed fetching is the reason to be on the database.

use std::collections::BTreeMap;

use alloy_primitives::{Address, B256, keccak256};
use reth_ethereum::trie::MultiProofTargets;
use reth_ethereum::{
    chainspec::ChainSpecBuilder,
    node::EthereumNode,
    provider::{HeaderProvider, StateProofProvider, providers::ReadOnlyConfig},
    storage::BlockNumReader,
};

use mpt_core::{
    Keccak256,
    hasher::keccak,
    trie::{Node, Trie, build_partial, count_stubs, node_root},
};

const DEFAULT_ADDR: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"; // USDC
const DEFAULT_SLOT: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

fn rlp_bytes(v: &[u8]) -> Vec<u8> {
    let mut s = rlp::RlpStream::new();
    s.append(&v);
    s.out().to_vec()
}

fn to_nibbles(b: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(b.len() * 2);
    for x in b {
        o.push(x >> 4);
        o.push(x & 0x0f);
    }
    o
}

/// Pack a nibble prefix into a 32-byte key, zero-padded on the right.
///
/// Any key with this prefix walks through the node at that path, so the
/// multiproof for it necessarily contains that node. The padding is arbitrary —
/// the key almost certainly does not exist, which is fine: an exclusion proof
/// contains the same nodes along the way.
fn key_with_prefix(prefix: &[u8]) -> B256 {
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

/// Walk `key` and report the deepest Fork on its path, as
/// `(path_to_fork, occupancy, [(nibble, child_is_stub)])`.
///
/// Removing `key` collapses that Fork only if it drops to exactly one occupant.
fn deepest_fork(
    node: &Node<Keccak256>,
    key: &[u8],
) -> Option<(Vec<u8>, usize, Vec<(u8, bool, Option<[u8; 32]>)>)> {
    fn walk(
        node: &Node<Keccak256>,
        suffix: &[u8],
        path: Vec<u8>,
        best: &mut Option<(Vec<u8>, usize, Vec<(u8, bool, Option<[u8; 32]>)>)>,
    ) {
        match node {
            Node::Fork { children, value } => {
                let occupants: Vec<(u8, bool, Option<[u8; 32]>)> = (0..16u8)
                    .filter_map(|n| {
                        children[n as usize].as_ref().map(|c| match &**c {
                            Node::Stub(h) => (n, true, Some(*h)),
                            _ => (n, false, None),
                        })
                    })
                    .collect();
                let occupancy = occupants.len() + usize::from(value.is_some());
                *best = Some((path.clone(), occupancy, occupants));

                if let Some((&n, rest)) = suffix.split_first() {
                    if let Some(c) = &children[n as usize] {
                        let mut p = path;
                        p.push(n);
                        walk(c, rest, p, best);
                    }
                }
            }
            Node::Skip { path: sp, child } if suffix.starts_with(sp) => {
                let mut p = path;
                p.extend_from_slice(sp);
                walk(child, &suffix[sp.len()..], p, best);
            }
            _ => {}
        }
    }

    let mut best = None;
    walk(node, key, Vec::new(), &mut best);
    best
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
    let _header = headers
        .header_by_number(number)?
        .ok_or_else(|| eyre::eyre!("no header"))?;

    let hashed_address = keccak256(address);
    let hashed_slot = keccak256(slot);
    let skey: [u8; 32] = hashed_slot.0;
    let skey_nibbles = to_nibbles(&skey);

    println!("block    {number}");
    println!("address  {address}");
    println!("slot     {slot}");
    println!("hashed   {}\n", hex::encode(skey));

    // ---- 1. the ordinary inclusion proof, as in live.rs ----

    let account_proof = state.proof(Default::default(), address, &[slot])?;
    let storage_root: [u8; 32] = account_proof.storage_root.0;
    let sp = account_proof
        .storage_proofs
        .first()
        .ok_or_else(|| eyre::eyre!("no storage proof"))?;

    // reth keeps the empty-trie sentinel that eth_getProof strips.
    let mut witness: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    for b in &sp.proof {
        let n = b.to_vec();
        if n.as_slice() != [0x80] {
            witness.insert(keccak(&n), n);
        }
    }
    eyre::ensure!(!witness.is_empty(), "account has no storage");
    eyre::ensure!(
        !sp.value.is_zero(),
        "slot is already zero — pick one with a value"
    );

    let value = sp.value.to_be_bytes_trimmed_vec();
    let partial: Node<Keccak256> = build_partial(&witness, &storage_root);
    eyre::ensure!(node_root(&partial) == storage_root, "reconstruction failed");
    println!(
        "storage witness: {} node(s), {} stub(s), root OK",
        witness.len(),
        count_stubs(&partial)
    );

    // ---- 2. will removing this slot collapse a Fork? ----

    let (fork_path, occupancy, occupants) = deepest_fork(&partial, &skey_nibbles)
        .ok_or_else(|| eyre::eyre!("no Fork on the path — trie is a bare leaf"))?;

    println!(
        "\ndeepest Fork on the path: /{}  occupancy {}",
        hex::encode(&fork_path),
        occupancy
    );

    if occupancy > 2 {
        println!(
            "  {} occupants remain after removal, so no collapse fires and the\n  \
             inclusion proof is sufficient. Nothing to fetch.",
            occupancy - 1
        );
        println!("\n(Try a different slot to exercise the collapse path.)");
        return Ok(());
    }

    // Exactly two occupants: removing ours leaves one, the Fork collapses, and
    // `normalize` must prepend a nibble onto the survivor.
    let taken = *skey_nibbles
        .get(fork_path.len())
        .ok_or_else(|| eyre::eyre!("key too short"))?;
    let (sib_nibble, is_stub, sib_hash) =
        occupants
            .iter()
            .find(|(n, _, _)| *n != taken)
            .copied()
            .ok_or_else(|| eyre::eyre!("value slot is the other occupant — no sibling node"))?;

    let mut sib_path = fork_path.clone();
    sib_path.push(sib_nibble);

    println!("  COLLAPSE WILL FIRE");
    println!("  our nibble     {taken:x}");
    println!(
        "  sibling nibble {sib_nibble:x}  at /{}",
        hex::encode(&sib_path)
    );
    println!(
        "  sibling in witness? {}",
        if is_stub {
            "NO — it is a Stub"
        } else {
            "yes"
        }
    );

    if !is_stub {
        println!("\n  Sibling came along inlined inside its parent, so the witness is");
        println!("  already complete. Nothing to fetch.");
        return Ok(());
    }

    let want = sib_hash.expect("stub carries a hash");
    println!("  need node      {}", hex::encode(want));

    // ---- 3. fetch it BY PATH ----
    //
    // This is the step eth_getProof cannot do. Targets are hashed keys, so we
    // synthesise one sharing the sibling's nibble prefix and ask for a
    // multiproof; the walk passes through the sibling and returns it.

    let probe = key_with_prefix(&sib_path);
    println!("\nfetching by path: probe key {}", hex::encode(probe.0));

    let mp = state.multiproof(
        Default::default(),
        MultiProofTargets::account_with_slots(hashed_address, [probe]),
    )?;

    let sub = mp
        .storages
        .get(&hashed_address)
        .ok_or_else(|| eyre::eyre!("multiproof returned no storage subtree"))?;

    println!(
        "  multiproof returned {} node(s), keyed by path:",
        sub.subtree.len()
    );
    let mut found: Option<Vec<u8>> = None;
    let mut paths: Vec<_> = sub
        .subtree
        .iter()
        .map(|(p, b)| (p.clone(), b.clone()))
        .collect();
    paths.sort_by_key(|(p, _)| p.len());
    for (p, b) in &paths {
        let h = keccak(b);
        let mark = if h == want {
            " <-- the one we need"
        } else {
            ""
        };
        println!(
            "    /{:<20} {:>5}b  {}{}",
            format!("{p:?}"),
            b.len(),
            hex::encode(h),
            mark
        );
        if h == want {
            found = Some(b.to_vec());
        }
    }

    let node = found.ok_or_else(|| {
        eyre::eyre!("multiproof did not contain the sibling — the probe prefix is wrong")
    })?;

    // Never trust the store: the stub's hash is the checksum.
    eyre::ensure!(
        keccak(&node) == want,
        "fetched node does not hash to the stub"
    );
    println!("  hash check OK");

    // ---- 4. now the removal works ----

    witness.insert(want, node);
    let resolved: Node<Keccak256> = build_partial(&witness, &storage_root);
    eyre::ensure!(
        node_root(&resolved) == storage_root,
        "root broke after adding the node"
    );
    println!(
        "\nwitness now {} node(s), {} stub(s), root still OK",
        witness.len(),
        count_stubs(&resolved)
    );

    let mut trie = Trie::<Keccak256>::from_node(resolved);
    eyre::ensure!(
        trie.remove(&skey).map_err(|e| eyre::eyre!("{e:?}"))?,
        "remove reported the key absent"
    );
    let after = trie.hash();
    println!("\nremoved slot (SSTORE -> 0)");
    println!(
        "  storageRoot  {}\n            -> {}",
        hex::encode(storage_root),
        hex::encode(after)
    );

    // Put it back. A partial trie is canonical or it is nothing: restoring the
    // value must restore the root byte-for-byte, or `normalize` produced a
    // shape the original trie never had.
    trie.insert(&skey, rlp_bytes(&value))
        .map_err(|e| eyre::eyre!("{e:?}"))?;
    eyre::ensure!(
        trie.hash() == storage_root,
        "re-inserting did not restore the root — collapse/prepend is not canonical"
    );
    println!("  revert       OK  root restored exactly");

    println!("\nOK — resolved a node the proof could not contain, by path, from reth");
    Ok(())
}
