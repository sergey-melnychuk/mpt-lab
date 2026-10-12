//! Live check against a running silt-exex (PTRIE.md §8.2, over HTTP):
//! fetch the account-trie root node by `(path = [], hash = stateRoot)`,
//! then descend to every hashed child the root fork references — each
//! fetch is path-directed and only succeeds if the returned node hashes
//! to the value the parent committed to.
//!
//! Usage: cargo run -p mpt-silt --example resolve -- http://127.0.0.1:8545

use eyre::{ContextCompat, eyre};
use mpt_core::partial::NodeProvider;
use mpt_silt::AccountProvider;

fn parse32(hex_str: &str) -> eyre::Result<[u8; 32]> {
    // the workspace `hex` is no_std/alloc-only, so FromHexError has no
    // std::error::Error impl for `?` to convert through
    let bytes =
        hex::decode(hex_str.trim_start_matches("0x")).map_err(|e| eyre!("bad hex: {e:?}"))?;
    Ok(<[u8; 32]>::try_from(bytes.as_slice())?)
}

fn main() -> eyre::Result<()> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:8545".into());

    let head = ureq::post(&url)
        .set("content-type", "application/json")
        .send_string(
            r#"{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["latest",false]}"#,
        )?
        .into_string()?;
    let head: serde_json::Value = serde_json::from_str(&head)?;
    let state_root = parse32(
        head["result"]["stateRoot"]
            .as_str()
            .context("no stateRoot")?,
    )?;
    let block_hash = parse32(head["result"]["hash"].as_str().context("no block hash")?)?;
    println!(
        "head {} stateRoot 0x{}",
        head["result"]["number"],
        hex::encode(state_root)
    );

    let provider = AccountProvider::new(&url, Some(block_hash));

    let root = provider
        .get(&[], &state_root)
        .ok_or_else(|| eyre!("root node not resolved"))?;
    println!(
        "root node resolved: {} bytes (hash == stateRoot)",
        root.len()
    );

    // Descend one level: a fork is a 17-item list whose first 16 items are
    // child references — empty, inline (<32 bytes), or a 32-byte hash. The
    // hashed ones are exactly what a Stub would hold.
    let rlp = rlp::Rlp::new(&root);
    if rlp.item_count()? != 17 {
        println!("root is not a fork (item_count != 17) — chain too small, done");
        return Ok(());
    }
    let (mut hashed, mut inline, mut empty) = (0u32, 0u32, 0u32);
    for nibble in 0..16u8 {
        let child = rlp.at(usize::from(nibble))?;
        let data = child.data()?;
        if child.is_data() && data.len() == 32 {
            let want = <[u8; 32]>::try_from(data)?;
            let node = provider
                .get(&[nibble], &want)
                .ok_or_else(|| eyre!("child {nibble:x} not resolved"))?;
            println!("  child {nibble:x}: {} bytes, hash verified", node.len());
            hashed += 1;
        } else if child.is_empty() {
            empty += 1;
        } else {
            inline += 1;
        }
    }
    println!("fork children: {hashed} hashed (all resolved), {inline} inline, {empty} empty");
    Ok(())
}
