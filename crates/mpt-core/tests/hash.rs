//! ethereum/tests TrieTests fixtures.
//!
//! Vendored from https://github.com/ethereum/tests/tree/develop/TrieTests
//!
//! Format notes:
//!  - keys and values are EITHER "0x"-prefixed hex OR raw ASCII. Both occur in
//!    the same file, sometimes in the same case.
//!  - a null value means DELETE that key.
//!  - `trieanyorder*.json` gives `in` as an object; `trietest*.json` gives it
//!    as an array, because deletes are interleaved and order matters.
//!  - the `*_secureTrie` variants use the SAME inputs with keccak256(key) as
//!    the trie key, and therefore different roots.
//!
//! Coverage: 7 anyorder cases + 7 anyorder_secure (insert only, order
//! independence checked) and 5 trietest + 3 trietest_secure (with deletes).

use mpt_core::Hasher;
use mpt_core::Keccak256 as K;
use mpt_core::trie::Trie;

const ANYORDER: &str = include_str!("fixtures/trieanyorder.json");
const ANYORDER_SECURE: &str = include_str!("fixtures/trieanyorder_secureTrie.json");
const TRIETEST: &str = include_str!("fixtures/trietest.json");
const TRIETEST_SECURE: &str = include_str!("fixtures/trietest_secureTrie.json");

/// A fixture entry: `None` value means delete.
type Pair = (Vec<u8>, Option<Vec<u8>>);

struct Case {
    name: String,
    pairs: Vec<Pair>,
    root: [u8; 32],
}

fn unhex(s: &str) -> Vec<u8> {
    match s.strip_prefix("0x") {
        Some(h) => hex::decode(h).unwrap_or_else(|e| panic!("bad hex {s:?}: {e}")),
        None => s.as_bytes().to_vec(),
    }
}

fn parse(src: &str) -> Vec<Case> {
    let doc: serde_json::Value = serde_json::from_str(src).expect("fixture is not valid json");
    doc.as_object()
        .expect("top level must be an object")
        .iter()
        .map(|(name, case)| {
            let root = unhex(case["root"].as_str().expect("root must be a string"))
                .try_into()
                .expect("root must be 32 bytes");
            let input = &case["in"];
            let pairs: Vec<Pair> = if let Some(map) = input.as_object() {
                map.iter()
                    .map(|(k, v)| (unhex(k), v.as_str().map(unhex)))
                    .collect()
            } else {
                input
                    .as_array()
                    .expect("`in` must be an object or an array")
                    .iter()
                    .map(|entry| {
                        let kv = entry.as_array().expect("entry must be a [k, v] pair");
                        (
                            unhex(kv[0].as_str().expect("key must be a string")),
                            kv[1].as_str().map(unhex),
                        )
                    })
                    .collect()
            };
            Case { name: name.clone(), pairs, root }
        })
        .collect()
}

/// A key appearing twice means last-write-wins, so insertion order is
/// significant even with no deletes. `branch-value-update` writes "abc" twice.
fn has_duplicate_keys(c: &Case) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    c.pairs.iter().any(|(k, _)| !seen.insert(k.clone()))
}

fn order_matters(c: &Case) -> bool {
    c.pairs.iter().any(|(_, v)| v.is_none()) || has_duplicate_keys(c)
}

/// Apply a case's pairs in the given order. `secure` hashes each key first.
fn apply(pairs: &[Pair], secure: bool) -> [u8; 32] {
    let mut t = Trie::<K>::new();
    for (k, v) in pairs {
        let key = if secure { K::hash_all(&[k]).to_vec() } else { k.clone() };
        match v {
            Some(v) => t.insert(&key, v.clone()),
            None => {
                t.remove(&key);
            }
        }
    }
    t.hash()
}

/// Cheap deterministic shuffle so we don't pull in a rand dependency.
fn shuffled(pairs: &[Pair], seed: u64) -> Vec<Pair> {
    let mut v = pairs.to_vec();
    let mut s = seed | 1;
    for i in (1..v.len()).rev() {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        v.swap(i, (s >> 33) as usize % (i + 1));
    }
    v
}

fn run(src: &str, label: &str, secure: bool) {
    let cases = parse(src);
    assert!(!cases.is_empty(), "{label}: parsed zero cases");

    for c in &cases {
        assert_eq!(
            hex::encode(apply(&c.pairs, secure)),
            hex::encode(c.root),
            "{label}/{}: root mismatch",
            c.name
        );

        // Order independence. Only sound when the case has no deletes and no
        // repeated keys: either one makes the final contents order-dependent.
        if order_matters(c) {
            continue;
        }
        for seed in [1u64, 0xdead_beef, 0x5eed] {
            assert_eq!(
                hex::encode(apply(&shuffled(&c.pairs, seed), secure)),
                hex::encode(c.root),
                "{label}/{} (order independence, seed {seed:#x}): root mismatch",
                c.name
            );
        }
    }

    eprintln!("{label}: {} case(s) passed", cases.len());
}

#[test]
fn anyorder() {
    run(ANYORDER, "trieanyorder", false);
}

#[test]
fn anyorder_secure() {
    run(ANYORDER_SECURE, "trieanyorder_secureTrie", true);
}

#[test]
fn trietest() {
    run(TRIETEST, "trietest", false);
}

#[test]
fn trietest_secure() {
    run(TRIETEST_SECURE, "trietest_secureTrie", true);
}
