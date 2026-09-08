//! Execute a real mainnet block N against block N-1's state with `yevm`
//! (the user's own EVM, pulled in as a dev-dependency), apply the resulting
//! diff — plus withdrawals, which yevm does not process (verified: zero
//! hits grepping its source for "withdrawal") — onto a **partial** trie
//! built for block N-1, and check the recomputed root against block N's
//! real header `stateRoot`.
//!
//! Both execution (`yevm-reth::RethDb`) and the trie-proof reads
//! (`mpt-reth`'s own `RethProvider`/`AccountTrieProvider`) share the SAME
//! `ProviderFactory` — `RethDb::factory()` — so this process opens exactly
//! one MDBX environment for the whole run. That's a hard requirement, not
//! just tidiness: MDBX allows one *environment* open per process, full
//! stop (confirmed empirically — a second `open_read_only` in this
//! process fails with "another write transaction is running" even
//! sequentially, first handle fully dropped before the second is
//! attempted). Minting more `StateProviderBox`es from one already-open
//! factory (`factory.latest()`/`factory.history_by_block_number()`) is
//! fine — those are just new MDBX read transactions, not new environments.
//!
//!     RETH_DATADIR=/path/to/reth/datadir cargo run -p mpt-reth --release --example block [N]
//!
//! `N` defaults to the datadir's latest persisted block when omitted. Any
//! older `N` still works as long as it's within the node's retained
//! account/storage history (~10064 blocks / ~1.4 days on a `--minimal`
//! node).

use std::collections::{BTreeMap, BTreeSet};

use alloy_consensus::BlockHeader;
use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_rlp::Encodable;
use reth_ethereum::{
    provider::{
        BlockReader, HeaderProvider, StateProofProvider, StateProvider, StateProviderBox,
        TransactionVariant,
    },
    trie::{EMPTY_ROOT_HASH, MultiProofTargets, TrieAccount},
};

use mpt_core::{
    Keccak256,
    hasher::keccak,
    partial::RecordingProvider,
    trie::{Node, Trie, build_partial, node_root},
};
use mpt_reth::{AccountTrieProvider, RethProvider};

use yevm_base::{Acc, Int};
use yevm_core::{
    cache::Cache,
    chain::Chain,
    exe::{Executor, pre_block},
    state::{Account, State as _},
    trace::{Event, Target, Trace},
};
use yevm_reth::RethDb;

fn acc_to_addr(acc: &Acc) -> Address {
    Address::from_slice(acc.as_ref())
}

fn addr_to_acc(addr: Address) -> Acc {
    Acc::from(addr.as_slice())
}

fn int_to_u256(v: &Int) -> U256 {
    U256::from_be_slice(v.as_ref())
}

fn u256_to_int(v: U256) -> Int {
    Int::from(v.to_be_bytes::<32>().as_slice())
}

/// A real node (reth + lighthouse) is live-syncing against this same
/// datadir, so the one `open_read_only` this process does (inside
/// `RethDb::latest`) can transiently race its writer commit ("another
/// write transaction is running") -- retry rather than fail on a timing
/// hiccup unrelated to the trie logic.
fn retry<T>(mut f: impl FnMut() -> eyre::Result<T>) -> eyre::Result<T> {
    let mut last = None;
    for attempt in 0..20 {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) => {
                if attempt > 0 {
                    eprintln!("  (retry {attempt}: {e})");
                }
                last = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
        }
    }
    Err(last.unwrap())
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let n_arg: Option<u64> = std::env::args().nth(1).map(|s| s.parse()).transpose()?;
    let datadir = std::env::var("RETH_DATADIR").map_err(|_| eyre::eyre!("set RETH_DATADIR"))?;

    // The ONE local DB handle (and its ONE ProviderFactory) this process
    // opens, for its whole lifetime.
    let db = retry(|| RethDb::latest(datadir.clone()))?;

    let tip = db.best_block_number()?;
    // Default one block behind the reported tip, not the tip itself: a
    // just-committed block's header can transiently 404 via `sealed_header`
    // right after `best_block_number()` reports it (observed empirically,
    // "header not found" immediately after being reported as tip) -- the
    // live node's static-file/MDBX views aren't perfectly atomic with each
    // other at the bleeding edge.
    let n = n_arg.unwrap_or(tip.saturating_sub(1));
    println!("datadir tip: {tip}, replaying block {n}\n");

    db.pin(n)?;
    let head = db.head(n).await?;
    let block = db.block(n).await?;
    println!("block {n}: {} tx(s)", block.txs.len());

    // A fresh `StateProviderBox` for block `target - 1`'s state, minted
    // from `db.factory()` (a new MDBX read transaction, not a new
    // environment) -- mirrors `RethDb::pin`'s own internal logic.
    // Uses the `tip` captured once at the top, NOT a freshly re-queried one
    // -- the live node keeps advancing during this run (183 txs' worth of
    // wall-clock time can cross several new blocks), so re-deriving "is
    // target-1 the tip" later raced `factory.latest()` onto a newer block
    // than the header/proof lookups below expect.
    // Try the historical index first, unconditionally -- a stale "is
    // target-1 the tip" guess is unsafe here: by the time this closure is
    // actually called (seconds into a long-running execution), the live
    // node may have advanced past whatever `tip` was captured as, and
    // `factory.latest()` always means "right now", not "as of `target`".
    // Only fall back to `.latest()` for the genuine edge case where the
    // target is too fresh to be in the historical index yet.
    let state_at = |target: u64| -> eyre::Result<StateProviderBox> {
        if target == 0 {
            return Ok(db.factory().latest()?);
        }
        match db.factory().history_by_block_number(target - 1) {
            Ok(state) => Ok(state),
            Err(_) => Ok(db.factory().latest()?),
        }
    };

    // 1. Execute block n against block (n-1) state via yevm.
    let mut cache = Cache::new();
    cache.set_chain_id(db.chain_id().await?);
    pre_block(&head, &mut cache, &db).await?;

    // Snapshot pre_block's own writes (EIP-4788 beacon root, etc.) BEFORE
    // the loop's first `cache.reset()`, which would otherwise silently
    // wipe them -- they never make it into `all_events` otherwise.
    let mut all_events: Vec<Trace> = cache.events.clone();
    for tx in block.txs {
        cache.reset(); // clears cache.events, NOT cache.accounts -- snapshot first
        let (t, call) = (tx.tx.clone(), tx.call.into());
        Executor::new(call)
            .run(t, head.clone(), &mut cache, &db)
            .await?;
        all_events.extend(cache.events.clone());
    }

    // EIP-7002 / EIP-7251: dequeue the withdrawal/consolidation request
    // queues -- runs unconditionally at block end, same timing class as
    // pre_block's EIP-4788/2935 writes, just at the other end of the block.
    cache.reset();
    yevm_core::exe::post_block(&mut cache, &db).await?;
    all_events.extend(cache.events.clone());

    // 2. Extract the diff from the accumulated events.
    let mut touched_accounts: BTreeSet<Address> = BTreeSet::new();
    let mut touched_slots: BTreeMap<Address, BTreeSet<B256>> = BTreeMap::new();
    let mut destroyed: BTreeSet<Address> = BTreeSet::new();

    // `event.reverted` marks events undone by `Cache::revert_to` (e.g. a
    // CREATE or SELFDESTRUCT inside a call frame that later reverted) --
    // they stay in the stream for tracing, but their effects never happened,
    // so they must not feed the diff (a reverted CREATE's account is gone
    // from `cache.accounts` entirely, which is what surfaced this).
    for event in all_events.iter().filter(|e| !e.reverted) {
        match &event.event {
            Event::Put(Target::Nonce { acc, .. }, _)
            | Event::Put(Target::Value { acc, .. }, _)
            | Event::Put(Target::Code { acc, .. }, _)
            | Event::Create(acc) => {
                touched_accounts.insert(acc_to_addr(acc));
            }
            Event::Delete(acc) => {
                destroyed.insert(acc_to_addr(acc));
            }
            Event::Move(a, b, _) => {
                touched_accounts.insert(acc_to_addr(a));
                touched_accounts.insert(acc_to_addr(b));
            }
            Event::Fee(sender, coinbase, ..) => {
                touched_accounts.insert(acc_to_addr(sender));
                touched_accounts.insert(acc_to_addr(coinbase));
            }
            Event::Put(Target::Store { acc, key, .. }, _) => {
                let addr = acc_to_addr(acc);
                touched_accounts.insert(addr);
                touched_slots
                    .entry(addr)
                    .or_default()
                    .insert(B256::from_slice(key.as_ref()));
            }
            _ => {}
        }
    }

    // 3. Withdrawals: the confirmed yevm gap. Read straight from the block
    // body (via the shared factory, no RPC), Gwei -> Wei, credit directly.
    let withdrawals = {
        let provider = db.factory().provider()?;
        let recovered = provider
            .sealed_block_with_senders(n.into(), TransactionVariant::WithHash)?
            .ok_or_else(|| eyre::eyre!("block {n} not found"))?;
        recovered.body().withdrawals.clone().unwrap_or_default()
    };
    println!("withdrawals: {}", withdrawals.len());

    for w in withdrawals.iter() {
        let addr = w.address;
        let amount_wei = U256::from(w.amount) * U256::from(1_000_000_000u64);
        let acc = addr_to_acc(addr);
        let current = match cache.account(&acc) {
            Some(a) => a.clone(),
            None => db.acc(&acc).await?,
        };
        let new_balance = int_to_u256(&current.value) + amount_wei;
        cache.insert_account(
            acc,
            Account {
                value: u256_to_int(new_balance),
                ..current
            },
        );
        touched_accounts.insert(addr);
    }

    println!(
        "touched accounts: {}, touched slots: {}, destroyed: {} {:?}\n",
        touched_accounts.len(),
        touched_slots.values().map(|s| s.len()).sum::<usize>(),
        destroyed.len(),
        destroyed
    );

    // 4. Bootstrap the partial account trie for block (n-1) from ordinary
    // inclusion proofs, batched into ONE `multiproof()` call for every
    // touched account instead of one `state.proof()` call per account.
    // Measured on a real 552-account block: per-account `proof()` calls cost
    // 5.44s of a 9.6s total run -- 552 independent root-to-leaf walks, each
    // redundantly re-touching the same shared upper trie levels. One
    // `multiproof()` call visits that shared prefix once and only fans out
    // where paths actually diverge, same as reth's own native incremental
    // state-root computation does internally (see PTRIE.md §8.5, where this
    // was flagged as a follow-up before actually doing it).
    // `AccountTrieProvider`/`RethProvider` (below) remain the on-demand
    // fallback (Phase B) for anything this batched proof doesn't carry, e.g.
    // a delete-collapse landing on an unincluded sibling.
    let state_root_n_minus_1 = db
        .factory()
        .provider()?
        .header_by_number(n - 1)?
        .ok_or_else(|| eyre::eyre!("header {} not found", n - 1))?
        .state_root();

    let proof_state = state_at(n)?;

    let mut proof_targets = MultiProofTargets::default();
    for &addr in touched_accounts.iter().chain(destroyed.iter()) {
        let entry = proof_targets.entry(keccak256(addr)).or_default();
        if let Some(slots) = touched_slots.get(&addr) {
            entry.extend(slots.iter().map(keccak256));
        }
    }
    let multiproof = proof_state.multiproof(Default::default(), proof_targets)?;

    let mut account_witness: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    let mut current_leaves: BTreeMap<Address, TrieAccount> = BTreeMap::new();
    let mut storage_tries: BTreeMap<Address, Trie<Keccak256>> = BTreeMap::new();

    for &addr in touched_accounts.iter().chain(destroyed.iter()) {
        let slots: Vec<B256> = touched_slots
            .get(&addr)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        let account_proof = multiproof
            .account_proof(addr, &slots)
            .map_err(|e| eyre::eyre!("account_proof for {addr}: {e}"))?;

        for b in &account_proof.proof {
            let bytes = b.to_vec();
            if bytes.as_slice() != [0x80] {
                account_witness.insert(keccak(&bytes), bytes);
            }
        }

        let info = account_proof.info.unwrap_or_default();
        current_leaves.insert(
            addr,
            TrieAccount {
                nonce: info.nonce,
                balance: info.balance,
                storage_root: account_proof.storage_root,
                code_hash: info.get_bytecode_hash(),
            },
        );

        if touched_slots.contains_key(&addr) {
            let mut storage_witness: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
            for sp in &account_proof.storage_proofs {
                for b in &sp.proof {
                    let bytes = b.to_vec();
                    if bytes.as_slice() != [0x80] {
                        storage_witness.insert(keccak(&bytes), bytes);
                    }
                }
            }
            let partial: Node<Keccak256> =
                build_partial(&storage_witness, &account_proof.storage_root.0);
            eyre::ensure!(
                node_root(&partial) == account_proof.storage_root.0,
                "storage reconstruction failed for {addr}"
            );
            storage_tries.insert(addr, Trie::from_node(partial));
        }
    }
    drop(proof_state);

    let account_partial: Node<Keccak256> = build_partial(&account_witness, &state_root_n_minus_1.0);
    eyre::ensure!(
        node_root(&account_partial) == state_root_n_minus_1.0,
        "account trie reconstruction failed"
    );
    let mut account_trie = Trie::<Keccak256>::from_node(account_partial);

    // 5. Apply the diff, driving every mutation through the on-demand
    // providers uniformly (Phase B's collapse-resolution kicks in
    // automatically if a removal needs a node the initial proof didn't
    // carry). One shared `StateProviderBox`, minted once -- for a block far
    // behind the chain tip, `history_by_block_number` can be expensive to
    // reconstruct, so it must NOT be re-minted per touched account.
    let apply_state = std::rc::Rc::new(state_at(n)?);
    let account_provider = RecordingProvider::new(AccountTrieProvider::new(apply_state.clone()));
    let mut stubs_resolved = 0usize;

    for addr in destroyed.iter() {
        let hashed = keccak256(addr);
        account_trie
            .remove_with(&account_provider, hashed.as_slice())
            .map_err(|e| eyre::eyre!("removing {addr}: {e:?}"))?;
    }

    for (addr, slots) in touched_slots.iter() {
        if destroyed.contains(addr) {
            continue;
        }
        let acc = addr_to_acc(*addr);
        let trie = storage_tries
            .get_mut(addr)
            .ok_or_else(|| eyre::eyre!("missing storage trie for {addr}"))?;
        let provider = RecordingProvider::new(RethProvider::new(apply_state.clone(), *addr));
        if std::env::var("DEBUG_ADDR")
            .map(|s| s.eq_ignore_ascii_case(&addr.to_string()))
            .unwrap_or(false)
        {
            eprintln!("DEBUG {addr}: {} touched slot(s)", slots.len());
            for slot in slots.iter() {
                let key: Int = Int::from(slot.as_slice());
                let value = cache.storage(&acc, &key).unwrap_or_default();
                eprintln!("  {slot} = {value}");
            }
        }
        for slot in slots.iter() {
            let key: Int = Int::from(slot.as_slice());
            let value = cache.storage(&acc, &key).unwrap_or_default();
            let hashed_slot = keccak256(slot.as_slice());
            let slot_key: [u8; 32] = hashed_slot.into();
            if value.is_zero() {
                trie.remove_with(&provider, &slot_key)
                    .map_err(|e| eyre::eyre!("removing {addr}/{slot}: {e:?}"))?;
            } else {
                let mut buf = Vec::new();
                int_to_u256(&value).encode(&mut buf);
                trie.insert_with(&provider, &slot_key, buf)
                    .map_err(|e| eyre::eyre!("inserting {addr}/{slot}: {e:?}"))?;
            }
        }
        let seen = provider.seen();
        stubs_resolved += seen.len();
    }

    // DIAGNOSTIC: cross-check each computed leaf against the real post-block
    // (state resulting from block n, i.e. "before n+1") account info, to
    // pinpoint which field/account first diverges instead of just the final
    // root. Fetched the same way as the n-1 bootstrap, just one block later.
    let real_state_n = state_at(n + 1)?;
    let mut mismatches = 0;
    // Bounded SAMPLE of accounts to spot-check (expensive: one `proof()` call
    // each) -- gated on how many we've LOOKED AT, not how many turned out
    // mismatched, which on a clean run never trips and ends up checking
    // every single touched account (the dominant cost after trie bootstrap).
    let mut checked = 0;

    // Per-slot check across EVERY touched (account, slot) pair -- not just
    // the accounts an account-level storageRoot mismatch happens to flag.
    // Cheap point lookups (`StateProvider::storage`), not a full proof
    // fetch per slot.
    let mut slot_mismatches = 0;
    for (addr, slots) in touched_slots.iter() {
        if destroyed.contains(addr) {
            continue;
        }
        let acc = addr_to_acc(*addr);
        for slot in slots.iter() {
            let key: Int = Int::from(slot.as_slice());
            let got = cache.storage(&acc, &key).unwrap_or_default();
            let expected = real_state_n.storage(*addr, *slot)?.unwrap_or_default();
            if int_to_u256(&got) != expected {
                slot_mismatches += 1;
                if slot_mismatches <= 20 {
                    eprintln!(
                        "SLOT MISMATCH {addr}/{slot}: got {}, expected {}",
                        int_to_u256(&got),
                        expected
                    );
                }
            }
        }
    }
    println!("slot-level mismatches found (capped at 20 printed): {slot_mismatches}\n");

    for addr in touched_accounts.iter() {
        if destroyed.contains(addr) {
            continue;
        }
        let acc = addr_to_acc(*addr);
        let account = cache
            .account(&acc)
            .cloned()
            .ok_or_else(|| eyre::eyre!("no final state for touched account {addr}"))?;

        let storage_root = match storage_tries.get_mut(addr) {
            Some(trie) => B256::from(trie.hash()),
            None => current_leaves
                .get(addr)
                .map(|l| l.storage_root)
                .unwrap_or(EMPTY_ROOT_HASH),
        };

        let code = account.code.0.0;
        let code_hash = if code.is_empty() {
            KECCAK_EMPTY
        } else {
            keccak256(&code)
        };

        let leaf = TrieAccount {
            nonce: int_to_u256(&account.nonce).try_into().unwrap_or_default(),
            balance: int_to_u256(&account.value),
            storage_root,
            code_hash,
        };

        if checked < 20 {
            checked += 1;
            let real_proof = real_state_n.proof(Default::default(), *addr, &[])?;
            let real = real_proof.info.unwrap_or_default();
            if real.nonce != leaf.nonce
                || real.balance != leaf.balance
                || real_proof.storage_root != leaf.storage_root
                || real.get_bytecode_hash() != leaf.code_hash
            {
                mismatches += 1;
                eprintln!("MISMATCH {addr}:");
                if real.nonce != leaf.nonce {
                    eprintln!("  nonce: got {}, expected {}", leaf.nonce, real.nonce);
                }
                if real.balance != leaf.balance {
                    eprintln!("  balance: got {}, expected {}", leaf.balance, real.balance);
                }
                if real_proof.storage_root != leaf.storage_root {
                    eprintln!(
                        "  storageRoot: got {}, expected {}",
                        leaf.storage_root, real_proof.storage_root
                    );
                }
                if real.get_bytecode_hash() != leaf.code_hash {
                    eprintln!(
                        "  codeHash: got {}, expected {}",
                        leaf.code_hash,
                        real.get_bytecode_hash()
                    );
                }
            }
        }

        let mut buf = Vec::new();
        leaf.encode(&mut buf);

        let hashed = keccak256(addr);
        account_trie
            .insert_with(&account_provider, hashed.as_slice(), buf)
            .map_err(|e| eyre::eyre!("inserting {addr}: {e:?}"))?;
    }
    println!("account-level mismatches found (capped at 20): {mismatches}\n");

    stubs_resolved += account_provider.seen().len();
    println!("{stubs_resolved} stubs resolved\n");

    // 6. Compare.
    let state_root_n = db
        .factory()
        .provider()?
        .header_by_number(n)?
        .ok_or_else(|| eyre::eyre!("header {n} not found"))?
        .state_root();
    let got = B256::from(account_trie.hash());

    println!("expected stateRoot: {state_root_n}");
    println!("computed stateRoot: {got}");
    println!(
        "\n{}",
        if state_root_n == got {
            "MATCH"
        } else {
            "MISMATCH"
        }
    );

    Ok(())
}
