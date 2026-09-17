//! Transaction pool.
//!
//! Plays the role of midstate's `mempool.rs` (fee floor, per-block pruning,
//! reorg restoration, bounded size) for MimbleWimble transactions.
//!
//! One MimbleWimble-specific wrinkle: a block body is an *aggregate*, so the
//! transactions it contained cannot be recovered from it once the kernel
//! offsets are summed. Midstate restores abandoned transactions after a reorg
//! by reading them back out of the orphaned blocks; that is impossible here.
//! Instead, as Grin does, transactions that leave the pool because they were
//! mined are kept in a small [`ReorgCache`] keyed by block height and offered
//! back to the pool if their block is reorganised away.

use crate::core::mw::{Context, Point32, Transaction};
use crate::core::state::apply_body;
use crate::core::types::{MAX_BLOCK_WEIGHT, MIN_FEE_PER_WEIGHT};
use crate::core::{Batch, State};
use anyhow::{bail, Result};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

/// Roughly 25 full blocks.
pub const MAX_POOL_WEIGHT: u64 = 25 * MAX_BLOCK_WEIGHT;
const REORG_CACHE_BLOCKS: usize = 128;

struct Entry {
    tx: Transaction,
    fee: u64,
    weight: u64,
    #[allow(dead_code)]
    received: Instant,
}

impl Entry {
    /// Fee per weight unit scaled by 2^16, for ordering without floats.
    fn rate(&self) -> u128 {
        ((self.fee as u128) << 16) / self.weight.max(1) as u128
    }
}

#[derive(Default)]
pub struct Mempool {
    entries: HashMap<[u8; 32], Entry>,
    spends: HashMap<Point32, [u8; 32]>,
    creates: HashMap<Point32, [u8; 32]>,
    kernels: HashMap<[u8; 32], [u8; 32]>,
    total_weight: u64,
}

impl Mempool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    pub fn contains(&self, tx_hash: &[u8; 32]) -> bool {
        self.entries.contains_key(tx_hash)
    }

    pub fn transactions(&self) -> Vec<Transaction> {
        self.entries.values().map(|e| e.tx.clone()).collect()
    }

    /// Everything the pool would do except insertion: relay policy, full
    /// stateless validation, stateful validation against `state`, and
    /// conflicts with pool contents.
    ///
    /// `already_validated` skips the expensive stateless checks (proofs and
    /// signatures) for transactions the caller verified off-thread.
    pub fn check(&self, tx: &Transaction, state: &State, already_validated: bool) -> Result<()> {
        if self.entries.contains_key(&tx.hash()) {
            bail!("transaction already in pool");
        }
        if already_validated {
            tx.validate_structure(Context::Relay)?;
            tx.verify_sums()?;
        } else {
            tx.validate(Context::Relay)?;
        }
        let fee = tx.fee()?;
        let min_fee = tx.weight().saturating_mul(MIN_FEE_PER_WEIGHT);
        if fee < min_fee {
            bail!(
                "fee {} below relay minimum {} for weight {}",
                fee,
                min_fee,
                tx.weight()
            );
        }
        if tx.lock_height() > state.height {
            bail!(
                "transaction is time-locked until height {}",
                tx.lock_height()
            );
        }
        for c in tx.input_commitments() {
            if self.spends.contains_key(c) {
                bail!("input already spent by a pool transaction");
            }
            if self.creates.contains_key(c) {
                bail!("spending unconfirmed outputs is not supported");
            }
        }
        for c in tx.output_commitments() {
            if self.creates.contains_key(c) {
                bail!("output commitment already created by a pool transaction");
            }
        }
        for k in tx.kernel_ids() {
            if self.kernels.contains_key(&k) {
                bail!("kernel already in pool");
            }
        }
        // Inputs exist with matching owner keys and maturity, outputs are new,
        // kernels have never been mined: exactly the consensus rules.
        apply_body(state, tx, None)?;
        Ok(())
    }

    /// Validates and inserts. Evicts lower-fee-rate transactions if full.
    pub fn add(&mut self, tx: Transaction, state: &State, already_validated: bool) -> Result<()> {
        self.check(&tx, state, already_validated)?;
        let entry = Entry {
            fee: tx.fee()?,
            weight: tx.weight(),
            tx,
            received: Instant::now(),
        };

        while self.total_weight + entry.weight > MAX_POOL_WEIGHT {
            let worst = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.rate())
                .map(|(h, e)| (*h, e.rate()));
            match worst {
                Some((hash, rate)) if rate < entry.rate() => {
                    self.remove(&hash);
                }
                _ => bail!("mempool full"),
            }
        }
        self.insert(entry);
        Ok(())
    }

    fn insert(&mut self, entry: Entry) {
        let hash = entry.tx.hash();
        for c in entry.tx.input_commitments() {
            self.spends.insert(*c, hash);
        }
        for c in entry.tx.output_commitments() {
            self.creates.insert(*c, hash);
        }
        for k in entry.tx.kernel_ids() {
            self.kernels.insert(k, hash);
        }
        self.total_weight += entry.weight;
        self.entries.insert(hash, entry);
    }

    fn remove(&mut self, hash: &[u8; 32]) -> Option<Transaction> {
        let entry = self.entries.remove(hash)?;
        for c in entry.tx.input_commitments() {
            self.spends.remove(c);
        }
        for c in entry.tx.output_commitments() {
            self.creates.remove(c);
        }
        for k in entry.tx.kernel_ids() {
            self.kernels.remove(&k);
        }
        self.total_weight -= entry.weight;
        Some(entry.tx)
    }

    /// Updates the pool after `batch` was applied, producing `state`.
    ///
    /// Returns the transactions that were mined (for the reorg cache). Any
    /// remaining transaction that no longer applies (its input was spent by a
    /// different transaction, a kernel collided, ...) is dropped.
    pub fn on_block(&mut self, batch: &Batch, state: &State) -> Vec<Transaction> {
        let mined_kernels: HashSet<[u8; 32]> = batch.body.kernel_ids().into_iter().collect();
        let spent: HashSet<&Point32> = batch.body.input_commitments().collect();

        let mut mined = Vec::new();
        let mut doomed = HashSet::new();
        for (hash, entry) in &self.entries {
            let ids = entry.tx.kernel_ids();
            if !ids.is_empty() && ids.iter().all(|k| mined_kernels.contains(k)) {
                mined.push(*hash);
            } else if ids.iter().any(|k| mined_kernels.contains(k))
                || entry.tx.input_commitments().any(|c| spent.contains(c))
            {
                doomed.insert(*hash);
            }
        }
        let mined_txs: Vec<Transaction> = mined.iter().filter_map(|h| self.remove(h)).collect();
        for h in doomed {
            self.remove(&h);
        }
        self.revalidate(state);
        mined_txs
    }

    /// Drops every transaction that no longer applies on `state`.
    pub fn revalidate(&mut self, state: &State) {
        let invalid: Vec<[u8; 32]> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                e.tx.lock_height() > state.height || apply_body(state, &e.tx, None).is_err()
            })
            .map(|(h, _)| *h)
            .collect();
        for h in invalid {
            self.remove(&h);
        }
    }

    /// Candidates for a block template, best fee rate first.
    pub fn candidates(&self) -> Vec<Transaction> {
        let mut entries: Vec<&Entry> = self.entries.values().collect();
        entries.sort_by(|a, b| b.rate().cmp(&a.rate()));
        entries.into_iter().map(|e| e.tx.clone()).collect()
    }
}

/// Recently mined transactions, kept so a reorg can put them back.
#[derive(Default)]
pub struct ReorgCache {
    blocks: VecDeque<(u64, Vec<Transaction>)>,
}

impl ReorgCache {
    pub fn record(&mut self, height: u64, txs: Vec<Transaction>) {
        if txs.is_empty() {
            return;
        }
        self.blocks.push_back((height, txs));
        while self.blocks.len() > REORG_CACHE_BLOCKS {
            self.blocks.pop_front();
        }
    }

    /// Removes and returns every cached transaction mined at `height` or above.
    pub fn take_from(&mut self, height: u64) -> Vec<Transaction> {
        let mut out = Vec::new();
        while let Some((h, _)) = self.blocks.back() {
            if *h < height {
                break;
            }
            if let Some((_, txs)) = self.blocks.pop_back() {
                out.extend(txs);
            }
        }
        out
    }
}

#[cfg(all(test, feature = "fast-mining"))]
mod tests {
    use super::*;
    use crate::core::mw::{build_transaction, scan_output, Payment, Spendable, WalletKeys};
    use crate::core::state::apply_batch;
    use crate::core::template::build_template;
    use crate::core::types::COINBASE_MATURITY;

    struct Setup {
        state: State,
        ts: Vec<u64>,
        coin: Spendable,
        keys: WalletKeys,
    }

    fn setup() -> Setup {
        let keys = WalletKeys::random();
        let mut state = State::genesis();
        apply_batch(&mut state, Batch::genesis(), &[]).unwrap();
        let mut ts = vec![Batch::genesis().timestamp];
        let mut coin = None;
        for i in 0..=COINBASE_MATURITY {
            let b = build_template(&state, &ts, &[], &keys.address(), None)
                .unwrap()
                .mine_blocking();
            if i == 0 {
                let out = &b.coinbase.as_ref().unwrap().outputs.outputs[0];
                let owned = scan_output(&keys, out).unwrap();
                coin = Some(Spendable {
                    commitment: out.commitment,
                    value: owned.value,
                    blinding: owned.blinding,
                    owner_secret: owned.owner_secret,
                });
            }
            apply_batch(&mut state, &b, &ts).unwrap();
            ts.push(b.timestamp);
        }
        Setup {
            state,
            ts,
            coin: coin.unwrap(),
            keys,
        }
    }

    fn pay(s: &Setup, value: u64, fee: u64) -> Transaction {
        build_transaction(
            &[s.coin.clone()],
            &[Payment {
                to: WalletKeys::random().address(),
                value,
            }],
            &s.keys.address(),
            fee,
            s.state.height,
        )
        .unwrap()
        .tx
    }

    #[test]
    fn admission_rules() {
        let s = setup();
        let mut pool = Mempool::new();
        let low = pay(&s, 10, 1);
        assert!(pool
            .add(low, &s.state, false)
            .unwrap_err()
            .to_string()
            .contains("below relay minimum"));
        let good = pay(&s, 10, 100_000);
        pool.add(good.clone(), &s.state, false).unwrap();
        assert!(pool.add(good, &s.state, false).is_err());
        let conflict = pay(&s, 11, 200_000);
        assert!(pool
            .add(conflict, &s.state, false)
            .unwrap_err()
            .to_string()
            .contains("already spent"));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn mined_transactions_leave_and_can_be_restored() {
        let s = setup();
        let mut pool = Mempool::new();
        let tx = pay(&s, 10, 100_000);
        pool.add(tx.clone(), &s.state, false).unwrap();

        let mut state = s.state.clone();
        let payout = WalletKeys::random().address();
        let block = build_template(&state, &s.ts, &pool.candidates(), &payout, None)
            .unwrap()
            .mine_blocking();
        apply_batch(&mut state, &block, &s.ts).unwrap();

        let mined = pool.on_block(&block, &state);
        assert_eq!(mined.len(), 1);
        assert!(pool.is_empty());

        let mut cache = ReorgCache::default();
        cache.record(s.state.height, mined);
        let restored = cache.take_from(s.state.height);
        assert_eq!(restored.len(), 1);
        // On the pre-block state (the reorg target) it is valid again.
        pool.add(restored[0].clone(), &s.state, true).unwrap();
        // On the post-block state it is not (inputs spent, kernel mined).
        assert!(Mempool::new()
            .add(restored[0].clone(), &state, true)
            .is_err());
    }
}
