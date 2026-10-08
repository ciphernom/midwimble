//! Provably fair Stratum pool, ported from midstate `src/pool.rs`.
//!
//! Every block pays the shares in a PPLNS window directly in its coinbase,
//! every job commits to that window before anyone hashes on it, and every
//! miner checks its own payout before mining:
//!
//! * **Shares.** Each accepted share gets a sequence number in a share log
//!   and weighs `2^(difficulty - minimum)`; each connection's difficulty is
//!   steered toward one share per [`PoolConfig::share_interval`].
//! * **Window.** A block pays the newest shares worth
//!   [`PoolConfig::window_blocks`] blocks, summed per owner ([`Window`]).
//!   Nothing is deducted when a block is found, so there are no balances to
//!   settle or restore after a reorganisation, and a share's expected payout
//!   does not depend on when in a round it was found.
//! * **Payouts.** A coinbase has room for [`MAX_PAID_MINERS`] miners. An
//!   owner entitled to at least 1/31 of the block is paid exactly that. The
//!   rest is split into equal slots assigned by systematic sampling, so each
//!   smaller owner's *expected* payout is exactly its entitlement
//!   ([`payout_weights`]). Splitting the same work across addresses changes
//!   nobody's expected payout; a top-N cutoff could not offer that.
//! * **Commitment.** The coinbase `extra` commits to the window a job pays
//!   and to the window it freezes for the next tip ([`job_commitment`]). The
//!   draw is seeded with the block the job builds on ([`draw_seed`]), and a
//!   job on a new tip must pay the window frozen on the previous one, which
//!   miners saw before the new tip existed: the pool cannot steer the draw by
//!   choosing which shares to count.
//! * **Ownership.** Each miner mines its own copy of a job, whose `extra`
//!   binds the commitment to the miner's address ([`bind_extra`]) and which
//!   the node signs again under the pool's bond (`/mining/bind`). A nonce one
//!   miner finds proves nothing for anyone else's copy, so nobody can be
//!   credited with someone else's work: not another miner replaying it, and
//!   not a man in the middle rewriting `mining.authorize`, who can only stop
//!   the victim, whose audit then fails.
//! * **Miner audit** ([`audit_job_with_fee_limit`], [`check_window_chain`]):
//!   the miner's copy must hash to the announced mining hash and pay the
//!   reward at the claimed height; its `extra` must bind the published
//!   windows to the miner's own address; the window must credit every share
//!   the pool told the miner it accepted; and the coinbase must pay the miner
//!   exactly what the payout rule gives it, proven by [`PayoutReceipt`]s. Any
//!   failure disconnects.
//!
//! The pool can still count shares of its own that nobody mined; making that
//! detectable needs the shares themselves published so anyone can re-check
//! a sample.
//!
//! **Verification.** Checking a share means recomputing its whole sequential
//! proof of work (about 70 ms of a core at mainnet settings), and a junk share
//! costs its sender nothing, so verification is the resource to protect:
//!
//! * A share is never dropped for lack of capacity. Each connection has at
//!   most one share in verification and is not read from until it finishes,
//!   so a busy pool slows its miners' submissions rather than losing them. A
//!   share is credited against the job it was submitted for, even if a newer
//!   job replaced that one while it waited.
//! * Worker threads serve connections that have already submitted a valid
//!   share first. Unproven connections, which is all an attacker without
//!   hashrate can have, share a bounded slice of the workers.
//! * Workers verify shares in SIMD batches ([`verify_pow_batch`]), several
//!   times the throughput of verifying them one at a time.
//! * A share that fails verification bans its IPv4 address or IPv6 /64, for a
//!   minute the first time and four times longer for each repeat within a day.
//!   A correct miner never sends one: it checks the hash before submitting.
//! * Connections are capped per address and in total, and a message longer
//!   than [`MAX_LINE`] bytes closes the connection.
//!
//! Wire format (JSON lines over TCP):
//!
//! ```text
//! → {"id":1,"method":"mining.authorize","params":[address, worker]}
//! ← {"id":1,"result":{"api": "<host:port>"}}
//! ← {"id":null,"method":"mining.notify","params":[job_id, mining_hash, template_hex, share_target, network_target, extra, miner_auth]}
//! → {"id":2,"method":"mining.submit","params":[address, job_id, nonce]}
//! ← {"id":2,"result":true,"block":false,"seq":n,"weight":w} | {"id":2,"result":false,"error":"..."}
//! ```
//!
//! `template_hex` is the same for every miner; `extra` and `miner_auth` (the
//! bond signature, or null) turn it into the miner's own copy, whose mining
//! hash is `mining_hash` ([`bind_template`]).
//!
//! The audit API answers for any of the last 16 jobs:
//! `/api/window?job=N` (the paid window, the next window's root, the fee and
//! the operator's address) and `/api/proof?address=A&job=N` (A's receipts).

use crate::core::extension::MiningResult;
use crate::core::mw::{PayoutReceipt, StealthAddress};
use crate::core::simd_mining::{detected_level, pow_seed, verify_pow_batch};
use crate::core::types::Extension;
use crate::core::types::{compute_header_hash, hash_concat, hash_domain, Batch};
use crate::rpc::RpcClient;
use anyhow::{anyhow, bail, Context, Result};
use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use redb::{Database, ReadableTable, TableDefinition};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, oneshot, RwLock};

/// One coinbase output is the pool fee; the rest pay miners.
pub const MAX_PAID_MINERS: usize = crate::core::mw::crypto::MAX_GROUP_OUTPUTS - 1;

/// The score table of the previous payout scheme. Read once, on the first
/// start of this version, to carry unpaid scores into the share log.
const LEGACY_SCORES: TableDefinition<&[u8], u64> = TableDefinition::new("shares");
/// Accepted shares by sequence number: owner key ‖ weight (little endian).
const SHARE_LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("share_log");
/// Blocks the pool found, by hash: a JSON record for `/pool/stats`.
const FOUND: TableDefinition<&[u8], &str> = TableDefinition::new("found_blocks");

/// scan ‖ spend ‖ recovery: a payout address in fixed-size form.
type AddrKey = [u8; 96];

fn addr_key(a: &StealthAddress) -> AddrKey {
    let mut k = [0u8; 96];
    k[..32].copy_from_slice(&a.scan);
    k[32..64].copy_from_slice(&a.spend);
    k[64..].copy_from_slice(&a.recovery);
    k
}

fn key_addr(k: &[u8]) -> Result<StealthAddress> {
    if k.len() != 96 {
        bail!("bad address key");
    }
    let mut scan = [0u8; 32];
    let mut spend = [0u8; 32];
    let mut recovery = [0u8; 32];
    scan.copy_from_slice(&k[..32]);
    spend.copy_from_slice(&k[32..64]);
    recovery.copy_from_slice(&k[64..]);
    Ok(StealthAddress {
        scan,
        spend,
        recovery,
    })
}

/// `2^(256-bits)`: a hash below it has at least `bits` leading zero bits.
pub fn target_from_leading_zero_bits(bits: u32) -> [u8; 32] {
    // The largest value with `bits` leading zeros: all ones shifted right.
    (primitive_types::U256::MAX >> bits.min(256) as usize).to_big_endian()
}

// ── Score commitment (midstate's ShareMerkleTree) ───────────────────────────

pub fn score_leaf(addr: &AddrKey, score: u64) -> [u8; 32] {
    hash_domain(b"midwimble.pool.leaf.v1", &[addr, &score.to_le_bytes()])
}

#[derive(Clone, Default)]
pub struct ShareMerkleTree {
    pub root: [u8; 32],
    pub leaves: Vec<(AddrKey, u64)>,
    layers: Vec<Vec<[u8; 32]>>,
}

impl ShareMerkleTree {
    pub fn build(mut shares: Vec<(AddrKey, u64)>) -> Self {
        if shares.is_empty() {
            return Self::default();
        }
        shares.sort_by(|a, b| a.0.cmp(&b.0));
        let mut layer: Vec<[u8; 32]> = shares.iter().map(|(a, s)| score_leaf(a, *s)).collect();
        let mut layers = vec![layer.clone()];
        while layer.len() > 1 {
            layer = layer
                .chunks(2)
                .map(|c| {
                    if c.len() == 2 {
                        hash_concat(&c[0], &c[1])
                    } else {
                        hash_concat(&c[0], &c[0])
                    }
                })
                .collect();
            layers.push(layer.clone());
        }
        Self {
            root: layer[0],
            leaves: shares,
            layers,
        }
    }

    pub fn proof(&self, addr: &AddrKey) -> Option<(usize, Vec<[u8; 32]>)> {
        let idx = self.leaves.iter().position(|(a, _)| a == addr)?;
        let mut proof = Vec::new();
        let mut i = idx;
        for layer in &self.layers[..self.layers.len() - 1] {
            let sibling = if i % 2 == 1 {
                i - 1
            } else {
                (i + 1).min(layer.len() - 1)
            };
            proof.push(layer[sibling]);
            i /= 2;
        }
        Some((idx, proof))
    }
}

pub fn fold_proof(leaf: [u8; 32], index: usize, proof: &[[u8; 32]]) -> [u8; 32] {
    let (mut h, mut i) = (leaf, index);
    for sibling in proof {
        h = if i % 2 == 1 {
            hash_concat(sibling, &h)
        } else {
            hash_concat(&h, sibling)
        };
        i /= 2;
    }
    h
}

// ── Payouts: a PPLNS window, exact or sampled ───────────────────────────────

// Use fixed-point fee fractions, not ceil(score * fee / (100 - fee)).
// The old formula paid 50% to the operator for a single share and a 2% fee.
const FEE_SCALE: u64 = 1_000_000;

fn fee_ppm(percent: f64) -> Result<u64> {
    if !percent.is_finite() || !(0.0..100.0).contains(&percent) {
        bail!("pool fee must be at least 0 and below 100 percent");
    }
    Ok((percent * 10_000.0).round() as u64)
}

/// The total that [`payout_weights`] divides. The node scales the weights
/// to the block's actual reward plus fees (`template::split_by_weight`), so
/// they only need to be precise, not to know the fees.
pub const PAYOUT_SCALE: u64 = 1 << 50;

/// The shares a block pays: the newest accepted shares, by sequence number
/// `start_seq..end_seq`, summed per owner.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Window {
    pub start_seq: u64,
    pub end_seq: u64,
    /// Total share weight per owner, sorted by key, every weight positive.
    pub owners: Vec<(AddrKey, u64)>,
}

impl Window {
    /// What a job commits to: the owners' Merkle root bound to how many
    /// owners there are, their total weight and the sequence range. The count
    /// keeps the tree's duplicated odd node from letting two lists share a
    /// root.
    pub fn root(&self) -> [u8; 32] {
        let tree = ShareMerkleTree::build(self.owners.clone());
        let total: u128 = self.owners.iter().map(|(_, w)| *w as u128).sum();
        hash_domain(
            b"midwimble.pool.window.v1",
            &[
                &tree.root,
                &(self.owners.len() as u64).to_le_bytes(),
                &total.to_le_bytes(),
                &self.start_seq.to_le_bytes(),
                &self.end_seq.to_le_bytes(),
            ],
        )
    }
}

/// The coinbase `extra` of a job: the window it pays, and the window it
/// freezes for the jobs on the next tip.
pub fn job_commitment(paying_root: &[u8; 32], next_root: &[u8; 32]) -> [u8; 32] {
    hash_domain(b"midwimble.pool.commit.v2", &[paying_root, next_root])
}

/// The coinbase `extra` of `miner`'s copy of a job with `commitment`. Each
/// miner hashes on its own copy, so a nonce one miner finds proves nothing
/// for anyone else's: a share cannot be credited to someone who did not do
/// its work, even by a man in the middle, who can only stop a miner whose
/// audit then fails.
pub fn bind_extra(commitment: &[u8; 32], miner: &[u8; 96]) -> [u8; 32] {
    hash_domain(b"midwimble.pool.bind.v1", &[commitment, miner])
}

/// The draw that decides the sampled payouts of a job built on the block
/// `prev_header_hash`. The window it pays was frozen and shown to miners
/// before that block existed, so the pool cannot steer the draw by choosing
/// which shares to include.
///
/// One way around this remains: a pool that holds back announcing a tip
/// until it has seen the next block can freeze that tip's window with the
/// next block's hash in view. Its miners then work on a stale job for a
/// block interval, which costs the pool its own chance of a block meanwhile;
/// a miner following the chain with a node of its own can see the delay.
pub fn draw_seed(prev_header_hash: &[u8; 32], paying_root: &[u8; 32]) -> [u8; 32] {
    hash_domain(b"midwimble.pool.draw.v1", &[prev_header_hash, paying_root])
}

/// Splits `total` among `owners` in proportion to weight, with at most
/// [`MAX_PAID_MINERS`] owners paid.
///
/// * An owner entitled to at least 1/31 of `total` is paid its entitlement,
///   rounded down.
/// * The rest is split into equal slots, one per remaining output, and the
///   slots are assigned by systematic sampling: the smaller owners are laid
///   end to end by key, each spanning its weight, and the slots are evenly
///   spaced points along that line, the first at `offset` (taken modulo the
///   smaller owners' total weight). Over a uniformly random offset each
///   owner's expected number of slots is exactly proportional to its weight,
///   so splitting the same work across addresses changes nobody's expected
///   payout.
///
/// Returns amounts in key order, and separately the rounding dust: what
/// rounding the exact payments and the slot value down left over.
fn allocate(total: u128, owners: &[(AddrKey, u64)], offset: u128) -> (Vec<(AddrKey, u128)>, u128) {
    let weight: u128 = owners.iter().map(|(_, w)| *w as u128).sum();
    if weight == 0 {
        return (Vec::new(), total);
    }
    let slots_total = MAX_PAID_MINERS as u128;
    let mut paid: Vec<(AddrKey, u128)> = Vec::new();
    let mut small: Vec<(AddrKey, u128)> = Vec::new();
    let mut exact = 0u128;
    for (key, w) in owners {
        let w = *w as u128;
        if w * slots_total >= weight {
            let amount = total * w / weight;
            exact += amount;
            paid.push((*key, amount));
        } else if w > 0 {
            small.push((*key, w));
        }
    }
    let rest = total - exact;
    if small.is_empty() {
        return (paid, rest);
    }
    // At least one slot is left: 31 owners of 1/31 or more would leave
    // nothing for the smaller ones.
    let slots = slots_total - paid.len() as u128;
    let small_weight: u128 = small.iter().map(|(_, w)| *w).sum();
    let offset = offset % small_weight;
    // Point k sits at offset + k·small_weight on a line where owner j spans
    // [slots·before_j, slots·(before_j + w_j)).
    let first_slot_at = |x: u128| -> u128 {
        if x <= offset {
            0
        } else {
            (x - offset).div_ceil(small_weight).min(slots)
        }
    };
    // Every slot is worth the same, whichever owner it lands on: a remainder
    // shared out by slot position would favour some positions on the line.
    let slot_value = rest / slots;
    let mut before = 0u128;
    for (key, w) in small {
        let from = first_slot_at(slots * before);
        before += w;
        let to = first_slot_at(slots * before);
        let amount = (to - from) * slot_value;
        if amount > 0 {
            paid.push((key, amount));
        }
    }
    paid.sort_by_key(|a| a.0);
    (paid, rest - slots * slot_value)
}

/// Coinbase payout weights for a job: the operator's fee and the miners'
/// payouts from `window`, drawn with `seed`, out of [`PAYOUT_SCALE`].
pub fn payout_weights(
    fee_ppm: u64,
    operator: &StealthAddress,
    window: &[(AddrKey, u64)],
    seed: &[u8; 32],
) -> Result<Vec<(StealthAddress, u64)>> {
    if fee_ppm >= FEE_SCALE {
        bail!("invalid pool fee fraction");
    }
    let scale = PAYOUT_SCALE as u128;
    let fee = scale * fee_ppm as u128 / FEE_SCALE as u128;
    let offset = primitive_types::U256::from_big_endian(seed);
    let offset = (offset % primitive_types::U256::from(u128::MAX)).as_u128();
    let (miners, dust) = allocate(scale - fee, window, offset);
    let mut weights = Vec::with_capacity(miners.len() + 1);
    if fee + dust > 0 {
        weights.push((*operator, (fee + dust) as u64));
    }
    for (key, amount) in miners {
        weights.push((key_addr(&key)?, amount as u64));
    }
    Ok(weights)
}

/// A frozen [`Window`] and its root.
struct WindowSnapshot {
    window: Window,
    root: [u8; 32],
}

impl WindowSnapshot {
    fn new(window: Window) -> Self {
        let root = window.root();
        Self { window, root }
    }
}

/// How much share weight a window holds: `window_blocks` blocks' worth at
/// `network_target`, in shares of the pool's minimum difficulty.
fn window_size(network_target: &[u8; 32], share_bits: u32, window_blocks: u64) -> u128 {
    use primitive_types::U256;
    let target = U256::from_big_endian(network_target).max(U256::one());
    let per_block = (U256::MAX / target) >> share_bits.min(255) as usize;
    let size = per_block.saturating_mul(U256::from(window_blocks.max(1)));
    if size > U256::from(u64::MAX) {
        u64::MAX as u128
    } else {
        size.as_u128().max(1)
    }
}

/// Accepted shares, oldest first, as far back as a window can still reach.
#[derive(Default)]
struct ShareLog {
    /// (sequence number, owner, weight)
    entries: VecDeque<(u64, AddrKey, u64)>,
    next_seq: u64,
}

impl ShareLog {
    fn load(db: &Database) -> Result<Self> {
        let txn = db.begin_read()?;
        let table = txn.open_table(SHARE_LOG)?;
        let mut log = Self::default();
        for entry in table.iter()? {
            let (seq, value) = entry?;
            let value = value.value();
            if value.len() != 104 {
                bail!("corrupt share log entry {}", seq.value());
            }
            let owner: AddrKey = value[..96].try_into().expect("length checked");
            let weight = u64::from_le_bytes(value[96..].try_into().expect("length checked"));
            log.entries.push_back((seq.value(), owner, weight));
            log.next_seq = seq.value() + 1;
        }
        Ok(log)
    }

    /// Appends a share, in `db` first and then in memory, and returns its
    /// sequence number.
    fn append(&mut self, db: &Database, owner: &AddrKey, weight: u64) -> Result<u64> {
        let seq = self.next_seq;
        let mut value = [0u8; 104];
        value[..96].copy_from_slice(owner);
        value[96..].copy_from_slice(&weight.to_le_bytes());
        let txn = db.begin_write()?;
        txn.open_table(SHARE_LOG)?.insert(seq, value.as_slice())?;
        txn.commit()?;
        self.entries.push_back((seq, *owner, weight));
        self.next_seq = seq + 1;
        Ok(seq)
    }

    /// The newest shares whose weights add up to at least `size`, or every
    /// share if there are not that many.
    fn window(&self, size: u128) -> Window {
        let mut owners: HashMap<AddrKey, u64> = HashMap::new();
        let mut total = 0u128;
        let mut start_seq = self.next_seq;
        for (seq, owner, weight) in self.entries.iter().rev() {
            if total >= size {
                break;
            }
            total += *weight as u128;
            let sum = owners.entry(*owner).or_default();
            *sum = sum.saturating_add(*weight);
            start_seq = *seq;
        }
        let mut owners: Vec<(AddrKey, u64)> = owners.into_iter().collect();
        owners.sort_by_key(|a| a.0);
        Window {
            start_seq,
            end_seq: self.next_seq,
            owners,
        }
    }

    /// Forgets shares older than `keep_from` that are also outside the newest
    /// `keep` weight, and returns the first sequence number kept.
    fn prune(&mut self, keep_from: u64, keep: u128) -> u64 {
        let mut weight = 0u128;
        let mut first_kept = self.next_seq;
        for (seq, _, w) in self.entries.iter().rev() {
            if weight >= keep && *seq < keep_from {
                break;
            }
            weight += *w as u128;
            first_kept = *seq;
        }
        while self
            .entries
            .front()
            .is_some_and(|(seq, _, _)| *seq < first_kept)
        {
            self.entries.pop_front();
        }
        first_kept
    }
}

/// Removes shares before `first_kept` from the log on disk.
fn prune_share_log(db: &Database, first_kept: u64) -> Result<()> {
    let txn = db.begin_write()?;
    txn.open_table(SHARE_LOG)?
        .retain_in(..first_kept, |_, _| false)?;
    txn.commit()?;
    Ok(())
}

/// Carries the unpaid scores of the previous payout scheme into an empty
/// share log, one share per miner weighing its score, so nobody's earned
/// work is lost on upgrade. Clears the old table.
fn migrate_legacy_scores(db: &Database) -> Result<usize> {
    let txn = db.begin_write()?;
    let moved = {
        let mut log = txn.open_table(SHARE_LOG)?;
        let mut legacy = txn.open_table(LEGACY_SCORES)?;
        if log.iter()?.next().is_some() {
            0
        } else {
            let mut scores: Vec<(AddrKey, u64)> = Vec::new();
            for entry in legacy.iter()? {
                let (key, score) = entry?;
                if let Ok(owner) = <AddrKey>::try_from(key.value()) {
                    if score.value() > 0 {
                        scores.push((owner, score.value()));
                    }
                }
            }
            scores.sort();
            for (seq, (owner, score)) in scores.iter().enumerate() {
                let mut value = [0u8; 104];
                value[..96].copy_from_slice(owner);
                value[96..].copy_from_slice(&score.to_le_bytes());
                log.insert(seq as u64, value.as_slice())?;
            }
            legacy.retain(|_, _| false)?;
            scores.len()
        }
    };
    txn.commit()?;
    Ok(moved)
}

/// Shares heavier than the pool's minimum difficulty count `2^extra_bits`
/// times; this caps `extra_bits`.
const MAX_WEIGHT_BITS: u32 = 30;

/// The hardest share difficulty a connection may be given on a job: no
/// harder than a block, and within [`MAX_WEIGHT_BITS`] of the minimum.
fn max_share_bits(network_target: &[u8; 32], min_bits: u32) -> u32 {
    crate::core::types::count_leading_zeros(network_target)
        .min(min_bits + MAX_WEIGHT_BITS)
        .max(min_bits)
}

/// A connection's share difficulty, in leading zero bits, steered toward
/// one share per `interval`. Shares count in proportion to difficulty, so a
/// fast miner sends few heavy shares instead of many light ones: the pool's
/// verification load grows with connections, not hashrate.
struct Vardiff {
    bits: u32,
    min_bits: u32,
    interval: Duration,
    since: Instant,
    shares: u32,
}

impl Vardiff {
    fn new(min_bits: u32, interval: Duration, now: Instant) -> Self {
        Self {
            bits: min_bits,
            min_bits,
            interval: interval.max(Duration::from_millis(1)),
            since: now,
            shares: 0,
        }
    }

    /// The difficulty for the next job. After four shares, or four intervals
    /// without them, it moves by whole bits toward one share per interval.
    fn retarget(&mut self, now: Instant, max_bits: u32) -> u32 {
        let elapsed = now.saturating_duration_since(self.since);
        if self.shares >= 4 || elapsed >= self.interval * 4 {
            let per_interval = (self.shares as f64 + 0.5) * self.interval.as_secs_f64()
                / elapsed.as_secs_f64().max(0.001);
            let step = per_interval.log2().round().clamp(-8.0, 8.0) as i64;
            self.bits = (self.bits as i64 + step).max(self.min_bits as i64) as u32;
            self.since = now;
            self.shares = 0;
        }
        self.bits = self.bits.clamp(self.min_bits, max_bits.max(self.min_bits));
        self.bits
    }
}

// ── Admission and verification ──────────────────────────────────────────────

/// Longest stratum message accepted. Real ones are a few hundred bytes.
pub const MAX_LINE: usize = 4_096;
/// Connections accepted at once from one IPv4 address or IPv6 /64.
const MAX_CONNECTIONS_PER_IP: usize = 64;
/// Connections accepted at once in total.
const MAX_CONNECTIONS: usize = 4_096;
/// First ban for an invalid share. Each repeat within a day lasts four times
/// longer, up to [`BAN_MAX`].
const BAN_BASE: Duration = Duration::from_secs(60);
const BAN_MAX: Duration = Duration::from_secs(24 * 3600);

/// Who a connection is for admission and bans: an IPv4 address, or an IPv6
/// /64, the smallest block one subscriber is usually given.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum IpKey {
    V4([u8; 4]),
    V6([u8; 8]),
}

fn ip_key(ip: IpAddr) -> IpKey {
    match ip {
        IpAddr::V4(v4) => IpKey::V4(v4.octets()),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpKey::V4(v4.octets()),
            None => {
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&v6.octets()[..8]);
                IpKey::V6(prefix)
            }
        },
    }
}

struct Ban {
    strikes: u32,
    until: Instant,
}

/// Addresses that sent a share failing its proof of work.
#[derive(Default)]
struct Bans {
    map: std::sync::Mutex<HashMap<IpKey, Ban>>,
}

impl Bans {
    fn is_banned(&self, ip: IpKey, now: Instant) -> bool {
        let map = self.map.lock().expect("ban list lock");
        map.get(&ip).is_some_and(|b| b.until > now)
    }

    /// Bans `ip` and returns for how long.
    fn strike(&self, ip: IpKey, now: Instant) -> Duration {
        let mut map = self.map.lock().expect("ban list lock");
        if map.len() > 100_000 {
            map.retain(|_, b| b.until + BAN_MAX > now);
        }
        let ban = map.entry(ip).or_insert(Ban {
            strikes: 0,
            until: now,
        });
        if ban.until + BAN_MAX <= now {
            ban.strikes = 0; // a clean day forgives earlier strikes
        }
        ban.strikes = ban.strikes.saturating_add(1);
        let length = BAN_BASE
            .saturating_mul(4u32.saturating_pow(ban.strikes - 1))
            .min(BAN_MAX);
        ban.until = now + length;
        length
    }
}

/// Open stratum connections, per address and in total.
#[derive(Default)]
struct Admission {
    per_ip: std::sync::Mutex<HashMap<IpKey, usize>>,
    total: AtomicUsize,
}

/// Releases a connection's place when it closes.
struct Admitted {
    admission: Arc<Admission>,
    ip: IpKey,
}

impl Admission {
    fn admit(self: &Arc<Self>, ip: IpKey) -> Option<Admitted> {
        let mut per_ip = self.per_ip.lock().expect("admission lock");
        let open = per_ip.entry(ip).or_insert(0);
        if *open >= MAX_CONNECTIONS_PER_IP || self.total.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            return None;
        }
        *open += 1;
        self.total.fetch_add(1, Ordering::SeqCst);
        Some(Admitted {
            admission: self.clone(),
            ip,
        })
    }
}

impl Drop for Admitted {
    fn drop(&mut self) {
        let mut per_ip = self.admission.per_ip.lock().expect("admission lock");
        if let Some(open) = per_ip.get_mut(&self.ip) {
            *open -= 1;
            if *open == 0 {
                per_ip.remove(&self.ip);
            }
        }
        self.admission.total.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Newline-delimited messages of at most `limit` bytes. Unlike
/// `AsyncBufReadExt::read_line`, [`LineReader::next_line`] is cancel safe,
/// so it can sit in a `tokio::select!` beside other events: a partial line
/// stays in `buf` until the rest arrives.
struct LineReader<R> {
    inner: BufReader<R>,
    buf: Vec<u8>,
    limit: usize,
}

impl<R: AsyncRead + Unpin> LineReader<R> {
    fn new(inner: R, limit: usize) -> Self {
        Self {
            inner: BufReader::new(inner),
            buf: Vec::new(),
            limit,
        }
    }

    /// The next line without its terminator; `None` at a clean end of input.
    async fn next_line(&mut self) -> Result<Option<String>> {
        loop {
            let available = self.inner.fill_buf().await?;
            if available.is_empty() {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                bail!("connection closed in the middle of a message");
            }
            let newline = available.iter().position(|b| *b == b'\n');
            let take = newline.map_or(available.len(), |i| i + 1);
            if self.buf.len() + take > self.limit + 1 {
                bail!("message longer than {} bytes", self.limit);
            }
            self.buf.extend_from_slice(&available[..take]);
            self.inner.consume(take);
            if newline.is_some() {
                let line = String::from_utf8(std::mem::take(&mut self.buf))
                    .context("message is not UTF-8")?;
                return Ok(Some(line.trim_end_matches(['\n', '\r']).to_string()));
            }
        }
    }
}

/// One share's proof of work to recompute.
struct VerifyTask {
    seed: [u8; 32],
    proven: bool,
    done: oneshot::Sender<[u8; 32]>,
}

#[derive(Default)]
struct VerifyQueues {
    /// From connections that have already submitted a valid share.
    proven: VecDeque<VerifyTask>,
    /// From connections that have not, served only within `unproven_limit`.
    unproven: VecDeque<VerifyTask>,
    unproven_running: usize,
    unproven_limit: usize,
}

impl VerifyQueues {
    /// Up to `max` tasks: proven connections' first, then unproven ones'
    /// while fewer than `unproven_limit` of those are being verified. Each
    /// connection queues at most one share, so first come first served is
    /// also round robin across connections.
    fn take(&mut self, max: usize) -> Vec<VerifyTask> {
        let mut batch = Vec::new();
        while batch.len() < max {
            if let Some(task) = self.proven.pop_front() {
                batch.push(task);
            } else if self.unproven_running < self.unproven_limit {
                match self.unproven.pop_front() {
                    Some(task) => {
                        self.unproven_running += 1;
                        batch.push(task);
                    }
                    None => break,
                }
            } else {
                break;
            }
        }
        batch
    }
}

struct VerifierShared {
    queues: std::sync::Mutex<VerifyQueues>,
    ready: std::sync::Condvar,
}

/// Worker threads that recompute shares' proof of work in SIMD batches.
struct Verifier {
    shared: Arc<VerifierShared>,
}

impl Verifier {
    fn start(workers: usize) -> Self {
        let lanes = detected_level().lanes().max(1);
        let workers = workers.max(1);
        let shared = Arc::new(VerifierShared {
            queues: std::sync::Mutex::new(VerifyQueues {
                // A quarter of the capacity, but never less than one batch.
                unproven_limit: (workers * lanes / 4).max(lanes),
                ..Default::default()
            }),
            ready: std::sync::Condvar::new(),
        });
        for i in 0..workers {
            let shared = shared.clone();
            std::thread::Builder::new()
                .name(format!("pool-verify-{i}"))
                .spawn(move || verify_worker(&shared, lanes))
                .expect("spawn a verification thread");
        }
        Self { shared }
    }

    /// Queues `seed` and returns the final hash of its proof of work.
    async fn verify(&self, seed: [u8; 32], proven: bool) -> Result<[u8; 32]> {
        let (done, result) = oneshot::channel();
        {
            let mut queues = self.shared.queues.lock().expect("verifier lock");
            let task = VerifyTask { seed, proven, done };
            if proven {
                queues.proven.push_back(task);
            } else {
                queues.unproven.push_back(task);
            }
        }
        self.shared.ready.notify_one();
        result.await.context("verifier stopped")
    }
}

fn verify_worker(shared: &VerifierShared, lanes: usize) {
    loop {
        let batch = {
            let mut queues = shared.queues.lock().expect("verifier lock");
            loop {
                let batch = queues.take(lanes);
                if !batch.is_empty() {
                    break batch;
                }
                queues = shared.ready.wait(queues).expect("verifier lock");
            }
        };
        let mut seeds: Vec<[u8; 32]> = batch.iter().map(|t| t.seed).collect();
        // Three or more shares verify faster as one full SIMD batch, padded
        // with throwaway seeds, than one after another.
        if seeds.len() >= 3 && seeds.len() < lanes {
            seeds.resize(lanes, [0u8; 32]);
        }
        let finals = verify_pow_batch(&seeds);
        let unproven = batch.iter().filter(|t| !t.proven).count();
        for (task, final_hash) in batch.into_iter().zip(finals) {
            let _ = task.done.send(final_hash);
        }
        if unproven > 0 {
            shared
                .queues
                .lock()
                .expect("verifier lock")
                .unproven_running -= unproven;
            shared.ready.notify_all();
        }
    }
}

// ── Server ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct PoolConfig {
    pub pool_address: StealthAddress,
    pub node_rpc: String,
    pub stratum_bind: SocketAddr,
    pub api_bind: SocketAddr,
    /// Address miners should use for the audit API (defaults to `api_bind`).
    pub api_public: Option<String>,
    pub fee_percent: f64,
    /// Minimum share difficulty, in leading zero bits. A share at this
    /// difficulty weighs 1; each connection's difficulty rises from here.
    pub share_bits: u32,
    /// How often each connection should find a share.
    pub share_interval: Duration,
    /// How many blocks' worth of shares a block pays (the PPLNS window).
    pub window_blocks: u64,
    pub data_dir: PathBuf,
    pub poll_interval: Duration,
}

struct Job {
    job_id: u64,
    /// The mining hash of the unbound template, which nobody mines.
    mining_hash: [u8; 32],
    network_target: [u8; 32],
    /// The unbound template, which each miner's copy patches.
    template_hex: String,
    batch: Batch,
    height: u64,
    /// The block this job builds on.
    prev_hash: [u8; 32],
    /// The window this job pays, and the one it freezes for the next tip.
    paying: Arc<WindowSnapshot>,
    next: Arc<WindowSnapshot>,
    /// [`job_commitment`] of the two windows: each miner's `extra` binds it.
    commitment: [u8; 32],
    fee_ppm: u64,
    receipts: Arc<HashMap<AddrKey, Vec<PayoutReceipt>>>,
    /// Each miner's copy of the job, by address.
    variants: std::sync::Mutex<HashMap<AddrKey, Arc<Variant>>>,
    /// (miner, nonce) submitted for this job, including those still in
    /// verification.
    seen: std::sync::Mutex<HashSet<(AddrKey, u64)>>,
}

/// One miner's copy of a job ([`bind_extra`], `template::rebind`).
struct Variant {
    extra: [u8; 32],
    mining_hash: [u8; 32],
    /// The copy's signature under the pool's bond, if blocks need one.
    miner: Option<crate::core::bond::MinerAuth>,
}

impl Job {
    /// This job's block with `variant`'s coinbase `extra` and signature.
    fn bound_batch(&self, variant: &Variant) -> Batch {
        let mut batch = self.batch.clone();
        if let Some(coinbase) = batch.coinbase.as_mut() {
            coinbase.extra = variant.extra;
        }
        batch.miner = variant.miner.clone();
        batch
    }
}

#[derive(Default)]
pub struct PoolStats {
    pub accepted_shares: AtomicU64,
    pub rejected_shares: AtomicU64,
    /// Shares that failed their proof of work (each one bans its sender).
    pub invalid_shares: AtomicU64,
    pub blocks_found: AtomicU64,
    pub blocks_rejected: AtomicU64,
    pub jobs: AtomicU64,
}

struct PoolState {
    cfg: PoolConfig,
    db: Database,
    current: RwLock<Option<Arc<Job>>>,
    /// The last [`RECENT_JOBS`] jobs, so a miner can audit exactly the job it
    /// was sent even if a newer one has been published since.
    recent: RwLock<VecDeque<Arc<Job>>>,
    notifier: broadcast::Sender<Arc<Job>>,
    /// Addresses with an authorized connection, and how many: each new job's
    /// copies are made for them in one request to the node.
    connected: std::sync::Mutex<HashMap<AddrKey, usize>>,
    log: std::sync::Mutex<ShareLog>,
    verifier: Verifier,
    bans: Bans,
    admission: Arc<Admission>,
    force_new_job: AtomicBool,
    stats: Arc<PoolStats>,
    api_public: String,
    /// Job whose block has already been submitted (one block per template).
    submitted_job: AtomicU64,
}

/// Opens the pool's database, creating its tables, and loads the share log.
fn open_db(path: &std::path::Path) -> Result<(Database, ShareLog)> {
    let db = Database::create(path)?;
    let txn = db.begin_write()?;
    {
        txn.open_table(LEGACY_SCORES)?;
        txn.open_table(SHARE_LOG)?;
        txn.open_table(FOUND)?;
    }
    txn.commit()?;
    let moved = migrate_legacy_scores(&db)?;
    if moved > 0 {
        tracing::info!("pool: carried {moved} miners' unpaid scores into the share log");
    }
    let log = ShareLog::load(&db)?;
    Ok((db, log))
}

/// Runs the pool until the process exits.
pub async fn run_pool(cfg: PoolConfig, stats: Arc<PoolStats>) -> Result<()> {
    std::fs::create_dir_all(&cfg.data_dir)?;
    fee_ppm(cfg.fee_percent)?;
    let (db, log) = open_db(&cfg.data_dir.join("pool.redb"))?;
    let stratum = tokio::net::TcpListener::bind(cfg.stratum_bind).await?;
    let api = tokio::net::TcpListener::bind(cfg.api_bind).await?;
    let api_public = cfg
        .api_public
        .clone()
        .unwrap_or_else(|| api.local_addr().map(|a| a.to_string()).unwrap_or_default());
    tracing::info!(
        "pool: stratum on {}, audit API on {}",
        stratum.local_addr()?,
        api.local_addr()?
    );
    let (notifier, _) = broadcast::channel(32);
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let state = Arc::new(PoolState {
        cfg,
        db,
        current: RwLock::new(None),
        recent: RwLock::default(),
        notifier,
        connected: Default::default(),
        log: std::sync::Mutex::new(log),
        verifier: Verifier::start(workers),
        bans: Bans::default(),
        admission: Arc::default(),
        force_new_job: AtomicBool::new(false),
        stats,
        api_public,
        submitted_job: AtomicU64::new(0),
    });

    let app = Router::new()
        .route("/pool/stats", get(api_stats))
        .route("/api/proof", get(api_proof))
        .route("/api/window", get(api_window))
        .route("/api/template", get(api_template))
        .with_state(state.clone());
    tokio::spawn(async move {
        if let Err(e) = axum::serve(api, app).await {
            tracing::error!("pool API stopped: {e}");
        }
    });

    tokio::spawn(job_loop(state.clone()));

    loop {
        let (socket, peer) = match stratum.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // Out of file descriptors, say: wait instead of exiting.
                tracing::warn!("pool: accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let ip = ip_key(peer.ip());
        if state.bans.is_banned(ip, Instant::now()) {
            continue;
        }
        let Some(admitted) = state.admission.admit(ip) else {
            tracing::debug!("pool: refused {peer}: too many connections");
            continue;
        };
        let st = state.clone();
        tokio::spawn(async move {
            let _admitted = admitted;
            if let Err(e) = handle_miner(socket, peer, st).await {
                tracing::debug!("pool: miner {} disconnected: {:#}", peer, e);
            }
        });
    }
}

/// The windows of the last published job.
struct Published {
    tip: [u8; 32],
    paying: Arc<WindowSnapshot>,
    next: Arc<WindowSnapshot>,
}

async fn job_loop(state: Arc<PoolState>) {
    let node = state.cfg.node_rpc.clone();
    let mut last_tip = String::new();
    let mut job_id: u64 = 0;
    // Miners check that a job on a new tip pays exactly the window the jobs
    // on the previous tip froze, which they saw before the new tip existed.
    let mut published: Option<Published> = None;
    loop {
        tokio::time::sleep(state.cfg.poll_interval).await;
        let node_state = {
            let node = node.clone();
            match tokio::task::spawn_blocking(move || RpcClient::new(node).get("/state")).await {
                Ok(Ok(v)) => v,
                _ => continue,
            }
        };
        if node_state["syncing"].as_bool().unwrap_or(false) {
            *state.current.write().await = None;
            last_tip.clear();
            continue;
        }
        let tip = node_state["tip"].as_str().unwrap_or_default().to_string();
        let forced = state.force_new_job.swap(false, Ordering::SeqCst);
        if tip == last_tip && !forced {
            continue;
        }
        let (Ok(tip_hash), Ok(network_target)) = (
            crate::core::auxpow::bytes32(&node_state["tip"]),
            crate::core::auxpow::bytes32(&node_state["target"]),
        ) else {
            continue;
        };
        let (paying, next) = match &published {
            Some(p) if p.tip == tip_hash => (p.paying.clone(), p.next.clone()),
            Some(p) => (p.next.clone(), freeze_window(&state, &network_target)),
            // Just started: nothing was frozen on an earlier tip.
            None => {
                let now = freeze_window(&state, &network_target);
                (now.clone(), now)
            }
        };
        match build_job(&state, job_id + 1, tip_hash, paying.clone(), next.clone()).await {
            Ok(job) => {
                // Copies for every connected miner in one request, before the
                // job is announced; a miner who connects later gets its own
                // on demand.
                let miners: Vec<AddrKey> = state
                    .connected
                    .lock()
                    .expect("connected lock")
                    .keys()
                    .copied()
                    .collect();
                if let Err(e) = bind_miners(&state, &job, miners).await {
                    tracing::warn!("pool: could not bind the job to its miners: {e:#}");
                }
                let job = Arc::new(job);
                job_id += 1;
                last_tip = tip;
                {
                    let mut recent = state.recent.write().await;
                    recent.push_back(job.clone());
                    while recent.len() > RECENT_JOBS {
                        recent.pop_front();
                    }
                }
                *state.current.write().await = Some(job.clone());
                state.stats.jobs.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    "pool: job {} at height {} pays {} owners (window {})",
                    job.job_id,
                    job.height,
                    job.paying.window.owners.len(),
                    hex::encode(&job.paying.root[..6])
                );
                let _ = state.notifier.send(job);
                let keep_from = paying.window.start_seq.min(next.window.start_seq);
                published = Some(Published {
                    tip: tip_hash,
                    paying,
                    next,
                });
                let size = window_size(
                    &network_target,
                    state.cfg.share_bits,
                    state.cfg.window_blocks,
                );
                let first_kept = state
                    .log
                    .lock()
                    .expect("share log lock")
                    .prune(keep_from, size.saturating_mul(4));
                let st = state.clone();
                let pruned =
                    tokio::task::spawn_blocking(move || prune_share_log(&st.db, first_kept)).await;
                if let Ok(Err(e)) | Err(e) = pruned.map_err(anyhow::Error::from) {
                    tracing::warn!("pool: pruning the share log failed: {e:#}");
                }
            }
            Err(e) => tracing::warn!("pool: could not build a job: {e:#}"),
        }
    }
}

/// The current window: the newest shares worth `window_blocks` blocks.
fn freeze_window(state: &PoolState, network_target: &[u8; 32]) -> Arc<WindowSnapshot> {
    let size = window_size(
        network_target,
        state.cfg.share_bits,
        state.cfg.window_blocks,
    );
    let window = state.log.lock().expect("share log lock").window(size);
    Arc::new(WindowSnapshot::new(window))
}

async fn build_job(
    state: &Arc<PoolState>,
    job_id: u64,
    tip: [u8; 32],
    paying: Arc<WindowSnapshot>,
    next: Arc<WindowSnapshot>,
) -> Result<Job> {
    let fee = fee_ppm(state.cfg.fee_percent)?;
    let seed = draw_seed(&tip, &paying.root);
    let payouts: Vec<Value> =
        payout_weights(fee, &state.cfg.pool_address, &paying.window.owners, &seed)?
            .iter()
            .map(|(address, weight)| json!({ "address": address.encode(), "weight": weight }))
            .collect();
    let extra = job_commitment(&paying.root, &next.root);
    let body = json!({ "payouts": payouts, "extra": hex::encode(extra) });
    let node = state.cfg.node_rpc.clone();
    let tpl =
        tokio::task::spawn_blocking(move || RpcClient::new(node).post("/mining/template", &body))
            .await??;
    let template_hex = tpl["template_hex"]
        .as_str()
        .ok_or_else(|| anyhow!("no template"))?
        .to_string();
    // The draw is seeded with the block the job builds on; a template built
    // after the node's tip moved would draw from the wrong seed.
    let batch: Batch = bincode::deserialize(&hex::decode(&template_hex)?)?;
    if batch.prev_header_hash != tip {
        bail!("the node's tip moved while the job was built");
    }

    let mut receipts: HashMap<AddrKey, Vec<PayoutReceipt>> = HashMap::new();
    for r in tpl["receipts"]
        .as_array()
        .ok_or_else(|| anyhow!("template without receipts"))?
    {
        let addr = StealthAddress::decode(r["address"].as_str().unwrap_or_default())?;
        let receipt = PayoutReceipt {
            output_index: r["output_index"].as_u64().unwrap_or(0) as usize,
            value: r["value"].as_u64().unwrap_or(0),
            blinding: crate::core::auxpow::bytes32(&r["blinding"])?,
            ephemeral_secret: crate::core::auxpow::bytes32(&r["ephemeral_secret"])?,
        };
        receipts.entry(addr_key(&addr)).or_default().push(receipt);
    }
    Ok(Job {
        job_id,
        mining_hash: crate::core::auxpow::bytes32(&tpl["mining_hash"])?,
        network_target: crate::core::auxpow::bytes32(&tpl["target"])?,
        template_hex,
        batch,
        height: tpl["height"].as_u64().unwrap_or(0),
        prev_hash: tip,
        paying,
        next,
        commitment: extra,
        fee_ppm: fee,
        receipts: Arc::new(receipts),
        variants: Default::default(),
        seen: Default::default(),
    })
}

/// Has the node make `miners`' copies of `job` and keeps them.
async fn bind_miners(state: &PoolState, job: &Job, miners: Vec<AddrKey>) -> Result<()> {
    let miners: Vec<AddrKey> = {
        let have = job.variants.lock().expect("variants lock");
        miners
            .into_iter()
            .filter(|m| !have.contains_key(m))
            .collect()
    };
    if miners.is_empty() {
        return Ok(());
    }
    let extras: Vec<String> = miners
        .iter()
        .map(|m| hex::encode(bind_extra(&job.commitment, m)))
        .collect();
    let body = json!({ "mining_hash": hex::encode(job.mining_hash), "extras": extras });
    let node = state.cfg.node_rpc.clone();
    let answer =
        tokio::task::spawn_blocking(move || RpcClient::new(node).post("/mining/bind", &body))
            .await??;
    let copies = answer["variants"]
        .as_array()
        .ok_or_else(|| anyhow!("the node returned no copies"))?;
    if copies.len() != miners.len() {
        bail!(
            "the node returned {} copies for {} miners",
            copies.len(),
            miners.len()
        );
    }
    let mut variants = job.variants.lock().expect("variants lock");
    for (miner, copy) in miners.into_iter().zip(copies) {
        let extra = crate::core::auxpow::bytes32(&copy["extra"])?;
        if extra != bind_extra(&job.commitment, &miner) {
            bail!("the node returned a copy for the wrong miner");
        }
        let auth = match copy["miner"].as_str() {
            Some(h) => Some(bincode::deserialize(&hex::decode(h)?)?),
            None => None,
        };
        let variant = Variant {
            extra,
            mining_hash: crate::core::auxpow::bytes32(&copy["mining_hash"])?,
            miner: auth,
        };
        // The copy must be what the miner will check: our own template with
        // this `extra` and signature hashes to this mining hash.
        let mut header = job.bound_batch(&variant).header();
        header.height = job.height;
        if compute_header_hash(&header) != variant.mining_hash {
            bail!("the node's copy does not hash to its mining hash");
        }
        variants.insert(miner, Arc::new(variant));
    }
    Ok(())
}

/// `miner`'s copy of `job`, made on first use.
async fn variant_for(state: &PoolState, job: &Job, miner: &AddrKey) -> Result<Arc<Variant>> {
    if let Some(v) = job.variants.lock().expect("variants lock").get(miner) {
        return Ok(v.clone());
    }
    bind_miners(state, job, vec![*miner]).await?;
    job.variants
        .lock()
        .expect("variants lock")
        .get(miner)
        .cloned()
        .ok_or_else(|| anyhow!("no copy of the job for this miner"))
}

#[derive(Debug, PartialEq, Eq)]
enum ShareOutcome {
    /// Credited as share `seq` of the log, weighing `weight`.
    Accepted {
        is_block: bool,
        seq: u64,
        weight: u64,
    },
    Duplicate,
    StaleJob,
    /// The proof of work does not meet the share target: the sender is banned.
    Invalid,
}

/// A share that passed the cheap checks and awaits its proof of work.
struct PendingShare {
    job: Arc<Job>,
    /// The submitter's copy of the job: the share's proof of work is checked
    /// against it, so a nonce found for anyone else's copy fails.
    variant: Arc<Variant>,
    miner: AddrKey,
    nonce: u64,
    /// The target this connection was given for the job, and what a share
    /// meeting it weighs.
    share_target: [u8; 32],
    weight: u64,
}

/// The cheap checks: the job is the current one and the nonce is new for it.
/// The nonce is reserved, so a copy submitted while it is being verified is a
/// duplicate rather than a second verification. `bits` is the difficulty the
/// connection was given for the job.
async fn precheck_share(
    state: &PoolState,
    miner: AddrKey,
    job_id: u64,
    nonce: u64,
    bits: u32,
) -> std::result::Result<PendingShare, ShareOutcome> {
    let job = match state.current.read().await.clone() {
        Some(j) if j.job_id == job_id => j,
        _ => return Err(ShareOutcome::StaleJob),
    };
    // The connection was sent this miner's copy before it could submit.
    let Some(variant) = job
        .variants
        .lock()
        .expect("variants lock")
        .get(&miner)
        .cloned()
    else {
        return Err(ShareOutcome::StaleJob);
    };
    if !job.seen.lock().expect("seen lock").insert((miner, nonce)) {
        return Err(ShareOutcome::Duplicate);
    }
    let extra_bits = bits
        .saturating_sub(state.cfg.share_bits)
        .min(MAX_WEIGHT_BITS);
    Ok(PendingShare {
        job,
        variant,
        miner,
        nonce,
        share_target: target_from_leading_zero_bits(bits),
        weight: 1 << extra_bits,
    })
}

/// Credits a verified share against the job it was submitted for, even if a
/// newer job has replaced that one since, and submits it if it is a block.
async fn finish_share(
    state: &Arc<PoolState>,
    share: PendingShare,
    final_hash: [u8; 32],
) -> Result<ShareOutcome> {
    let job = share.job;
    if final_hash >= share.share_target && final_hash >= job.network_target {
        job.seen
            .lock()
            .expect("seen lock")
            .remove(&(share.miner, share.nonce));
        return Ok(ShareOutcome::Invalid);
    }
    let st = state.clone();
    let (miner, weight) = (share.miner, share.weight);
    let seq = tokio::task::spawn_blocking(move || {
        st.log
            .lock()
            .expect("share log lock")
            .append(&st.db, &miner, weight)
    })
    .await??;
    let is_block = final_hash < job.network_target;
    if is_block && state.submitted_job.swap(job.job_id, Ordering::SeqCst) != job.job_id {
        let ext = Extension {
            nonce: share.nonce,
            final_hash,
        };
        submit_block(state.clone(), job, share.variant, share.miner, ext);
    }
    Ok(ShareOutcome::Accepted {
        is_block,
        seq,
        weight,
    })
}

/// Checks, verifies and credits one share. `proven` says whether the
/// submitting connection has already had a share accepted; `bits` is the
/// difficulty it was given for the job.
async fn process_share(
    state: Arc<PoolState>,
    miner: AddrKey,
    job_id: u64,
    nonce: u64,
    proven: bool,
    bits: u32,
) -> Result<ShareOutcome> {
    let share = match precheck_share(&state, miner, job_id, nonce, bits).await {
        Ok(share) => share,
        Err(outcome) => return Ok(outcome),
    };
    let seed = pow_seed(&share.variant.mining_hash, nonce);
    let final_hash = state.verifier.verify(seed, proven).await?;
    finish_share(&state, share, final_hash).await
}

/// Submits a found block. Nothing is settled afterwards: each block's
/// coinbase pays its own window, so a block that is later orphaned simply
/// pays nobody, like any other orphaned block.
fn submit_block(
    state: Arc<PoolState>,
    job: Arc<Job>,
    variant: Arc<Variant>,
    miner: AddrKey,
    ext: Extension,
) {
    tokio::spawn(async move {
        let mut sealed = job.bound_batch(&variant);
        sealed.extension = ext.clone();
        let block_hex = match bincode::serialize(&sealed) {
            Ok(b) => hex::encode(b),
            Err(_) => return,
        };
        let node = state.cfg.node_rpc.clone();
        let res = tokio::task::spawn_blocking(move || {
            RpcClient::new(node).post("/mining/submit", &json!({ "block_hex": block_hex }))
        })
        .await;
        let rejection = match res {
            Ok(Ok(_)) => None,
            Ok(Err(e)) => Some(format!("{e:#}")),
            Err(e) => Some(e.to_string()),
        };
        match rejection {
            None => {
                state.stats.blocks_found.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    "pool: block {} accepted at height {}",
                    hex::encode(&ext.final_hash[..6]),
                    job.height
                );
                let record = json!({
                    "hash": hex::encode(ext.final_hash),
                    "height": job.height,
                    "window": hex::encode(job.paying.root),
                    "window_start": job.paying.window.start_seq,
                    "window_end": job.paying.window.end_seq,
                    "finder": hex::encode(miner),
                    "commitment": hex::encode(job.commitment),
                })
                .to_string();
                let st = state.clone();
                let recorded = tokio::task::spawn_blocking(move || -> Result<()> {
                    let txn = st.db.begin_write()?;
                    txn.open_table(FOUND)?
                        .insert(ext.final_hash.as_slice(), record.as_str())?;
                    txn.commit()?;
                    Ok(())
                })
                .await;
                if let Ok(Err(e)) | Err(e) = recorded.map_err(anyhow::Error::from) {
                    tracing::error!("pool: recording the block failed: {e:#}");
                }
            }
            Some(msg) => {
                state.stats.blocks_rejected.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("pool: block rejected ({msg}); requesting a fresh job");
                state.force_new_job.store(true, Ordering::SeqCst);
            }
        }
    });
}

/// A job as one miner sees it: its own copy's mining hash, plus the coinbase
/// `extra` and signature that turn the shared template into that copy.
fn notify_line(job: &Job, share_bits: u32, variant: &Variant) -> Result<String> {
    let miner = match &variant.miner {
        Some(auth) => Value::String(hex::encode(bincode::serialize(auth)?)),
        None => Value::Null,
    };
    Ok(json!({
        "id": null,
        "method": "mining.notify",
        "params": [
            job.job_id,
            hex::encode(variant.mining_hash),
            job.template_hex,
            hex::encode(target_from_leading_zero_bits(share_bits)),
            hex::encode(job.network_target),
            hex::encode(variant.extra),
            miner,
        ],
    })
    .to_string()
        + "\n")
}

type ShareFuture = Pin<Box<dyn Future<Output = Result<ShareOutcome>> + Send>>;

/// Keeps an address in [`PoolState::connected`] while a connection is
/// authorized for it.
struct Registered {
    state: Arc<PoolState>,
    miner: AddrKey,
}

impl Registered {
    fn new(state: &Arc<PoolState>, miner: AddrKey) -> Self {
        *state
            .connected
            .lock()
            .expect("connected lock")
            .entry(miner)
            .or_default() += 1;
        Self {
            state: state.clone(),
            miner,
        }
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        let mut connected = self.state.connected.lock().expect("connected lock");
        if let Some(count) = connected.get_mut(&self.miner) {
            *count -= 1;
            if *count == 0 {
                connected.remove(&self.miner);
            }
        }
    }
}

/// A connection's share difficulty and the difficulty it was given for each
/// recent job, which is what its shares for that job are judged against.
struct Difficulty {
    vardiff: Vardiff,
    announced: VecDeque<(u64, u32)>,
}

impl Difficulty {
    /// Retargets for `job` and returns the notify line announcing `miner`'s
    /// copy of it.
    async fn announce(&mut self, state: &PoolState, job: &Job, miner: &AddrKey) -> Result<String> {
        let variant = variant_for(state, job, miner).await?;
        let max_bits = max_share_bits(&job.network_target, self.vardiff.min_bits);
        let bits = self.vardiff.retarget(Instant::now(), max_bits);
        self.announced.push_back((job.job_id, bits));
        while self.announced.len() > 8 {
            self.announced.pop_front();
        }
        notify_line(job, bits, &variant)
    }

    fn for_job(&self, job_id: u64) -> Option<u32> {
        self.announced
            .iter()
            .find(|(id, _)| *id == job_id)
            .map(|(_, bits)| *bits)
    }
}

/// One miner's connection. A submitted share is verified while job
/// notifications keep flowing, but nothing more is read from the miner until
/// it finishes: a busy pool slows a connection down instead of dropping its
/// shares.
async fn handle_miner(
    socket: tokio::net::TcpStream,
    peer: SocketAddr,
    state: Arc<PoolState>,
) -> Result<()> {
    let ip = ip_key(peer.ip());
    let (read, mut write) = socket.into_split();
    let mut lines = LineReader::new(read, MAX_LINE);
    let mut jobs = state.notifier.subscribe();
    let mut authorized: Option<AddrKey> = None;
    let mut _registered: Option<Registered> = None;
    // Whether this connection has had a share accepted: its shares are then
    // verified ahead of unproven connections'.
    let mut proven = false;
    let mut difficulty = Difficulty {
        vardiff: Vardiff::new(
            state.cfg.share_bits,
            state.cfg.share_interval,
            Instant::now(),
        ),
        announced: VecDeque::new(),
    };
    let mut pending: Option<(Value, ShareFuture)> = None;
    loop {
        tokio::select! {
            line = lines.next_line(), if pending.is_none() => {
                let Some(line) = line? else { return Ok(()) };
                let msg: Value = serde_json::from_str(&line).context("bad JSON")?;
                let id = msg["id"].clone();
                let params = msg["params"].as_array().cloned().unwrap_or_default();
                let reply = match msg["method"].as_str().unwrap_or_default() {
                    "mining.authorize" => {
                        let addr = StealthAddress::decode(
                            params.first().and_then(Value::as_str).unwrap_or_default(),
                        )?;
                        let miner = addr_key(&addr);
                        authorized = Some(miner);
                        _registered = Some(Registered::new(&state, miner));
                        // Jobs announced for another address are stale now.
                        difficulty.announced.clear();
                        let ok = json!({ "id": id, "result": { "api": state.api_public } });
                        write.write_all((ok.to_string() + "\n").as_bytes()).await?;
                        if let Some(job) = state.current.read().await.clone() {
                            let notify = difficulty.announce(&state, &job, &miner).await?;
                            write.write_all(notify.as_bytes()).await?;
                        }
                        continue;
                    }
                    "mining.submit" => {
                        let Some(miner) = authorized else { bail!("submit before authorize") };
                        if state.bans.is_banned(ip, Instant::now()) {
                            bail!("{peer} is banned");
                        }
                        let job_id = params.get(1).and_then(Value::as_u64).unwrap_or(0);
                        let nonce = params.get(2).and_then(Value::as_u64).unwrap_or(0);
                        match difficulty.for_job(job_id) {
                            Some(bits) => {
                                let share =
                                    process_share(state.clone(), miner, job_id, nonce, proven, bits);
                                pending = Some((id, Box::pin(share)));
                                continue;
                            }
                            None => {
                                state.stats.rejected_shares.fetch_add(1, Ordering::Relaxed);
                                json!({ "id": id, "result": false, "error": "stale job" })
                            }
                        }
                    }
                    other => json!({ "id": id, "error": format!("unknown method {other}") }),
                };
                write.write_all((reply.to_string() + "\n").as_bytes()).await?;
            }
            outcome = async { pending.as_mut().expect("guarded").1.as_mut().await },
                if pending.is_some() =>
            {
                let (id, _) = pending.take().expect("guarded");
                let reply = match outcome? {
                    ShareOutcome::Accepted { is_block, seq, weight } => {
                        proven = true;
                        difficulty.vardiff.shares += 1;
                        state.stats.accepted_shares.fetch_add(1, Ordering::Relaxed);
                        json!({
                            "id": id, "result": true, "block": is_block,
                            "seq": seq, "weight": weight,
                        })
                    }
                    ShareOutcome::Invalid => {
                        state.stats.invalid_shares.fetch_add(1, Ordering::Relaxed);
                        let ban = state.bans.strike(ip, Instant::now());
                        let reply = json!({ "id": id, "result": false, "error": "invalid share" });
                        let _ = write.write_all((reply.to_string() + "\n").as_bytes()).await;
                        bail!("invalid share from {peer}: banned for {}s", ban.as_secs());
                    }
                    other => {
                        state.stats.rejected_shares.fetch_add(1, Ordering::Relaxed);
                        let reason = match other {
                            ShareOutcome::Duplicate => "duplicate share",
                            _ => "stale job",
                        };
                        json!({ "id": id, "result": false, "error": reason })
                    }
                };
                write.write_all((reply.to_string() + "\n").as_bytes()).await?;
            }
            job = jobs.recv() => {
                match job {
                    // Each job is bound to the miner, so nothing goes out
                    // before it says who it is.
                    Ok(job) => {
                        if let Some(miner) = authorized {
                            let notify = difficulty.announce(&state, &job, &miner).await?;
                            write.write_all(notify.as_bytes()).await?;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return Ok(()),
                }
            }
        }
    }
}

// ── Audit API ───────────────────────────────────────────────────────────────

/// Jobs the audit API still answers for.
const RECENT_JOBS: usize = 16;

#[derive(Deserialize)]
struct AddressQuery {
    address: String,
    job: Option<u64>,
}

#[derive(Deserialize)]
struct JobQuery {
    job: Option<u64>,
}

/// Job `job_id` if it is still recent, or the current job.
async fn find_job(state: &PoolState, job_id: Option<u64>) -> Option<Arc<Job>> {
    match job_id {
        Some(id) => state
            .recent
            .read()
            .await
            .iter()
            .find(|j| j.job_id == id)
            .cloned(),
        None => state.current.read().await.clone(),
    }
}

/// The receipts for one address's outputs in a job's coinbase.
async fn api_proof(
    State(state): State<Arc<PoolState>>,
    Query(q): Query<AddressQuery>,
) -> Json<Value> {
    let Some(job) = find_job(&state, q.job).await else {
        return Json(json!({ "error": "no such job" }));
    };
    let addr = match StealthAddress::decode(&q.address) {
        Ok(a) => addr_key(&a),
        Err(e) => return Json(json!({ "error": e.to_string() })),
    };
    let receipts: Vec<Value> = job
        .receipts
        .get(&addr)
        .map(|rs| {
            rs.iter()
                .map(|r| serde_json::to_value(r).unwrap_or_default())
                .collect()
        })
        .unwrap_or_default();
    Json(json!({ "job_id": job.job_id, "receipts": receipts }))
}

fn window_json(window: &Window) -> Value {
    json!({
        "start_seq": window.start_seq,
        "end_seq": window.end_seq,
        "owners": window
            .owners
            .iter()
            .map(|(k, w)| json!({ "key": hex::encode(k), "weight": w }))
            .collect::<Vec<_>>(),
    })
}

/// Everything a miner needs to recompute a job's payouts: the window it
/// pays, the root of the window it freezes, the fee and the operator's
/// address.
async fn api_window(State(state): State<Arc<PoolState>>, Query(q): Query<JobQuery>) -> Json<Value> {
    let Some(job) = find_job(&state, q.job).await else {
        return Json(json!({ "error": "no such job" }));
    };
    Json(json!({
        "job_id": job.job_id,
        "height": job.height,
        "prev_hash": hex::encode(job.prev_hash),
        "fee_ppm": job.fee_ppm,
        "pool_address": state.cfg.pool_address.encode(),
        "max_paid": MAX_PAID_MINERS,
        "window": window_json(&job.paying.window),
        "window_root": hex::encode(job.paying.root),
        "next_root": hex::encode(job.next.root),
        "commitment": hex::encode(job.commitment),
    }))
}

async fn api_template(State(state): State<Arc<PoolState>>) -> Json<Value> {
    match state.current.read().await.clone() {
        Some(job) => Json(json!({
            "job_id": job.job_id,
            "mining_hash": hex::encode(job.mining_hash),
            "template_hex": job.template_hex,
            "share_target": hex::encode(target_from_leading_zero_bits(state.cfg.share_bits)),
            "network_target": hex::encode(job.network_target),
        })),
        None => Json(json!({ "error": "no job" })),
    }
}

async fn api_stats(State(state): State<Arc<PoolState>>) -> Json<Value> {
    let job = state.current.read().await.clone();
    let blocks: Vec<Value> = state
        .db
        .begin_read()
        .ok()
        .and_then(|t| t.open_table(FOUND).ok())
        .map(|t| {
            t.iter()
                .map(|it| {
                    it.filter_map(|e| e.ok())
                        .filter_map(|(_, v)| serde_json::from_str(v.value()).ok())
                        .collect()
                })
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let s = &state.stats;
    Json(json!({
        "height": job.as_ref().map(|j| j.height),
        "job_id": job.as_ref().map(|j| j.job_id),
        "miners": job.as_ref().map_or(0, |j| j.paying.window.owners.len()),
        "window_weight": job.as_ref().map_or(0, |j| {
            j.paying.window.owners.iter().map(|(_, w)| *w as u128).sum::<u128>()
        }).to_string(),
        "fee_percent": state.cfg.fee_percent,
        "share_bits": state.cfg.share_bits,
        "share_interval_secs": state.cfg.share_interval.as_secs_f64(),
        "window_blocks": state.cfg.window_blocks,
        "accepted_shares": s.accepted_shares.load(Ordering::Relaxed),
        "rejected_shares": s.rejected_shares.load(Ordering::Relaxed),
        "invalid_shares": s.invalid_shares.load(Ordering::Relaxed),
        "blocks_found": s.blocks_found.load(Ordering::Relaxed),
        "blocks_rejected": s.blocks_rejected.load(Ordering::Relaxed),
        "blocks": blocks,
    }))
}

// ── Miner ───────────────────────────────────────────────────────────────────

/// What a passed audit established about a job, for the checks that span
/// jobs ([`check_window_chain`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditedJob {
    /// The block the job builds on.
    pub prev_hash: [u8; 32],
    /// The window the job pays, and the one it freezes for the next tip.
    pub window_root: [u8; 32],
    pub next_root: [u8; 32],
    /// The first share sequence number the paid window covers.
    pub window_start: u64,
}

fn parse_window(value: &Value) -> Result<Window> {
    let owners: Vec<(AddrKey, u64)> = value["owners"]
        .as_array()
        .ok_or_else(|| anyhow!("missing window owners"))?
        .iter()
        .map(|entry| {
            let key: AddrKey = hex::decode(
                entry["key"]
                    .as_str()
                    .ok_or_else(|| anyhow!("missing owner key"))?,
            )?
            .try_into()
            .map_err(|_| anyhow!("bad owner key length"))?;
            let weight = entry["weight"]
                .as_u64()
                .ok_or_else(|| anyhow!("missing owner weight"))?;
            Ok((key, weight))
        })
        .collect::<Result<_>>()?;
    // One canonical list per window: strictly increasing keys, no empty
    // entries. Anything else could share a root with a different list.
    if owners.windows(2).any(|w| w[0].0 >= w[1].0) || owners.iter().any(|(_, w)| *w == 0) {
        bail!("window owners are not a sorted list of distinct, positive entries");
    }
    Ok(Window {
        start_seq: value["start_seq"]
            .as_u64()
            .ok_or_else(|| anyhow!("missing window start"))?,
        end_seq: value["end_seq"]
            .as_u64()
            .ok_or_else(|| anyhow!("missing window end"))?,
        owners,
    })
}

/// Verifies a job before mining it: the template, the commitment to the
/// window it pays, our own weight in that window, and that the coinbase pays
/// us exactly what the payout rule ([`payout_weights`]) gives us.
///
/// * `proof` and `window` are the pool's `/api/proof` and `/api/window`
///   answers for the job.
/// * `max_fee_ppm` is the miner's own limit, never a pool-supplied setting.
/// * `my_shares` are `(sequence number, weight)` of shares the pool accepted
///   from us: the window must credit us at least the ones inside its range.
///
/// The height comes from the pool (a batch on the wire carries none); the
/// coinbase total pins it to the reward at that height, but only a node of
/// one's own can confirm the chain itself.
pub fn audit_job_with_fee_limit(
    address: &StealthAddress,
    mining_hash: &[u8; 32],
    template_hex: &str,
    proof: &Value,
    window: &Value,
    max_fee_ppm: u64,
    my_shares: &[(u64, u64)],
) -> Result<AuditedJob> {
    let batch: Batch = bincode::deserialize(&hex::decode(template_hex)?)?;
    if &compute_header_hash(&batch.header()) != mining_hash {
        bail!("template does not hash to the announced mining hash");
    }
    if proof["job_id"].as_u64() != window["job_id"].as_u64() {
        bail!("proof and window describe different jobs");
    }
    let height = window["height"]
        .as_u64()
        .ok_or_else(|| anyhow!("missing pool height"))?;
    let fee = window["fee_ppm"]
        .as_u64()
        .ok_or_else(|| anyhow!("missing pool fee"))?;
    if fee >= FEE_SCALE || fee > max_fee_ppm {
        bail!("pool fee exceeds miner's configured fee limit");
    }
    let operator = StealthAddress::decode(
        window["pool_address"]
            .as_str()
            .ok_or_else(|| anyhow!("missing pool payout address"))?,
    )?;
    let paying = parse_window(&window["window"])?;
    let window_root = paying.root();
    let next_root = crate::core::auxpow::bytes32(&window["next_root"])?;
    let audited = AuditedJob {
        prev_hash: batch.prev_header_hash,
        window_root,
        next_root,
        window_start: paying.start_seq,
    };
    let total = crate::core::types::block_reward(height)
        .checked_add(batch.body.fee()?)
        .ok_or_else(|| anyhow!("reward overflow"))?;
    let cb = match batch.coinbase.as_ref() {
        Some(cb) if total > 0 => cb,
        None if total == 0 => return Ok(audited), // unpayable, post-issuance block
        None => bail!("template drops a payable coinbase"),
        Some(_) => bail!("template has a coinbase when no reward or fees are payable"),
    };
    // The height comes from the pool's API, not from the template, so a pool
    // could claim a later era and pay every miner exactly what the audit then
    // expects while keeping the rest. The coinbase commits to its total: this
    // passes only if its outputs sum to the reward at `height` plus the fees.
    cb.verify_sum(total)
        .context("coinbase does not pay the reward for the claimed height")?;
    // Our copy binds the commitment to our address: work on it is worthless
    // to anyone else, and a job bound to someone else stops here.
    let key = addr_key(address);
    if cb.extra != bind_extra(&job_commitment(&window_root, &next_root), &key) {
        bail!("the job is not bound to our address, or its windows are not the committed ones");
    }
    // A pool that drops us from the window, or shrinks our weight, is caught
    // here: the shares it told us it accepted must all be counted.
    let listed = paying
        .owners
        .iter()
        .find(|(k, _)| *k == key)
        .map_or(0, |(_, w)| *w as u128);
    let ours: u128 = my_shares
        .iter()
        .filter(|(seq, _)| (paying.start_seq..paying.end_seq).contains(seq))
        .map(|(_, w)| *w as u128)
        .sum();
    if listed < ours {
        bail!("the window credits us {listed} but our accepted shares in it weigh {ours}");
    }
    let seed = draw_seed(&batch.prev_header_hash, &window_root);
    let weights = payout_weights(fee, &operator, &paying.owners, &seed)?;
    let expected = crate::core::template::split_by_weight(total, &weights)?
        .iter()
        .filter(|(a, _)| *a == *address)
        .try_fold(0u64, |acc, (_, amount)| acc.checked_add(*amount))
        .ok_or_else(|| anyhow!("expected payout overflow"))?;
    let receipts: Vec<PayoutReceipt> = serde_json::from_value(proof["receipts"].clone())?;
    let mut used = HashSet::new();
    let mut proven = 0u64;
    for receipt in receipts {
        if !used.insert(receipt.output_index) {
            bail!("duplicate payout receipt for one output");
        }
        let output = cb
            .outputs
            .outputs
            .get(receipt.output_index)
            .ok_or_else(|| anyhow!("payout receipt index out of bounds"))?;
        if !receipt.verify(address, output) {
            bail!("invalid payout receipt");
        }
        proven = proven
            .checked_add(receipt.value)
            .ok_or_else(|| anyhow!("proved payout overflow"))?;
    }
    if proven != expected {
        bail!("pool payout mismatch: expected {expected} base units, verified {proven}");
    }
    Ok(audited)
}

/// The pool's shared `template_hex` turned into one miner's copy: its
/// coinbase `extra` and bond signature replaced.
pub fn bind_template(
    template_hex: &str,
    extra: [u8; 32],
    miner: Option<crate::core::bond::MinerAuth>,
) -> Result<String> {
    let mut batch: Batch = bincode::deserialize(&hex::decode(template_hex)?)?;
    if let Some(coinbase) = batch.coinbase.as_mut() {
        coinbase.extra = extra;
    }
    batch.miner = miner;
    Ok(hex::encode(bincode::serialize(&batch)?))
}

/// [`audit_job_with_fee_limit`] for callers with no fee limit of their own
/// and no record of accepted shares.
pub fn audit_job(
    address: &StealthAddress,
    mining_hash: &[u8; 32],
    template_hex: &str,
    proof: &Value,
    window: &Value,
) -> Result<AuditedJob> {
    audit_job_with_fee_limit(
        address,
        mining_hash,
        template_hex,
        proof,
        window,
        FEE_SCALE,
        &[],
    )
}

/// Checks a newly audited job against the previous one. On the same tip
/// both windows must be unchanged. On a new tip the job must pay the window
/// the previous tip's jobs froze, which we saw before the new tip existed, so
/// the pool could not have chosen it to suit the new tip's draw.
pub fn check_window_chain(last: Option<&AuditedJob>, job: &AuditedJob) -> Result<()> {
    let Some(last) = last else { return Ok(()) };
    if job.prev_hash == last.prev_hash {
        if (job.window_root, job.next_root) != (last.window_root, last.next_root) {
            bail!("the pool changed its windows without a new tip");
        }
    } else if job.window_root != last.next_root {
        bail!("the job on the new tip does not pay the window frozen on the previous one");
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct PoolMinerConfig {
    pub pool: String,
    pub address: StealthAddress,
    pub worker: String,
    pub threads: usize,
}

#[derive(Default, Debug)]
pub struct PoolMinerStats {
    pub jobs: AtomicU64,
    pub audits_passed: AtomicU64,
    pub audits_failed: AtomicU64,
    pub shares_sent: AtomicU64,
    pub shares_accepted: AtomicU64,
    pub hashes: Arc<AtomicU64>,
}

fn search(
    mining_hash: [u8; 32],
    target: [u8; 32],
    share: [u8; 32],
    threads: usize,
    cancel: Arc<AtomicBool>,
    counter: Arc<AtomicU64>,
) -> Option<MiningResult> {
    #[cfg(feature = "gpu")]
    {
        crate::core::gpu_mining::mine(mining_hash, target, Some(share), threads, cancel, counter)
    }
    #[cfg(not(feature = "gpu"))]
    {
        crate::core::extension::mine_extension(
            mining_hash,
            target,
            Some(share),
            threads,
            cancel,
            counter,
        )
    }
}

/// Backwards-compatible client entrypoint; accepts any valid advertised fee.
/// CLI miners use `run_pool_miner_with_fee_percent` to enforce a local limit.
pub async fn run_pool_miner(
    cfg: PoolMinerConfig,
    stop: Arc<AtomicBool>,
    stats: Arc<PoolMinerStats>,
) -> Result<()> {
    run_pool_miner_with_fee_percent(cfg, stop, stats, 99.9999).await
}

/// Mine only when the advertised pool fee is at most `max_fee_percent`.
/// This local policy does not come from the unauthenticated pool API.
pub async fn run_pool_miner_with_fee_percent(
    cfg: PoolMinerConfig,
    stop: Arc<AtomicBool>,
    stats: Arc<PoolMinerStats>,
    max_fee_percent: f64,
) -> Result<()> {
    let stream =
        tokio::net::TcpStream::connect(cfg.pool.trim_start_matches("stratum+tcp://")).await?;
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    let hello = json!({ "id": 1, "method": "mining.authorize", "params": [cfg.address.encode(), cfg.worker] });
    write
        .write_all((hello.to_string() + "\n").as_bytes())
        .await?;

    let (share_tx, mut share_rx) = tokio::sync::mpsc::channel::<(u64, u64)>(256);
    let mut api = String::new();
    let mut cancel = Arc::new(AtomicBool::new(false));
    let mut next_id = 2u64;
    let mut ticker = tokio::time::interval(Duration::from_millis(200));
    let max_fee_ppm = fee_ppm(max_fee_percent)?;
    // (sequence number, weight) of our shares the pool accepted, which every
    // window covering them must credit to us.
    let mut my_shares: VecDeque<(u64, u64)> = VecDeque::new();
    let mut last_audit: Option<AuditedJob> = None;
    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line? else { bail!("pool closed the connection") };
                let msg: Value = serde_json::from_str(&line)?;
                if msg["id"] == 1 {
                    api = msg["result"]["api"].as_str().unwrap_or_default().to_string();
                    continue;
                }
                if msg["method"] != "mining.notify" {
                    if msg["result"] == true {
                        stats.shares_accepted.fetch_add(1, Ordering::Relaxed);
                        if let (Some(seq), Some(weight)) = (msg["seq"].as_u64(), msg["weight"].as_u64()) {
                            my_shares.push_back((seq, weight));
                        }
                    }
                    continue;
                }
                cancel.store(true, Ordering::Relaxed);
                let p = msg["params"].as_array().cloned().unwrap_or_default();
                let job_id = p.first().and_then(Value::as_u64).unwrap_or(0);
                let mining_hash = crate::core::auxpow::bytes32(&p[1])?;
                // The pool sends one template for everyone and, for us, the
                // coinbase extra and signature that make it our copy.
                let extra = crate::core::auxpow::bytes32(p.get(5).unwrap_or(&Value::Null))?;
                let auth = match p.get(6).and_then(Value::as_str) {
                    Some(h) => Some(bincode::deserialize(&hex::decode(h)?)?),
                    None => None,
                };
                let template_hex = bind_template(p[2].as_str().unwrap_or_default(), extra, auth)?;
                let share_target = crate::core::auxpow::bytes32(&p[3])?;
                let network_target = crate::core::auxpow::bytes32(&p[4])?;
                stats.jobs.fetch_add(1, Ordering::Relaxed);

                let (api2, addr) = (api.clone(), cfg.address);
                let th = template_hex.clone();
                let shares: Vec<(u64, u64)> = my_shares.iter().copied().collect();
                let audit = tokio::task::spawn_blocking(move || -> Result<AuditedJob> {
                    let client = RpcClient::new(api2);
                    let proof = client
                        .get(&format!("/api/proof?address={}&job={job_id}", addr.encode()))?;
                    let window = client.get(&format!("/api/window?job={job_id}"))?;
                    if proof["job_id"].as_u64() != Some(job_id)
                        || window["job_id"].as_u64() != Some(job_id) {
                        bail!("the audit API does not describe the announced job");
                    }
                    audit_job_with_fee_limit(
                        &addr, &mining_hash, &th, &proof, &window, max_fee_ppm, &shares,
                    )
                })
                .await?;
                let audited = match audit
                    .and_then(|a| check_window_chain(last_audit.as_ref(), &a).map(|()| a))
                {
                    Ok(audited) => audited,
                    Err(e) => {
                        stats.audits_failed.fetch_add(1, Ordering::Relaxed);
                        bail!("audit failed, disconnecting: {e:#}");
                    }
                };
                stats.audits_passed.fetch_add(1, Ordering::Relaxed);
                // Shares before the paid window are behind later windows too,
                // unless blocks get easier and windows longer; forgetting
                // them then only makes the check above more lenient.
                while my_shares.front().is_some_and(|(seq, _)| *seq < audited.window_start) {
                    my_shares.pop_front();
                }
                last_audit = Some(audited);

                cancel = Arc::new(AtomicBool::new(false));
                let (c, tx, threads, counter) = (cancel.clone(), share_tx.clone(), cfg.threads, stats.hashes.clone());
                std::thread::spawn(move || {
                    while !c.load(Ordering::Relaxed) {
                        match search(mining_hash, network_target, share_target, threads, c.clone(), counter.clone()) {
                            Some(MiningResult::Block(ext)) | Some(MiningResult::Share(ext)) => {
                                if tx.blocking_send((job_id, ext.nonce)).is_err() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                });
            }
            Some((job_id, nonce)) = share_rx.recv() => {
                let submit = json!({ "id": next_id, "method": "mining.submit", "params": [cfg.address.encode(), job_id, nonce] });
                next_id += 1;
                stats.shares_sent.fetch_add(1, Ordering::Relaxed);
                write.write_all((submit.to_string() + "\n").as_bytes()).await?;
            }
            _ = ticker.tick() => {
                if stop.load(Ordering::Relaxed) {
                    cancel.store(true, Ordering::Relaxed);
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::mw::WalletKeys;
    use tokio::io::AsyncReadExt;

    /// A pool whose minimum share difficulty is `share_bits`: 0 makes every
    /// share valid, 256 makes none valid.
    fn test_state(dir: &std::path::Path, share_bits: u32) -> Arc<PoolState> {
        let (db, log) = open_db(&dir.join("pool.redb")).unwrap();
        Arc::new(PoolState {
            cfg: PoolConfig {
                pool_address: WalletKeys::random().address(),
                node_rpc: String::new(),
                stratum_bind: "127.0.0.1:0".parse().unwrap(),
                api_bind: "127.0.0.1:0".parse().unwrap(),
                api_public: None,
                fee_percent: 1.0,
                share_bits,
                share_interval: Duration::from_secs(10),
                window_blocks: 2,
                data_dir: dir.to_path_buf(),
                poll_interval: Duration::from_secs(1),
            },
            db,
            current: RwLock::new(None),
            recent: RwLock::default(),
            notifier: broadcast::channel(4).0,
            connected: Default::default(),
            log: std::sync::Mutex::new(log),
            verifier: Verifier::start(1),
            bans: Bans::default(),
            admission: Arc::default(),
            force_new_job: AtomicBool::new(false),
            stats: Arc::default(),
            api_public: String::new(),
            submitted_job: AtomicU64::new(0),
        })
    }

    /// A job whose network target is never met, so no block is submitted,
    /// with a copy for each of `miners`.
    fn test_job(job_id: u64, miners: &[AddrKey]) -> Arc<Job> {
        let empty = Arc::new(WindowSnapshot::new(Window::default()));
        let commitment = hash_domain(b"test commitment", &[&job_id.to_le_bytes()]);
        let variants = miners
            .iter()
            .map(|m| {
                let variant = Variant {
                    extra: bind_extra(&commitment, m),
                    mining_hash: hash_domain(b"test copy", &[&job_id.to_le_bytes(), m]),
                    miner: None,
                };
                (*m, Arc::new(variant))
            })
            .collect();
        Arc::new(Job {
            job_id,
            mining_hash: hash_domain(b"test job", &[&job_id.to_le_bytes()]),
            network_target: [0; 32],
            template_hex: String::new(),
            batch: Batch::genesis().clone(),
            height: 1,
            prev_hash: [0; 32],
            paying: empty.clone(),
            next: empty,
            commitment,
            fee_ppm: 0,
            receipts: Arc::default(),
            variants: std::sync::Mutex::new(variants),
            seen: Default::default(),
        })
    }

    /// Total weight credited to `miner` in the share log.
    fn credited(state: &PoolState, miner: &AddrKey) -> u64 {
        let log = state.log.lock().unwrap();
        log.entries
            .iter()
            .filter(|(_, owner, _)| owner == miner)
            .map(|(_, _, w)| *w)
            .sum()
    }

    fn task(proven: bool) -> VerifyTask {
        VerifyTask {
            seed: [0; 32],
            proven,
            done: oneshot::channel().0,
        }
    }

    fn key(i: u32) -> AddrKey {
        let mut k = [0u8; 96];
        k[..4].copy_from_slice(&i.to_be_bytes());
        k
    }

    /// Average allocation per owner over every offset the draw can take.
    fn expected(total: u128, owners: &[(AddrKey, u64)]) -> HashMap<AddrKey, f64> {
        let weight: u128 = owners.iter().map(|(_, w)| *w as u128).sum();
        let slots = MAX_PAID_MINERS as u128;
        let small: u128 = owners
            .iter()
            .map(|(_, w)| *w as u128)
            .filter(|w| w * slots < weight)
            .sum();
        let draws = small.max(1);
        let mut sum: HashMap<AddrKey, f64> = HashMap::new();
        for offset in 0..draws {
            let (paid, dust) = allocate(total, owners, offset);
            assert_eq!(paid.iter().map(|(_, a)| a).sum::<u128>() + dust, total);
            assert!(paid.len() <= MAX_PAID_MINERS);
            for (k, a) in paid {
                *sum.entry(k).or_default() += a as f64;
            }
        }
        sum.values_mut().for_each(|v| *v /= draws as f64);
        sum
    }

    // ── Payouts ─────────────────────────────────────────────────────────────

    #[test]
    fn large_owners_are_paid_exactly_and_small_ones_by_slot() {
        let mut owners = vec![(key(0), 50), (key(1), 30)];
        owners.extend((2..42).map(|i| (key(i), 1)));
        let total = 1_000_000u128;
        let (paid, dust) = allocate(total, &owners, 7);
        // Only the rounding of 29 equal slots is left over.
        assert!(dust < 29);
        assert_eq!(paid.iter().map(|(_, a)| a).sum::<u128>() + dust, total);
        let get = |k: AddrKey| paid.iter().find(|(o, _)| *o == k).map_or(0, |(_, a)| *a);
        assert_eq!(get(key(0)), total * 50 / 120);
        assert_eq!(get(key(1)), total * 30 / 120);
        // 29 slots are left for the 40 owners of weight 1.
        assert_eq!(paid.len(), 2 + 29);
    }

    #[test]
    fn every_owner_expects_exactly_its_entitlement() {
        let mut owners = vec![(key(9), 1_000)];
        owners.extend(
            [1u64, 2, 3, 5, 8, 13]
                .iter()
                .enumerate()
                .map(|(i, w)| (key(i as u32), *w)),
        );
        owners.sort();
        let total = 1_000_000_000u128;
        let weight: u128 = owners.iter().map(|(_, w)| *w as u128).sum();
        let exact = total * 1_000 / weight;
        let rest = total - exact;
        let got = expected(total, &owners);
        assert_eq!(got[&key(9)], exact as f64);
        // 30 equal slots over the owners of weight 1..13, 32 in all.
        let slot = (rest / 30) as f64;
        for (k, w) in owners.iter().filter(|(k, _)| *k != key(9)) {
            let want = 30.0 * *w as f64 / 32.0 * slot;
            assert!((got[k] - want).abs() < 1e-6, "{} vs {want}", got[k]);
        }
    }

    #[test]
    fn splitting_an_owner_changes_no_expected_payout() {
        let total = 1_000_000_000u128;
        // One owner at exactly 1/31 of the window, paid exactly, against the
        // same weight split in two, each half sampled.
        let mut whole: Vec<(AddrKey, u64)> = (0..60).map(|i| (key(i), 50)).collect();
        whole.push((key(100), 100));
        let mut split: Vec<(AddrKey, u64)> = (0..60).map(|i| (key(i), 50)).collect();
        split.push((key(100), 50));
        split.push((key(101), 50));
        let a = expected(total, &whole);
        let b = expected(total, &split);
        let alone = a[&key(100)];
        let halves = b[&key(100)] + b[&key(101)];
        assert!((alone - halves).abs() < 1e-6, "{alone} vs {halves}");
        // Nobody else's expectation moves either.
        for i in 0..60 {
            assert!((a[&key(i)] - b[&key(i)]).abs() < 1e-6);
        }
        // Splitting a sampled owner, too.
        let mut small = vec![(key(9), 1_000)];
        small.extend(
            [1u64, 2, 3, 5, 21]
                .iter()
                .enumerate()
                .map(|(i, w)| (key(i as u32), *w)),
        );
        let mut smaller = small.clone();
        smaller.retain(|(k, _)| *k != key(4));
        smaller.extend([(key(4), 9), (key(5), 12)]);
        smaller.sort();
        small.sort();
        let (x, y) = (expected(total, &small), expected(total, &smaller));
        assert!((x[&key(4)] - (y[&key(4)] + y[&key(5)])).abs() < 1e-6);
        assert!((x[&key(9)] - y[&key(9)]).abs() < 1e-6);
    }

    #[test]
    fn payout_weights_fit_one_coinbase() {
        let operator = WalletKeys::random().address();
        let owners: Vec<(AddrKey, u64)> = (0..1_000)
            .map(|i| {
                let w = WalletKeys::random().address();
                (addr_key(&w), 1 + (i * 7919) % 500)
            })
            .collect();
        let mut owners = owners;
        owners.sort();
        let weights = payout_weights(fee_ppm(1.0).unwrap(), &operator, &owners, &[3; 32]).unwrap();
        assert!(weights.len() <= crate::core::mw::crypto::MAX_GROUP_OUTPUTS);
        assert_eq!(
            weights.iter().map(|(_, w)| *w as u128).sum::<u128>(),
            PAYOUT_SCALE as u128
        );
        assert_eq!(
            weights,
            payout_weights(fee_ppm(1.0).unwrap(), &operator, &owners, &[3; 32]).unwrap()
        );
        // An empty window pays the operator.
        assert_eq!(
            payout_weights(10_000, &operator, &[], &[3; 32]).unwrap(),
            vec![(operator, PAYOUT_SCALE)]
        );
    }

    #[test]
    fn fee_is_proportional_even_with_one_share() {
        let operator = WalletKeys::random().address();
        let miner = WalletKeys::random().address();
        let weights = payout_weights(
            fee_ppm(2.0).unwrap(),
            &operator,
            &[(addr_key(&miner), 1)],
            &[0; 32],
        )
        .unwrap();
        let split = crate::core::template::split_by_weight(100_000, &weights).unwrap();
        assert_eq!(split.iter().find(|(a, _)| *a == operator).unwrap().1, 2_000);
        assert_eq!(split.iter().find(|(a, _)| *a == miner).unwrap().1, 98_000);
    }

    #[test]
    fn a_window_is_the_newest_shares_until_it_is_full() {
        let mut log = ShareLog::default();
        for (i, w) in [5u64, 1, 2, 3, 4].iter().enumerate() {
            log.entries
                .push_back((10 + i as u64, key(i as u32 % 2), *w));
        }
        log.next_seq = 15;
        let w = log.window(6);
        // The newest shares: 4, 3 (7 >= 6).
        assert_eq!((w.start_seq, w.end_seq), (13, 15));
        assert_eq!(w.owners, vec![(key(0), 4), (key(1), 3)]);
        assert_eq!(log.window(1_000).start_seq, 10);
        // Pruning keeps the newest weight and anything a window still uses.
        assert_eq!(log.prune(12, 3), 12);
        assert_eq!(log.entries.front().unwrap().0, 12);
    }

    #[test]
    fn a_window_root_binds_its_owners_and_range() {
        let w = Window {
            start_seq: 3,
            end_seq: 9,
            owners: vec![(key(0), 4), (key(1), 2), (key(2), 1)],
        };
        let mut moved = w.clone();
        moved.start_seq = 4;
        let mut padded = w.clone();
        padded.owners.push((key(2), 1));
        assert_ne!(w.root(), moved.root());
        assert_ne!(w.root(), padded.root());
        assert_eq!(w.root(), w.clone().root());
    }

    #[test]
    fn windows_are_sized_in_blocks_of_minimum_difficulty_shares() {
        // A target with 20 leading zero bits is about 2^20 hashes a block:
        // 2^8 shares of 12 bits.
        let target = target_from_leading_zero_bits(20);
        assert_eq!(window_size(&target, 12, 2), 2 * 256);
        assert_eq!(window_size(&[0xff; 32], 12, 2), 1);
        assert_eq!(window_size(&[0; 32], 0, 2), u64::MAX as u128);
    }

    #[test]
    fn vardiff_moves_toward_one_share_per_interval() {
        let t0 = Instant::now();
        let interval = Duration::from_secs(10);
        let mut v = Vardiff::new(12, interval, t0);
        assert_eq!(v.retarget(t0, 40), 12);
        // 16 shares in 10 s, a sixteenth of the aim: four bits harder.
        v.shares = 16;
        assert_eq!(v.retarget(t0 + interval, 40), 16);
        // Nothing for four intervals: easier, never below the minimum.
        assert!(v.retarget(t0 + interval * 5, 40) < 16);
        for i in 0..10 {
            v.retarget(t0 + interval * (10 + 4 * i), 40);
        }
        assert_eq!(v.bits, 12);
        // Never harder than the cap.
        v.shares = 1_000;
        assert_eq!(v.retarget(t0 + interval * 60, 13), 13);
        assert_eq!(max_share_bits(&target_from_leading_zero_bits(20), 12), 20);
        assert_eq!(max_share_bits(&[0; 32], 12), 12 + MAX_WEIGHT_BITS);
        assert_eq!(max_share_bits(&[0xff; 32], 12), 12);
    }

    #[test]
    fn a_job_on_a_new_tip_must_pay_the_window_frozen_on_the_last() {
        let job = |prev: u8, paying: u8, next: u8| AuditedJob {
            prev_hash: [prev; 32],
            window_root: [paying; 32],
            next_root: [next; 32],
            window_start: 0,
        };
        assert!(check_window_chain(None, &job(1, 1, 2)).is_ok());
        assert!(check_window_chain(Some(&job(1, 1, 2)), &job(1, 1, 2)).is_ok());
        assert!(check_window_chain(Some(&job(1, 1, 2)), &job(2, 2, 3)).is_ok());
        // A new window on the same tip, or a new tip paying something else.
        assert!(check_window_chain(Some(&job(1, 1, 2)), &job(1, 1, 4)).is_err());
        assert!(check_window_chain(Some(&job(1, 1, 2)), &job(2, 4, 3)).is_err());
    }

    #[test]
    fn unpaid_scores_carry_over_into_the_share_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.redb");
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut t = txn.open_table(LEGACY_SCORES).unwrap();
                t.insert(key(1).as_slice(), 7).unwrap();
                t.insert(key(2).as_slice(), 0).unwrap();
                t.insert(key(3).as_slice(), 2).unwrap();
            }
            txn.commit().unwrap();
        }
        let (db, log) = open_db(&path).unwrap();
        let entries: Vec<(AddrKey, u64)> = log.entries.iter().map(|(_, k, w)| (*k, *w)).collect();
        assert_eq!(entries, vec![(key(1), 7), (key(3), 2)]);
        drop((db, log));
        let (_, again) = open_db(&path).unwrap();
        assert_eq!(again.entries.len(), 2);
    }

    // ── Verification and admission ──────────────────────────────────────────

    #[test]
    fn proven_connections_go_first_and_unproven_ones_share_a_cap() {
        let mut q = VerifyQueues {
            unproven_limit: 2,
            ..Default::default()
        };
        for _ in 0..5 {
            q.unproven.push_back(task(false));
        }
        for _ in 0..3 {
            q.proven.push_back(task(true));
        }
        let first = q.take(4);
        assert_eq!(first.iter().filter(|t| t.proven).count(), 3);
        assert_eq!(first.len(), 4);
        // One unproven share is in flight: only one more may start.
        assert_eq!(q.take(4).len(), 1);
        assert!(q.take(4).is_empty());
        q.unproven_running -= 2; // both finished
        assert_eq!(q.take(4).len(), 2);
        // New proven work is never held back by the cap.
        q.proven.push_back(task(true));
        assert_eq!(q.take(4).len(), 1);
    }

    #[test]
    fn addresses_group_by_ipv4_and_ipv6_slash_64() {
        let ip = |s: &str| ip_key(s.parse().unwrap());
        assert_eq!(ip("2001:db8:1:2::1"), ip("2001:db8:1:2:ffff::9"));
        assert_ne!(ip("2001:db8:1:2::1"), ip("2001:db8:1:3::1"));
        assert_eq!(ip("::ffff:192.0.2.7"), ip("192.0.2.7"));
        assert_ne!(ip("192.0.2.7"), ip("192.0.2.8"));
    }

    #[test]
    fn bans_escalate_and_a_clean_day_resets_them() {
        let bans = Bans::default();
        let ip = ip_key("192.0.2.1".parse().unwrap());
        let t0 = Instant::now();
        assert!(!bans.is_banned(ip, t0));
        assert_eq!(bans.strike(ip, t0), BAN_BASE);
        assert!(bans.is_banned(ip, t0 + BAN_BASE / 2));
        assert!(!bans.is_banned(ip, t0 + BAN_BASE));
        assert_eq!(bans.strike(ip, t0 + BAN_BASE), BAN_BASE * 4);
        let later = t0 + BAN_BASE * 5 + BAN_MAX;
        assert_eq!(bans.strike(ip, later), BAN_BASE);
        for _ in 0..20 {
            assert!(bans.strike(ip, later) <= BAN_MAX);
        }
    }

    #[test]
    fn connections_are_capped_per_address_and_released_on_close() {
        let admission: Arc<Admission> = Arc::default();
        let ip = ip_key("192.0.2.1".parse().unwrap());
        let held: Vec<Admitted> = (0..MAX_CONNECTIONS_PER_IP)
            .map(|_| admission.admit(ip).unwrap())
            .collect();
        assert!(admission.admit(ip).is_none());
        assert!(admission
            .admit(ip_key("192.0.2.2".parse().unwrap()))
            .is_some());
        drop(held);
        assert_eq!(admission.total.load(Ordering::SeqCst), 0);
        assert!(admission.admit(ip).is_some());
    }

    #[tokio::test]
    async fn line_reader_limits_lines_and_survives_split_writes() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let mut lines = LineReader::new(rx, 16);
        tx.write_all(b"hello\r\nwor").await.unwrap();
        assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("hello"));
        tx.write_all(b"ld\n").await.unwrap();
        assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("world"));
        tx.write_all(&[b'x'; 40]).await.unwrap();
        assert!(lines.next_line().await.is_err());
    }

    #[tokio::test]
    async fn shares_queue_instead_of_being_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), 0);
        *state.current.write().await = Some(test_job(1, &[key(7)]));
        let miner = key(7);
        // Far more shares than the one worker can take at once.
        let shares: Vec<_> = (0..40u64)
            .map(|nonce| {
                tokio::spawn(process_share(
                    state.clone(),
                    miner,
                    1,
                    nonce,
                    nonce % 2 == 0,
                    0,
                ))
            })
            .collect();
        for share in shares {
            assert!(matches!(
                share.await.unwrap().unwrap(),
                ShareOutcome::Accepted {
                    is_block: false,
                    weight: 1,
                    ..
                }
            ));
        }
        assert_eq!(credited(&state, &miner), 40);
        // Sequence numbers are distinct and dense.
        let mut seqs: Vec<u64> = state
            .log
            .lock()
            .unwrap()
            .entries
            .iter()
            .map(|e| e.0)
            .collect();
        seqs.sort();
        assert_eq!(seqs, (0..40).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn shares_weigh_two_to_the_extra_bits_of_difficulty() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), 0);
        *state.current.write().await = Some(test_job(1, &[key(1)]));
        // Difficulty 3 above the minimum: a share counts 8 times, provided
        // its hash has the three leading zero bits.
        let mut accepted = 0;
        for nonce in 0..64u64 {
            match process_share(state.clone(), key(1), 1, nonce, true, 3)
                .await
                .unwrap()
            {
                ShareOutcome::Accepted { weight, .. } => {
                    assert_eq!(weight, 8);
                    accepted += 1;
                }
                ShareOutcome::Invalid => {}
                other => panic!("{other:?}"),
            }
        }
        assert!(accepted > 0 && accepted < 64);
        assert_eq!(credited(&state, &key(1)), 8 * accepted);
    }

    #[tokio::test]
    async fn a_share_counts_even_if_its_job_is_replaced_while_it_waits() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), 0);
        *state.current.write().await = Some(test_job(1, &[key(7)]));
        let miner = key(7);
        let share = precheck_share(&state, miner, 1, 5, 0).await.ok().unwrap();
        // A copy submitted while the first is in verification is a duplicate.
        assert!(matches!(
            precheck_share(&state, miner, 1, 5, 0).await,
            Err(ShareOutcome::Duplicate)
        ));
        *state.current.write().await = Some(test_job(2, &[]));
        let final_hash = state
            .verifier
            .verify(pow_seed(&share.job.mining_hash, 5), true)
            .await
            .unwrap();
        assert!(matches!(
            finish_share(&state, share, final_hash).await.unwrap(),
            ShareOutcome::Accepted {
                is_block: false,
                ..
            }
        ));
        assert_eq!(credited(&state, &miner), 1);
        // New submissions for the replaced job are stale.
        assert!(matches!(
            precheck_share(&state, miner, 1, 6, 0).await,
            Err(ShareOutcome::StaleJob)
        ));
    }

    #[tokio::test]
    async fn batched_verification_matches_the_extension() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), 0);
        let mining_hash = [3u8; 32];
        let checks: Vec<_> = (0..11u64)
            .map(|nonce| {
                let st = state.clone();
                tokio::spawn(async move {
                    let got = st
                        .verifier
                        .verify(pow_seed(&mining_hash, nonce), false)
                        .await;
                    (nonce, got.unwrap())
                })
            })
            .collect();
        for check in checks {
            let (nonce, got) = check.await.unwrap();
            let want = crate::core::extension::create_extension(mining_hash, nonce).final_hash;
            assert_eq!(got, want);
        }
    }

    #[tokio::test]
    async fn an_invalid_share_is_refused_and_bans_its_sender() {
        let dir = tempfile::tempdir().unwrap();
        // No hash meets a 256-bit difficulty: every share is invalid.
        let state = test_state(dir.path(), 256);
        let me = WalletKeys::random().address();
        *state.current.write().await = Some(test_job(1, &[addr_key(&me)]));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let st = state.clone();
        let server = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            handle_miner(socket, peer, st).await
        });
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let hello = json!({ "id": 1, "method": "mining.authorize", "params": [me.encode(), "w"] });
        let submit = json!({ "id": 2, "method": "mining.submit", "params": [me.encode(), 1, 9] });
        client
            .write_all(format!("{hello}\n{submit}\n").as_bytes())
            .await
            .unwrap();
        let mut replies = String::new();
        client.read_to_string(&mut replies).await.unwrap();
        assert!(replies.contains("invalid share"), "{replies}");
        assert!(server.await.unwrap().is_err());
        let ip = ip_key("127.0.0.1".parse().unwrap());
        assert!(state.bans.is_banned(ip, Instant::now()));
        assert_eq!(credited(&state, &addr_key(&me)), 0);
        let job = state.current.read().await.clone().unwrap();
        assert!(!job.seen.lock().unwrap().contains(&(addr_key(&me), 9)));
    }

    #[tokio::test]
    async fn a_share_is_worth_nothing_under_another_address() {
        let dir = tempfile::tempdir().unwrap();
        // Shares need 8 leading zero bits: a nonce meets that for a given
        // copy of the job about one time in 256.
        let state = test_state(dir.path(), 8);
        let (victim, thief) = (key(1), key(2));
        let job = test_job(1, &[victim, thief]);
        let target = target_from_leading_zero_bits(8);
        let hash_of = |miner: &AddrKey, nonce: u64| {
            let mining_hash = job.variants.lock().unwrap()[miner].mining_hash;
            crate::core::extension::create_extension(mining_hash, nonce).final_hash
        };
        // A nonce the victim found: a share for its own copy only.
        let nonce = (0..u64::MAX)
            .find(|n| hash_of(&victim, *n) < target && hash_of(&thief, *n) >= target)
            .unwrap();
        *state.current.write().await = Some(job.clone());
        // Replayed under the thief's address, it fails (and bans the thief).
        assert_eq!(
            process_share(state.clone(), thief, 1, nonce, true, 8)
                .await
                .unwrap(),
            ShareOutcome::Invalid
        );
        assert!(matches!(
            process_share(state.clone(), victim, 1, nonce, true, 8)
                .await
                .unwrap(),
            ShareOutcome::Accepted { .. }
        ));
        assert_eq!(credited(&state, &thief), 0);
        assert_eq!(credited(&state, &victim), 1);
    }

    #[tokio::test]
    async fn the_same_nonce_counts_once_per_miner() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path(), 0);
        *state.current.write().await = Some(test_job(1, &[key(1), key(2)]));
        // Different copies of the job: the same nonce is different work.
        for miner in [key(1), key(2)] {
            assert!(matches!(
                process_share(state.clone(), miner, 1, 5, true, 0)
                    .await
                    .unwrap(),
                ShareOutcome::Accepted { .. }
            ));
            assert_eq!(
                process_share(state.clone(), miner, 1, 5, true, 0)
                    .await
                    .unwrap(),
                ShareOutcome::Duplicate
            );
        }
        // Without a copy of the job there is nothing to have mined.
        assert_eq!(
            process_share(state.clone(), key(3), 1, 5, true, 0)
                .await
                .unwrap(),
            ShareOutcome::StaleJob
        );
    }

    // ── Commitment and audit ────────────────────────────────────────────────

    #[test]
    fn share_target_has_the_requested_zero_bits() {
        let t = target_from_leading_zero_bits(12);
        assert_eq!(&t[..2], &[0x00, 0x0f]);
        assert!(t[2..].iter().all(|b| *b == 0xff));
    }

    #[test]
    fn proofs_verify_for_every_leaf() {
        let leaves: Vec<(AddrKey, u64)> = (0..7u8).map(|i| ([i; 96], 10 + i as u64)).collect();
        let tree = ShareMerkleTree::build(leaves.clone());
        for (k, s) in &leaves {
            let (idx, proof) = tree.proof(k).unwrap();
            assert_eq!(fold_proof(score_leaf(k, *s), idx, &proof), tree.root);
            assert_ne!(fold_proof(score_leaf(k, s + 1), idx, &proof), tree.root);
        }
    }

    #[test]
    fn audit_catches_a_lying_pool() {
        use crate::core::bond::{
            est_midstate_height, BondEntry, MinerBond, MIN_MINING_BOND, MIN_REMAINING_BOND_LOCK,
        };
        use crate::core::state::apply_batch;
        use crate::core::template::{build_template_bonded, split_by_weight};
        use crate::core::types::{block_reward, hash, State, HALVING_INTERVAL};
        let me = WalletKeys::random().address();
        let other = WalletKeys::random().address();
        let pool = WalletKeys::random().address();
        let mut state = State::genesis();
        apply_batch(&mut state, Batch::genesis(), &[]).unwrap();
        let ts = vec![Batch::genesis().timestamp];

        // Production builds require every block to be authorised by a bond
        // (`core::bond::BONDED_MINING_FROM`). Registering one here would mean
        // mining real midstate headers, so the bond is put straight into the
        // state instead: a template needs nothing else.
        let bond = MinerBond {
            co_bonds: Vec::new(),
            secret: curve25519_dalek::scalar::Scalar::from_bytes_mod_order(hash(b"pool audit")),
            bond_id: hash(b"pool audit bond"),
            registration: None,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        state.bonds.insert(
            bond.bond_id,
            BondEntry {
                mining_key: bond.mining_key(),
                value: MIN_MINING_BOND,
                bonded_until: est_midstate_height(now) + MIN_REMAINING_BOND_LOCK + 1_440,
            },
        );
        let fee = fee_ppm(1.0).unwrap();
        let mut owners = vec![(addr_key(&me), 5), (addr_key(&other), 3)];
        owners.sort();
        let window = Window {
            start_seq: 100,
            end_seq: 110,
            owners,
        };
        let next_root = hash(b"next window");
        // A template for `window` paying `weights`, with the API answers.
        // A template for `window` paying `weights`, the node's copy of it
        // for `bound_to` (`template::rebind`), and the API answers.
        let job = |window: &Window,
                   weights: &[(StealthAddress, u64)],
                   height: u64,
                   fee: u64,
                   bound_to: &StealthAddress| {
            let commitment = job_commitment(&window.root(), &next_root);
            let (base, receipts) =
                build_template_bonded(&state, &ts, &[], weights, commitment, None, Some(&bond))
                    .unwrap();
            let extra = bind_extra(&commitment, &addr_key(bound_to));
            let tpl = crate::core::template::rebind(&base, extra, Some(&bond)).unwrap();
            let mine: Vec<Value> = receipts
                .iter()
                .filter(|(a, _)| *a == me)
                .map(|(_, r)| serde_json::to_value(r).unwrap())
                .collect();
            let api = json!({
                "job_id": 1, "height": height, "fee_ppm": fee, "pool_address": pool.encode(),
                "window": window_json(window), "next_root": hex::encode(next_root),
            });
            (tpl, json!({ "job_id": 1, "receipts": mine }), api)
        };
        let honest = |window: &Window| {
            let seed = draw_seed(&state.header_hash, &window.root());
            payout_weights(fee, &pool, &window.owners, &seed).unwrap()
        };
        let audit = |tpl: &crate::core::template::BlockTemplate,
                     proof: &Value,
                     api: &Value,
                     shares: &[(u64, u64)]| {
            let hex = hex::encode(bincode::serialize(&tpl.batch).unwrap());
            audit_job_with_fee_limit(&me, &tpl.mining_hash, &hex, proof, api, 20_000, shares)
        };

        let (tpl, proof, api) = job(&window, &honest(&window), state.height, fee, &me);
        let audited = audit(&tpl, &proof, &api, &[(101, 2), (105, 3), (90, 7)]).unwrap();
        assert_eq!(audited.window_root, window.root());
        assert_eq!(audited.prev_hash, state.header_hash);

        // The miner rebuilds its copy from the shared template plus the
        // extra and signature the pool sends: exactly the node's copy.
        let commitment = job_commitment(&window.root(), &next_root);
        let (base, _) = build_template_bonded(
            &state,
            &ts,
            &[],
            &honest(&window),
            commitment,
            None,
            Some(&bond),
        )
        .unwrap();
        let extra = bind_extra(&commitment, &addr_key(&me));
        let copy = crate::core::template::rebind(&base, extra, Some(&bond)).unwrap();
        let base_hex = hex::encode(bincode::serialize(&base.batch).unwrap());
        let rebuilt = bind_template(&base_hex, extra, copy.batch.miner.clone()).unwrap();
        let rebuilt: Batch = bincode::deserialize(&hex::decode(rebuilt).unwrap()).unwrap();
        assert_eq!(compute_header_hash(&rebuilt.header()), copy.mining_hash);
        // A job bound to someone else is refused: our work would be theirs.
        let (t, p, a) = job(&window, &honest(&window), state.height, fee, &other);
        assert!(audit(&t, &p, &a, &[]).is_err());

        // A valid coinbase that pays us less than the rule gives us.
        let skim: Vec<(StealthAddress, u64)> = honest(&window)
            .into_iter()
            .map(|(a, w)| if a == me { (a, w / 2) } else { (a, w) })
            .collect();
        let (t, p, a) = job(&window, &skim, state.height, fee, &me);
        assert!(audit(&t, &p, &a, &[]).is_err());
        // A fee above our limit, even if the coinbase matches it.
        let greedy = {
            let seed = draw_seed(&state.header_hash, &window.root());
            payout_weights(50_000, &pool, &window.owners, &seed).unwrap()
        };
        let (t, p, a) = job(&window, &greedy, state.height, 50_000, &me);
        assert!(audit(&t, &p, &a, &[]).is_err());
        // A later era claimed, every miner paid what that height would give.
        let claimed = HALVING_INTERVAL;
        let shrunk = split_by_weight(block_reward(claimed), &honest(&window)).unwrap();
        let to_miners: Vec<(StealthAddress, u64)> =
            shrunk.into_iter().filter(|(a, _)| *a != pool).collect();
        let real = block_reward(state.height);
        let mut skim = vec![(pool, real - to_miners.iter().map(|(_, v)| v).sum::<u64>())];
        skim.extend(to_miners);
        let (t, p, a) = job(&window, &skim, claimed, fee, &me);
        assert!(audit(&t, &p, &a, &[]).is_err());
        // A published window other than the committed one.
        let mut forged = api.clone();
        forged["window"]["owners"][0]["weight"] = json!(9);
        assert!(audit(&tpl, &proof, &forged, &[]).is_err());
        let mut forged = api.clone();
        forged["next_root"] = json!(hex::encode([7u8; 32]));
        assert!(audit(&tpl, &proof, &forged, &[]).is_err());
        // Duplicate or unsorted owners are refused outright.
        let mut forged = api.clone();
        let first = forged["window"]["owners"][0].clone();
        forged["window"]["owners"]
            .as_array_mut()
            .unwrap()
            .push(first);
        assert!(audit(&tpl, &proof, &forged, &[]).is_err());
        // A window that leaves us out: honest-looking on its own, caught by
        // the shares the pool told us it accepted.
        let mut without = window.clone();
        without.owners.retain(|(k, _)| *k != addr_key(&me));
        let (t, p, a) = job(&without, &honest(&without), state.height, fee, &me);
        assert!(audit(&t, &p, &a, &[]).is_ok());
        assert!(audit(&t, &p, &a, &[(104, 1)]).is_err());
        // Shares outside the window's range do not count against it.
        assert!(audit(&t, &p, &a, &[(99, 1), (110, 1)]).is_ok());
        // Someone else's receipts, and a template that is not the job.
        let theirs = json!({ "job_id": 1, "receipts": [] });
        assert!(audit(&tpl, &theirs, &api, &[]).is_err());
        let hex = hex::encode(bincode::serialize(&tpl.batch).unwrap());
        assert!(audit_job(&me, &[0; 32], &hex, &proof, &api).is_err());
    }
}
