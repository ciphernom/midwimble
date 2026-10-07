//! Provably fair Stratum pool, ported from midstate `src/pool.rs`.
//!
//! Every job commits to the pool's full score table before anyone hashes on
//! it, and every miner audits its own position before mining:
//!
//! * **Score commitment.** The Merkle root of `(address, score)` leaves goes
//!   in the coinbase `extra` field, where midstate used `coinbase[0].salt`.
//!   The block's header hash commits to it.
//! * **Payouts in the coinbase.** The pool fee plus the top
//!   [`MAX_PAID_MINERS`] scorers are paid directly, in proportion to score.
//!   Outputs are stealth outputs, so the pool also hands each paid miner a
//!   [`PayoutReceipt`] proving, with public data only, that a specific output
//!   pays that miner that amount.
//! * **Miner audit** ([`audit_job`]): the template must hash to the announced
//!   mining hash; the miner's leaf must prove into `extra`; a paid miner's
//!   receipt must match the actual coinbase output; an unpaid miner with a
//!   score must be outranked by every paid miner. Any failure disconnects.
//!
//! Kept from midstate: share replay protection per job, proof-of-work checks
//! off the async reactor behind a semaphore, score deduction only after the
//! node accepts the block, and orphan reconciliation once blocks mature,
//! which restores the scores of miners whose block was reorganised away.
//!
//! Wire format (JSON lines over TCP):
//!
//! ```text
//! → {"id":1,"method":"mining.authorize","params":[address, worker]}
//! ← {"id":1,"result":{"api": "<host:port>"}}
//! ← {"id":null,"method":"mining.notify","params":[job_id, mining_hash, template_hex, share_target, network_target]}
//! → {"id":2,"method":"mining.submit","params":[address, job_id, nonce]}
//! ← {"id":2,"result":true} | {"id":2,"error":"..."}
//! ```

use crate::core::extension::{create_extension, MiningResult};
use crate::core::mw::{PayoutReceipt, StealthAddress};
use crate::core::types::Extension;
use crate::core::types::{compute_header_hash, hash_concat, hash_domain, Batch, COINBASE_MATURITY};
use crate::rpc::{template_from_hex, RpcClient};
use anyhow::{anyhow, bail, Context, Result};
use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use redb::{Database, ReadableTable, TableDefinition};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, RwLock, Semaphore};

/// One coinbase output is the pool fee; the rest pay miners.
pub const MAX_PAID_MINERS: usize = crate::core::mw::crypto::MAX_GROUP_OUTPUTS - 1;

const SHARES: TableDefinition<&[u8], u64> = TableDefinition::new("shares");
const BLOCKS: TableDefinition<u64, &str> = TableDefinition::new("blocks");
const PENDING: TableDefinition<u64, &str> = TableDefinition::new("pending_blocks");

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

/// Miners paid by a job: the top scorers, ties broken by address.
pub fn select_paid(scores: &[(AddrKey, u64)]) -> Vec<(AddrKey, u64)> {
    let mut ranked: Vec<(AddrKey, u64)> = scores.iter().filter(|(_, s)| *s > 0).cloned().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    ranked.truncate(MAX_PAID_MINERS);
    ranked
}

// Use fixed-point fee fractions, not ceil(score * fee / (100 - fee)).
// The old formula paid 50% to the operator for a single share and a 2% fee.
const FEE_SCALE: u64 = 1_000_000;

fn fee_ppm(percent: f64) -> Result<u64> {
    if !percent.is_finite() || !(0.0..100.0).contains(&percent) {
        bail!("pool fee must be at least 0 and below 100 percent");
    }
    Ok((percent * 10_000.0).round() as u64)
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

fn payout_weights(
    paid: &[(AddrKey, u64)],
    operator: &StealthAddress,
    fee: u64,
) -> Result<Vec<(StealthAddress, u64)>> {
    if fee >= FEE_SCALE {
        bail!("invalid pool fee fraction");
    }
    if paid.is_empty() {
        return Ok(vec![(*operator, 1)]);
    }
    // Reduce numerator/denominator before multiplication to minimise the
    // chance that u64 template weights overflow in long-lived pools.
    let divisor = gcd(fee, FEE_SCALE - fee);
    let operator_factor = fee / divisor;
    let miner_factor = (FEE_SCALE - fee) / divisor;
    let total: u128 = paid.iter().map(|(_, score)| *score as u128).sum();
    let mut weights = Vec::with_capacity(paid.len() + usize::from(fee > 0));
    if fee > 0 {
        let weight = u64::try_from(total * operator_factor as u128)
            .context("pool fee weight exceeds u64; share scores must be settled")?;
        weights.push((*operator, weight));
    }
    for (key, score) in paid {
        let weight = u64::try_from(*score as u128 * miner_factor as u128)
            .context("miner payout weight exceeds u64; share scores must be settled")?;
        weights.push((key_addr(key)?, weight));
    }
    Ok(weights)
}

// A payout must only consume scores that were committed when its job was
// built. Shares received after that snapshot belong to a later settlement.
fn snapshot_deduction(
    amount: u128,
    distributable: u128,
    total_at_snapshot: u128,
    miner_at_snapshot: u64,
) -> u64 {
    if amount == 0 || distributable == 0 {
        return 0;
    }
    (amount * total_at_snapshot / distributable)
        .min(miner_at_snapshot as u128) as u64
}

// Historical pending values stored one record. New values are arrays so
// replacement blocks at the same height do not overwrite unresolved debts.
fn parse_pending(raw: &str) -> Result<Vec<Value>> {
    match serde_json::from_str::<Value>(raw)? {
        Value::Array(records) => Ok(records),
        one @ Value::Object(_) => Ok(vec![one]),
        _ => bail!("invalid pending-block entry"),
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
    pub share_bits: u32,
    pub data_dir: PathBuf,
    pub poll_interval: Duration,
}

#[derive(Clone)]
struct Job {
    job_id: u64,
    mining_hash: [u8; 32],
    share_target: [u8; 32],
    network_target: [u8; 32],
    template_hex: String,
    height: u64,
    tree: Arc<ShareMerkleTree>,
    paid: Arc<Vec<(AddrKey, u64)>>,
    receipts: Arc<HashMap<AddrKey, Vec<PayoutReceipt>>>,
}

#[derive(Default)]
pub struct PoolStats {
    pub accepted_shares: AtomicU64,
    pub rejected_shares: AtomicU64,
    pub blocks_found: AtomicU64,
    pub blocks_rejected: AtomicU64,
    pub jobs: AtomicU64,
}

struct PoolState {
    cfg: PoolConfig,
    db: Database,
    current: RwLock<Option<Job>>,
    notifier: broadcast::Sender<Job>,
    share_target: [u8; 32],
    valid_shares: RwLock<HashSet<u64>>,
    verify_permits: Semaphore,
    force_new_job: AtomicBool,
    stats: Arc<PoolStats>,
    api_public: String,
    /// Job whose block has already been submitted (one block per template).
    submitted_job: AtomicU64,
}

fn load_scores(db: &Database) -> Result<Vec<(AddrKey, u64)>> {
    let txn = db.begin_read()?;
    let table = txn.open_table(SHARES)?;
    let mut out = Vec::new();
    for entry in table.iter()? {
        let (k, v) = entry?;
        if v.value() == 0 {
            continue;
        }
        let key: AddrKey = k.value().try_into().map_err(|_| anyhow!("bad key"))?;
        out.push((key, v.value()));
    }
    Ok(out)
}

/// Runs the pool until the process exits.
pub async fn run_pool(cfg: PoolConfig, stats: Arc<PoolStats>) -> Result<()> {
    std::fs::create_dir_all(&cfg.data_dir)?;
    let db = Database::create(cfg.data_dir.join("pool.redb"))?;
    {
        let txn = db.begin_write()?;
        {
            txn.open_table(SHARES)?;
            txn.open_table(BLOCKS)?;
            txn.open_table(PENDING)?;
        }
        txn.commit()?;
    }
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
    let share_target = target_from_leading_zero_bits(cfg.share_bits);
    let (notifier, _) = broadcast::channel(32);
    let permits = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let state = Arc::new(PoolState {
        cfg,
        db,
        current: RwLock::new(None),
        notifier,
        share_target,
        valid_shares: RwLock::new(HashSet::new()),
        verify_permits: Semaphore::new(permits),
        force_new_job: AtomicBool::new(false),
        stats,
        api_public,
        submitted_job: AtomicU64::new(0),
    });

    let app = Router::new()
        .route("/pool/stats", get(api_stats))
        .route("/api/proof", get(api_proof))
        .route("/api/scores", get(api_scores))
        .route("/api/template", get(api_template))
        .route("/api/submit", post(api_submit))
        .with_state(state.clone());
    tokio::spawn(async move {
        if let Err(e) = axum::serve(api, app).await {
            tracing::error!("pool API stopped: {e}");
        }
    });

    tokio::spawn(job_loop(state.clone()));

    loop {
        let (socket, peer) = stratum.accept().await?;
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_miner(socket, st).await {
                tracing::debug!("pool: miner {} disconnected: {:#}", peer, e);
            }
        });
    }
}

async fn job_loop(state: Arc<PoolState>) {
    let node = state.cfg.node_rpc.clone();
    let mut last_tip = String::new();
    let mut job_id: u64 = 0;
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
        let height = node_state["height"].as_u64().unwrap_or(0);
        let forced = state.force_new_job.swap(false, Ordering::SeqCst);
        if tip == last_tip && !forced {
            continue;
        }
        if tip != last_tip {
            if let Err(e) = reconcile_pending(&state, height).await {
                tracing::warn!("pool: reconciliation failed: {e:#}");
            }
        }
        match build_job(&state, job_id + 1).await {
            Ok(job) => {
                job_id += 1;
                last_tip = tip;
                state.valid_shares.write().await.clear();
                *state.current.write().await = Some(job.clone());
                state.stats.jobs.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    "pool: job {} at height {} (root {})",
                    job.job_id,
                    job.height,
                    hex::encode(&job.tree.root[..6])
                );
                let _ = state.notifier.send(job);
            }
            Err(e) => tracing::warn!("pool: could not build a job: {e:#}"),
        }
    }
}

async fn build_job(state: &Arc<PoolState>, job_id: u64) -> Result<Job> {
    let scores = load_scores(&state.db)?;
    let tree = ShareMerkleTree::build(scores.clone());
    let paid = select_paid(&scores);
    let payouts: Vec<Value> = payout_weights(&paid, &state.cfg.pool_address, fee_ppm(state.cfg.fee_percent)?)?
        .iter()
        .map(|(address, weight)| json!({ "address": address.encode(), "weight": weight }))
        .collect();
    let body = json!({ "payouts": payouts, "extra": hex::encode(tree.root) });
    let node = state.cfg.node_rpc.clone();
    let tpl =
        tokio::task::spawn_blocking(move || RpcClient::new(node).post("/mining/template", &body))
            .await??;

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
        share_target: state.share_target,
        network_target: crate::core::auxpow::bytes32(&tpl["target"])?,
        template_hex: tpl["template_hex"]
            .as_str()
            .ok_or_else(|| anyhow!("no template"))?
            .to_string(),
        height: tpl["height"].as_u64().unwrap_or(0),
        tree: Arc::new(tree),
        paid: Arc::new(paid),
        receipts: Arc::new(receipts),
    })
}

enum ShareOutcome {
    Accepted { is_block: bool },
    Duplicate,
    LowDifficulty,
    StaleJob,
    Busy,
}

async fn process_share(
    state: &Arc<PoolState>,
    miner: AddrKey,
    job_id: u64,
    nonce: u64,
) -> Result<ShareOutcome> {
    let job = match state.current.read().await.clone() {
        Some(j) if j.job_id == job_id => j,
        _ => return Ok(ShareOutcome::StaleJob),
    };
    if state.valid_shares.read().await.contains(&nonce) {
        return Ok(ShareOutcome::Duplicate);
    }
    let ext = {
        let _permit = match state.verify_permits.try_acquire() {
            Ok(p) => p,
            Err(_) => return Ok(ShareOutcome::Busy),
        };
        let hash = job.mining_hash;
        tokio::task::spawn_blocking(move || create_extension(hash, nonce)).await?
    };
    if ext.final_hash >= job.share_target && ext.final_hash >= job.network_target {
        return Ok(ShareOutcome::LowDifficulty);
    }
    if !state.valid_shares.write().await.insert(nonce) {
        return Ok(ShareOutcome::Duplicate);
    }
    if !matches!(state.current.read().await.as_ref(), Some(j) if j.job_id == job_id) {
        return Ok(ShareOutcome::StaleJob);
    }
    {
        let txn = state.db.begin_write()?;
        {
            let mut table = txn.open_table(SHARES)?;
            let current = table.get(miner.as_slice())?.map(|v| v.value()).unwrap_or(0);
            table.insert(miner.as_slice(), current + 1)?;
        }
        txn.commit()?;
    }
    let is_block = ext.final_hash < job.network_target;
    if is_block && state.submitted_job.swap(job_id, Ordering::SeqCst) != job_id {
        submit_block(state.clone(), job, ext);
    }
    Ok(ShareOutcome::Accepted { is_block })
}

/// Submits a found block; deducts the paid miners' scores only once the node
/// has accepted it.
fn submit_block(state: Arc<PoolState>, job: Job, ext: Extension) {
    tokio::spawn(async move {
        let sealed = match template_from_hex(&job.template_hex, job.mining_hash) {
            Ok(t) => t.seal(ext.clone()),
            Err(e) => {
                tracing::error!("pool: cannot rebuild the block: {e:#}");
                return;
            }
        };
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
                if let Err(e) = record_accepted(&state, &job, &ext) {
                    tracing::error!("pool: recording the block failed: {e:#}");
                }
            }
            Some(msg) => {
                state.stats.blocks_rejected.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("pool: block rejected ({msg}); scores kept, requesting a fresh job");
                state.force_new_job.store(true, Ordering::SeqCst);
            }
        }
    });
}

fn record_accepted(state: &PoolState, job: &Job, ext: &Extension) -> Result<()> {
    let distributable: u128 = job
        .paid
        .iter()
        .filter_map(|(k, _)| job.receipts.get(k))
        .flatten()
        .map(|r| r.value as u128)
        .sum();
    let txn = state.db.begin_write()?;
    {
        let mut table = txn.open_table(SHARES)?;
        let total_at_snapshot: u128 = job.tree.leaves.iter().map(|(_, s)| *s as u128).sum();
        let mut deductions = Vec::new();
        let mut payouts = Vec::new();
        for (k, miner_at_snapshot) in job.paid.iter() {
            let amount: u128 = job
                .receipts
                .get(k)
                .map(|rs| rs.iter().map(|r| r.value as u128).sum())
                .unwrap_or(0);
            if amount == 0 || distributable == 0 {
                continue;
            }
            let deduction = snapshot_deduction(
                amount, distributable, total_at_snapshot, *miner_at_snapshot,
            );
            let current = table.get(k.as_slice())?.map(|v| v.value()).unwrap_or(0);
            let taken = deduction.min(current);
            if current > taken {
                table.insert(k.as_slice(), current - taken)?;
            } else {
                table.remove(k.as_slice())?;
            }
            deductions.push(json!([hex::encode(k), taken]));
            payouts.push(json!({ "address": key_addr(k)?.encode(), "value": amount as u64 }));
        }
        let record = json!({
            "hash": hex::encode(ext.final_hash),
            "height": job.height,
            "root": hex::encode(job.tree.root),
            "payouts": payouts,
            "deductions": deductions,
            "status": "pending",
        })
        .to_string();
        txn.open_table(BLOCKS)?
            .insert(job.height, record.as_str())?;
        let mut pending = txn.open_table(PENDING)?;
        let mut records = match pending.get(job.height)? {
            Some(existing) => parse_pending(existing.value())?,
            None => Vec::new(),
        };
        records.push(serde_json::from_str(&record)?);
        let encoded = serde_json::to_string(&records)?;
        pending.insert(job.height, encoded.as_str())?;
    }
    txn.commit()?;
    Ok(())
}

/// On each tip change, restore scores from orphaned blocks immediately.
/// Canonical blocks remain pending until maturity, so a later reorg can be
/// reconciled exactly once. Heights may have multiple candidate blocks.
async fn reconcile_pending(state: &Arc<PoolState>, height: u64) -> Result<()> {
    let threshold = height.saturating_sub(COINBASE_MATURITY + 1);
    let pending_heights: Vec<u64> = {
        let txn = state.db.begin_read()?;
        let table = txn.open_table(PENDING)?;
        table.iter()?.map(|entry| Ok(entry?.0.value())).collect::<Result<_>>()?
    };
    for h in pending_heights {
        // Node state.height is the next height. A missing block at or above
        // that height is orphaned; below it, the node must return a block.
        let canonical_hash = if h >= height {
            None
        } else {
            let node = state.cfg.node_rpc.clone();
            let blocks = tokio::task::spawn_blocking(move || RpcClient::new(node).blocks(h, 1)).await??;
            let block = blocks.first().ok_or_else(|| anyhow!("missing canonical block at height {h}"))?;
            Some(hex::encode(block.extension.final_hash))
        };
        let matured = h <= threshold;
        let txn = state.db.begin_write()?;
        {
            // Re-read inside the write transaction. A just-accepted block
            // might have appended another record while RPC was in flight.
            let mut pending_table = txn.open_table(PENDING)?;
            let Some(existing) = pending_table.get(h)? else { continue };
            let records = parse_pending(existing.value())?;
            drop(existing);
            let mut keep = Vec::new();
            for record in records {
                let expected = record["hash"].as_str()
                    .ok_or_else(|| anyhow!("pending block without a hash"))?;
                let confirmed = canonical_hash.as_deref() == Some(expected);
                if confirmed && !matured {
                    keep.push(record);
                    continue;
                }
                let mut result = record.clone();
                result["status"] = json!(if confirmed { "confirmed" } else { "orphaned" });
                txn.open_table(BLOCKS)?.insert(h, result.to_string().as_str())?;
                if !confirmed {
                    let deductions = record["deductions"].as_array()
                        .ok_or_else(|| anyhow!("pending block without deductions"))?;
                    let mut shares = txn.open_table(SHARES)?;
                    for d in deductions {
                        let key = hex::decode(d[0].as_str().ok_or_else(|| anyhow!("bad deduction key"))?)?;
                        let amount = d[1].as_u64().ok_or_else(|| anyhow!("bad deduction amount"))?;
                        let current = shares.get(key.as_slice())?.map(|v| v.value()).unwrap_or(0);
                        let restored = current.checked_add(amount)
                            .ok_or_else(|| anyhow!("share score overflow while restoring orphan"))?;
                        shares.insert(key.as_slice(), restored)?;
                    }
                    tracing::warn!("pool: block {} at height {} was orphaned; shares restored", expected, h);
                }
            }
            if keep.is_empty() {
                pending_table.remove(h)?;
            } else {
                let encoded = serde_json::to_string(&keep)?;
                pending_table.insert(h, encoded.as_str())?;
            }
        }
        txn.commit()?;
    }
    Ok(())
}

fn notify_line(job: &Job) -> String {
    json!({
        "id": null,
        "method": "mining.notify",
        "params": [
            job.job_id,
            hex::encode(job.mining_hash),
            job.template_hex,
            hex::encode(job.share_target),
            hex::encode(job.network_target),
        ],
    })
    .to_string()
        + "\n"
}

async fn handle_miner(socket: tokio::net::TcpStream, state: Arc<PoolState>) -> Result<()> {
    let (read, mut write) = socket.into_split();
    let mut lines = BufReader::new(read).lines();
    let mut jobs = state.notifier.subscribe();
    let mut authorized: Option<AddrKey> = None;
    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line? else { return Ok(()) };
                let msg: Value = serde_json::from_str(&line).context("bad JSON")?;
                let id = msg["id"].clone();
                let params = msg["params"].as_array().cloned().unwrap_or_default();
                let reply = match msg["method"].as_str().unwrap_or_default() {
                    "mining.authorize" => {
                        let addr = StealthAddress::decode(params.first().and_then(Value::as_str).unwrap_or_default())?;
                        authorized = Some(addr_key(&addr));
                        write.write_all((json!({ "id": id, "result": { "api": state.api_public } }).to_string() + "\n").as_bytes()).await?;
                        if let Some(job) = state.current.read().await.clone() {
                            write.write_all(notify_line(&job).as_bytes()).await?;
                        }
                        continue;
                    }
                    "mining.submit" => {
                        let Some(miner) = authorized else { bail!("submit before authorize") };
                        let job_id = params.get(1).and_then(Value::as_u64).unwrap_or(0);
                        let nonce = params.get(2).and_then(Value::as_u64).unwrap_or(0);
                        match process_share(&state, miner, job_id, nonce).await? {
                            ShareOutcome::Accepted { is_block } => {
                                state.stats.accepted_shares.fetch_add(1, Ordering::Relaxed);
                                json!({ "id": id, "result": true, "block": is_block })
                            }
                            other => {
                                state.stats.rejected_shares.fetch_add(1, Ordering::Relaxed);
                                let reason = match other {
                                    ShareOutcome::Duplicate => "duplicate share",
                                    ShareOutcome::LowDifficulty => "low difficulty",
                                    ShareOutcome::StaleJob => "stale job",
                                    _ => "busy",
                                };
                                json!({ "id": id, "result": false, "error": reason })
                            }
                        }
                    }
                    other => json!({ "id": id, "error": format!("unknown method {other}") }),
                };
                write.write_all((reply.to_string() + "\n").as_bytes()).await?;
            }
            job = jobs.recv() => {
                match job {
                    Ok(job) => write.write_all(notify_line(&job).as_bytes()).await?,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return Ok(()),
                }
            }
        }
    }
}

// ── Audit API ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AddressQuery {
    address: String,
}

async fn api_proof(
    State(state): State<Arc<PoolState>>,
    Query(q): Query<AddressQuery>,
) -> Json<Value> {
    let Some(job) = state.current.read().await.clone() else {
        return Json(json!({ "error": "no job" }));
    };
    let addr = match StealthAddress::decode(&q.address) {
        Ok(a) => addr_key(&a),
        Err(e) => return Json(json!({ "error": e.to_string() })),
    };
    let score = job
        .tree
        .leaves
        .iter()
        .find(|(a, _)| *a == addr)
        .map(|(_, s)| *s)
        .unwrap_or(0);
    let (index, proof) = job.tree.proof(&addr).unwrap_or((0, Vec::new()));
    let receipts: Vec<Value> = job
        .receipts
        .get(&addr)
        .map(|rs| {
            rs.iter()
                .map(|r| serde_json::to_value(r).unwrap_or_default())
                .collect()
        })
        .unwrap_or_default();
    Json(json!({
        "job_id": job.job_id,
        "root": hex::encode(job.tree.root),
        "score": score,
        "index": index,
        "proof": proof.iter().map(hex::encode).collect::<Vec<_>>(),
        "paid": job.paid.iter().any(|(a, _)| *a == addr),
        "receipts": receipts,
    }))
}

async fn api_scores(State(state): State<Arc<PoolState>>) -> Json<Value> {
    let Some(job) = state.current.read().await.clone() else {
        return Json(json!({ "error": "no job" }));
    };
    let scores: Vec<Value> = job
        .tree
        .leaves
        .iter()
        .map(|(a, s)| json!({ "key": hex::encode(a), "score": s }))
        .collect();
    Json(json!({
        "job_id": job.job_id,
        "root": hex::encode(job.tree.root),
        "height": job.height,
        "fee_ppm": fee_ppm(state.cfg.fee_percent).expect("validated pool fee"),
        "pool_address": state.cfg.pool_address.encode(),
        "max_paid": MAX_PAID_MINERS,
        "scores": scores,
    }))
}

async fn api_template(State(state): State<Arc<PoolState>>) -> Json<Value> {
    match state.current.read().await.clone() {
        Some(job) => Json(json!({
            "job_id": job.job_id,
            "mining_hash": hex::encode(job.mining_hash),
            "template_hex": job.template_hex,
            "share_target": hex::encode(job.share_target),
            "network_target": hex::encode(job.network_target),
        })),
        None => Json(json!({ "error": "no job" })),
    }
}

#[derive(Deserialize)]
struct HttpShare {
    address: String,
    job_id: u64,
    nonce: u64,
}

async fn api_submit(
    State(state): State<Arc<PoolState>>,
    Json(share): Json<HttpShare>,
) -> Json<Value> {
    let addr = match StealthAddress::decode(&share.address) {
        Ok(a) => addr_key(&a),
        Err(e) => return Json(json!({ "accepted": false, "error": e.to_string() })),
    };
    match process_share(&state, addr, share.job_id, share.nonce).await {
        Ok(ShareOutcome::Accepted { is_block }) => {
            state.stats.accepted_shares.fetch_add(1, Ordering::Relaxed);
            Json(json!({ "accepted": true, "block": is_block }))
        }
        Ok(_) => {
            state.stats.rejected_shares.fetch_add(1, Ordering::Relaxed);
            Json(json!({ "accepted": false }))
        }
        Err(e) => Json(json!({ "accepted": false, "error": e.to_string() })),
    }
}

async fn api_stats(State(state): State<Arc<PoolState>>) -> Json<Value> {
    let job = state.current.read().await.clone();
    let scores = load_scores(&state.db).unwrap_or_default();
    let blocks: Vec<Value> = state
        .db
        .begin_read()
        .ok()
        .and_then(|t| t.open_table(BLOCKS).ok())
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
        "miners": scores.len(),
        "total_score": scores.iter().map(|(_, s)| *s).sum::<u64>(),
        "fee_percent": state.cfg.fee_percent,
        "share_bits": state.cfg.share_bits,
        "accepted_shares": s.accepted_shares.load(Ordering::Relaxed),
        "rejected_shares": s.rejected_shares.load(Ordering::Relaxed),
        "blocks_found": s.blocks_found.load(Ordering::Relaxed),
        "blocks_rejected": s.blocks_rejected.load(Ordering::Relaxed),
        "blocks": blocks,
    }))
}

// ── Miner ───────────────────────────────────────────────────────────────────

/// Verify the entire committed score table and this miner's exact payout.
/// Height is supplied by the pool API (the wire-format Batch omits height):
/// this protects against arbitrary underpayment at that claimed height, but
/// an independently trusted node is required to authenticate chain height.
/// `max_fee_ppm` is the miner's own limit, never a pool-supplied setting.
pub fn audit_job_with_fee_limit(
    address: &StealthAddress,
    mining_hash: &[u8; 32],
    template_hex: &str,
    proof: &Value,
    scores: &Value,
    max_fee_ppm: u64,
) -> Result<()> {
    let batch: Batch = bincode::deserialize(&hex::decode(template_hex)?)?;
    if &compute_header_hash(&batch.header()) != mining_hash {
        bail!("template does not hash to the announced mining hash");
    }
    if proof["job_id"].as_u64() != scores["job_id"].as_u64() {
        bail!("proof and score table describe different jobs");
    }
    let height = scores["height"].as_u64().ok_or_else(|| anyhow!("missing pool height"))?;
    let fee = scores["fee_ppm"].as_u64().ok_or_else(|| anyhow!("missing pool fee"))?;
    if fee >= FEE_SCALE || fee > max_fee_ppm {
        bail!("pool fee exceeds miner's configured fee limit");
    }
    let operator = StealthAddress::decode(
        scores["pool_address"].as_str().ok_or_else(|| anyhow!("missing pool payout address"))?
    )?;
    let total = crate::core::types::block_reward(height)
        .checked_add(batch.body.fee()?)
        .ok_or_else(|| anyhow!("reward overflow"))?;
    let cb = match batch.coinbase.as_ref() {
        Some(cb) if total > 0 => cb,
        None if total == 0 => return Ok(()), // unpayable, post-issuance block
        None => bail!("template drops a payable coinbase"),
        Some(_) => bail!("template has a coinbase when no reward or fees are payable"),
    };
    let key = addr_key(address);
    let root = hex::encode(cb.extra);
    if scores["root"].as_str() != Some(root.as_str())
        || proof["root"].as_str() != Some(root.as_str()) {
        bail!("pool API roots do not match the block's commitment");
    }
    let listed: Vec<(AddrKey, u64)> = scores["scores"].as_array()
        .ok_or_else(|| anyhow!("missing committed score list"))?
        .iter()
        .map(|entry| {
            let addr: AddrKey = hex::decode(
                entry["key"].as_str().ok_or_else(|| anyhow!("missing score address"))?
            )?.try_into().map_err(|_| anyhow!("bad score address length"))?;
            let score = entry["score"].as_u64().ok_or_else(|| anyhow!("missing score amount"))?;
            Ok((addr, score))
        }).collect::<Result<_>>()?;
    let mut seen = HashSet::new();
    if listed.iter().any(|(k, _)| !seen.insert(*k)) {
        bail!("duplicate address in score table");
    }
    let tree = ShareMerkleTree::build(listed.clone());
    if tree.root != cb.extra {
        bail!("published score list does not match committed root");
    }
    let score = proof["score"].as_u64().ok_or_else(|| anyhow!("missing claimed score"))?;
    let expected_score = listed.iter().find(|(k, _)| *k == key).map_or(0, |(_, s)| *s);
    if score != expected_score {
        bail!("claimed score does not match committed score list");
    }
    if score > 0 {
        let index = usize::try_from(
            proof["index"].as_u64().ok_or_else(|| anyhow!("missing leaf index"))?
        )?;
        let siblings: Vec<[u8; 32]> = proof["proof"].as_array()
            .ok_or_else(|| anyhow!("missing Merkle proof"))?
            .iter().map(crate::core::auxpow::bytes32).collect::<Result<_>>()?;
        if fold_proof(score_leaf(&key, score), index, &siblings) != cb.extra {
            bail!("our share score is not committed in the coinbase");
        }
    }
    let paid = select_paid(&listed);
    let selected = paid.iter().any(|(k, _)| *k == key);
    if proof["paid"].as_bool() != Some(selected) {
        bail!("pool's paid flag contradicts score ranking");
    }
    let expected = crate::core::template::split_by_weight(
        total, &payout_weights(&paid, &operator, fee)?
    )?.iter().filter(|(a, _)| *a == *address)
        .try_fold(0u64, |acc, (_, amount)| acc.checked_add(*amount))
        .ok_or_else(|| anyhow!("expected payout overflow"))?;
    let receipts: Vec<PayoutReceipt> = serde_json::from_value(proof["receipts"].clone())?;
    let mut used = HashSet::new();
    let mut proven = 0u64;
    for receipt in receipts {
        if !used.insert(receipt.output_index) {
            bail!("duplicate payout receipt for one output");
        }
        let output = cb.outputs.outputs.get(receipt.output_index)
            .ok_or_else(|| anyhow!("payout receipt index out of bounds"))?;
        if !receipt.verify(address, output) {
            bail!("invalid payout receipt");
        }
        proven = proven.checked_add(receipt.value)
            .ok_or_else(|| anyhow!("proved payout overflow"))?;
    }
    if proven != expected {
        bail!("pool payout mismatch: expected {expected} base units, verified {proven}");
    }
    Ok(())
}

/// Default call for callers that have not configured a local fee policy.
pub fn audit_job(
    address: &StealthAddress,
    mining_hash: &[u8; 32],
    template_hex: &str,
    proof: &Value,
    scores: &Value,
) -> Result<()> {
    audit_job_with_fee_limit(address, mining_hash, template_hex, proof, scores, FEE_SCALE)
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
                    }
                    continue;
                }
                cancel.store(true, Ordering::Relaxed);
                let p = msg["params"].as_array().cloned().unwrap_or_default();
                let job_id = p.first().and_then(Value::as_u64).unwrap_or(0);
                let mining_hash = crate::core::auxpow::bytes32(&p[1])?;
                let template_hex = p[2].as_str().unwrap_or_default().to_string();
                let share_target = crate::core::auxpow::bytes32(&p[3])?;
                let network_target = crate::core::auxpow::bytes32(&p[4])?;
                stats.jobs.fetch_add(1, Ordering::Relaxed);

                let (api2, addr) = (api.clone(), cfg.address);
                let th = template_hex.clone();
                let audit = tokio::task::spawn_blocking(move || -> Result<()> {
                    let client = RpcClient::new(api2);
                    let proof = client.get(&format!("/api/proof?address={}", addr.encode()))?;
                    let scores = client.get("/api/scores")?;
                    if proof["job_id"].as_u64() != Some(job_id)
                        || scores["job_id"].as_u64() != Some(job_id) {
                        bail!("audit API job differs from the announced job; reconnecting");
                    }
                    audit_job_with_fee_limit(&addr, &mining_hash, &th, &proof, &scores, max_fee_ppm)
                })
                .await?;
                if let Err(e) = audit {
                    stats.audits_failed.fetch_add(1, Ordering::Relaxed);
                    bail!("audit failed, disconnecting: {e:#}");
                }
                stats.audits_passed.fetch_add(1, Ordering::Relaxed);

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

    #[test]
    fn share_target_has_the_requested_zero_bits() {
        let t = target_from_leading_zero_bits(12);
        assert_eq!(&t[..2], &[0x00, 0x0f]);
        assert!(t[2..].iter().all(|b| *b == 0xff));
    }

    #[test]
    fn fee_is_proportional_even_with_one_share() {
        let operator = WalletKeys::random().address();
        let miner = WalletKeys::random().address();
        let weights = payout_weights(&[(addr_key(&miner), 1)], &operator, fee_ppm(2.0).unwrap()).unwrap();
        let split = crate::core::template::split_by_weight(100_000, &weights).unwrap();
        assert_eq!(split.iter().find(|(a, _)| *a == operator).unwrap().1, 2_000);
        assert_eq!(split.iter().find(|(a, _)| *a == miner).unwrap().1, 98_000);
    }

    #[test]
    fn sybil_addresses_do_not_receive_independent_minimums() {
        let large = WalletKeys::random().address();
        let tiny = WalletKeys::random().address();
        let split = crate::core::template::split_by_weight(2, &[(large, 100), (tiny, 1)]).unwrap();
        assert_eq!(split, vec![(large, 2)]);
    }

    #[test]
    fn deduct_only_scores_in_the_committed_job() {
        // B submits 1000 additional shares after a 100/100 job snapshot.
        // Deductions of that job may never consume those new shares.
        assert_eq!(snapshot_deduction(500, 1000, 200, 100), 100);
        assert_eq!(snapshot_deduction(1000, 1000, 200, 100), 100);
    }

    #[test]
    fn same_height_pending_records_and_legacy_records() {
        let a = json!({ "hash": "aaa", "deductions": [] });
        let b = json!({ "hash": "bbb", "deductions": [] });
        assert_eq!(parse_pending(&a.to_string()).unwrap(), vec![a.clone()]);
        assert_eq!(parse_pending(&json!([a.clone(), b.clone()]).to_string()).unwrap(), vec![a, b]);
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
    fn paid_set_is_the_top_scorers() {
        let scores: Vec<(AddrKey, u64)> = (0..40u8).map(|i| ([i; 96], i as u64)).collect();
        let paid = select_paid(&scores);
        assert_eq!(paid.len(), MAX_PAID_MINERS);
        assert_eq!(paid[0].1, 39);
        assert!(paid.iter().all(|(_, s)| *s >= 40 - MAX_PAID_MINERS as u64));
    }

    #[test]
    fn audit_catches_a_lying_pool() {
        use crate::core::bond::{
            est_midstate_height, BondEntry, MinerBond, MIN_MINING_BOND, MIN_REMAINING_BOND_LOCK,
        };
        use crate::core::state::apply_batch;
        use crate::core::template::build_template_bonded;
        use crate::core::types::{hash, State};
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

        let scores = vec![(addr_key(&me), 5), (addr_key(&other), 3)];
        let tree = ShareMerkleTree::build(scores.clone());
        let payouts = payout_weights(&select_paid(&scores), &pool, fee_ppm(1.0).unwrap()).unwrap();
        let (tpl, receipts) =
            build_template_bonded(&state, &ts, &[], &payouts, tree.root, None, Some(&bond))
                .unwrap();
        let template_hex = hex::encode(bincode::serialize(&tpl.batch).unwrap());
        let my_receipts: Vec<Value> = receipts
            .iter()
            .filter(|(a, _)| *a == me)
            .map(|(_, r)| serde_json::to_value(r).unwrap())
            .collect();
        let (idx, proof) = tree.proof(&addr_key(&me)).unwrap();
        let proof_json = |score: u64, receipts: Vec<Value>| {
            json!({ "job_id": 1, "root": hex::encode(tree.root),
                "score": score, "index": idx, "proof": proof.iter().map(hex::encode).collect::<Vec<_>>(),
                "paid": true, "receipts": receipts })
        };
        let scores_json = json!({ "job_id": 1, "root": hex::encode(tree.root), "height": state.height,
            "fee_ppm": fee_ppm(1.0).unwrap(), "pool_address": pool.encode(),
            "scores": scores.iter().map(|(k, s)| json!({ "key": hex::encode(k), "score": s })).collect::<Vec<_>>() });

        audit_job(
            &me,
            &tpl.mining_hash,
            &template_hex,
            &proof_json(5, my_receipts.clone()),
            &scores_json,
        )
        .unwrap();
        // A dishonest pool can build a valid coinbase that pays us less
        // than the share table entitles us to. The receipt is cryptographically
        // valid, but the deterministic payout audit must still reject it.
        let dishonest_payouts = [(pool, 600), (me, 5), (other, 3)];
        let (dishonest_tpl, dishonest_receipts) = build_template_bonded(
            &state, &ts, &[], &dishonest_payouts, tree.root, None, Some(&bond)
        ).unwrap();
        let dishonest_hex = hex::encode(bincode::serialize(&dishonest_tpl.batch).unwrap());
        let dishonest_mine: Vec<Value> = dishonest_receipts.iter()
            .filter(|(a, _)| *a == me)
            .map(|(_, r)| serde_json::to_value(r).unwrap())
            .collect();
        assert!(!dishonest_mine.is_empty());
        assert!(audit_job(
            &me, &dishonest_tpl.mining_hash, &dishonest_hex,
            &proof_json(5, dishonest_mine), &scores_json
        ).is_err());
        // A dishonest API claims a fee that does not match actual allocations.
        let mut dishonest = scores_json.clone();
        dishonest["fee_ppm"] = json!(fee_ppm(20.0).unwrap());
        assert!(audit_job(&me, &tpl.mining_hash, &template_hex,
            &proof_json(5, my_receipts.clone()), &dishonest).is_err());
        // Changing the height must also require the claimed reward to match.
        let mut bad_height = scores_json.clone();
        bad_height["height"] = json!(0);
        assert!(audit_job(&me, &tpl.mining_hash, &template_hex,
            &proof_json(5, my_receipts.clone()), &bad_height).is_err());
        // Wrong score claimed.
        assert!(audit_job(
            &me,
            &tpl.mining_hash,
            &template_hex,
            &proof_json(6, my_receipts.clone()),
            &scores_json
        )
        .is_err());
        // Receipt withheld or pointing at someone else's output.
        assert!(audit_job(
            &me,
            &tpl.mining_hash,
            &template_hex,
            &proof_json(5, vec![]),
            &scores_json
        )
        .is_err());
        let theirs: Vec<Value> = receipts
            .iter()
            .filter(|(a, _)| *a == other)
            .map(|(_, r)| serde_json::to_value(r).unwrap())
            .collect();
        assert!(audit_job(
            &me,
            &tpl.mining_hash,
            &template_hex,
            &proof_json(5, theirs),
            &scores_json
        )
        .is_err());
        // Mismatched mining hash.
        assert!(audit_job(
            &me,
            &[0; 32],
            &template_hex,
            &proof_json(5, my_receipts.clone()),
            &scores_json
        )
        .is_err());
        // Score list that does not match the committed root.
        let forged = json!({ "scores": [{ "key": hex::encode(addr_key(&me)), "score": 5 }] });
        assert!(audit_job(
            &me,
            &tpl.mining_hash,
            &template_hex,
            &proof_json(5, my_receipts),
            &forged
        )
        .is_err());
    }
}
