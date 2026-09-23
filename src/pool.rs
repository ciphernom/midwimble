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
    let paid_total: u128 = paid.iter().map(|(_, s)| *s as u128).sum();

    let mut payouts: Vec<Value> = Vec::new();
    let fee = state.cfg.fee_percent.clamp(0.0, 100.0);
    if paid.is_empty() {
        payouts.push(json!({ "address": state.cfg.pool_address.encode(), "weight": 1 }));
    } else {
        // Weight so that the pool receives `fee` percent of the reward.
        let fee_weight = if fee >= 100.0 {
            u64::MAX / 2
        } else {
            ((paid_total as f64) * fee / (100.0 - fee)).ceil() as u64
        };
        if fee_weight > 0 {
            payouts
                .push(json!({ "address": state.cfg.pool_address.encode(), "weight": fee_weight }));
        }
        for (k, s) in paid.iter() {
            payouts.push(json!({ "address": key_addr(k)?.encode(), "weight": s }));
        }
    }
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
        let mut total_score = 0u128;
        for entry in table.iter()? {
            total_score += entry?.1.value() as u128;
        }
        let mut deductions = Vec::new();
        let mut payouts = Vec::new();
        for (k, _) in job.paid.iter() {
            let amount: u128 = job
                .receipts
                .get(k)
                .map(|rs| rs.iter().map(|r| r.value as u128).sum())
                .unwrap_or(0);
            if amount == 0 || distributable == 0 {
                continue;
            }
            let deduction = (amount * total_score / distributable) as u64;
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
        txn.open_table(PENDING)?
            .insert(job.height, record.as_str())?;
    }
    txn.commit()?;
    Ok(())
}

/// Confirms matured blocks; restores the scores of orphaned ones.
async fn reconcile_pending(state: &Arc<PoolState>, height: u64) -> Result<()> {
    let threshold = height.saturating_sub(COINBASE_MATURITY + 1);
    let pending: Vec<(u64, Value)> = {
        let txn = state.db.begin_read()?;
        let table = txn.open_table(PENDING)?;
        let mut out = Vec::new();
        for entry in table.range(..=threshold)? {
            let (k, v) = entry?;
            out.push((k.value(), serde_json::from_str(v.value())?));
        }
        out
    };
    for (h, record) in pending {
        let node = state.cfg.node_rpc.clone();
        let canonical =
            tokio::task::spawn_blocking(move || RpcClient::new(node).blocks(h, 1)).await??;
        let expected = record["hash"].as_str().unwrap_or_default();
        let confirmed = canonical
            .first()
            .map(|b| hex::encode(b.extension.final_hash))
            .as_deref()
            == Some(expected);
        let txn = state.db.begin_write()?;
        {
            txn.open_table(PENDING)?.remove(h)?;
            let mut rec = record.clone();
            rec["status"] = json!(if confirmed { "confirmed" } else { "orphaned" });
            txn.open_table(BLOCKS)?
                .insert(h, rec.to_string().as_str())?;
            if !confirmed {
                let mut shares = txn.open_table(SHARES)?;
                for d in record["deductions"].as_array().cloned().unwrap_or_default() {
                    let key = hex::decode(d[0].as_str().unwrap_or_default())?;
                    let amount = d[1].as_u64().unwrap_or(0);
                    let current = shares.get(key.as_slice())?.map(|v| v.value()).unwrap_or(0);
                    shares.insert(key.as_slice(), current + amount)?;
                }
                tracing::warn!("pool: block at height {} was orphaned; scores restored", h);
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
    Json(
        json!({ "job_id": job.job_id, "root": hex::encode(job.tree.root), "max_paid": MAX_PAID_MINERS, "scores": scores }),
    )
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

/// What a miner checks before hashing on a job. `proof` is the pool's
/// `/api/proof` answer and `scores` its `/api/scores` answer.
pub fn audit_job(
    address: &StealthAddress,
    mining_hash: &[u8; 32],
    template_hex: &str,
    proof: &Value,
    scores: &Value,
) -> Result<()> {
    let batch: Batch = bincode::deserialize(&hex::decode(template_hex)?)?;
    if &compute_header_hash(&batch.header()) != mining_hash {
        bail!("template does not hash to the announced mining hash");
    }
    // After issuance ends a block with no fees pays nobody and carries no
    // coinbase (`core::state::validate_block_contents`). There is no score
    // commitment and no payout to check, and consensus rejects such a block
    // if it did have something to claim, so the pool gains nothing by it.
    let cb = match batch.coinbase.as_ref() {
        Some(cb) => cb,
        None => {
            if batch.body.fee().unwrap_or(u64::MAX) != 0 {
                bail!("template drops a coinbase but its transactions pay fees");
            }
            return Ok(());
        }
    };
    let key = addr_key(address);
    let score = proof["score"].as_u64().unwrap_or(0);
    let index = proof["index"].as_u64().unwrap_or(0) as usize;
    let siblings: Vec<[u8; 32]> = proof["proof"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(crate::core::auxpow::bytes32)
        .collect::<Result<_>>()?;
    if score > 0 && fold_proof(score_leaf(&key, score), index, &siblings) != cb.extra {
        bail!("our score is not in the committed score tree");
    }
    // The committed score list must itself hash to the same root.
    let listed: Vec<(AddrKey, u64)> = scores["scores"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|s| {
            let k: AddrKey = hex::decode(s["key"].as_str().unwrap_or_default())?
                .try_into()
                .map_err(|_| anyhow!("bad key"))?;
            Ok((k, s["score"].as_u64().unwrap_or(0)))
        })
        .collect::<Result<_>>()?;
    if !listed.is_empty() && ShareMerkleTree::build(listed.clone()).root != cb.extra {
        bail!("published score list does not match the committed root");
    }
    let paid = select_paid(&listed);
    let should_be_paid = paid.iter().any(|(k, _)| *k == key);
    let receipts: Vec<PayoutReceipt> =
        serde_json::from_value(proof["receipts"].clone()).unwrap_or_default();
    if should_be_paid {
        let outputs = &cb.outputs.outputs;
        let proven: u64 = receipts
            .iter()
            .filter(|r| {
                outputs
                    .get(r.output_index)
                    .map_or(false, |o| r.verify(address, o))
            })
            .map(|r| r.value)
            .sum();
        if proven == 0 {
            bail!("we rank among the paid miners but the coinbase pays us nothing");
        }
    } else if score > 0 && proof["paid"].as_bool() == Some(true) {
        bail!("pool claims to pay us contrary to its own ranking");
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

/// Connects to a pool, audits every job, and mines until `stop` is set.
pub async fn run_pool_miner(
    cfg: PoolMinerConfig,
    stop: Arc<AtomicBool>,
    stats: Arc<PoolMinerStats>,
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
                    if proof["job_id"].as_u64() != Some(job_id) {
                        // The pool moved on between notify and our query;
                        // the next notify will be audited instead.
                        return Ok(());
                    }
                    audit_job(&addr, &mining_hash, &th, &proof, &scores)
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
        let payouts = [(pool, 1), (me, 5), (other, 3)];
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
            json!({ "score": score, "index": idx, "proof": proof.iter().map(hex::encode).collect::<Vec<_>>(),
                    "paid": true, "receipts": receipts })
        };
        let scores_json = json!({ "scores": scores.iter().map(|(k, s)| json!({ "key": hex::encode(k), "score": s })).collect::<Vec<_>>() });

        audit_job(
            &me,
            &tpl.mining_hash,
            &template_hex,
            &proof_json(5, my_receipts.clone()),
            &scores_json,
        )
        .unwrap();
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
