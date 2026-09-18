//! Merged mining: one proof-of-work search that can produce blocks for both
//! midstate and midwimble.
//!
//! The miner talks to a midstate node (unmodified) and a midwimble node over
//! their HTTP RPCs:
//!
//! 1. Fetch a midwimble template (`/mining/template`) and take its mining hash.
//! 2. Ask midstate for its coinbase total (its `/block_template` answers a
//!    wrong total with the expected one), split it into midstate's
//!    power-of-two outputs, and put the merge commitment in the salt of the
//!    last (largest) output so no outputs follow it in the proof.
//! 3. Rebuild midstate's fold from the returned `batch_template` and check it
//!    reproduces the node's `mining_midstate` exactly; refuse to hash otherwise.
//! 4. Hash against the easier of the two targets. A result below midstate's
//!    target is submitted to midstate (`/submit_batch`); one below
//!    midwimble's becomes a merged-mined midwimble block (`/mining/submit`).
//!    Often both.
//! 5. Start over whenever either chain's tip moves.
//!
//! Every midstate coinbase output is appended to a JSONL log (address, value,
//! salt, coin id): midstate coins can only be spent by someone who knows their
//! salt, so keep that file.

use crate::core::auxpow::{bytes32, merge_commitment, midstate_coin_id, ParentTemplate};
use crate::core::extension::MiningResult;
use crate::core::mw::StealthAddress;
use crate::core::types::hash_domain;
use crate::rpc::{template_from_hex, RpcClient};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct MergeMineConfig {
    /// midstate RPC, e.g. `127.0.0.1:8545`.
    pub midstate_rpc: String,
    /// midwimble RPC, e.g. `127.0.0.1:9434`.
    pub midwimble_rpc: String,
    /// midstate address (32-byte hash) that receives midstate rewards.
    pub midstate_address: [u8; 32],
    /// midwimble address that receives midwimble rewards.
    pub midwimble_address: StealthAddress,
    pub threads: usize,
    /// JSONL record of every midstate coinbase output submitted.
    pub coinbase_log: PathBuf,
    /// Longest time spent on one pair of templates.
    pub refresh: Duration,
    /// Where to record blocks anchored by merged mining (none: don't record).
    pub anchor_store: Option<PathBuf>,
    /// Midstate blocks (the parent included) before an anchor is recorded.
    pub anchor_depth: usize,
}

#[derive(Debug, Default)]
pub struct MergeStats {
    pub rounds: AtomicU64,
    pub midstate_blocks: AtomicU64,
    pub midwimble_blocks: AtomicU64,
    pub rejected: AtomicU64,
    pub hashes: Arc<AtomicU64>,
    pub anchors_recorded: AtomicU64,
}

/// Midstate's `decompose_value`: the set bits of `value`, ascending.
pub fn decompose_value(mut value: u64) -> Vec<u64> {
    let mut parts = Vec::new();
    let mut bit = 1u64;
    while value > 0 {
        if value & 1 == 1 {
            parts.push(bit);
        }
        value >>= 1;
        if value > 0 {
            bit <<= 1;
        }
    }
    parts
}

fn hex32(v: &Value) -> Result<[u8; 32]> {
    bytes32(v)
}

/// The coinbase total midstate expects right now.
fn midstate_expected_total(midstate: &RpcClient) -> Result<u64> {
    let (status, body) = midstate.post_raw("/block_template", &json!({ "coinbase": [] }))?;
    if (200..300).contains(&status) {
        bail!("midstate accepted an empty coinbase; cannot learn the reward");
    }
    if let Some(total) = body.get("expected_total").and_then(Value::as_u64) {
        return Ok(total);
    }
    let msg = body
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or_default();
    msg.rsplit("Expected:")
        .next()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| anyhow!("unexpected midstate reply: {}", body))
}

struct Round {
    aux_mining_hash: [u8; 32],
    midwimble_height: u64,
    midwimble_target: [u8; 32],
    midwimble_template: String,
    midwimble_tip: String,
    parent: ParentTemplate,
    parent_mining_hash: [u8; 32],
    midstate_target: [u8; 32],
    midstate_batch: Value,
    midstate_height: u64,
    midstate_tip: String,
    coinbase: Vec<Value>,
}

fn prepare(
    cfg: &MergeMineConfig,
    ms: &RpcClient,
    mw: &RpcClient,
    nonce_seed: &[u8; 32],
) -> Result<Round> {
    let mw_state = mw.get("/state")?;
    let tpl = mw.post(
        "/mining/template",
        &json!({ "payouts": [{ "address": cfg.midwimble_address.encode(), "weight": 1 }] }),
    )?;
    let aux_mining_hash = hex32(&tpl["mining_hash"])?;
    let midwimble_target = hex32(&tpl["target"])?;
    let midwimble_template = tpl["template_hex"]
        .as_str()
        .ok_or_else(|| anyhow!("no template"))?
        .to_string();

    let ms_state = ms.get("/state")?;
    let midstate_height = ms_state["height"].as_u64().unwrap_or(0);
    let total = midstate_expected_total(ms)?;
    let values = decompose_value(total);
    if values.is_empty() {
        bail!("midstate coinbase total is zero");
    }
    let last = values.len() - 1;
    let commitment = merge_commitment(&aux_mining_hash);
    let coinbase: Vec<Value> = values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let salt = if i == last {
                commitment
            } else {
                hash_domain(
                    b"midwimble.midstate-payout.v1",
                    &[nonce_seed, &midstate_height.to_le_bytes(), &(i as u64).to_le_bytes(), &aux_mining_hash],
                )
            };
            json!({ "address": hex::encode(cfg.midstate_address), "value": v, "salt": hex::encode(salt) })
        })
        .collect();
    let resp = ms.post("/block_template", &json!({ "coinbase": coinbase }))?;
    let parent_mining_hash = hex32(&resp["mining_midstate"])?;
    let midstate_target = hex32(&resp["target"])?;
    let midstate_batch = resp["batch_template"].clone();
    let parent = ParentTemplate::from_midstate_json(&midstate_batch, last)?;
    parent
        .check(&aux_mining_hash, &parent_mining_hash)
        .context("refusing to merge-mine: the midstate template cannot be proven")?;
    Ok(Round {
        aux_mining_hash,
        midwimble_height: tpl["height"].as_u64().unwrap_or(0),
        midwimble_target,
        midwimble_template,
        midwimble_tip: mw_state["tip"].as_str().unwrap_or_default().to_string(),
        parent,
        parent_mining_hash,
        midstate_target,
        midstate_batch,
        midstate_height,
        midstate_tip: ms_state["header_hash"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        coinbase,
    })
}

fn search(
    mining_hash: [u8; 32],
    target: [u8; 32],
    threads: usize,
    cancel: Arc<AtomicBool>,
    counter: Arc<AtomicU64>,
) -> Option<MiningResult> {
    #[cfg(feature = "gpu")]
    {
        crate::core::gpu_mining::mine(mining_hash, target, None, threads, cancel, counter)
    }
    #[cfg(not(feature = "gpu"))]
    {
        crate::core::extension::mine_extension(mining_hash, target, None, threads, cancel, counter)
    }
}

fn log_coinbase(cfg: &MergeMineConfig, round: &Round, accepted: bool, error: Option<String>) {
    let outputs: Vec<Value> = round
        .coinbase
        .iter()
        .map(|cb| {
            let address = hex32(&cb["address"]).unwrap_or_default();
            let salt = hex32(&cb["salt"]).unwrap_or_default();
            let value = cb["value"].as_u64().unwrap_or(0);
            json!({
                "address": cb["address"], "value": value, "salt": cb["salt"],
                "coin_id": hex::encode(midstate_coin_id(&address, value, &salt)),
            })
        })
        .collect();
    let line = json!({
        "chain": "midstate",
        "height": round.midstate_height,
        "accepted": accepted,
        "error": error,
        "coinbase": outputs,
    });
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&cfg.coinbase_log)
    {
        let _ = writeln!(f, "{line}");
    }
}

/// Runs until `stop` is set. Blocking; call from a dedicated thread.
pub fn run(cfg: MergeMineConfig, stop: Arc<AtomicBool>, stats: Arc<MergeStats>) -> Result<()> {
    let ms = RpcClient::new(cfg.midstate_rpc.clone());
    let mw = RpcClient::new(cfg.midwimble_rpc.clone());
    let nonce_seed: [u8; 32] = rand::random();
    let mut pending_anchors: Vec<crate::anchor::PendingMergedAnchor> = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        if let Some(store) = &cfg.anchor_store {
            match crate::anchor::collect_merged_anchors(
                &mw,
                &ms,
                store,
                &mut pending_anchors,
                cfg.anchor_depth,
                0,
            ) {
                Ok(n) => {
                    stats
                        .anchors_recorded
                        .fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(e) => tracing::debug!("merge-mine: anchor collection: {e:#}"),
            }
        }
        let round = match prepare(&cfg, &ms, &mw, &nonce_seed) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("merge-mine: {:#}", e);
                std::thread::sleep(Duration::from_secs(2));
                continue;
            }
        };
        stats.rounds.fetch_add(1, Ordering::Relaxed);

        // Cancel when either tip moves, the round is old, or we are stopped.
        let cancel = Arc::new(AtomicBool::new(false));
        let watcher = {
            let (cancel, stop) = (cancel.clone(), stop.clone());
            let (ms, mw) = (
                RpcClient::new(cfg.midstate_rpc.clone()),
                RpcClient::new(cfg.midwimble_rpc.clone()),
            );
            let (ms_tip, mw_tip, refresh) = (
                round.midstate_tip.clone(),
                round.midwimble_tip.clone(),
                cfg.refresh,
            );
            std::thread::spawn(move || {
                let started = Instant::now();
                while !cancel.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(250));
                    let moved = |c: &RpcClient, key: &str, old: &str| {
                        c.get("/state")
                            .map(|s| s[key].as_str().unwrap_or_default() != old)
                            .unwrap_or(false)
                    };
                    if stop.load(Ordering::Relaxed)
                        || started.elapsed() > refresh
                        || moved(&ms, "header_hash", &ms_tip)
                        || moved(&mw, "tip", &mw_tip)
                    {
                        cancel.store(true, Ordering::Relaxed);
                    }
                }
            })
        };

        let easier = round.midstate_target.max(round.midwimble_target);
        let found = search(
            round.parent_mining_hash,
            easier,
            cfg.threads,
            cancel.clone(),
            stats.hashes.clone(),
        );
        cancel.store(true, Ordering::Relaxed);
        let _ = watcher.join();

        let ext = match found {
            Some(MiningResult::Block(ext)) | Some(MiningResult::Share(ext)) => ext,
            None => continue,
        };

        let mut midstate_accepted = false;
        if ext.final_hash < round.midstate_target {
            let mut batch = round.midstate_batch.clone();
            batch["extension"] =
                json!({ "nonce": ext.nonce, "final_hash": ext.final_hash.to_vec() });
            match ms.post("/submit_batch", &batch) {
                Ok(_) => {
                    midstate_accepted = true;
                    stats.midstate_blocks.fetch_add(1, Ordering::Relaxed);
                    tracing::info!(
                        "merge-mine: midstate block accepted at height {}",
                        round.midstate_height
                    );
                    log_coinbase(&cfg, &round, true, None);
                }
                Err(e) => {
                    stats.rejected.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!("merge-mine: midstate rejected the block: {:#}", e);
                    log_coinbase(&cfg, &round, false, Some(format!("{e:#}")));
                }
            }
        }

        if ext.final_hash < round.midwimble_target {
            let proof = round.parent.proof(ext.nonce, ext.final_hash);
            let sealed = template_from_hex(&round.midwimble_template, round.aux_mining_hash)?
                .seal_aux(proof);
            let block_hex = hex::encode(bincode::serialize(&sealed)?);
            match mw.post("/mining/submit", &json!({ "block_hex": block_hex })) {
                Ok(_) => {
                    stats.midwimble_blocks.fetch_add(1, Ordering::Relaxed);
                    tracing::info!("merge-mine: merged-mined midwimble block accepted");
                    if midstate_accepted && cfg.anchor_store.is_some() {
                        // The Midstate block that carries this block's work
                        // is on Midstate's chain: the block is anchored.
                        pending_anchors.push(crate::anchor::PendingMergedAnchor {
                            midstate_height: round.midstate_height,
                            midstate_final_hash: ext.final_hash,
                            mw_height: round.midwimble_height,
                            mw_block_id: sealed.extension.final_hash,
                            mw_mining_hash: round.aux_mining_hash,
                            commit_address: round.parent.commit_address,
                            commit_value: round.parent.commit_value,
                        });
                    }
                }
                Err(e) => {
                    stats.rejected.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!("merge-mine: midwimble rejected the block: {:#}", e);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decomposition_matches_midstate() {
        assert_eq!(decompose_value(0), Vec::<u64>::new());
        assert_eq!(decompose_value(13), vec![1, 4, 8]);
        assert_eq!(decompose_value(1 << 30), vec![1 << 30]);
        assert_eq!(decompose_value(u64::MAX).len(), 64);
    }
}
