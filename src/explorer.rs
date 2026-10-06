//! Read-only JSON for the block explorer served at `/` (`GET /explorer/...`).
//!
//! The chain state answers questions about the present: which outputs are
//! unspent, which bonds are registered. The explorer also asks about the past:
//! where a spent output was created and where it was spent, which block holds
//! a kernel, which block has a given hash, and which blocks a bond signed. An
//! in-memory index answers those. It is built from the stored blocks on first
//! use, extended as the chain grows, and unwound when a reorg replaces blocks.
//!
//! Midwimble aggregates each block's transactions into one body, so an output
//! can be traced from the block that created it to the block that spent it,
//! but not to particular outputs inside a block: that link is exactly what
//! aggregation removes.

use crate::core::bond::{signer_cap, CAP_WINDOW};
use crate::core::mw::transaction::{Kernel, Output};
use crate::core::state::calculate_work;
use crate::core::types::{block_reward, Batch, State, COINBASE_MATURITY};
use crate::node::NodeHandle;
use axum::extract::{Path, Query, State as AxState};
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

type ApiError = (StatusCode, Json<Value>);
type ApiResult = Result<Json<Value>, ApiError>;

/// Blocks of history kept for unwinding a reorg; anything deeper rebuilds.
const REORG_LOG: usize = 2048;

/// The index, shared by every explorer request on one node.
pub type SharedIndex = Arc<Mutex<ExplorerIndex>>;

/// What one block added to the index, kept so a reorg can take it out again.
struct BlockLog {
    height: u64,
    hash: [u8; 32],
    created: Vec<[u8; 32]>,
    spent: Vec<[u8; 32]>,
    kernels: Vec<[u8; 32]>,
    registered: Vec<[u8; 32]>,
    signer: Option<[u8; 32]>,
}

#[derive(Default)]
pub struct ExplorerIndex {
    /// Blocks `0..next` are indexed.
    next: u64,
    hashes: HashMap<[u8; 32], u64>,
    /// Output commitment to the height of the block that created it.
    created: HashMap<[u8; 32], u64>,
    /// Output commitment to the height of the block that spent it.
    spent: HashMap<[u8; 32], u64>,
    /// Kernel excess to the height of its block.
    kernels: HashMap<[u8; 32], u64>,
    /// Bond id to the height of the block that registered it.
    registered: HashMap<[u8; 32], u64>,
    /// Bond id to the heights of the blocks it signed, ascending.
    signed: HashMap<[u8; 32], Vec<u64>>,
    log: VecDeque<BlockLog>,
}

fn body_outputs(b: &Batch) -> impl Iterator<Item = &Output> {
    b.body.body.outputs.iter().flat_map(|g| g.outputs.iter())
}

fn coinbase_outputs(b: &Batch) -> impl Iterator<Item = &Output> {
    b.coinbase.iter().flat_map(|c| c.outputs.outputs.iter())
}

fn all_kernels(b: &Batch) -> impl Iterator<Item = &Kernel> {
    b.body.body.kernels.iter().chain(b.coinbase.iter().map(|c| &c.kernel))
}

impl ExplorerIndex {
    fn add(&mut self, height: u64, b: &Batch) {
        let mut log = BlockLog {
            height,
            hash: b.extension.final_hash,
            created: Vec::new(),
            spent: Vec::new(),
            kernels: Vec::new(),
            registered: Vec::new(),
            signer: None,
        };
        for input in &b.body.body.inputs {
            self.spent.insert(input.commitment, height);
            log.spent.push(input.commitment);
        }
        for output in body_outputs(b).chain(coinbase_outputs(b)) {
            self.created.insert(output.commitment, height);
            log.created.push(output.commitment);
        }
        for kernel in all_kernels(b) {
            self.kernels.insert(kernel.excess, height);
            log.kernels.push(kernel.excess);
        }
        for registration in &b.registrations {
            let id = registration.bond_id();
            self.registered.insert(id, height);
            log.registered.push(id);
        }
        if let Some(auth) = &b.miner {
            self.signed.entry(auth.bond_id).or_default().push(height);
            log.signer = Some(auth.bond_id);
        }
        self.hashes.insert(log.hash, height);
        self.log.push_back(log);
        if self.log.len() > REORG_LOG {
            self.log.pop_front();
        }
        self.next = height + 1;
    }

    /// Takes the newest block back out. False once there is no history left.
    fn unwind(&mut self) -> bool {
        let Some(log) = self.log.pop_back() else {
            return false;
        };
        let h = log.height;
        let forget = |map: &mut HashMap<[u8; 32], u64>, keys: Vec<[u8; 32]>| {
            for k in keys {
                if map.get(&k) == Some(&h) {
                    map.remove(&k);
                }
            }
        };
        forget(&mut self.spent, log.spent);
        forget(&mut self.created, log.created);
        forget(&mut self.kernels, log.kernels);
        forget(&mut self.registered, log.registered);
        forget(&mut self.hashes, vec![log.hash]);
        if let Some(signer) = log.signer {
            if let Some(heights) = self.signed.get_mut(&signer) {
                if heights.last() == Some(&h) {
                    heights.pop();
                }
            }
        }
        self.next = h;
        true
    }

    /// Brings the index level with the node's chain: unwinds blocks a reorg
    /// replaced, then indexes the new ones.
    fn sync(&mut self, node: &NodeHandle) -> anyhow::Result<()> {
        let storage = node.storage();
        while self.next > 0 {
            let stored = storage.load_batch(self.next - 1)?.map(|b| b.extension.final_hash);
            if stored.is_some() && stored == self.log.back().map(|l| l.hash) {
                break;
            }
            if !self.unwind() {
                *self = Self::default();
                break;
            }
        }
        let tip = node.state().height;
        while self.next < tip {
            let batches = storage.load_batches(self.next, 256, 64 << 20)?;
            if batches.is_empty() {
                break; // pruned history: the index starts where the blocks do
            }
            for b in &batches {
                let height = self.next;
                self.add(height, b);
            }
        }
        Ok(())
    }
}

fn not_found(what: &str) -> ApiError {
    (StatusCode::NOT_FOUND, Json(json!({ "error": format!("no such {what}") })))
}

fn bad(e: impl std::fmt::Display) -> ApiError {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() })))
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() })))
}

fn hex32(s: &str) -> Result<[u8; 32], ApiError> {
    hex::decode(s.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| bad("expected 32 bytes of hex"))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Syncs the index, then answers from it, off the async runtime: the first
/// call reads every stored block.
async fn with_index<F>(node: NodeHandle, index: SharedIndex, answer: F) -> ApiResult
where
    F: FnOnce(&ExplorerIndex, &NodeHandle) -> ApiResult + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut idx = index.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        idx.sync(&node).map_err(internal)?;
        answer(&idx, &node)
    })
    .await
    .map_err(internal)?
}

/// log2 of the expected attempts per block: 256 minus log2(target).
fn difficulty_bits(target: &[u8; 32]) -> f64 {
    let value = target.iter().fold(0f64, |acc, &b| acc * 256.0 + b as f64);
    if value <= 0.0 {
        256.0
    } else {
        256.0 - value.log2()
    }
}

fn fees(b: &Batch) -> u64 {
    b.body.body.kernels.iter().fold(0u64, |acc, k| acc.saturating_add(k.fee))
}

fn summary(height: u64, b: &Batch, prev_timestamp: Option<u64>) -> Value {
    json!({
        "height": height,
        "hash": hex::encode(b.extension.final_hash),
        "timestamp": b.timestamp,
        "interval": prev_timestamp.map(|p| b.timestamp as i64 - p as i64),
        "difficulty_bits": difficulty_bits(&b.target),
        "inputs": b.body.body.inputs.len(),
        "outputs": body_outputs(b).count() + coinbase_outputs(b).count(),
        "kernels": b.body.body.kernels.len(),
        "fees": fees(b),
        "reward": block_reward(height),
        "size": bincode::serialized_size(b).unwrap_or(0),
        "miner": b.miner.as_ref().map(|m| hex::encode(m.bond_id)),
        "merged": b.aux_pow.is_some(),
        "registrations": b.registrations.len(),
    })
}

fn output_json(o: &Output, idx: &ExplorerIndex, state: &State) -> Value {
    json!({
        "commitment": hex::encode(o.commitment),
        "owner_key": hex::encode(o.owner_key),
        "ephemeral_key": hex::encode(o.ephemeral_key),
        "view_tag": o.view_tag,
        "payload_bytes": o.payload.len(),
        "recovery_commitment": hex::encode(o.recovery_commitment),
        "unspent": state.utxos.contains_key(&o.commitment),
        "spent_height": idx.spent.get(&o.commitment),
    })
}

fn kernel_json(k: &Kernel) -> Value {
    json!({
        "excess": hex::encode(k.excess),
        "owner_excess": hex::encode(k.owner_excess),
        "fee": k.fee,
        "min_height": k.min_height,
        "features": serde_json::to_value(k.features).unwrap_or(Value::Null),
    })
}

/// The coinbase's 32 spare bytes as text, when a miner put text there.
fn printable(extra: &[u8; 32]) -> Option<String> {
    let text: String = extra.iter().take_while(|&&b| b != 0).map(|&b| b as char).collect();
    let clean = !text.is_empty() && text.chars().all(|c| c.is_ascii_graphic() || c == ' ');
    clean.then_some(text)
}

#[derive(Deserialize)]
pub struct BlocksQuery {
    before: Option<u64>,
    count: Option<u64>,
}

/// Block summaries, newest first, ending just below `before` (default: tip).
pub async fn blocks(
    AxState(node): AxState<NodeHandle>,
    Extension(index): Extension<SharedIndex>,
    Query(q): Query<BlocksQuery>,
) -> ApiResult {
    with_index(node, index, move |_, node| {
        let tip = node.state().height;
        let before = q.before.unwrap_or(tip).min(tip);
        let count = q.count.unwrap_or(25).clamp(1, 200);
        let start = before.saturating_sub(count);
        let from = start.saturating_sub(1); // one more, for the first interval
        let batches = node
            .storage()
            .load_batches(from, before - from, 64 << 20)
            .map_err(internal)?;
        let mut out: Vec<Value> = batches
            .iter()
            .enumerate()
            .filter(|(i, _)| from + *i as u64 >= start)
            .map(|(i, b)| {
                let prev = i.checked_sub(1).map(|p| batches[p].timestamp);
                summary(from + i as u64, b, prev)
            })
            .collect();
        out.reverse();
        Ok(Json(json!({ "tip": tip, "blocks": out })))
    })
    .await
}

fn resolve_block(idx: &ExplorerIndex, id: &str, tip: u64) -> Result<u64, ApiError> {
    let height = match id.parse::<u64>() {
        Ok(h) => h,
        Err(_) => *idx.hashes.get(&hex32(id)?).ok_or_else(|| not_found("block"))?,
    };
    if height >= tip {
        return Err(not_found("block"));
    }
    Ok(height)
}

/// One block in full, by height or hash.
pub async fn block(
    AxState(node): AxState<NodeHandle>,
    Extension(index): Extension<SharedIndex>,
    Path(id): Path<String>,
) -> ApiResult {
    with_index(node, index, move |idx, node| {
        let state = node.state();
        let tip = state.height;
        let height = resolve_block(idx, &id, tip)?;
        let storage = node.storage();
        let load = |h: u64| storage.load_batch(h).map_err(internal);
        let b = load(height)?.ok_or_else(|| not_found("block"))?;
        let prev = if height > 0 { load(height - 1)? } else { None };
        let next = if height + 1 < tip { load(height + 1)? } else { None };
        let mut v = summary(height, &b, prev.map(|p| p.timestamp));

        let body = &b.body.body;
        v["prev_hash"] = json!(hex::encode(b.prev_header_hash));
        v["next_hash"] = json!(next.map(|n| hex::encode(n.extension.final_hash)));
        v["confirmations"] = json!(tip - height);
        v["target"] = json!(hex::encode(b.target));
        v["work"] = json!(calculate_work(&b.target).to_string());
        v["nonce"] = json!(b.extension.nonce);
        v["state_root"] = json!(hex::encode(b.state_root));
        v["prev_midstate"] = json!(hex::encode(b.prev_midstate));
        v["kernel_offset"] = json!(hex::encode(b.body.kernel_offset));
        v["owner_offset"] = json!(hex::encode(b.body.owner_offset));
        v["inputs"] = json!(body
            .inputs
            .iter()
            .map(|i| json!({
                "commitment": hex::encode(i.commitment),
                "owner_key": hex::encode(i.owner_key),
                "created_height": idx.created.get(&i.commitment),
            }))
            .collect::<Vec<_>>());
        v["outputs"] = json!(body_outputs(&b).map(|o| output_json(o, idx, &state)).collect::<Vec<_>>());
        v["output_groups"] = json!(body
            .outputs
            .iter()
            .map(|g| json!({ "outputs": g.outputs.len(), "range_proof_bytes": g.range_proof.len() }))
            .collect::<Vec<_>>());
        v["kernels"] = json!(body.kernels.iter().map(kernel_json).collect::<Vec<_>>());
        v["coinbase"] = json!(b.coinbase.as_ref().map(|c| json!({
            "outputs": c.outputs.outputs.iter().map(|o| output_json(o, idx, &state)).collect::<Vec<_>>(),
            "range_proof_bytes": c.outputs.range_proof.len(),
            "kernel": kernel_json(&c.kernel),
            "extra": hex::encode(c.extra),
            "extra_text": printable(&c.extra),
        })));
        v["miner"] = json!(b.miner.as_ref().map(|m| json!({ "bond_id": hex::encode(m.bond_id) })));
        v["merged"] = json!(b.aux_pow.as_ref().map(|a| json!({
            "midstate_block": hex::encode(a.final_hash),
            "midstate_prev": hex::encode(a.prev_header_hash),
            "midstate_timestamp": a.timestamp,
            "midstate_target": hex::encode(a.target),
            "commit_address": hex::encode(a.commit_address),
            "commit_value": a.commit_value,
        })));
        v["registrations"] = json!(b
            .registrations
            .iter()
            .map(|r| json!({
                "bond_id": hex::encode(r.bond_id()),
                "mining_key": hex::encode(r.proof.coin.script.mining_key),
                "value": r.proof.coin.value,
                "bonded_until": r.proof.coin.script.bonded_until,
                "midstate_height": r.proof.midstate_height,
                "headers": r.headers.len(),
            }))
            .collect::<Vec<_>>());
        Ok(Json(v))
    })
    .await
}

/// An output's life: the block that created it and the one that spent it.
pub async fn output(
    AxState(node): AxState<NodeHandle>,
    Extension(index): Extension<SharedIndex>,
    Path(commitment): Path<String>,
) -> ApiResult {
    let key = hex32(&commitment)?;
    with_index(node, index, move |idx, node| {
        let created = *idx.created.get(&key).ok_or_else(|| not_found("output"))?;
        let storage = node.storage();
        let b = storage
            .load_batch(created)
            .map_err(internal)?
            .ok_or_else(|| not_found("output"))?;
        let in_coinbase = coinbase_outputs(&b).find(|o| o.commitment == key);
        let o = in_coinbase
            .or_else(|| body_outputs(&b).find(|o| o.commitment == key))
            .ok_or_else(|| not_found("output"))?;
        let state = node.state();
        let spent = idx.spent.get(&key).copied().filter(|&s| s >= created);
        let spent_hash = match spent {
            Some(s) => storage.load_batch(s).map_err(internal)?.map(|sb| hex::encode(sb.extension.final_hash)),
            None => None,
        };
        let mut v = output_json(o, idx, &state);
        v["created_height"] = json!(created);
        v["created_hash"] = json!(hex::encode(b.extension.final_hash));
        v["coinbase"] = json!(in_coinbase.is_some());
        v["matures_at"] = json!(in_coinbase.map(|_| created + COINBASE_MATURITY));
        v["spent_height"] = json!(spent);
        v["spent_hash"] = json!(spent_hash);
        v["tip"] = json!(state.height);
        Ok(Json(v))
    })
    .await
}

/// A kernel and the block that carries it.
pub async fn kernel(
    AxState(node): AxState<NodeHandle>,
    Extension(index): Extension<SharedIndex>,
    Path(excess): Path<String>,
) -> ApiResult {
    let key = hex32(&excess)?;
    with_index(node, index, move |idx, node| {
        let height = *idx.kernels.get(&key).ok_or_else(|| not_found("kernel"))?;
        let b = node
            .storage()
            .load_batch(height)
            .map_err(internal)?
            .ok_or_else(|| not_found("kernel"))?;
        let coinbase = b.coinbase.as_ref().is_some_and(|c| c.kernel.excess == key);
        let k = all_kernels(&b).find(|k| k.excess == key).ok_or_else(|| not_found("kernel"))?;
        let mut v = kernel_json(k);
        v["height"] = json!(height);
        v["hash"] = json!(hex::encode(b.extension.final_hash));
        v["coinbase"] = json!(coinbase);
        v["block_kernels"] = json!(b.body.body.kernels.len());
        Ok(Json(v))
    })
    .await
}

fn bond_json(id: &[u8; 32], idx: &ExplorerIndex, state: &State, now: u64) -> Value {
    let entry = state.bonds.get(id);
    let signed = idx.signed.get(id);
    json!({
        "bond_id": hex::encode(id),
        "mining_key": entry.map(|e| hex::encode(e.mining_key)),
        "value": entry.map(|e| e.value),
        "bonded_until": entry.map(|e| e.bonded_until),
        "eligible_now": entry.map(|e| e.eligible_at(now)),
        "registered_height": idx.registered.get(id),
        "blocks_signed": signed.map_or(0, |v| v.len()),
        "last_signed": signed.and_then(|v| v.last()),
        "window_signed": state.signer_counts.get(id).copied().unwrap_or(0),
    })
}

fn window_json(state: &State, now: u64) -> Value {
    json!({
        "size": CAP_WINDOW,
        "filled": state.recent_signers.len(),
        "cap": signer_cap(&state.bonds, now),
    })
}

/// Every registered bond, with its share of the fork-choice window.
pub async fn bonds(
    AxState(node): AxState<NodeHandle>,
    Extension(index): Extension<SharedIndex>,
) -> ApiResult {
    with_index(node, index, move |idx, node| {
        let state = node.state();
        let now = unix_now();
        let mut list: Vec<Value> = state.bonds.keys().map(|id| bond_json(id, idx, &state, now)).collect();
        list.sort_by_key(|b| std::cmp::Reverse(b["window_signed"].as_u64().unwrap_or(0)));
        Ok(Json(json!({ "bonds": list, "window": window_json(&state, now) })))
    })
    .await
}

/// One bond: its terms, its quota, and the blocks it signed.
pub async fn bond(
    AxState(node): AxState<NodeHandle>,
    Extension(index): Extension<SharedIndex>,
    Path(id): Path<String>,
) -> ApiResult {
    let id = hex32(&id)?;
    with_index(node, index, move |idx, node| {
        let state = node.state();
        if !state.bonds.contains_key(&id) && !idx.registered.contains_key(&id) {
            return Err(not_found("bond"));
        }
        let now = unix_now();
        let mut v = bond_json(&id, idx, &state, now);
        v["window"] = window_json(&state, now);
        v["recent_blocks"] = json!(idx
            .signed
            .get(&id)
            .map(|h| h.iter().rev().take(60).copied().collect::<Vec<_>>())
            .unwrap_or_default());
        Ok(Json(v))
    })
    .await
}

/// What a search term names: a height, or a block hash, output commitment,
/// kernel excess or bond id.
pub async fn search(
    AxState(node): AxState<NodeHandle>,
    Extension(index): Extension<SharedIndex>,
    Path(q): Path<String>,
) -> ApiResult {
    with_index(node, index, move |idx, node| {
        let q = q.trim().to_ascii_lowercase();
        let found = |kind: &str, id: String| Ok(Json(json!({ "kind": kind, "id": id })));
        if !q.is_empty() && q.len() <= 20 && q.bytes().all(|c| c.is_ascii_digit()) {
            let h: u64 = q.parse().map_err(bad)?;
            return if h < node.state().height { found("block", h.to_string()) } else { Err(not_found("block")) };
        }
        let key = hex32(&q).map_err(|_| not_found("height, hash, commitment, kernel or bond"))?;
        if let Some(h) = idx.hashes.get(&key) {
            return found("block", h.to_string());
        }
        if idx.created.contains_key(&key) {
            return found("output", q);
        }
        if idx.kernels.contains_key(&key) {
            return found("kernel", q);
        }
        if node.state().bonds.contains_key(&key) || idx.registered.contains_key(&key) {
            return found("bond", q);
        }
        Err(not_found("height, hash, commitment, kernel or bond"))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::bond::MinerAuth;
    use crate::core::mw::crypto::{KernelSig, SchnorrSig};
    use crate::core::mw::transaction::{Input, KernelFeatures, OutputGroup};

    /// A block whose kernel excess and hash are both `[tag; 32]`.
    fn block(tag: u8, spends: &[[u8; 32]], creates: &[[u8; 32]], signer: Option<[u8; 32]>) -> Batch {
        let sig = SchnorrSig { e: [0; 32], s: [0; 32] };
        let mut b = Batch::genesis().clone();
        b.extension.final_hash = [tag; 32];
        b.coinbase = None;
        b.body.body.inputs = spends
            .iter()
            .map(|c| Input { commitment: *c, owner_key: [0; 32], signature: sig.clone() })
            .collect();
        b.body.body.outputs = vec![OutputGroup {
            outputs: creates
                .iter()
                .map(|c| Output {
                    commitment: *c,
                    owner_key: [0; 32],
                    ephemeral_key: [0; 32],
                    view_tag: 0,
                    payload: Vec::new(),
                    recovery_commitment: [0; 32],
                })
                .collect(),
            range_proof: Vec::new(),
        }];
        b.body.body.kernels = vec![Kernel {
            features: KernelFeatures::Plain,
            fee: 0,
            min_height: 0,
            excess: [tag; 32],
            owner_excess: [0; 32],
            signature: KernelSig { c: [0; 32], s1: [0; 32], s2: [0; 32] },
        }];
        b.miner = signer.map(|bond_id| MinerAuth { bond_id, signature: sig });
        b
    }

    #[test]
    fn a_reorg_unwinds_exactly_what_its_blocks_added() {
        let (a, b, c, bond) = ([0xa; 32], [0xb; 32], [0xc; 32], [0x77; 32]);
        let mut idx = ExplorerIndex::default();
        idx.add(0, &block(1, &[], &[a], None));
        idx.add(1, &block(2, &[a], &[b], Some(bond)));
        assert_eq!(idx.spent.get(&a), Some(&1));
        assert_eq!(idx.created.get(&b), Some(&1));
        assert_eq!(idx.signed[&bond], vec![1]);
        assert_eq!(idx.hashes.get(&[2; 32]), Some(&1));

        // A reorg replaces block 1: a is unspent again and b never existed.
        assert!(idx.unwind());
        assert_eq!(idx.next, 1);
        assert!(!idx.spent.contains_key(&a));
        assert!(!idx.created.contains_key(&b));
        assert!(!idx.kernels.contains_key(&[2; 32]));
        assert!(!idx.hashes.contains_key(&[2; 32]));
        assert!(idx.signed[&bond].is_empty());
        assert_eq!(idx.created.get(&a), Some(&0), "earlier blocks are untouched");

        // The replacement spends a into c instead.
        idx.add(1, &block(3, &[a], &[c], None));
        assert_eq!(idx.spent.get(&a), Some(&1));
        assert_eq!(idx.created.get(&c), Some(&1));
        assert_eq!(idx.hashes.get(&[3; 32]), Some(&1));

        // Unwinding everything leaves nothing behind.
        assert!(idx.unwind());
        assert!(idx.unwind());
        assert!(!idx.unwind(), "no history left to unwind");
        assert!(idx.created.is_empty() && idx.spent.is_empty());
        assert!(idx.kernels.is_empty() && idx.hashes.is_empty());
    }

    #[test]
    fn the_reorg_log_is_bounded() {
        let mut idx = ExplorerIndex::default();
        for h in 0..(REORG_LOG as u64 + 5) {
            idx.add(h, &block((h % 251) as u8, &[], &[], None));
        }
        assert_eq!(idx.log.len(), REORG_LOG);
        assert_eq!(idx.next, REORG_LOG as u64 + 5);
    }

    #[test]
    fn difficulty_bits_counts_expected_attempts() {
        let mut t = [0u8; 32];
        t[1] = 0x01; // 2^(256 - 16)
        assert!((difficulty_bits(&t) - 16.0).abs() < 1e-9);
        assert_eq!(difficulty_bits(&[0xff; 32]).round(), 0.0);
    }

    #[test]
    fn coinbase_text_is_shown_only_when_printable() {
        let mut extra = [0u8; 32];
        extra[..5].copy_from_slice(b"hello");
        assert_eq!(printable(&extra).as_deref(), Some("hello"));
        extra[0] = 0xff;
        assert_eq!(printable(&extra), None);
        assert_eq!(printable(&[0u8; 32]), None);
    }
}
