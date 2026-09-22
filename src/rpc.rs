//! Local JSON RPC (axum, as midstate's `rpc/server.rs`).
//!
//! Bind it to localhost: there is no authentication. The endpoints are the
//! ones a wallet and an operator need.
//!
//! | method | path | purpose |
//! |---|---|---|
//! | GET | `/state` | tip, supply, peers, sync and mining status |
//! | GET | `/blocks/{start}/{count}` | hex-encoded blocks, for wallet scanning |
//! | GET | `/headers/{start}/{count}` | hex-encoded headers |
//! | GET | `/utxo/{commitment}` | whether an output is unspent |
//! | GET | `/mempool` | pool size and transaction hashes |
//! | POST | `/tx` | `{"tx_hex": ...}` submit via Dandelion++ |
//! | POST | `/mining` | `{"address": "mw1..." \| null}` |
//! | POST | `/peers` | `{"addr": multiaddr}` dial |
//! | POST | `/mining/template` | `{"payouts": [{"address", "weight"}], "extra"?}` → template, mining hash, receipts |
//! | POST | `/mining/submit` | `{"block_hex"}` solved block (native or merged-mined) |

use crate::core::mw::{StealthAddress, Transaction};
use crate::network::protocol::BATCH_RESPONSE_SOFT_LIMIT;
use crate::node::NodeHandle;
use anyhow::{anyhow, bail, Result};
use axum::extract::{Path, Query, State as AxState};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;

type ApiResult = std::result::Result<Json<Value>, (StatusCode, Json<Value>)>;

fn bad(e: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": e.to_string() })),
    )
}

pub fn router(node: NodeHandle) -> Router {
    Router::new()
        .route("/state", get(state))
        .route("/blocks/{start}/{count}", get(blocks))
        .route("/bonds", get(bonds))
        .route("/miners/{start}/{count}", get(miners))
        .route("/headers/{start}/{count}", get(headers))
        .route("/utxo/{commitment}", get(utxo))
        .route("/utxos", get(unspent_outputs))
        .route("/mempool", get(mempool))
        .route("/tx", post(submit_tx))
        .route("/mining", post(mining))
        .route("/peers", post(dial))
        .route("/anchors", get(list_anchors).post(submit_anchor))
        .route("/finality", get(finality))
        .route("/mining/template", post(mining_template))
        .route("/mining/submit", post(mining_submit))
        .with_state(node)
}

pub async fn serve(node: NodeHandle, addr: SocketAddr) -> Result<()> {
    if !addr.ip().is_loopback() {
        tracing::warn!(
            "RPC bound to non-loopback address {} with no authentication",
            addr
        );
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("RPC listening on http://{}", addr);
    serve_on(node, listener).await
}

/// Serves on an already-bound listener (lets callers bind port 0).
pub async fn serve_on(node: NodeHandle, listener: tokio::net::TcpListener) -> Result<()> {
    axum::serve(listener, router(node)).await?;
    Ok(())
}

fn midwimble_max_supply() -> u64 {
    crate::core::types::MAX_SUPPLY
}

/// Height of the next halving, or `null` once nothing is left to halve.
/// Explorers and halving countdowns read this.
fn next_halving(height: u64) -> Option<u64> {
    let interval = crate::core::types::HALVING_INTERVAL;
    let next = (height / interval + 1) * interval;
    (crate::core::types::block_reward(next) > 0).then_some(next)
}

/// The registered mining bonds, and whether each could authorise a block now.
async fn bonds(AxState(node): AxState<NodeHandle>) -> Json<Value> {
    let state = node.state();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut list: Vec<Value> = state
        .bonds
        .iter()
        .map(|(id, e)| {
            json!({
                "bond_id": hex::encode(id),
                "mining_key": hex::encode(e.mining_key),
                "value": e.value,
                "bonded_until": e.bonded_until,
                "eligible_now": e.eligible_at(now),
            })
        })
        .collect();
    list.sort_by(|a, b| a["bond_id"].as_str().cmp(&b["bond_id"].as_str()));
    let from = crate::core::bond::BONDED_MINING_FROM;
    Json(json!({
        "bonds": list,
        "bonded_mining_from": if from == u64::MAX { Value::Null } else { json!(from) },
    }))
}

/// Which bond signed each block, and which bonds each block registered.
async fn miners(
    AxState(node): AxState<NodeHandle>,
    Path((start, count)): Path<(u64, u64)>,
) -> ApiResult {
    let batches = node
        .storage()
        .load_batches(start, count.min(256), BATCH_RESPONSE_SOFT_LIMIT)
        .map_err(bad)?;
    let blocks: Vec<Value> = batches
        .iter()
        .enumerate()
        .map(|(i, b)| {
            json!({
                "height": start + i as u64,
                "bond_id": b.miner.as_ref().map(|m| hex::encode(m.bond_id)),
                "registrations": b
                    .registrations
                    .iter()
                    .map(|r| hex::encode(r.bond_id()))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(Json(json!({ "start": start, "blocks": blocks })))
}

async fn state(AxState(node): AxState<NodeHandle>) -> Json<Value> {
    let info = node.info();
    let s = &info.state;
    Json(json!({
        "height": s.height,
        "tip": hex::encode(s.header_hash),
        "depth": s.depth.to_string(),
        "target": hex::encode(s.target),
        "timestamp": s.timestamp,
        "state_root": hex::encode(s.state_root()),
        "supply": s.supply,
        "max_supply": midwimble_max_supply(),
        "decimals": 8,
        "block_reward": crate::core::types::block_reward(s.height),
        "era": s.height / crate::core::types::HALVING_INTERVAL,
        "next_halving_height": next_halving(s.height),
        "utxos": s.utxos.len(),
        "kernels": s.kernels.len(),
        "peer_id": info.peer_id,
        "peers": info.peers,
        "listen_addrs": info.listen_addrs,
        "syncing": info.syncing,
        "mempool_count": info.mempool_count,
        "mempool_weight": info.mempool_weight,
        "mining": info.mining,
        "hashes": info.hashes,
    }))
}

async fn blocks(
    AxState(node): AxState<NodeHandle>,
    Path((start, count)): Path<(u64, u64)>,
) -> ApiResult {
    let batches = node
        .storage()
        .load_batches(start, count.min(64), BATCH_RESPONSE_SOFT_LIMIT)
        .map_err(bad)?;
    let hex_blocks: Vec<String> = batches
        .iter()
        .map(|b| bincode::serialize(b).map(hex::encode))
        .collect::<std::result::Result<_, _>>()
        .map_err(bad)?;
    Ok(Json(json!({ "start": start, "blocks": hex_blocks })))
}

async fn headers(
    AxState(node): AxState<NodeHandle>,
    Path((start, count)): Path<(u64, u64)>,
) -> ApiResult {
    let headers = node
        .storage()
        .load_headers(start, count.min(5000))
        .map_err(bad)?;
    let bytes = bincode::serialize(&headers).map_err(bad)?;
    Ok(Json(
        json!({ "start": start, "headers_hex": hex::encode(bytes) }),
    ))
}

async fn utxo(AxState(node): AxState<NodeHandle>, Path(commitment): Path<String>) -> ApiResult {
    let key = crate::wallet::parse_point(&commitment).map_err(bad)?;
    let state = node.state();
    match state.utxos.get(&key) {
        Some(e) => Ok(Json(json!({
            "unspent": true,
            "height": e.height,
            "coinbase": e.coinbase,
            "owner_key": hex::encode(e.owner_key),
        }))),
        None => Ok(Json(json!({ "unspent": false }))),
    }
}

#[derive(Deserialize)]
struct UtxoPage {
    after: Option<String>,
    limit: Option<usize>,
}

/// Unspent outputs, for wallets restoring from a pruned node.
async fn unspent_outputs(
    AxState(node): AxState<NodeHandle>,
    Query(q): Query<UtxoPage>,
) -> ApiResult {
    let after = match q.after {
        Some(a) => Some(crate::wallet::parse_point(&a).map_err(bad)?),
        None => None,
    };
    let limit = q.limit.unwrap_or(256).min(1000);
    let page = node.storage().unspent_outputs(after, limit).map_err(bad)?;
    let outputs: Vec<Value> = page
        .iter()
        .map(|(o, e)| {
            Ok(json!({
                "output_hex": hex::encode(bincode::serialize(o)?),
                "height": e.height,
                "coinbase": e.coinbase,
            }))
        })
        .collect::<Result<_>>()
        .map_err(bad)?;
    let next = page.last().map(|(o, _)| hex::encode(o.commitment));
    Ok(Json(
        json!({ "outputs": outputs, "next": next, "height": node.info().state.height }),
    ))
}

async fn mempool(AxState(node): AxState<NodeHandle>) -> ApiResult {
    let txs = node.mempool().await.map_err(bad)?;
    let hashes: Vec<String> = txs.iter().map(|t| hex::encode(t.hash())).collect();
    Ok(Json(json!({ "count": txs.len(), "transactions": hashes })))
}

#[derive(Deserialize)]
struct TxBody {
    tx_hex: String,
}

async fn submit_tx(AxState(node): AxState<NodeHandle>, Json(body): Json<TxBody>) -> ApiResult {
    let bytes = hex::decode(&body.tx_hex).map_err(bad)?;
    let tx: Transaction = bincode::deserialize(&bytes).map_err(bad)?;
    let hash = hex::encode(tx.hash());
    node.submit_transaction(tx).await.map_err(bad)?;
    Ok(Json(json!({ "accepted": true, "tx_hash": hash })))
}

#[derive(Deserialize)]
struct MiningBody {
    address: Option<String>,
}

async fn mining(AxState(node): AxState<NodeHandle>, Json(body): Json<MiningBody>) -> ApiResult {
    let to = match body.address {
        Some(a) => Some(StealthAddress::decode(&a).map_err(bad)?),
        None => None,
    };
    node.set_mining(to);
    Ok(Json(json!({ "mining": to.is_some() })))
}

#[derive(Deserialize)]
struct DialBody {
    addr: String,
}

async fn dial(AxState(node): AxState<NodeHandle>, Json(body): Json<DialBody>) -> ApiResult {
    let addr = body.addr.parse().map_err(bad)?;
    node.dial(addr);
    Ok(Json(json!({ "dialing": body.addr })))
}

async fn list_anchors(AxState(node): AxState<NodeHandle>) -> ApiResult {
    let records = node.anchors().await.map_err(bad)?;
    Ok(Json(json!({ "anchors": records })))
}

async fn submit_anchor(
    AxState(node): AxState<NodeHandle>,
    Json(record): Json<crate::anchor::AnchorRecord>,
) -> ApiResult {
    node.submit_anchor(record).await.map_err(bad)?;
    Ok(Json(json!({ "accepted": true })))
}

async fn finality(AxState(node): AxState<NodeHandle>) -> ApiResult {
    let info = node.info();
    let base = node.storage().base().map_err(bad)?;
    Ok(Json(json!({
        "floor": info.finality.floor,
        "checkpoint_id": info.finality.checkpoint_id.map(hex::encode),
        "retain_from": info.finality.retain_from,
        "pruned_below": info.finality.pruned_below,
        "anchors_known": info.anchors_known,
        "snapshot_base": base.map(|b| b.height),
    })))
}

#[derive(Deserialize)]
struct PayoutWeight {
    address: String,
    weight: u64,
}

#[derive(Deserialize)]
struct TemplateBody {
    payouts: Vec<PayoutWeight>,
    #[serde(default)]
    extra: Option<String>,
}

/// A block template for external miners (pools, merged miners, GPUs).
async fn mining_template(
    AxState(node): AxState<NodeHandle>,
    Json(body): Json<TemplateBody>,
) -> ApiResult {
    let payouts: Vec<(StealthAddress, u64)> = body
        .payouts
        .iter()
        .map(|p| StealthAddress::decode(&p.address).map(|a| (a, p.weight)))
        .collect::<Result<_>>()
        .map_err(bad)?;
    let extra = match body.extra {
        Some(h) => crate::core::auxpow::bytes32(&Value::String(h)).map_err(bad)?,
        None => [0u8; 32],
    };
    let info = node.info();
    if info.syncing {
        return Err(bad("node is syncing"));
    }
    let state = info.state;
    let timestamps = node
        .storage()
        .load_timestamps(state.height, crate::core::types::DIFFICULTY_LOOKBACK)
        .map_err(bad)?;
    let pool = node.mempool().await.map_err(bad)?;
    let bond = node.mining_bond();
    let (template, receipts) = tokio::task::spawn_blocking(move || {
        use crate::core::types::{KERNEL_WEIGHT, MAX_BLOCK_WEIGHT, OUTPUT_WEIGHT};
        let registration_weight = bond
            .as_ref()
            .filter(|b| !state.bonds.contains_key(&b.bond_id))
            .and_then(|b| b.registration.as_ref())
            .map_or(0, |r| r.weight());
        let budget = (MAX_BLOCK_WEIGHT - (payouts.len() as u64) * OUTPUT_WEIGHT - KERNEL_WEIGHT)
            .saturating_sub(registration_weight);
        let txs = crate::core::template::select_transactions(&pool, state.height, budget);
        crate::core::template::build_template_bonded(&state, &timestamps, &txs, &payouts, extra, None, bond.as_ref())
            .or_else(|_| {
                crate::core::template::build_template_bonded(
                    &state,
                    &timestamps,
                    &[],
                    &payouts,
                    extra,
                    None,
                    bond.as_ref(),
                )
            })
            .map(|(t, r)| (t, r))
    })
    .await
    .map_err(bad)?
    .map_err(bad)?;
    let receipts: Vec<Value> = receipts
        .iter()
        .map(|(a, r)| {
            json!({
                "address": a.encode(),
                "output_index": r.output_index,
                "value": r.value,
                "blinding": hex::encode(r.blinding),
                "ephemeral_secret": hex::encode(r.ephemeral_secret),
            })
        })
        .collect();
    Ok(Json(json!({
        "height": template.height,
        "target": hex::encode(template.batch.target),
        "mining_hash": hex::encode(template.mining_hash),
        "reward": crate::core::types::block_reward(template.height),
        "fees": template.fees,
        "template_hex": hex::encode(bincode::serialize(&template.batch).map_err(bad)?),
        "receipts": receipts,
    })))
}

#[derive(Deserialize)]
struct SubmitBody {
    block_hex: String,
}

async fn mining_submit(
    AxState(node): AxState<NodeHandle>,
    Json(body): Json<SubmitBody>,
) -> ApiResult {
    let batch: crate::core::Batch =
        bincode::deserialize(&hex::decode(&body.block_hex).map_err(bad)?).map_err(bad)?;
    let hash = hex::encode(batch.extension.final_hash);
    let merged = batch.aux_pow.is_some();
    node.submit_block(batch).await.map_err(bad)?;
    Ok(Json(
        json!({ "accepted": true, "hash": hash, "merged_mined": merged }),
    ))
}

/// Reassembles a solved template (as returned by `/mining/template`).
pub fn template_from_hex(
    template_hex: &str,
    mining_hash: [u8; 32],
) -> Result<crate::core::template::BlockTemplate> {
    let batch: crate::core::Batch = bincode::deserialize(&hex::decode(template_hex)?)?;
    let height = 0;
    Ok(crate::core::template::BlockTemplate {
        fees: batch.body.fee()?,
        batch,
        mining_hash,
        height,
    })
}

// ── Client ──────────────────────────────────────────────────────────────────

/// A deliberately tiny HTTP/1.1 client for talking to a local node, so the
/// CLI needs no HTTP client stack (and no TLS: the RPC is loopback-only).
pub struct RpcClient {
    addr: String,
}

impl RpcClient {
    /// Accepts `host:port` or `http://host:port[/]`.
    pub fn new(addr: impl Into<String>) -> Self {
        let addr: String = addr.into();
        let addr = addr
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();
        Self { addr }
    }

    fn request(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        let (status, value) = self.request_raw(method, path, body)?;
        if !(200..300).contains(&status) {
            let msg = value
                .get("error")
                .and_then(|e| e.as_str())
                .map(str::to_string)
                .unwrap_or(value.to_string());
            bail!("RPC {} {} failed ({}): {}", method, path, status, msg);
        }
        Ok(value)
    }

    /// Like `post`, but returns the status and body even for errors.
    pub fn post_raw(&self, path: &str, body: &Value) -> Result<(u16, Value)> {
        self.request_raw("POST", path, Some(body))
    }

    fn request_raw(&self, method: &str, path: &str, body: Option<&Value>) -> Result<(u16, Value)> {
        use std::io::{Read, Write};
        let payload = body.map(|b| b.to_string()).unwrap_or_default();
        let mut stream = std::net::TcpStream::connect(&self.addr)
            .map_err(|e| anyhow!("cannot reach node RPC at {}: {}", self.addr, e))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(120)))?;
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{payload}",
            self.addr,
            payload.len()
        )?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw)?;
        let text = String::from_utf8(raw)?;
        let (head, body) = text
            .split_once("\r\n\r\n")
            .ok_or_else(|| anyhow!("malformed HTTP response"))?;
        let status: u16 = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow!("malformed status line"))?;
        let body = if head
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
        {
            dechunk(body)?
        } else {
            body.to_string()
        };
        let value: Value = serde_json::from_str(&body).unwrap_or(Value::String(body));
        Ok((status, value))
    }

    pub fn get(&self, path: &str) -> Result<Value> {
        self.request("GET", path, None)
    }

    pub fn post(&self, path: &str, body: &Value) -> Result<Value> {
        self.request("POST", path, Some(body))
    }

    pub fn height(&self) -> Result<u64> {
        self.get("/state")?["height"]
            .as_u64()
            .ok_or_else(|| anyhow!("bad /state response"))
    }

    /// One page of unspent outputs: `(output, height, coinbase)` plus the
    /// cursor for the next page.
    pub fn unspent_outputs(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<(crate::core::mw::Output, u64, bool)>, Option<String>)> {
        let path = match after {
            Some(a) => format!("/utxos?limit={limit}&after={a}"),
            None => format!("/utxos?limit={limit}"),
        };
        let v = self.get(&path)?;
        let outputs = v["outputs"]
            .as_array()
            .ok_or_else(|| anyhow!("bad /utxos response"))?
            .iter()
            .map(|o| {
                let bytes = hex::decode(o["output_hex"].as_str().unwrap_or_default())?;
                Ok((
                    bincode::deserialize(&bytes)?,
                    o["height"].as_u64().unwrap_or(0),
                    o["coinbase"].as_bool().unwrap_or(false),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((outputs, v["next"].as_str().map(str::to_string)))
    }

    pub fn blocks(&self, start: u64, count: u64) -> Result<Vec<crate::core::Batch>> {
        let v = self.get(&format!("/blocks/{start}/{count}"))?;
        v["blocks"]
            .as_array()
            .ok_or_else(|| anyhow!("bad /blocks response"))?
            .iter()
            .map(|b| {
                let bytes = hex::decode(b.as_str().unwrap_or_default())?;
                Ok(bincode::deserialize(&bytes)?)
            })
            .collect()
    }

    pub fn submit(&self, tx: &Transaction) -> Result<String> {
        let v = self.post(
            "/tx",
            &json!({ "tx_hex": hex::encode(bincode::serialize(tx)?) }),
        )?;
        Ok(v["tx_hash"].as_str().unwrap_or_default().to_string())
    }
}

fn dechunk(body: &str) -> Result<String> {
    let mut out = String::new();
    let mut rest = body;
    loop {
        let (size_line, after) = rest
            .split_once("\r\n")
            .ok_or_else(|| anyhow!("bad chunk"))?;
        let size = usize::from_str_radix(size_line.trim(), 16)?;
        if size == 0 {
            return Ok(out);
        }
        out.push_str(after.get(..size).ok_or_else(|| anyhow!("short chunk"))?);
        rest = after
            .get(size + 2..)
            .ok_or_else(|| anyhow!("short chunk"))?;
    }
}
