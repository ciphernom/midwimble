//! Local JSON RPC (axum, as midstate's `rpc/server.rs`).
//!
//! Bind it to localhost: there is no authentication. The endpoints are the
//! ones a wallet and an operator need, and some change what the node does
//! (`/mining` sets where its rewards go), so:
//!
//! * The RPC answers only requests whose `Host` is an IP address, `localhost`
//!   or a name given with `--rpc-allow-host`. A web page the operator opens
//!   can point a domain of its own at 127.0.0.1 (DNS rebinding) and then call
//!   the RPC from the browser as if it were its own origin; the `Host` it
//!   sends still names that domain. Every `POST` also takes only
//!   `application/json`, which a page cannot send to another origin without
//!   a CORS preflight this server never grants.
//! * The block explorer (`/`, `/state` and `/explorer/...`) can be served on
//!   a listener of its own (`--explorer`), which has nothing else on it and
//!   can be published as it is.
//!
//! | method | path | purpose |
//! |---|---|---|
//! | GET | `/state` | tip, supply, peers (and those banned), sync and mining status |
//! | GET | `/blocks/{start}/{count}` | hex-encoded blocks, for wallet scanning |
//! | GET | `/headers/{start}/{count}` | hex-encoded headers |
//! | GET | `/utxo/{commitment}` | whether an output is unspent |
//! | GET | `/mempool` | pool size and transaction hashes |
//! | POST | `/mempool/txs` | `{"hashes": [hex]}` → those transactions, hex-encoded |
//! | POST | `/tx` | `{"tx_hex": ...}` submit via Dandelion++ |
//! | POST | `/mining` | `{"address": "mw1..." \| null}` |
//! | POST | `/peers` | `{"addr": multiaddr}` dial |
//! | POST | `/mining/template` | `{"payouts": [{"address", "weight"}], "extra"?}` → template, mining hash, receipts |
//! | POST | `/mining/bind` | `{"mining_hash", "extras": [hex]}` → one copy of that template per `extra`, re-signed |
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

/// What the RPC listener answers to besides its routes.
#[derive(Clone, Debug, Default)]
pub struct RpcOptions {
    /// Host names the RPC answers to besides `localhost` names and IP
    /// addresses (`--rpc-allow-host`); `*` allows any.
    pub allowed_hosts: Vec<String>,
    /// When set, the RPC answers browser cross-origin requests with this
    /// `Access-Control-Allow-Origin` (`--rpc-cors`; `*` allows any). This is
    /// what lets a web wallet use the node as an HTTPS fallback for WebRTC,
    /// so it is off unless an operator running a public gateway turns it on.
    pub cors_origin: Option<String>,
}

/// The RPC with default options and an explorer index of its own.
pub fn router(node: NodeHandle) -> Router {
    router_with(node, &RpcOptions::default(), SharedIndex::default())
}

/// The RPC, sharing `index` with an explorer listener if there is one.
pub fn router_with(node: NodeHandle, options: &RpcOptions, index: SharedIndex) -> Router {
    Router::new()
        .route("/", get(explorer))
        .route("/logo.svg", get(logo))
        .route("/state", get(state))
        .route("/link", get(link_page))
        // The light protocol over HTTP: a browser wallet's fallback when it
        // cannot reach the node over WebRTC. Same request and response shape
        // as the WebRTC light stream, so the wallet needs no translation.
        .route("/light", post(light))
        .route("/blocks/{start}/{count}", get(blocks))
        .route("/bonds", get(bonds))
        .route("/relay", get(relay))
        .route("/merge/job", post(merge_job))
        .route("/merge/found", post(merge_found))
        .route("/miners/{start}/{count}", get(miners))
        .route("/headers/{start}/{count}", get(headers))
        .route("/utxo/{commitment}", get(utxo))
        .route("/utxos", get(unspent_outputs))
        .route("/mempool", get(mempool))
        .route("/mempool/txs", post(mempool_txs))
        .route("/tx", post(submit_tx))
        .route("/mining", post(mining))
        .route("/peers", post(dial))
        .route("/anchors", get(list_anchors).post(submit_anchor))
        .route("/finality", get(finality))
        .route("/mining/template", post(mining_template))
        .route("/mining/bind", post(mining_bind))
        .route("/mining/submit", post(mining_submit))
        .route("/explorer/blocks", get(crate::explorer::blocks))
        .route("/explorer/block/{id}", get(crate::explorer::block))
        .route(
            "/explorer/output/{commitment}",
            get(crate::explorer::output),
        )
        .route("/explorer/kernel/{excess}", get(crate::explorer::kernel))
        .route("/explorer/bonds", get(crate::explorer::bonds))
        .route("/explorer/bond/{id}", get(crate::explorer::bond))
        .route("/explorer/search/{q}", get(crate::explorer::search))
        .layer(axum::Extension(index))
        .layer(axum::middleware::from_fn_with_state(
            std::sync::Arc::new(options.allowed_hosts.clone()),
            check_host,
        ))
        // Outermost, so a browser preflight is answered before the host check.
        .layer(axum::middleware::from_fn_with_state(
            std::sync::Arc::new(options.cors_origin.clone()),
            cors,
        ))
        .with_state(node)
}

/// The block explorer alone: its page and the read-only JSON it reads.
/// Nothing on it changes the node, so it can be published as it is.
pub fn explorer_router(node: NodeHandle, index: SharedIndex) -> Router {
    Router::new()
        .route("/", get(explorer))
        .route("/logo.svg", get(logo))
        .route("/state", get(state))
        .route("/link", get(link_page))
        .route("/explorer/blocks", get(crate::explorer::blocks))
        .route("/explorer/block/{id}", get(crate::explorer::block))
        .route(
            "/explorer/output/{commitment}",
            get(crate::explorer::output),
        )
        .route("/explorer/kernel/{excess}", get(crate::explorer::kernel))
        .route("/explorer/bonds", get(crate::explorer::bonds))
        .route("/explorer/bond/{id}", get(crate::explorer::bond))
        .route("/explorer/search/{q}", get(crate::explorer::search))
        .layer(axum::Extension(index))
        .with_state(node)
}

use crate::explorer::SharedIndex;

/// Refuses a request whose `Host` the RPC does not answer to
/// ([`host_allowed`]).
async fn check_host(
    AxState(allowed): AxState<std::sync::Arc<Vec<String>>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| request.uri().authority().map(|a| a.to_string()));
    match host {
        Some(host) if !host_allowed(&host, &allowed) => (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": format!(
                    "this RPC does not answer to host {host:?}; \
                     start the node with --rpc-allow-host to allow it"
                )
            })),
        )
            .into_response(),
        _ => next.run(request).await,
    }
}

/// Whether the RPC answers to `host` (a `Host` header: a name or address,
/// with or without a port): an IP address, which no other site can point
/// at, `localhost` or a name under it, which resolve only to this machine,
/// or a name in `allowed`.
pub fn host_allowed(host: &str, allowed: &[String]) -> bool {
    let host = host.trim();
    if let Some(rest) = host.strip_prefix('[') {
        return rest
            .split_once(']')
            .is_some_and(|(addr, _)| addr.parse::<std::net::Ipv6Addr>().is_ok());
    }
    let name = match host.rsplit_once(':') {
        Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    };
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() {
        return false;
    }
    name.parse::<std::net::Ipv4Addr>().is_ok()
        || name == "localhost"
        || name.ends_with(".localhost")
        || allowed
            .iter()
            .any(|a| a == "*" || a.trim_end_matches('.').eq_ignore_ascii_case(&name))
}

pub async fn serve(node: NodeHandle, addr: SocketAddr) -> Result<()> {
    serve_with(node, addr, &RpcOptions::default(), SharedIndex::default()).await
}

/// Binds `addr` and serves the RPC on it.
pub async fn serve_with(
    node: NodeHandle,
    addr: SocketAddr,
    options: &RpcOptions,
    index: SharedIndex,
) -> Result<()> {
    if !addr.ip().is_loopback() {
        tracing::warn!(
            "RPC bound to non-loopback address {} with no authentication: anyone who \
             can reach it can redirect this node's mining rewards. Publish the explorer \
             with --explorer instead.",
            addr
        );
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("RPC listening on http://{}", addr);
    axum::serve(listener, router_with(node, options, index)).await?;
    Ok(())
}

/// Serves on an already-bound listener (lets callers bind port 0).
pub async fn serve_on(node: NodeHandle, listener: tokio::net::TcpListener) -> Result<()> {
    axum::serve(listener, router(node)).await?;
    Ok(())
}

/// Binds `addr` and serves the block explorer alone on it.
pub async fn serve_explorer(node: NodeHandle, addr: SocketAddr, index: SharedIndex) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Explorer listening on http://{}", addr);
    serve_explorer_on(node, listener, index).await
}

/// [`serve_explorer`] on an already-bound listener.
pub async fn serve_explorer_on(
    node: NodeHandle,
    listener: tokio::net::TcpListener,
    index: SharedIndex,
) -> Result<()> {
    axum::serve(listener, explorer_router(node, index)).await?;
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

/// The midstate relay (`core/relay.rs`): the midstate chain this chain's
/// blocks have relayed, which bond registrations are proven against.
async fn relay(AxState(node): AxState<NodeHandle>) -> Json<Value> {
    let state = node.state();
    let (tip, base) = (state.relay.tip(), state.relay.base());
    let feed = node.relay_feed();
    let feed = feed.read().expect("relay feed lock poisoned");
    Json(json!({
        "tip_height": tip.height,
        "tip_hash": hex::encode(tip.hash),
        "chain_work": tip.chain_work.to_string(),
        "base_height": base.height,
        "entries": state.relay.len(),
        "registration_work": crate::core::bond::registration_work(&state.target).to_string(),
        "registration_cap": crate::core::bond::registration_cap(&state.target).to_string(),
        "feed_tip_height": feed.tip_height(),
        "would_relay": feed.next_for(&state.relay).map_or(0, |r| r.headers.len()),
    }))
}

/// The registered mining bonds that can still sign (expired ones leave the
/// set), and whether each could authorise a block now.
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
    use crate::core::bond::{
        min_mining_bond, min_remaining_bond_lock, registration_min_bond,
        work_doublings_since_genesis, BONDED_MINING_FROM, BOND_RETARGET_FROM, EARLY_BONDS_UNTIL,
        MAX_MINING_BOND, WORK_DOUBLINGS_PER_BOND_DOUBLING,
    };
    let from = BONDED_MINING_FROM;
    Json(json!({
        "bonds": list,
        "bonded_mining_from": if from == u64::MAX { Value::Null } else { json!(from) },
        // What `eligible_at` asks of any bond, old or new: the launch
        // minimum. A bond in the set above is judged by this and nothing
        // else, which is why the retarget below can never strand one.
        "min_bond_now": min_mining_bond(now),
        "min_remaining_lock_now": min_remaining_bond_lock(now),
        "early_bonds_until": if EARLY_BONDS_UNTIL == 0 { Value::Null } else { json!(EARLY_BONDS_UNTIL) },
        // What a *new* registration must lock at this chain's difficulty:
        // the figure to check before locking a coin on midstate.
        "registration_min_bond": registration_min_bond(&state.target, now),
        "bond_retarget_from": BOND_RETARGET_FROM,
        "bond_retarget_active": now >= BOND_RETARGET_FROM,
        "bond_retarget_ceiling": MAX_MINING_BOND,
        "work_doublings_per_bond_doubling": WORK_DOUBLINGS_PER_BOND_DOUBLING,
        "work_doublings_since_genesis": work_doublings_since_genesis(&state.target),
    }))
}

/// Which bond signed each block, which bonds it registered, and whether its
/// proof of work came from a midstate block (merged mining).
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
                "merged": b.aux_pow.is_some(),
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

/// This node's own block explorer: one self-contained page, served from the
/// binary, reading the endpoints below. No fonts, scripts or images come from
/// anywhere else, so it works on a machine with no internet at all.
async fn logo() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "image/svg+xml")],
        include_str!("../docs/assets/midwimble-logo.svg"),
    )
}

async fn explorer() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("explorer.html"))
}

/// A page that shows a QR a phone/web wallet scans to pair with this node.
/// The address the wallet should dial is built from the `Host` header — the
/// very address the operator opened this page at — so viewing it over the LAN
/// (e.g. `http://192.168.1.5:9434/link`) yields a LAN-dialable QR with no
/// configuration.
async fn link_page(
    AxState(node): AxState<NodeHandle>,
    headers: axum::http::HeaderMap,
) -> axum::response::Html<String> {
    use axum::response::Html;
    let info = node.info();
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(crate::link::host_from_header)
        .unwrap_or_else(|| "localhost".to_string());
    let templates = if info.webrtc_listen.is_empty() {
        &info.webrtc_addrs
    } else {
        &info.webrtc_listen
    };
    let addrs: Vec<String> = templates
        .iter()
        .filter_map(|a| crate::link::rehost(a, &host))
        .collect();
    if addrs.is_empty() {
        return Html(link_html_message(
            "This node has no WebRTC address yet. Build it with <code>--features webrtc</code> \
             and give it a moment to start listening, then reload.",
        ));
    }
    let uri = crate::link::node_link_uri(&addrs, true);
    let svg = match qrcode::QrCode::new(uri.as_bytes()) {
        Ok(code) => code
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(300, 300)
            .quiet_zone(true)
            .build(),
        Err(_) => return Html(link_html_message("Could not render the QR code.")),
    };
    Html(link_html(&svg, &uri, &addrs))
}

fn link_page_shell(body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>Link a wallet · midwimble</title><style>\
         :root{{color-scheme:light dark}}\
         body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;\
         background:#0b0d10;color:#e7e9ee;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}\
         .card{{max-width:420px;margin:24px;padding:28px;background:#14181d;border:1px solid #232a32;\
         border-radius:16px;text-align:center;box-shadow:0 8px 40px rgba(0,0,0,.4)}}\
         h1{{font-size:20px;margin:0 0 4px}} p{{margin:8px 0;color:#aab2bd}}\
         .qr{{width:300px;max-width:100%;margin:16px auto;background:#fff;border-radius:12px;padding:12px}}\
         .qr svg{{width:100%;height:auto;display:block}}\
         code,.addr{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;word-break:break-all}}\
         .addr{{display:block;margin-top:12px;padding:10px;background:#0b0d10;border:1px solid #232a32;\
         border-radius:8px;color:#8b94a0}}</style></head><body><div class=\"card\">{body}</div></body></html>"
    )
}

fn link_html(svg: &str, uri: &str, addrs: &[String]) -> String {
    let addr_list = addrs
        .iter()
        .map(|a| format!("<span class=\"addr\">{}</span>", html_escape(a)))
        .collect::<String>();
    link_page_shell(&format!(
        "<h1>Link a wallet</h1>\
         <p>Scan this with the midwimble wallet:<br>Network → Node list → Scan node QR.</p>\
         <div class=\"qr\">{svg}</div>\
         <p>Or add this address by hand:</p>{addr_list}\
         <p style=\"margin-top:16px\"><code>{}</code></p>",
        html_escape(uri)
    ))
}

fn link_html_message(msg: &str) -> String {
    link_page_shell(&format!("<h1>Link a wallet</h1><p>{msg}</p>"))
}

/// Minimal HTML-escaping for text embedded in the link page.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn state(AxState(node): AxState<NodeHandle>) -> Json<Value> {
    let info = node.info();
    let s = &info.state;
    Json(json!({
        "height": s.height,
        "tip": hex::encode(s.header_hash),
        "depth": s.depth.to_string(),
        "weight": s.weight().to_string(),
        "target": hex::encode(s.target),
        "timestamp": s.timestamp,
        "state_root": hex::encode(s.state_root()),
        "supply": s.supply,
        "max_supply": midwimble_max_supply(),
        "decimals": 8,
        // The emission schedule's figure for the next block. From the
        // mainnet switch it is a ceiling rather than a promise: a block whose
        // signer is over its per-bond cap mints `cap / n` of it and the rest
        // is burned (`bond::capped_subsidy`), so a reader that wants what a
        // block actually paid takes it from the explorer, which records it
        // per block. `tapering` says whether that rule is live yet.
        "block_reward": crate::core::types::block_reward(s.height),
        "tapering": s.timestamp >= crate::core::bond::EARLY_BONDS_UNTIL,
        "era": s.height / crate::core::types::HALVING_INTERVAL,
        "next_halving_height": next_halving(s.height),
        "utxos": s.utxos.len(),
        "kernels": s.kernels.len(),
        "peer_id": info.peer_id,
        "peers": info.peers,
        "banned": info.banned,
        "listen_addrs": info.listen_addrs,
        "webrtc_addrs": info.webrtc_addrs,
        "webrtc_listen": info.webrtc_listen,
        "syncing": info.syncing,
        "mempool_count": info.mempool_count,
        "mempool_weight": info.mempool_weight,
        "mining": info.mining,
        "hashes": info.hashes,
    }))
}

async fn light(AxState(node): AxState<NodeHandle>, Json(mut body): Json<Value>) -> Json<Value> {
    if let Some(obj) = body.as_object_mut() {
        obj.remove("id");
    }
    let req: crate::network::light_protocol::LightRequest = match serde_json::from_value(body) {
        Ok(r) => r,
        Err(e) => return Json(json!({ "ok": false, "error": format!("bad light request: {e}") })),
    };
    match light_data(&node, req).await {
        Ok(data) => Json(json!({ "ok": true, "data": data })),
        Err(e) => Json(json!({ "ok": false, "error": format!("{e:#}") })),
    }
}

/// Answers the light methods a wallet needs to sync and send over HTTP,
/// reusing the same code as the WebRTC light stream so the shapes match.
async fn light_data(
    node: &NodeHandle,
    req: crate::network::light_protocol::LightRequest,
) -> anyhow::Result<Value> {
    use crate::network::light_protocol::LightRequest as L;
    Ok(match req {
        L::GetState => {
            let info = node.info();
            let s = &info.state;
            json!({
                "height": s.height,
                "tip": hex::encode(s.header_hash),
                "target": hex::encode(s.target),
                "timestamp": s.timestamp,
                "state_root": hex::encode(s.state_root()),
                "supply": s.supply,
                "utxos": s.utxos.len(),
                "syncing": info.syncing,
                "pruned_below": info.finality.pruned_below,
                "webrtc_addrs": info.webrtc_addrs,
            })
        }
        L::SubmitTransaction { tx_hex } => {
            let bytes = hex::decode(tx_hex.trim())?;
            let tx: crate::core::mw::Transaction = bincode::deserialize(&bytes)?;
            node.submit_transaction(tx).await?;
            json!({ "accepted": true })
        }
        L::GetNodes => json!({ "nodes": node.info().webrtc_addrs }),
        // Headers, block(s), scan data, utxos, filters — the storage reads a
        // scan needs, answered exactly as the WebRTC path answers them.
        other => crate::node::light_from_storage(node.storage(), node.state().height, other)?,
    })
}

/// Adds CORS headers (and answers preflight) when the operator turns it on,
/// so a browser wallet on another origin may use this node as a fallback.
async fn cors(
    AxState(origin): AxState<std::sync::Arc<Option<String>>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let allow = match origin.as_ref() {
        Some(o) => o.clone(),
        None => return next.run(request).await,
    };
    let preflight = request.method() == axum::http::Method::OPTIONS;
    let mut resp = if preflight {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(request).await
    };
    let headers = resp.headers_mut();
    let value = axum::http::HeaderValue::from_str(&allow)
        .unwrap_or(axum::http::HeaderValue::from_static("*"));
    headers.insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
    headers.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
        axum::http::HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
        axum::http::HeaderValue::from_static("content-type"),
    );
    resp
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

/// Most transactions one `/mempool/txs` request may ask for.
pub const MAX_RPC_MEMPOOL_TXS: usize = 256;

#[derive(Deserialize)]
struct MempoolTxsBody {
    hashes: Vec<String>,
}

/// Transactions waiting in the mempool, by hash (`/mempool` lists them), as
/// hex-encoded bincode: a wallet scans their outputs to see payments to it
/// before a block confirms them. Any that left the pool are left out.
async fn mempool_txs(
    AxState(node): AxState<NodeHandle>,
    Json(body): Json<MempoolTxsBody>,
) -> ApiResult {
    if body.hashes.len() > MAX_RPC_MEMPOOL_TXS {
        return Err(bad(format!(
            "at most {MAX_RPC_MEMPOOL_TXS} transactions per request"
        )));
    }
    let hashes = body
        .hashes
        .iter()
        .map(|h| hex32_of(h))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let txs = node.mempool_txs(hashes).await.map_err(bad)?;
    let transactions: Vec<Value> = txs
        .iter()
        .map(|tx| {
            Ok(json!({
                "hash": hex::encode(tx.hash()),
                "tx_hex": hex::encode(bincode::serialize(tx)?),
            }))
        })
        .collect::<Result<_>>()
        .map_err(bad)?;
    Ok(Json(json!({ "transactions": transactions })))
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

/// Templates handed to a merged-mining pool, kept by mining hash until the
/// pool asks for a fresh one. A pool refreshes its job whenever either chain's
/// tip moves, so a handful is plenty (`docs/POOL_MERGED_MINING.md`).
static MERGE_JOBS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::VecDeque<([u8; 32], crate::core::template::BlockTemplate)>>,
> = std::sync::OnceLock::new();

fn merge_jobs() -> &'static std::sync::Mutex<
    std::collections::VecDeque<([u8; 32], crate::core::template::BlockTemplate)>,
> {
    MERGE_JOBS.get_or_init(|| std::sync::Mutex::new(std::collections::VecDeque::new()))
}

#[derive(Deserialize)]
struct MergeFoundBody {
    /// The mining hash `/merge/job` returned.
    mining_hash: String,
    /// The midstate batch template the pool mined on.
    batch_template: Value,
    /// Which coinbase output of that template carries the commitment.
    commit_index: usize,
    nonce: u64,
    final_hash: String,
}

/// What a midstate pool must commit to in order to mine midwimble at the same
/// time: the commitment to plant in a coinbase output's salt, and the target a
/// share must beat to be a midwimble block.
async fn merge_job(
    AxState(node): AxState<NodeHandle>,
    Json(body): Json<TemplateBody>,
) -> ApiResult {
    let (template, _) = build_mining_template(&node, body).await?;
    let commitment = crate::core::auxpow::merge_commitment(&template.mining_hash);
    let answer = json!({
        "commitment": hex::encode(commitment),
        "target": hex::encode(template.batch.target),
        "mining_hash": hex::encode(template.mining_hash),
        "height": template.height,
    });
    let mut jobs = merge_jobs().lock().map_err(|e| bad(e.to_string()))?;
    jobs.push_back((template.mining_hash, template));
    while jobs.len() > 16 {
        jobs.pop_front();
    }
    Ok(Json(answer))
}

/// A pool's share cleared midwimble's target: rebuild the parent proof from
/// the midstate template it mined, seal the block and apply it.
async fn merge_found(
    AxState(node): AxState<NodeHandle>,
    Json(body): Json<MergeFoundBody>,
) -> ApiResult {
    let mining_hash = hex32_of(&body.mining_hash)?;
    let final_hash = hex32_of(&body.final_hash)?;
    let template = {
        let jobs = merge_jobs().lock().map_err(|e| bad(e.to_string()))?;
        jobs.iter()
            .find(|(hash, _)| *hash == mining_hash)
            .map(|(_, template)| template.clone())
            .ok_or_else(|| bad("no merged-mining job with that mining hash; ask for a fresh one"))?
    };
    let parent = crate::core::auxpow::ParentTemplate::from_midstate_json(
        &body.batch_template,
        body.commit_index,
    )
    .map_err(bad)?;
    let sealed = template.seal_aux(parent.proof(body.nonce, final_hash));
    let merged = sealed.aux_pow.is_some();
    let height = template.height;
    node.submit_block(sealed).await.map_err(bad)?;
    Ok(Json(
        json!({ "accepted": true, "height": height, "merged_mined": merged }),
    ))
}

fn hex32_of(s: &str) -> std::result::Result<[u8; 32], (StatusCode, Json<Value>)> {
    hex::decode(s)
        .map_err(bad)?
        .try_into()
        .map_err(|_| bad("expected 32 bytes of hex"))
}

#[derive(Deserialize)]
struct TemplateBody {
    payouts: Vec<PayoutWeight>,
    #[serde(default)]
    extra: Option<String>,
}

/// A block template for external miners (pools, merged miners, GPUs).
/// Builds a signed block template for an external miner: pools, merged
/// miners and GPUs all come through here.
async fn build_mining_template(
    node: &NodeHandle,
    body: TemplateBody,
) -> std::result::Result<
    (
        crate::core::template::BlockTemplate,
        Vec<(StealthAddress, crate::core::mw::PayoutReceipt)>,
    ),
    (StatusCode, Json<Value>),
> {
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
    let feed = node.relay_feed();
    let (template, receipts) = tokio::task::spawn_blocking(move || {
        use crate::core::types::{KERNEL_WEIGHT, MAX_BLOCK_WEIGHT, OUTPUT_WEIGHT};
        let feed = feed.read().expect("relay feed lock poisoned");
        let registration_weight = bond
            .as_ref()
            .filter(|b| !state.bonds.contains_key(&b.bond_id))
            .and_then(|b| b.registration.as_ref())
            .map_or(0, |r| r.weight());
        let relay_weight = feed.next_for(&state.relay).map_or(0, |r| r.weight());
        let budget = (MAX_BLOCK_WEIGHT - (payouts.len() as u64) * OUTPUT_WEIGHT - KERNEL_WEIGHT)
            .saturating_sub(registration_weight)
            .saturating_sub(relay_weight);
        let txs = crate::core::template::select_transactions(&pool, state.height, budget);
        let build = |txs: &[crate::core::mw::Transaction]| {
            crate::core::template::build_template_relayed(
                &state,
                &timestamps,
                txs,
                &payouts,
                extra,
                None,
                bond.as_ref(),
                Some(&feed),
            )
        };
        build(&txs).or_else(|_| build(&[]))
    })
    .await
    .map_err(bad)?
    .map_err(bad)?;
    Ok((template, receipts))
}

/// Recent templates by mining hash, newest last.
type TemplateCache =
    std::sync::Mutex<std::collections::VecDeque<([u8; 32], crate::core::template::BlockTemplate)>>;

/// Templates handed out by `/mining/template`, by mining hash, so that
/// `/mining/bind` only ever re-signs a block this node built itself.
static MINING_TEMPLATES: std::sync::OnceLock<TemplateCache> = std::sync::OnceLock::new();

fn mining_templates() -> &'static TemplateCache {
    MINING_TEMPLATES.get_or_init(Default::default)
}

#[derive(Deserialize)]
struct BindBody {
    /// The mining hash `/mining/template` returned.
    mining_hash: String,
    /// One coinbase `extra` per copy wanted.
    extras: Vec<String>,
}

/// Copies of a template from `/mining/template`, one per `extra`, each
/// signed again under the same bond (`template::rebind`). A pool gives each
/// miner its own copy, so a share found by one miner is worthless to any
/// other.
async fn mining_bind(AxState(node): AxState<NodeHandle>, Json(body): Json<BindBody>) -> ApiResult {
    const MAX_EXTRAS: usize = 4_096;
    if body.extras.len() > MAX_EXTRAS {
        return Err(bad(format!("at most {MAX_EXTRAS} copies per request")));
    }
    let mining_hash = hex32_of(&body.mining_hash)?;
    let extras: Vec<[u8; 32]> = body
        .extras
        .iter()
        .map(|e| hex32_of(e))
        .collect::<std::result::Result<_, _>>()?;
    let template = {
        let templates = mining_templates().lock().map_err(|e| bad(e.to_string()))?;
        templates
            .iter()
            .find(|(hash, _)| *hash == mining_hash)
            .map(|(_, template)| template.clone())
            .ok_or_else(|| bad("no template with that mining hash; ask for a fresh one"))?
    };
    let bond = node.mining_bond();
    let variants = tokio::task::spawn_blocking(move || -> Result<Vec<Value>> {
        extras
            .iter()
            .map(|extra| {
                let copy = crate::core::template::rebind(&template, *extra, bond.as_ref())?;
                let miner = match &copy.batch.miner {
                    Some(auth) => Value::String(hex::encode(bincode::serialize(auth)?)),
                    None => Value::Null,
                };
                Ok(json!({
                    "extra": hex::encode(extra),
                    "mining_hash": hex::encode(copy.mining_hash),
                    "miner": miner,
                }))
            })
            .collect()
    })
    .await
    .map_err(bad)?
    .map_err(bad)?;
    Ok(Json(json!({ "variants": variants })))
}

async fn mining_template(
    AxState(node): AxState<NodeHandle>,
    Json(body): Json<TemplateBody>,
) -> ApiResult {
    let (template, receipts) = build_mining_template(&node, body).await?;
    {
        let mut templates = mining_templates().lock().map_err(|e| bad(e.to_string()))?;
        templates.push_back((template.mining_hash, template.clone()));
        while templates.len() > 16 {
            templates.pop_front();
        }
    }
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
        "reward": template.subsidy,
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
        // Not known without the chain: a reassembled template is only ever
        // sealed with a solution, never re-costed, so `height` is a
        // placeholder here too.
        subsidy: 0,
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

    /// The ids of blocks `start..start + count` the node has (fewer past its
    /// tip): what the next block links to (`prev_header_hash`).
    pub fn block_ids(&self, start: u64, count: u64) -> Result<Vec<(u64, [u8; 32])>> {
        let v = self.get(&format!("/headers/{start}/{count}"))?;
        let bytes = hex::decode(
            v["headers_hex"]
                .as_str()
                .ok_or_else(|| anyhow!("bad /headers response"))?,
        )?;
        let headers: Vec<crate::core::BatchHeader> = bincode::deserialize(&bytes)?;
        Ok(headers
            .iter()
            .map(|h| (h.height, h.extension.final_hash))
            .collect())
    }

    /// The hashes of the transactions waiting in the node's mempool.
    pub fn mempool_hashes(&self) -> Result<Vec<String>> {
        let v = self.get("/mempool")?;
        Ok(v["transactions"]
            .as_array()
            .ok_or_else(|| anyhow!("bad /mempool response"))?
            .iter()
            .filter_map(|h| h.as_str().map(str::to_string))
            .collect())
    }

    /// The mempool's transactions with these hashes, those still there. A
    /// node from before `/mempool/txs` fails this with a 404.
    pub fn mempool_txs(&self, hashes: &[String]) -> Result<Vec<Transaction>> {
        let mut txs = Vec::new();
        for chunk in hashes.chunks(MAX_RPC_MEMPOOL_TXS) {
            let v = self.post("/mempool/txs", &json!({ "hashes": chunk }))?;
            for t in v["transactions"]
                .as_array()
                .ok_or_else(|| anyhow!("bad /mempool/txs response"))?
            {
                let bytes = hex::decode(t["tx_hex"].as_str().unwrap_or_default())?;
                txs.push(bincode::deserialize(&bytes)?);
            }
        }
        Ok(txs)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rpc_answers_to_addresses_localhost_and_allowed_names() {
        let none: &[String] = &[];
        for host in [
            "127.0.0.1:9434",
            "127.0.0.1",
            "192.168.1.20:9434",
            "[::1]:9434",
            "[::1]",
            "localhost:9434",
            "LOCALHOST",
            "localhost.",
            "node.localhost:9434",
        ] {
            assert!(host_allowed(host, none), "{host}");
        }
        for host in [
            "evil.example:9434",
            "evil.example",
            "localhost.evil.example",
            "127.0.0.1.evil.example:9434",
            "[not-an-address]:9434",
            "",
            ":9434",
        ] {
            assert!(!host_allowed(host, none), "{host:?}");
        }
        let allowed = vec!["node.internal".to_string()];
        assert!(host_allowed("node.internal:9434", &allowed));
        assert!(host_allowed("NODE.internal", &allowed));
        assert!(!host_allowed("other.internal", &allowed));
        assert!(host_allowed("anything.example", &["*".to_string()]));
    }

    /// A browser that a page has pointed at this machine through its own
    /// domain still names that domain, and is refused; local clients are not.
    #[tokio::test]
    async fn requests_for_other_hosts_are_refused() {
        let app = Router::new().route("/state", get(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(
                std::sync::Arc::new(vec!["node.internal".to_string()]),
                check_host,
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        let status = |host: Option<&'static str>| {
            tokio::task::spawn_blocking(move || {
                use std::io::{Read, Write};
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                let host = host.map_or(String::new(), |h| format!("Host: {h}\r\n"));
                let version = if host.is_empty() { "1.0" } else { "1.1" };
                write!(
                    stream,
                    "GET /state HTTP/{version}\r\n{host}Connection: close\r\n\r\n"
                )
                .unwrap();
                let mut reply = String::new();
                stream.read_to_string(&mut reply).unwrap();
                reply
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .parse::<u16>()
                    .unwrap()
            })
        };
        assert_eq!(status(Some("127.0.0.1:9434")).await.unwrap(), 200);
        assert_eq!(status(Some("localhost:9434")).await.unwrap(), 200);
        assert_eq!(status(Some("node.internal:9434")).await.unwrap(), 200);
        assert_eq!(status(None).await.unwrap(), 200, "HTTP/1.0 without a Host");
        assert_eq!(
            status(Some("rebound.evil.example:9434")).await.unwrap(),
            403
        );
    }
}
