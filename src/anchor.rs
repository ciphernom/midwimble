//! Anchoring Midwimble checkpoints in Midstate (`docs/ANCHORING.md` §4).
//!
//! Works against an unmodified Midstate node over its RPC:
//! `GET /state`, `GET /batch/{h}` and `POST /commit`. The Midwimble side is
//! read over this crate's own RPC (`/state`, `/headers`), so the anchoring
//! tool can run beside a live node.

use crate::core::anchor::{AnchoredItem, Checkpoint, MidstateInclusion};
use crate::core::auxpow::bytes32;
use crate::core::state::calculate_work;
use crate::core::types::{compute_header_hash, count_leading_zeros, hash, BatchHeader};
use crate::rpc::RpcClient;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::Path;

/// Midstate's minimum commit proof of work (its `MIN_COMMIT_POW_BITS`).
#[cfg(not(feature = "fast-mining"))]
pub const MIDSTATE_MIN_COMMIT_BITS: u32 = 24;
#[cfg(feature = "fast-mining")]
pub const MIDSTATE_MIN_COMMIT_BITS: u32 = 16;

/// A checkpoint and, once found, the evidence that Midstate recorded it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnchorRecord {
    pub checkpoint: Checkpoint,
    pub checkpoint_id: String,
    pub posted_at_midstate_height: u64,
    pub evidence: Option<MidstateInclusion>,
    /// The checkpointed Midwimble header. Needed to check merged-mining
    /// evidence (whose payload is this header's mining hash) without having
    /// the header locally, e.g. on a competing fork.
    #[serde(default)]
    pub mw_header: Option<BatchHeader>,
}

impl AnchorRecord {
    /// Verifies the record on its own: the checkpoint id, the header (if
    /// carried) and the Midstate evidence.
    pub fn verify_standalone(&self, depth: usize, min_work: u128) -> Result<()> {
        let id = self.checkpoint.id();
        if hex::encode(id) != self.checkpoint_id {
            bail!("stored id does not match the checkpoint");
        }
        let evidence = self
            .evidence
            .as_ref()
            .ok_or_else(|| anyhow!("no Midstate evidence"))?;
        let payload = match (&evidence.kind, &self.mw_header) {
            (AnchoredItem::Commit, _) => id,
            (AnchoredItem::MergeMined { .. }, Some(h)) => {
                if h.height + 1 != self.checkpoint.mw_height
                    || h.extension.final_hash != self.checkpoint.mw_header_hash
                    || h.state_root != self.checkpoint.mw_state_root
                {
                    bail!("carried header does not match the checkpoint");
                }
                compute_header_hash(h)
            }
            (AnchoredItem::MergeMined { .. }, None) => {
                bail!("merged-mining record without its header")
            }
        };
        evidence.verify(&payload, depth, min_work)
    }
}

/// Headers `start..end` from a Midwimble node.
fn headers_range(mw: &RpcClient, start: u64, end: u64) -> Result<Vec<BatchHeader>> {
    let mut out = Vec::with_capacity(end.saturating_sub(start) as usize);
    while start + (out.len() as u64) < end {
        let from = start + out.len() as u64;
        let v = mw.get(&format!("/headers/{}/{}", from, (end - from).min(5000)))?;
        let chunk: Vec<BatchHeader> =
            bincode::deserialize(&hex::decode(v["headers_hex"].as_str().unwrap_or_default())?)?;
        if chunk.is_empty() {
            bail!("node has no header at {from}");
        }
        out.extend(chunk);
    }
    Ok(out)
}

/// The checkpoint for `height` blocks of a node's chain. Cumulative work is
/// the tip's minus the blocks after `height`, so only recent headers are read.
pub fn checkpoint_at(mw: &RpcClient, height: u64, previous: [u8; 32]) -> Result<Checkpoint> {
    Ok(checkpoint_with_header(mw, height, previous)?.0)
}

fn checkpoint_with_header(
    mw: &RpcClient,
    height: u64,
    previous: [u8; 32],
) -> Result<(Checkpoint, BatchHeader)> {
    let state = mw.get("/state")?;
    let tip = state["height"]
        .as_u64()
        .ok_or_else(|| anyhow!("bad /state"))?;
    let depth: u128 = state["depth"]
        .as_str()
        .and_then(|d| d.parse().ok())
        .ok_or_else(|| anyhow!("bad /state depth"))?;
    if height == 0 || height > tip {
        bail!("no checkpoint at height {height} (tip {tip})");
    }
    let headers = headers_range(mw, height - 1, tip)?;
    let after: u128 = headers[1..].iter().fold(0u128, |acc, h| {
        acc.saturating_add(calculate_work(&h.target))
    });
    let work = depth
        .checked_sub(after)
        .ok_or_else(|| anyhow!("inconsistent work (chain moved?)"))?;
    Ok((
        Checkpoint::new(&headers[0], work, previous),
        headers[0].clone(),
    ))
}

/// A checkpoint `lag` blocks below the tip (so a short reorg cannot orphan
/// it), chained to `previous`.
pub fn make_checkpoint(mw: &RpcClient, lag: u64, previous: [u8; 32]) -> Result<Checkpoint> {
    let tip = mw.get("/state")?["height"]
        .as_u64()
        .ok_or_else(|| anyhow!("bad /state"))?;
    checkpoint_at(mw, tip.saturating_sub(lag).max(1), previous)
}

/// Checks a checkpoint against a Midwimble node's chain.
pub fn checkpoint_matches_chain(mw: &RpcClient, checkpoint: &Checkpoint) -> Result<()> {
    let ours = checkpoint_at(mw, checkpoint.mw_height, checkpoint.previous_checkpoint)?;
    if &ours != checkpoint {
        bail!(
            "checkpoint does not describe this chain at height {}",
            checkpoint.mw_height
        );
    }
    Ok(())
}

/// The 32 bytes a record's evidence must anchor: the checkpoint id for
/// Commit anchors, the Midwimble block's mining hash for merged-mined ones.
fn anchored_payload(
    mw: &RpcClient,
    record: &AnchorRecord,
    evidence: &MidstateInclusion,
) -> Result<[u8; 32]> {
    match evidence.kind {
        AnchoredItem::Commit => Ok(record.checkpoint.id()),
        AnchoredItem::MergeMined { .. } => {
            let h = record.checkpoint.mw_height - 1;
            let header = headers_range(mw, h, h + 1)?
                .pop()
                .ok_or_else(|| anyhow!("no header at {h}"))?;
            Ok(compute_header_hash(&header))
        }
    }
}

/// A merged-mined Midwimble block whose Midstate parent was accepted: it is
/// anchored already and only needs confirmations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingMergedAnchor {
    pub midstate_height: u64,
    pub midstate_final_hash: [u8; 32],
    pub mw_height: u64,
    pub mw_block_id: [u8; 32],
    pub mw_mining_hash: [u8; 32],
    pub commit_address: [u8; 32],
    pub commit_value: u64,
}

/// Turns pending merged-mining anchors into stored records once `depth`
/// Midstate blocks exist. Anchors whose blocks were reorganised away on
/// either chain are dropped. Returns how many records were written.
pub fn collect_merged_anchors(
    mw: &RpcClient,
    ms: &RpcClient,
    store: &Path,
    pending: &mut Vec<PendingMergedAnchor>,
    depth: usize,
    min_work: u128,
) -> Result<usize> {
    let tip = ms.get("/state")?["height"]
        .as_u64()
        .ok_or_else(|| anyhow!("bad midstate /state"))?;
    let mut written = 0;
    let mut keep = Vec::new();
    for p in pending.drain(..) {
        let needed = depth.saturating_sub(1) as u64;
        if p.midstate_height + needed >= tip {
            keep.push(p);
            continue;
        }
        let result = (|| -> Result<AnchorRecord> {
            let block = ms.get(&format!("/batch/{}", p.midstate_height))?;
            if bytes32(&block["extension"]["final_hash"])? != p.midstate_final_hash {
                bail!("midstate block was reorganised away");
            }
            let following: Vec<Value> = (p.midstate_height + 1..=p.midstate_height + needed)
                .map(|k| ms.get(&format!("/batch/{k}")))
                .collect::<Result<_>>()?;
            let kind = AnchoredItem::MergeMined {
                address: p.commit_address,
                value: p.commit_value,
            };
            let evidence = MidstateInclusion::from_midstate_json(
                p.midstate_height,
                &block,
                kind,
                &p.mw_mining_hash,
                &following,
            )?;
            evidence.verify(&p.mw_mining_hash, depth, min_work)?;
            let previous = load_records(store)?
                .last()
                .map(|r| r.checkpoint.id())
                .unwrap_or([0u8; 32]);
            let (checkpoint, header) = checkpoint_with_header(mw, p.mw_height + 1, previous)?;
            if checkpoint.mw_header_hash != p.mw_block_id {
                bail!("midwimble block was reorganised away");
            }
            Ok(AnchorRecord {
                checkpoint_id: hex::encode(checkpoint.id()),
                checkpoint,
                posted_at_midstate_height: p.midstate_height,
                evidence: Some(evidence),
                mw_header: Some(header),
            })
        })();
        match result {
            Ok(record) => {
                append_record(store, &record)?;
                written += 1;
            }
            Err(e) => tracing::warn!(
                "dropping merged-mining anchor at midstate height {}: {e:#}",
                p.midstate_height
            ),
        }
    }
    *pending = keep;
    Ok(written)
}

/// Midstate's commit proof of work: `H(anchor_block_hash ‖ commitment ‖ nonce_le32)`
/// with at least `bits` leading zero bits.
pub fn mine_commit_nonce(
    anchor_block_hash: &[u8; 32],
    commitment: &[u8; 32],
    bits: u32,
) -> Result<u32> {
    let mut data = [0u8; 68];
    data[..32].copy_from_slice(anchor_block_hash);
    data[32..64].copy_from_slice(commitment);
    for nonce in 0..=u32::MAX {
        data[64..].copy_from_slice(&nonce.to_le_bytes());
        if count_leading_zeros(&hash(&data)) >= bits {
            return Ok(nonce);
        }
    }
    bail!("no commit nonce found")
}

/// Posts `commitment` as a Midstate Commit transaction. Returns Midstate's
/// height at posting time (the search for inclusion starts there).
pub fn post_commit(ms: &RpcClient, commitment: &[u8; 32]) -> Result<u64> {
    let height = ms.get("/state")?["height"]
        .as_u64()
        .ok_or_else(|| anyhow!("bad midstate /state"))?;
    if height < 2 {
        bail!("midstate chain too short to anchor a commit proof of work");
    }
    let anchor_height = height - 1;
    let anchor_block = ms.get(&format!("/batch/{anchor_height}"))?;
    let anchor_hash = bytes32(&anchor_block["extension"]["final_hash"])?;
    let mut bits = MIDSTATE_MIN_COMMIT_BITS;
    for _ in 0..4 {
        let nonce = mine_commit_nonce(&anchor_hash, commitment, bits)?;
        let spam_nonce = (anchor_height << 32) | nonce as u64;
        let (status, body) = ms.post_raw(
            "/commit",
            &json!({ "commitment": hex::encode(commitment), "spam_nonce": spam_nonce }),
        )?;
        if (200..300).contains(&status) {
            return Ok(height);
        }
        // "Insufficient PoW: need N leading zeros, got M": mine harder.
        let msg = body["error"].as_str().unwrap_or_default().to_string();
        match msg
            .split("need ")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|n| n.parse::<u32>().ok())
        {
            Some(need) if need > bits => bits = need,
            _ => bail!("midstate refused the commit: {msg}"),
        }
    }
    bail!("midstate kept raising the commit difficulty")
}

/// Looks for a Commit carrying `commitment` in Midstate blocks from
/// `from_height`, returning evidence once `depth` blocks (the anchor block
/// included) exist.
pub fn find_commit(
    ms: &RpcClient,
    commitment: &[u8; 32],
    from_height: u64,
    depth: usize,
) -> Result<Option<MidstateInclusion>> {
    let tip = ms.get("/state")?["height"]
        .as_u64()
        .ok_or_else(|| anyhow!("bad midstate /state"))?;
    for h in from_height.saturating_sub(1)..tip {
        let block = ms.get(&format!("/batch/{h}"))?;
        let found = block["transactions"]
            .as_array()
            .map(|txs| {
                txs.iter()
                    .filter_map(|t| t.get("Commit"))
                    .any(|c| bytes32(&c["commitment"]).map_or(false, |x| &x == commitment))
            })
            .unwrap_or(false);
        if !found {
            continue;
        }
        let needed = depth.saturating_sub(1) as u64;
        if h + needed >= tip {
            return Ok(None); // present, not yet deep enough
        }
        let following: Vec<Value> = (h + 1..=h + needed)
            .map(|k| ms.get(&format!("/batch/{k}")))
            .collect::<Result<_>>()?;
        let evidence = MidstateInclusion::from_midstate_json(
            h,
            &block,
            AnchoredItem::Commit,
            commitment,
            &following,
        )?;
        return Ok(Some(evidence));
    }
    Ok(None)
}

pub fn load_records(path: &Path) -> Result<Vec<AnchorRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = std::fs::File::open(path)?;
    std::io::BufReader::new(file)
        .lines()
        .filter(|l| l.as_ref().map_or(true, |s| !s.trim().is_empty()))
        .map(|l| Ok(serde_json::from_str(&l?)?))
        .collect()
}

pub fn append_record(path: &Path, record: &AnchorRecord) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    writeln!(f, "{}", serde_json::to_string(record)?)?;
    Ok(())
}

/// One full anchoring round: checkpoint, post, wait for `depth`, record.
pub fn anchor_once(
    mw: &RpcClient,
    ms: &RpcClient,
    store: &Path,
    lag: u64,
    depth: usize,
    min_work: u128,
    timeout: std::time::Duration,
) -> Result<AnchorRecord> {
    let previous = load_records(store)?
        .iter()
        .rev()
        .find(|r| r.evidence.is_some())
        .map(|r| r.checkpoint.id())
        .unwrap_or([0u8; 32]);
    let tip = mw.get("/state")?["height"]
        .as_u64()
        .ok_or_else(|| anyhow!("bad /state"))?;
    let (checkpoint, header) =
        checkpoint_with_header(mw, tip.saturating_sub(lag).max(1), previous)?;
    let id = checkpoint.id();
    let posted = post_commit(ms, &id)?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(evidence) = find_commit(ms, &id, posted, depth)? {
            evidence.verify(&id, depth, min_work)?;
            let record = AnchorRecord {
                checkpoint,
                checkpoint_id: hex::encode(id),
                posted_at_midstate_height: posted,
                evidence: Some(evidence),
                mw_header: Some(header),
            };
            append_record(store, &record)?;
            return Ok(record);
        }
        if std::time::Instant::now() > deadline {
            bail!(
                "checkpoint {} not anchored with depth {} before the timeout",
                hex::encode(id),
                depth
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

/// Verifies every stored record against Midstate evidence and the local chain.
pub fn verify_records(
    mw: &RpcClient,
    store: &Path,
    depth: usize,
    min_work: u128,
) -> Result<Vec<(String, Result<()>)>> {
    let mut out = Vec::new();
    for r in load_records(store)? {
        let id = r.checkpoint.id();
        let result = (|| -> Result<()> {
            if hex::encode(id) != r.checkpoint_id {
                bail!("stored id does not match the checkpoint");
            }
            let evidence = r
                .evidence
                .as_ref()
                .ok_or_else(|| anyhow!("no Midstate evidence yet"))?;
            checkpoint_matches_chain(mw, &r.checkpoint)?;
            evidence.verify(&anchored_payload(mw, &r, evidence)?, depth, min_work)
        })();
        out.push((r.checkpoint_id.clone(), result));
    }
    Ok(out)
}
