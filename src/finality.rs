//! Finalized checkpoints (`docs/PRUNING.md` §3).
//!
//! An anchor proves a checkpoint was *published* in Midstate, not that it is
//! valid: anyone can post a Commit. A checkpoint `C` at height `h` is
//! finalized for this node when:
//!
//! 1. its Midstate evidence verifies with at least `anchor_depth` blocks;
//! 2. it describes this node's own chain (header, state root, cumulative
//!    work) and the tip is at least `finality_depth` blocks past it;
//! 3. no *conflicting* anchored checkpoint is known at or below `h`, meaning
//!    one whose header differs from this chain at its height.
//!
//! A conflict means someone out-mined an anchored chain by more than
//! `finality_depth` blocks. The node then refuses to finalize past it and
//! logs the event rather than guessing.
//!
//! Verifying evidence costs a full proof-of-work extension per Midstate
//! header, so the tracker never does it on the caller's thread unless asked
//! to ([`FinalityTracker::add`]): the node verifies off its event loop and
//! hands over finished records ([`FinalityTracker::insert_verified`]). The
//! set of records is bounded ([`MAX_RECORDS`]); records below the finalized
//! floor are dropped unless they are retained checkpoints.

use crate::anchor::AnchorRecord;
use crate::core::state::calculate_work;
use crate::core::State;
use crate::storage::{FinalityInfo, Storage};
use anyhow::Result;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

/// Most anchor records a node keeps. Honest anchors arrive at most once a
/// block (merged-mined ones), and only those above the floor matter.
pub const MAX_RECORDS: usize = 256;

#[derive(Clone, Debug)]
pub struct FinalityConfig {
    /// Midstate blocks (the anchor block included) required: 1,000, the life
    /// of a midstate commitment, about 17 hours. Forging an anchor means
    /// mining that many headers privately.
    pub anchor_depth: usize,
    /// Midwimble blocks required after the checkpoint.
    ///
    /// This is a reorg floor, not advice, so it must be the same for
    /// everyone: nodes that finalise at different depths disagree about which
    /// reorgs are legal. `core/finality.rs`'s estimator works from each node's
    /// own observations and is deliberately not used here; it is for telling a
    /// wallet how many confirmations to wait for.
    pub finality_depth: u64,
    /// Minimum work per midstate header in anchor evidence, as a target
    /// threshold. Default 2^19 attempts a header: with 1,000 headers, forging
    /// evidence costs on the order of an hour of midstate's whole network,
    /// while leaving room for midstate's difficulty to fall eightfold. A
    /// tighter floor near today's difficulty would start rejecting honest
    /// anchors after a halving; the durable fix is to count cumulative work
    /// against midwimble's own target, as bond registrations do.
    pub min_work: u128,
    /// Finalized checkpoints whose past state stays derivable (undo window).
    pub retained_checkpoints: usize,
    /// Delete block bodies below the floor.
    pub prune: bool,
}

impl Default for FinalityConfig {
    fn default() -> Self {
        Self {
            anchor_depth: 1_000,
            finality_depth: 100,
            min_work: 1 << 19,
            retained_checkpoints: 4,
            prune: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// Matches this chain and is deep enough.
    Final,
    /// Matches this chain but is not deep enough yet.
    Pending,
    /// Contradicts this chain.
    Conflict,
    /// Beyond this node's tip.
    Ahead,
}

/// Why a record was not accepted.
#[derive(Debug)]
pub enum RecordFault {
    /// Weaker than this node's policy asks (too few confirmations, too little
    /// work a header), or for another network. Another node may accept it,
    /// so whoever sent it is not at fault.
    Policy(anyhow::Error),
    /// The evidence is forged: its proofs of work or its fold do not hold.
    Invalid(anyhow::Error),
}

impl std::fmt::Display for RecordFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordFault::Policy(e) => write!(f, "{e:#}"),
            RecordFault::Invalid(e) => write!(f, "invalid evidence: {e:#}"),
        }
    }
}

/// The cheap checks on a record: the stored id is the checkpoint's, it is
/// for this network, and its evidence meets `cfg`'s policy. Trims the
/// evidence to what the policy needs. Never hashes a proof-of-work chain.
pub fn precheck(record: &mut AnchorRecord, cfg: &FinalityConfig) -> Result<(), RecordFault> {
    if record.checkpoint.network != crate::core::types::network_anchor() {
        return Err(RecordFault::Policy(anyhow::anyhow!(
            "anchor for another network"
        )));
    }
    if hex::encode(record.checkpoint.id()) != record.checkpoint_id {
        return Err(RecordFault::Invalid(anyhow::anyhow!(
            "stored id does not match the checkpoint"
        )));
    }
    let Some(evidence) = record.evidence.as_mut() else {
        return Err(RecordFault::Policy(anyhow::anyhow!("no Midstate evidence")));
    };
    evidence
        .check_policy(cfg.anchor_depth, cfg.min_work)
        .map_err(RecordFault::Policy)?;
    evidence.trim(cfg.anchor_depth);
    Ok(())
}

/// The expensive check, for a record that passed [`precheck`]: every proof
/// of work in its evidence that `checked` has not seen verified before. Run
/// it off any event loop.
pub fn verify_evidence(
    record: &AnchorRecord,
    cfg: &FinalityConfig,
    checked: &CheckedLinks,
) -> Result<(), RecordFault> {
    let keys = record
        .verify_standalone_with(cfg.anchor_depth, cfg.min_work, |k| checked.contains(k))
        .map_err(RecordFault::Invalid)?;
    checked.insert_all(keys);
    Ok(())
}

/// Most Midstate headers [`CheckedLinks`] remembers: a few records' worth.
pub const CHECKED_LINKS: usize = 16_384;

/// Midstate headers whose proof of work this node has verified as part of
/// accepted evidence. Anchors made close together share nearly all their
/// confirmations, so each further record costs only its new headers.
#[derive(Clone, Default)]
pub struct CheckedLinks(Arc<Mutex<LinkSet>>);

#[derive(Default)]
struct LinkSet {
    keys: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

impl CheckedLinks {
    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.0.lock().map_or(false, |set| set.keys.contains(key))
    }

    fn insert_all(&self, keys: Vec<[u8; 32]>) {
        let Ok(mut set) = self.0.lock() else { return };
        for key in keys {
            if set.keys.insert(key) {
                set.order.push_back(key);
            }
        }
        while set.order.len() > CHECKED_LINKS {
            if let Some(old) = set.order.pop_front() {
                set.keys.remove(&old);
            }
        }
    }
}

#[derive(Default)]
pub struct FinalityTracker {
    pub cfg: FinalityConfig,
    /// Verified records by checkpoint id.
    records: BTreeMap<[u8; 32], AnchorRecord>,
    /// Heights of checkpoints this node has finalized, oldest first.
    finalized: Vec<(u64, [u8; 32])>,
    floor: u64,
    /// The chain height at the last refresh, for choosing what to evict.
    tip: u64,
}

impl FinalityTracker {
    pub fn new(cfg: FinalityConfig, info: &FinalityInfo) -> Self {
        let finalized = info
            .checkpoint_id
            .map(|id| vec![(info.floor, id)])
            .unwrap_or_default();
        Self {
            cfg,
            records: BTreeMap::new(),
            finalized,
            floor: info.floor,
            tip: info.floor,
        }
    }

    pub fn floor(&self) -> u64 {
        self.floor
    }

    pub fn get(&self, id: &[u8; 32]) -> Option<&AnchorRecord> {
        self.records.get(id)
    }

    pub fn knows(&self, id: &[u8; 32]) -> bool {
        self.records.contains_key(id)
    }

    /// How many records are held.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Newest first, at most `limit`.
    pub fn records(&self, limit: usize) -> Vec<AnchorRecord> {
        let mut all: Vec<&AnchorRecord> = self.records.values().collect();
        all.sort_by(|a, b| b.checkpoint.mw_height.cmp(&a.checkpoint.mw_height));
        all.into_iter().take(limit).cloned().collect()
    }

    /// Newest first, at most `limit` and at most `max_bytes` serialized, so a
    /// reply carrying them always fits a network message.
    pub fn records_within(&self, limit: usize, max_bytes: usize) -> Vec<AnchorRecord> {
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for record in self.records(limit) {
            let size = bincode::serialized_size(&record).unwrap_or(u64::MAX) as usize;
            if bytes.saturating_add(size) > max_bytes {
                break;
            }
            bytes += size;
            out.push(record);
        }
        out
    }

    /// Verifies a record on the caller's thread, then keeps it. Returns
    /// whether it was new. The node does not use this (verification costs an
    /// extension per Midstate header); tools and tests may.
    pub fn add(&mut self, mut record: AnchorRecord) -> Result<bool> {
        let id = record.checkpoint.id();
        if self.records.contains_key(&id) {
            return Ok(false);
        }
        precheck(&mut record, &self.cfg).map_err(|e| anyhow::anyhow!("{e}"))?;
        verify_evidence(&record, &self.cfg, &CheckedLinks::default())
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(self.insert_verified(record))
    }

    /// Keeps a record whose evidence the caller verified ([`precheck`] and
    /// [`verify_evidence`]). Returns whether it was kept as a new record.
    pub fn insert_verified(&mut self, record: AnchorRecord) -> bool {
        let id = record.checkpoint.id();
        if self.records.contains_key(&id) {
            return false;
        }
        self.records.insert(id, record);
        self.evict();
        self.records.contains_key(&id)
    }

    /// Past [`MAX_RECORDS`], drops the records least likely to matter:
    /// first those furthest beyond the tip (anyone can anchor a checkpoint
    /// for a height that does not exist yet), then the lowest. Retained
    /// finalized checkpoints are never dropped.
    fn evict(&mut self) {
        if self.records.len() <= MAX_RECORDS {
            return;
        }
        let tip = self.tip;
        let keep: HashSet<[u8; 32]> = self.finalized.iter().map(|(_, id)| *id).collect();
        let mut order: Vec<(bool, u64, [u8; 32])> = self
            .records
            .iter()
            .filter(|(id, _)| !keep.contains(*id))
            .map(|(id, r)| {
                let h = r.checkpoint.mw_height;
                // Beyond the tip: highest first. Otherwise: lowest first.
                if h > tip {
                    (false, u64::MAX - h, *id)
                } else {
                    (true, h, *id)
                }
            })
            .collect();
        order.sort();
        let excess = self.records.len() - MAX_RECORDS;
        for (_, _, id) in order.into_iter().take(excess) {
            self.records.remove(&id);
        }
    }

    /// How a checkpoint relates to this node's chain.
    pub fn standing(
        &self,
        record: &AnchorRecord,
        storage: &Storage,
        state: &State,
    ) -> Result<Standing> {
        let cp = &record.checkpoint;
        let h = cp.mw_height;
        if h == 0 || h > state.height {
            return Ok(Standing::Ahead);
        }
        let Some(ours) = storage.load_header(h - 1)? else {
            // Below a snapshot base: only the base checkpoint itself is known.
            return Ok(if storage.base()?.map_or(false, |b| b.checkpoint == *cp) {
                Standing::Final
            } else {
                Standing::Ahead
            });
        };
        if ours.extension.final_hash != cp.mw_header_hash || ours.state_root != cp.mw_state_root {
            return Ok(Standing::Conflict);
        }
        let work = match storage.depth_after(h - 1)? {
            Some(work) => work,
            // A database from before the cumulative-work table: sum the
            // headers since (slow, and only until the table fills in).
            None => {
                let after = storage.load_headers(h, state.height - h)?;
                if after.len() as u64 != state.height - h {
                    return Ok(Standing::Pending);
                }
                let work_after = after.iter().fold(0u128, |acc, x| {
                    acc.saturating_add(calculate_work(&x.target))
                });
                match state.depth.checked_sub(work_after) {
                    Some(w) => w,
                    None => return Ok(Standing::Conflict),
                }
            }
        };
        if work != cp.mw_cumulative_work {
            return Ok(Standing::Conflict);
        }
        Ok(if state.height - h >= self.cfg.finality_depth {
            Standing::Final
        } else {
            Standing::Pending
        })
    }

    /// Recomputes the floor. Returns the new bookkeeping if it rose.
    ///
    /// Also forgets records that can no longer matter: those at or below the
    /// floor that agree with this chain, except the retained checkpoints.
    /// Conflicting ones are kept, since they are what stops finalization.
    pub fn refresh(&mut self, storage: &Storage, state: &State) -> Result<Option<FinalityInfo>> {
        self.tip = state.height;
        let mut standings = Vec::with_capacity(self.records.len());
        for (id, record) in &self.records {
            standings.push((
                *id,
                record.checkpoint.mw_height,
                self.standing(record, storage, state)?,
            ));
        }
        let floor = self.floor;
        let keep: HashSet<[u8; 32]> = self.finalized.iter().map(|(_, id)| *id).collect();
        let stale: HashSet<[u8; 32]> = standings
            .iter()
            .filter(|(id, h, s)| *h <= floor && *s != Standing::Conflict && !keep.contains(id))
            .map(|(id, _, _)| *id)
            .collect();
        if !stale.is_empty() {
            self.records.retain(|id, _| !stale.contains(id));
            standings.retain(|(id, _, _)| !stale.contains(id));
        }
        let lowest_conflict = standings
            .iter()
            .filter(|(_, _, s)| *s == Standing::Conflict)
            .map(|(_, h, _)| *h)
            .min()
            .unwrap_or(u64::MAX);
        if lowest_conflict != u64::MAX {
            tracing::warn!("an anchored checkpoint at height {} contradicts this chain; not finalizing past it", lowest_conflict);
        }
        let candidates: Vec<(u64, [u8; 32])> = standings
            .iter()
            .filter(|(_, h, s)| *s == Standing::Final && *h < lowest_conflict)
            .map(|(id, h, _)| (*h, *id))
            .collect();
        let Some(&(height, id)) = candidates.iter().max_by_key(|(h, _)| *h) else {
            return Ok(None);
        };
        if height <= self.floor {
            return Ok(None);
        }
        self.floor = height;
        self.finalized.push((height, id));
        self.finalized.sort();
        self.finalized.dedup();
        let keep = self.cfg.retained_checkpoints.max(1);
        if self.finalized.len() > keep {
            let drop = self.finalized.len() - keep;
            self.finalized.drain(..drop);
        }
        let retain_from = self
            .finalized
            .iter()
            .map(|(h, _)| *h)
            .min()
            .unwrap_or(height);
        let mut info = storage.finality()?;
        info.floor = height;
        info.checkpoint_id = Some(id);
        info.retain_from = retain_from;
        Ok(Some(info))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::anchor::{AnchoredItem, Checkpoint, HeaderLink, MidstateInclusion};

    fn record(height: u64, confirmations: usize) -> AnchorRecord {
        let checkpoint = Checkpoint {
            version: crate::core::anchor::CHECKPOINT_VERSION,
            network: crate::core::types::network_anchor(),
            mw_height: height,
            mw_header_hash: crate::core::types::hash(&height.to_le_bytes()),
            mw_state_root: [0; 32],
            mw_cumulative_work: 0,
            previous_checkpoint: [0; 32],
        };
        let link = HeaderLink {
            post_tx_midstate: [0; 32],
            state_root: [0; 32],
            timestamp: 0,
            target: [0xff; 32],
            nonce: 0,
            final_hash: [0; 32],
        };
        AnchorRecord {
            checkpoint_id: hex::encode(checkpoint.id()),
            checkpoint,
            posted_at_midstate_height: 0,
            evidence: Some(MidstateInclusion {
                midstate_height: 0,
                kind: AnchoredItem::Commit,
                pre_item_midstate: [0; 32],
                items_after: vec![],
                prev_header_hash: [0; 32],
                block: link.clone(),
                confirmations: vec![link; confirmations],
            }),
            mw_header: None,
        }
    }

    fn cfg(depth: usize) -> FinalityConfig {
        FinalityConfig {
            anchor_depth: depth,
            min_work: 1,
            ..FinalityConfig::default()
        }
    }

    /// The cheap gate tells weak evidence from forged evidence, trims what it
    /// keeps, and hashes nothing.
    #[test]
    fn precheck_sorts_policy_from_forgery_and_trims() {
        let mut short = record(5, 1);
        assert!(matches!(
            precheck(&mut short, &cfg(3)),
            Err(RecordFault::Policy(_))
        ));
        let mut wrong_id = record(5, 4);
        wrong_id.checkpoint_id = hex::encode([7u8; 32]);
        assert!(matches!(
            precheck(&mut wrong_id, &cfg(3)),
            Err(RecordFault::Invalid(_))
        ));
        let mut long = record(5, 9);
        precheck(&mut long, &cfg(3)).unwrap();
        assert_eq!(long.evidence.unwrap().confirmations.len(), 2);
        // The made-up headers fail the expensive check as forgery, and are
        // not remembered as checked.
        let mut forged = record(5, 2);
        precheck(&mut forged, &cfg(3)).unwrap();
        let checked = CheckedLinks::default();
        assert!(matches!(
            verify_evidence(&forged, &cfg(3), &checked),
            Err(RecordFault::Invalid(_))
        ));
        assert!(checked.0.lock().unwrap().keys.is_empty());
    }

    #[test]
    fn checked_links_are_bounded() {
        let checked = CheckedLinks::default();
        let keys: Vec<[u8; 32]> = (0..CHECKED_LINKS as u64 + 10)
            .map(|i| crate::core::types::hash(&i.to_le_bytes()))
            .collect();
        checked.insert_all(keys.clone());
        checked.insert_all(keys[keys.len() - 5..].to_vec());
        assert_eq!(checked.0.lock().unwrap().keys.len(), CHECKED_LINKS);
        assert!(!checked.contains(&keys[0]));
        assert!(checked.contains(&keys[keys.len() - 1]));
    }

    #[test]
    fn records_are_bounded_and_replies_fit() {
        let n = MAX_RECORDS as u64 + 40;
        // Below the tip, the lowest go first.
        let mut t = FinalityTracker::new(cfg(1), &FinalityInfo::default());
        t.tip = 10_000;
        for h in 1..=n {
            assert!(t.insert_verified(record(h, 0)));
        }
        assert!(!t.insert_verified(record(n, 0)), "already known");
        assert_eq!(t.len(), MAX_RECORDS);
        assert!(t.knows(&record(n, 0).checkpoint.id()));
        assert!(!t.knows(&record(40, 0).checkpoint.id()));
        let heights: Vec<u64> = t
            .records(3)
            .iter()
            .map(|r| r.checkpoint.mw_height)
            .collect();
        assert_eq!(heights, vec![n, n - 1, n - 2]);
        let one = bincode::serialized_size(&record(1, 0)).unwrap() as usize;
        assert_eq!(t.records_within(64, one * 5 + one / 2).len(), 5);

        // Checkpoints for heights that do not exist yet cannot push out the
        // ones that do: the furthest ahead go first.
        let mut t = FinalityTracker::new(cfg(1), &FinalityInfo::default());
        t.tip = 100;
        for h in 1..=100 {
            t.insert_verified(record(h, 0));
        }
        for h in 0..MAX_RECORDS as u64 {
            t.insert_verified(record(1_000_000 + h, 0));
        }
        assert_eq!(t.len(), MAX_RECORDS);
        assert!((1..=100).all(|h| t.knows(&record(h, 0).checkpoint.id())));
        assert!(t.knows(&record(1_000_000, 0).checkpoint.id()));
        assert!(!t.knows(
            &record(1_000_000 + MAX_RECORDS as u64 - 1, 0)
                .checkpoint
                .id()
        ));
    }
}
