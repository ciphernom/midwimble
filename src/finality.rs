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

use crate::anchor::AnchorRecord;
use crate::core::state::calculate_work;
use crate::core::State;
use crate::storage::{FinalityInfo, Storage};
use anyhow::Result;
use std::collections::BTreeMap;

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

#[derive(Default)]
pub struct FinalityTracker {
    pub cfg: FinalityConfig,
    /// Verified records by checkpoint id.
    records: BTreeMap<[u8; 32], AnchorRecord>,
    /// Heights of checkpoints this node has finalized, oldest first.
    finalized: Vec<(u64, [u8; 32])>,
    floor: u64,
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
        }
    }

    pub fn floor(&self) -> u64 {
        self.floor
    }

    pub fn get(&self, id: &[u8; 32]) -> Option<&AnchorRecord> {
        self.records.get(id)
    }

    /// Newest first, at most `limit`.
    pub fn records(&self, limit: usize) -> Vec<AnchorRecord> {
        let mut all: Vec<&AnchorRecord> = self.records.values().collect();
        all.sort_by(|a, b| b.checkpoint.mw_height.cmp(&a.checkpoint.mw_height));
        all.into_iter().take(limit).cloned().collect()
    }

    /// Adds a record after verifying it standalone. Returns whether it was new.
    pub fn add(&mut self, record: AnchorRecord) -> Result<bool> {
        let id = record.checkpoint.id();
        if self.records.contains_key(&id) {
            return Ok(false);
        }
        record.verify_standalone(self.cfg.anchor_depth, self.cfg.min_work)?;
        if record.checkpoint.network != crate::core::types::network_anchor() {
            anyhow::bail!("anchor for another network");
        }
        self.records.insert(id, record);
        Ok(true)
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
        let after = storage.load_headers(h, state.height - h)?;
        if after.len() as u64 != state.height - h {
            return Ok(Standing::Pending);
        }
        let work_after = after.iter().fold(0u128, |acc, x| {
            acc.saturating_add(calculate_work(&x.target))
        });
        if state.depth.checked_sub(work_after) != Some(cp.mw_cumulative_work) {
            return Ok(Standing::Conflict);
        }
        Ok(if state.height - h >= self.cfg.finality_depth {
            Standing::Final
        } else {
            Standing::Pending
        })
    }

    /// Recomputes the floor. Returns the new bookkeeping if it rose.
    pub fn refresh(&mut self, storage: &Storage, state: &State) -> Result<Option<FinalityInfo>> {
        let mut standings = Vec::with_capacity(self.records.len());
        for (id, record) in &self.records {
            standings.push((
                *id,
                record.checkpoint.mw_height,
                self.standing(record, storage, state)?,
            ));
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
        let retain_from = self
            .finalized
            .iter()
            .rev()
            .take(keep)
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
