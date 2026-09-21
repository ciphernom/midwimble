//! State snapshots at a checkpoint (`docs/PRUNING.md` §4).
//!
//! A snapshot lets a node start at a checkpoint without replaying history.
//! Everything in it is checked against the checkpoint's state root and
//! re-verified (kernel signatures, range proofs, the supply audit); only the
//! checkpoint itself and its claimed cumulative work are trusted.

use super::anchor::Checkpoint;
use super::auxpow::verify_pow;
use super::mmr::{mmr_size, peaks, MerkleMountainRange, UtxoAccumulator};
use super::mw::crypto::{compress, decompress, sum_points, Point32, IDENTITY};
use super::mw::{GroupMember, Kernel, KernelFeatures, StoredGroup};
use super::state::calculate_target;
use super::types::{compute_header_hash, utxo_leaf, BatchHeader, State, StateRootParts, UtxoEntry};
use anyhow::{anyhow, bail, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Headers carried for the timestamp window (median-time-past) and targets.
pub const SNAPSHOT_HEADERS: usize = 60;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub checkpoint: Checkpoint,
    /// The last ≤ 60 headers, ending with block `mw_height - 1`.
    pub headers: Vec<BatchHeader>,
    pub parts: StateRootParts,
    /// Peaks of the chain MMR over blocks `0..mw_height - 1` (the tip's own
    /// hash excluded, as in the committed state root).
    pub mmr_peaks: Vec<[u8; 32]>,
    pub utxos: Vec<(Point32, UtxoEntry)>,
    pub groups: Vec<StoredGroup>,
    pub kernels: Vec<Kernel>,
}

/// Peak values of an MMR, in position order.
pub fn mmr_peak_values(mmr: &MerkleMountainRange) -> Result<Vec<[u8; 32]>> {
    peaks(mmr_size(mmr.leaf_count()))
        .into_iter()
        .map(|p| {
            mmr.get(p)
                .copied()
                .ok_or_else(|| anyhow!("MMR missing peak {p}"))
        })
        .collect()
}

/// An MMR over `leaves` leaves that holds only its peaks. Appending and
/// computing roots only ever read peaks; old inclusion proofs cannot be
/// produced from it (a checkpoint-synced node never needs them).
pub fn mmr_from_peaks(leaves: u64, values: &[[u8; 32]]) -> Result<MerkleMountainRange> {
    let size = mmr_size(leaves);
    let positions = peaks(size);
    if positions.len() != values.len() {
        bail!(
            "expected {} MMR peaks, got {}",
            positions.len(),
            values.len()
        );
    }
    let mut nodes = vec![[0u8; 32]; size as usize];
    for (p, v) in positions.into_iter().zip(values) {
        nodes[p as usize] = *v;
    }
    Ok(MerkleMountainRange::from_raw_parts(
        nodes.into_iter().collect(),
        leaves,
    ))
}

fn check_headers(checkpoint: &Checkpoint, headers: &[BatchHeader]) -> Result<()> {
    let tip = headers
        .last()
        .ok_or_else(|| anyhow!("snapshot has no headers"))?;
    if tip.height + 1 != checkpoint.mw_height
        || tip.extension.final_hash != checkpoint.mw_header_hash
        || tip.state_root != checkpoint.mw_state_root
    {
        bail!("snapshot headers do not end at the checkpoint");
    }
    let expected = (checkpoint.mw_height as usize).min(SNAPSHOT_HEADERS);
    if headers.len() != expected {
        bail!(
            "snapshot must carry {} headers, has {}",
            expected,
            headers.len()
        );
    }
    for (i, h) in headers.iter().enumerate() {
        if i > 0 {
            let prev = &headers[i - 1];
            if h.height != prev.height + 1
                || h.prev_header_hash != prev.extension.final_hash
                || h.prev_midstate != prev.post_tx_midstate
                || h.target != calculate_target(h.height, prev.timestamp)
            {
                bail!("snapshot headers do not link at height {}", h.height);
            }
        }
    }
    let bad = headers.par_iter().filter(|h| h.height > 0).find_any(|h| {
        verify_pow(
            compute_header_hash(h),
            &h.extension,
            &h.target,
            h.aux_pow.as_ref(),
        )
        .is_err()
    });
    if let Some(h) = bad {
        bail!("snapshot header {} has invalid proof of work", h.height);
    }
    Ok(())
}

impl Snapshot {
    /// Verifies the snapshot against a trusted checkpoint id and returns the
    /// state after `mw_height` blocks.
    pub fn verify(&self, trusted_id: &[u8; 32]) -> Result<State> {
        let cp = &self.checkpoint;
        if &cp.id() != trusted_id {
            bail!(
                "snapshot is for checkpoint {}, not the trusted one",
                hex::encode(cp.id())
            );
        }
        cp.matches(
            self.headers.last().ok_or_else(|| anyhow!("no headers"))?,
            cp.mw_cumulative_work,
        )?;
        check_headers(cp, &self.headers)?;
        if self.parts.root() != cp.mw_state_root {
            bail!("snapshot state parts do not hash to the checkpoint's state root");
        }

        // UTXO set.
        let mut utxos = im::HashMap::new();
        let mut leaves = im::OrdSet::new();
        for (c, e) in &self.utxos {
            if utxos.insert(*c, *e).is_some() {
                bail!("duplicate UTXO in snapshot");
            }
            leaves.insert(utxo_leaf(c, e));
        }
        let utxo_set = UtxoAccumulator::from_canonical_coins(leaves, true);
        if utxo_set.root(true) != self.parts.utxo_root {
            bail!("snapshot UTXO set does not match the checkpoint");
        }

        // Kernels: all signatures valid, ids unique, sums and root match.
        if !self
            .kernels
            .par_iter()
            .all(|k| k.check_rules().is_ok() && k.verify_signature())
        {
            bail!("snapshot contains an invalid kernel");
        }
        let ids: im::OrdSet<[u8; 32]> = self.kernels.iter().map(Kernel::id).collect();
        if ids.len() != self.kernels.len() {
            bail!("duplicate kernel in snapshot");
        }
        let kernels = UtxoAccumulator::from_canonical_coins(ids, true);
        if kernels.root(true) != self.parts.kernel_root {
            bail!("snapshot kernels do not match the checkpoint");
        }
        let excess = sum_points(self.kernels.iter().map(|k| &k.excess))?;
        if compress(&excess) != self.parts.kernel_excess_sum {
            bail!("snapshot kernel excesses do not sum to the committed total");
        }
        let coinbase_kernels = self
            .kernels
            .iter()
            .filter(|k| k.features == KernelFeatures::Coinbase)
            .count();
        // Every block that mints carries exactly one coinbase kernel. Blocks
        // above the schedule's last rewarded height only carry one when they
        // collect fees, so they are not counted here.
        let minting_blocks = crate::core::types::EMISSION
            .final_reward_height()
            .map_or(cp.mw_height - 1, |end| end.min(cp.mw_height - 1));
        if (coinbase_kernels as u64) < minting_blocks {
            bail!("snapshot is missing coinbase kernels");
        }

        // Range-proof groups: all valid, covering every UTXO exactly once.
        if !self.groups.par_iter().all(StoredGroup::verify) {
            bail!("snapshot contains an invalid range-proof group");
        }
        let mut covered: HashMap<Point32, &crate::core::mw::Output> = HashMap::new();
        let mut group_ids = HashSet::new();
        for g in &self.groups {
            if !group_ids.insert(g.id()) || g.is_fully_spent() {
                bail!("snapshot has a duplicate or fully spent group");
            }
            for m in &g.members {
                if let GroupMember::Unspent(o) = m {
                    if covered.insert(o.commitment, o).is_some() {
                        bail!("output covered by two groups");
                    }
                }
            }
        }
        if covered.len() != utxos.len() {
            bail!("snapshot groups do not cover the UTXO set exactly");
        }
        for (c, e) in &self.utxos {
            let o = covered
                .get(c)
                .ok_or_else(|| anyhow!("UTXO {} has no range proof", hex::encode(c)))?;
            if e.output_hash != o.metadata_hash()
                || e.owner_key != o.owner_key
                || e.recovery_commitment != o.recovery_commitment
            {
                bail!("UTXO {} does not match its stored output", hex::encode(c));
            }
        }

        // Chain MMR: peaks over blocks before the tip, then the tip itself.
        let mut chain_mmr = mmr_from_peaks(cp.mw_height - 1, &self.mmr_peaks)?;
        if chain_mmr.root(true) != self.parts.chain_mmr_root {
            bail!("snapshot MMR does not match the checkpoint");
        }
        chain_mmr.append(&cp.mw_header_hash, true);

        let tip = self.headers.last().expect("checked");
        let state = State {
            mw_midstate: tip.post_tx_midstate,
            utxos,
            utxo_set,
            kernels,
            kernel_excess_sum: self.parts.kernel_excess_sum,
            total_kernel_offset: self.parts.total_kernel_offset,
            supply: self.parts.supply,
            depth: cp.mw_cumulative_work,
            target: calculate_target(cp.mw_height, tip.timestamp),
            height: cp.mw_height,
            timestamp: tip.timestamp,
            chain_mmr,
            header_hash: cp.mw_header_hash,
        };
        // Two independent supply checks. The Pedersen audit proves the coins
        // in the snapshot match its kernels; this one proves the number
        // itself is one the emission schedule could ever have produced, so a
        // node bootstrapping from a snapshot inherits the 1,000,000 cap
        // rather than taking the snapshot's word for it.
        let scheduled = crate::core::types::issued_before(cp.mw_height);
        if state.supply != scheduled {
            bail!(
                "snapshot claims a supply of {} at height {}, but the schedule allows {}",
                state.supply,
                cp.mw_height,
                scheduled
            );
        }
        state.verify_supply()?;
        if state.checkpoint_parts() != self.parts {
            bail!("rebuilt state does not reproduce the checkpoint");
        }
        Ok(state)
    }
}

/// Sanity helper for tests: an empty excess sum encodes as the identity.
pub fn empty_excess() -> Point32 {
    debug_assert!(decompress(&IDENTITY).is_some());
    IDENTITY
}
