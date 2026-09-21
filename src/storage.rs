//! Persistent chain storage (redb, as midstate uses).
//!
//! State is stored **incrementally**: a block writes only its diff plus an
//! undo record. Anchored pruning (`docs/PRUNING.md`) adds:
//!
//! - **Full kernels**, kept forever, so pruned nodes can audit supply.
//! - **Range-proof groups with pruning bookkeeping.** Spent members shrink to
//!   `(commitment, metadata hash)`, and fully spent groups are deleted.
//! - **A finality floor.** No rewrites below it; block bodies below it may be
//!   pruned.
//! - **Snapshots.** Export at any checkpoint the undo window still covers;
//!   import to start a node at a checkpoint (the *snapshot base*).
//!
//! | table | key | value |
//! |---|---|---|
//! | `batches` | height | `Batch` (pruned below the floor) |
//! | `headers` | height | `BatchHeader` |
//! | `utxos` | commitment | `UtxoEntry` |
//! | `kernels` | kernel id | `Kernel` |
//! | `output_groups` | group id | `StoredGroup` |
//! | `group_members` | commitment | `(group id, index)` of an unspent output |
//! | `undo` | height | [`BlockUndo`] |
//! | `meta` | `state_meta` / `base` / `finality` | [`StateMeta`] / [`SnapshotBase`] / [`FinalityInfo`] |
//! | `sync_headers` | height | verified headers of an unfinished sync |
//! | `peers` | multiaddr | empty |
//!
//! Every chain mutation goes through [`Storage::commit_chain`], one atomic
//! transaction whose result is cross-checked against the caller's state.

use crate::core::anchor::Checkpoint;
use crate::core::mmr::{MerkleMountainRange, UtxoAccumulator};
use crate::core::mw::crypto::{compress, decompress, scalar_from_bytes, Point32, Scalar32};
use crate::core::mw::{Kernel, StoredGroup};
use crate::core::snapshot::{mmr_from_peaks, mmr_peak_values, Snapshot, SNAPSHOT_HEADERS};
use crate::core::state::{calculate_target, calculate_work};
use crate::core::types::{block_reward, utxo_leaf, UtxoEntry};
use crate::core::{Batch, BatchHeader, State};
use anyhow::{anyhow, bail, Context, Result};
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

const BATCHES: TableDefinition<u64, &[u8]> = TableDefinition::new("batches");
const HEADERS: TableDefinition<u64, &[u8]> = TableDefinition::new("headers");
const UTXOS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("utxos");
const KERNELS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("kernels");
const GROUPS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("output_groups");
const MEMBERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("group_members");
const UNDO: TableDefinition<u64, &[u8]> = TableDefinition::new("undo");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const SYNC_HEADERS: TableDefinition<u64, &[u8]> = TableDefinition::new("sync_headers");
const PEERS: TableDefinition<&str, &[u8]> = TableDefinition::new("peers");

/// Undo records always kept (at least); more if a retained checkpoint needs them.
pub const UNDO_KEEP: u64 = 1_200;
const MAX_PEERS_STORED: usize = 500;

/// The scalar part of [`State`] (everything except the sets and the MMR).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateMeta {
    pub mw_midstate: [u8; 32],
    pub kernel_excess_sum: Point32,
    pub total_kernel_offset: Scalar32,
    pub supply: u64,
    pub depth: u128,
    pub target: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub header_hash: [u8; 32],
    /// Registered mining bonds. Kept here so every undo record's copy of the
    /// previous meta restores them on a reorg.
    #[serde(default)]
    pub bonds: im::HashMap<[u8; 32], crate::core::bond::BondEntry>,
}

impl StateMeta {
    pub fn of(s: &State) -> Self {
        Self {
            mw_midstate: s.mw_midstate,
            kernel_excess_sum: s.kernel_excess_sum,
            total_kernel_offset: s.total_kernel_offset,
            supply: s.supply,
            depth: s.depth,
            target: s.target,
            height: s.height,
            timestamp: s.timestamp,
            header_hash: s.header_hash,
            bonds: s.bonds.clone(),
        }
    }

    /// The scalars after `batch` (at `self.height`): the same updates
    /// `apply_batch` makes, for blocks already validated.
    pub fn advance(&self, batch: &Batch) -> Result<Self> {
        let height = self.height;
        let mut excess =
            decompress(&self.kernel_excess_sum).ok_or_else(|| anyhow!("corrupt excess sum"))?;
        for k in batch
            .body
            .body
            .kernels
            .iter()
            .chain(batch.coinbase.as_ref().map(|c| &c.kernel))
        {
            excess += decompress(&k.excess).ok_or_else(|| anyhow!("invalid kernel excess"))?;
        }
        let offset = scalar_from_bytes(&self.total_kernel_offset)
            .ok_or_else(|| anyhow!("corrupt offset"))?
            + scalar_from_bytes(&batch.body.kernel_offset)
                .ok_or_else(|| anyhow!("invalid offset"))?;
        let reward = if batch.coinbase.is_some() {
            block_reward(height)
        } else {
            0
        };
        Ok(Self {
            mw_midstate: crate::core::types::fold_block(&self.mw_midstate, batch),
            kernel_excess_sum: compress(&excess),
            total_kernel_offset: offset.to_bytes(),
            supply: self
                .supply
                .checked_add(reward)
                .ok_or_else(|| anyhow!("supply overflow"))?,
            depth: self.depth.saturating_add(calculate_work(&batch.target)),
            target: calculate_target(height + 1, batch.timestamp),
            height: height + 1,
            timestamp: batch.timestamp,
            header_hash: batch.extension.final_hash,
            bonds: {
                let mut bonds = self.bonds.clone();
                for registration in &batch.registrations {
                    bonds.insert(registration.bond_id(), registration.entry());
                }
                bonds
            },
        })
    }
}

/// Everything needed to take one block back off the chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockUndo {
    pub spent: Vec<(Point32, UtxoEntry)>,
    pub created: Vec<Point32>,
    pub kernels: Vec<[u8; 32]>,
    pub prev: StateMeta,
    /// Range-proof groups the block created.
    pub created_groups: Vec<[u8; 32]>,
    /// Groups the block's spends touched, as they were before it.
    pub touched_groups: Vec<([u8; 32], StoredGroup)>,
    /// Group membership of the outputs it spent.
    pub spent_members: Vec<(Point32, [u8; 32], u32)>,
}

/// Where a checkpoint-synced database begins.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotBase {
    pub height: u64,
    /// Chain MMR peaks over blocks `0..height - 1`.
    pub mmr_peaks: Vec<[u8; 32]>,
    pub checkpoint: Checkpoint,
}

/// Finality bookkeeping (`docs/PRUNING.md` §3).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalityInfo {
    /// No block below this height may be rewritten.
    pub floor: u64,
    pub checkpoint_id: Option<[u8; 32]>,
    /// Undo records are kept from this height (so older snapshots and
    /// recovery claims stay derivable).
    pub retain_from: u64,
    /// Block bodies below this height have been deleted.
    pub pruned_below: u64,
}

impl Default for FinalityInfo {
    fn default() -> Self {
        Self {
            floor: 0,
            checkpoint_id: None,
            retain_from: u64::MAX,
            pruned_below: 0,
        }
    }
}

#[derive(Clone)]
pub struct Storage {
    db: Arc<Database>,
}

fn enc<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    Ok(bincode::serialize(v)?)
}

fn load_header_range(
    db: &Database,
    def: TableDefinition<u64, &[u8]>,
    start: u64,
    count: u64,
) -> Result<Vec<BatchHeader>> {
    let txn = db.begin_read()?;
    let table = txn.open_table(def)?;
    let mut out = Vec::new();
    for entry in table.range(start..start.saturating_add(count))? {
        let (_, v) = entry?;
        out.push(bincode::deserialize(v.value())?);
    }
    Ok(out)
}

impl Storage {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join("chain.redb");
        let db = Database::create(&path).with_context(|| format!("opening {}", path.display()))?;
        let txn = db.begin_write()?;
        {
            txn.open_table(BATCHES)?;
            txn.open_table(HEADERS)?;
            txn.open_table(UTXOS)?;
            txn.open_table(KERNELS)?;
            txn.open_table(GROUPS)?;
            txn.open_table(MEMBERS)?;
            txn.open_table(UNDO)?;
            txn.open_table(META)?;
            txn.open_table(SYNC_HEADERS)?;
            txn.open_table(PEERS)?;
        }
        txn.commit()?;
        Ok(Self { db: Arc::new(db) })
    }

    fn meta<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<Option<T>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(META)?;
        let value = table.get(key)?;
        Ok(match value {
            Some(v) => Some(bincode::deserialize(v.value())?),
            None => None,
        })
    }

    // ── Blocks and headers ──────────────────────────────────────────────

    pub fn load_batch(&self, height: u64) -> Result<Option<Batch>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BATCHES)?;
        let value = table.get(height)?;
        Ok(match value {
            Some(v) => Some(bincode::deserialize(v.value())?),
            None => None,
        })
    }

    /// Up to `count` consecutive stored blocks from `start`, stopping once the
    /// encoded size would pass `byte_limit` (at least one block if any).
    pub fn load_batches(&self, start: u64, count: u64, byte_limit: usize) -> Result<Vec<Batch>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BATCHES)?;
        let mut out = Vec::new();
        let mut bytes = 0usize;
        let mut expect = start;
        for entry in table.range(start..start.saturating_add(count))? {
            let (k, v) = entry?;
            if k.value() != expect {
                break; // pruned gap
            }
            expect += 1;
            let raw = v.value();
            if !out.is_empty() && bytes + raw.len() > byte_limit {
                break;
            }
            bytes += raw.len();
            out.push(bincode::deserialize(raw)?);
        }
        Ok(out)
    }

    pub fn load_header(&self, height: u64) -> Result<Option<BatchHeader>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(HEADERS)?;
        let value = table.get(height)?;
        Ok(match value {
            Some(v) => Some(bincode::deserialize(v.value())?),
            None => None,
        })
    }

    pub fn load_headers(&self, start: u64, count: u64) -> Result<Vec<BatchHeader>> {
        load_header_range(&self.db, HEADERS, start, count)
    }

    /// Timestamps of the (up to) `n` blocks below `end`, oldest first.
    pub fn load_timestamps(&self, end: u64, n: u64) -> Result<Vec<u64>> {
        let start = end.saturating_sub(n);
        Ok(self
            .load_headers(start, end - start)?
            .into_iter()
            .map(|h| h.timestamp)
            .collect())
    }

    // ── State ───────────────────────────────────────────────────────────

    pub fn load_meta(&self) -> Result<Option<StateMeta>> {
        self.meta("state_meta")
    }

    pub fn base(&self) -> Result<Option<SnapshotBase>> {
        self.meta("base")
    }

    pub fn finality(&self) -> Result<FinalityInfo> {
        Ok(self.meta("finality")?.unwrap_or_default())
    }

    pub fn set_finality(&self, info: &FinalityInfo) -> Result<()> {
        let txn = self.db.begin_write()?;
        txn.open_table(META)?
            .insert("finality", enc(info)?.as_slice())?;
        txn.commit()?;
        Ok(())
    }

    /// Rebuilds the tip state from the tables and verifies it against the
    /// state root the tip header commits to.
    pub fn load_state(&self) -> Result<Option<State>> {
        let Some(meta) = self.load_meta()? else {
            return Ok(None);
        };
        if meta.height == 0 {
            bail!("stored state has no blocks; the database is corrupt");
        }
        let base = self.base()?;
        let txn = self.db.begin_read()?;

        let mut utxos = im::HashMap::new();
        let mut leaves = im::OrdSet::new();
        for entry in txn.open_table(UTXOS)?.iter()? {
            let (k, v) = entry?;
            let commitment: Point32 = k
                .value()
                .try_into()
                .map_err(|_| anyhow!("corrupt utxo key"))?;
            let record: UtxoEntry = bincode::deserialize(v.value())?;
            leaves.insert(utxo_leaf(&commitment, &record));
            utxos.insert(commitment, record);
        }
        let mut kernel_ids = im::OrdSet::new();
        for entry in txn.open_table(KERNELS)?.iter()? {
            let (k, _) = entry?;
            let id: [u8; 32] = k
                .value()
                .try_into()
                .map_err(|_| anyhow!("corrupt kernel key"))?;
            kernel_ids.insert(id);
        }

        // Chain MMR over every block but the tip (which the tip header's
        // state root excludes), starting from the snapshot base if any.
        let tip = meta.height - 1;
        let (mut mmr, first) = match &base {
            Some(b) => (mmr_from_peaks(b.height - 1, &b.mmr_peaks)?, b.height - 1),
            None => (MerkleMountainRange::new(), 0),
        };
        let mut tip_header = None;
        let mut expected = first;
        for entry in txn.open_table(HEADERS)?.range(first..meta.height)? {
            let (k, v) = entry?;
            if k.value() != expected {
                bail!("header {} missing; the database is corrupt", expected);
            }
            expected += 1;
            let h: BatchHeader = bincode::deserialize(v.value())?;
            if k.value() == tip {
                tip_header = Some(h);
            } else {
                mmr.append(&h.extension.final_hash, true);
            }
        }
        let tip_header = tip_header
            .ok_or_else(|| anyhow!("tip header {} missing; the database is corrupt", tip))?;

        let mut state = State {
            mw_midstate: meta.mw_midstate,
            bonds: meta.bonds.clone(),
            utxos,
            utxo_set: UtxoAccumulator::from_canonical_coins(leaves, true),
            kernels: UtxoAccumulator::from_canonical_coins(kernel_ids, true),
            kernel_excess_sum: meta.kernel_excess_sum,
            total_kernel_offset: meta.total_kernel_offset,
            supply: meta.supply,
            depth: meta.depth,
            target: meta.target,
            height: meta.height,
            timestamp: meta.timestamp,
            chain_mmr: mmr,
            header_hash: meta.header_hash,
        };
        if state.state_root() != tip_header.state_root
            || tip_header.extension.final_hash != meta.header_hash
        {
            bail!(
                "stored state does not match the tip header's commitments; the database is corrupt"
            );
        }
        state
            .chain_mmr
            .append(&tip_header.extension.final_hash, true);
        Ok(Some(state))
    }

    /// The state after `height` blocks, derived from `current` (the tip) by
    /// applying undo records in memory.
    pub fn state_at(&self, current: &State, height: u64) -> Result<State> {
        if height > current.height {
            bail!("cannot derive a future state");
        }
        let mut state = current.clone();
        let txn = self.db.begin_read()?;
        let undo_table = txn.open_table(UNDO)?;
        for h in (height..current.height).rev() {
            let undo: BlockUndo = match undo_table.get(h)? {
                Some(v) => bincode::deserialize(v.value())?,
                None => bail!(
                    "no undo record for block {} (outside the retained window)",
                    h
                ),
            };
            for c in &undo.created {
                let entry = state
                    .utxos
                    .remove(c)
                    .ok_or_else(|| anyhow!("undo: created output {} missing", h))?;
                state.utxo_set.remove(&utxo_leaf(c, &entry), true);
            }
            for (c, entry) in &undo.spent {
                state.utxo_set.insert(utxo_leaf(c, entry), true);
                state.utxos.insert(*c, *entry);
            }
            for k in &undo.kernels {
                state.kernels.remove(k, true);
            }
            let p = undo.prev;
            state.mw_midstate = p.mw_midstate;
            state.kernel_excess_sum = p.kernel_excess_sum;
            state.total_kernel_offset = p.total_kernel_offset;
            state.supply = p.supply;
            state.depth = p.depth;
            state.target = p.target;
            state.height = p.height;
            state.timestamp = p.timestamp;
            state.header_hash = p.header_hash;
        }
        state.chain_mmr = current.chain_mmr.truncated(height);
        Ok(state)
    }

    /// Replaces every block at or above `first_height` with `batches`, whose
    /// application yields `state`. The blocks must already be validated.
    pub fn commit_chain(&self, first_height: u64, batches: &[Batch], state: &State) -> Result<()> {
        if first_height + batches.len() as u64 != state.height {
            bail!(
                "commit_chain: {} blocks from {} do not end at state height {}",
                batches.len(),
                first_height,
                state.height
            );
        }
        let finality = self.finality()?;
        if first_height < finality.floor {
            bail!(
                "refusing to rewrite height {} below the finalized floor {}",
                first_height,
                finality.floor
            );
        }
        if let Some(b) = self.base()? {
            if first_height < b.height {
                bail!("cannot rewrite below the snapshot base {}", b.height);
            }
        }
        let txn = self.db.begin_write()?;
        {
            let mut blocks = txn.open_table(BATCHES)?;
            let mut headers = txn.open_table(HEADERS)?;
            let mut utxos = txn.open_table(UTXOS)?;
            let mut kernels = txn.open_table(KERNELS)?;
            let mut groups = txn.open_table(GROUPS)?;
            let mut members = txn.open_table(MEMBERS)?;
            let mut undo_table = txn.open_table(UNDO)?;
            let mut meta_table = txn.open_table(META)?;

            let stored: Option<StateMeta> = match meta_table.get("state_meta")? {
                Some(v) => Some(bincode::deserialize(v.value())?),
                None => None,
            };
            let old_len = stored.as_ref().map_or(0, |m| m.height);
            if first_height > old_len {
                bail!(
                    "commit_chain: gap between stored tip {} and {}",
                    old_len,
                    first_height
                );
            }
            let mut meta = stored.unwrap_or_else(|| StateMeta::of(&State::genesis()));

            // 1. Revert replaced blocks, newest first.
            for h in (first_height..old_len).rev() {
                let undo: BlockUndo = match undo_table.remove(h)? {
                    Some(v) => bincode::deserialize(v.value())?,
                    None => bail!(
                        "no undo record for block {}; cannot reorganise that deep",
                        h
                    ),
                };
                for gid in &undo.created_groups {
                    groups.remove(gid.as_slice())?;
                }
                for c in &undo.created {
                    utxos.remove(c.as_slice())?;
                    members.remove(c.as_slice())?;
                }
                for (gid, before) in &undo.touched_groups {
                    groups.insert(gid.as_slice(), enc(before)?.as_slice())?;
                }
                for (c, gid, idx) in &undo.spent_members {
                    members.insert(c.as_slice(), enc(&(*gid, *idx))?.as_slice())?;
                }
                for (c, entry) in &undo.spent {
                    utxos.insert(c.as_slice(), enc(entry)?.as_slice())?;
                }
                for k in &undo.kernels {
                    kernels.remove(k.as_slice())?;
                }
                blocks.remove(h)?;
                headers.remove(h)?;
                meta = undo.prev;
            }

            // 2. Apply the new blocks' diffs.
            for (i, batch) in batches.iter().enumerate() {
                let height = first_height + i as u64;
                if meta.height != height {
                    bail!(
                        "commit_chain: scalar height {} != block height {}",
                        meta.height,
                        height
                    );
                }

                // Spends: UTXO records and group bookkeeping.
                let mut spent = Vec::with_capacity(batch.body.body.inputs.len());
                let mut spent_members = Vec::with_capacity(spent.capacity());
                let mut working: HashMap<[u8; 32], StoredGroup> = HashMap::new();
                let mut touched: Vec<([u8; 32], StoredGroup)> = Vec::new();
                for input in &batch.body.body.inputs {
                    let old = utxos.remove(input.commitment.as_slice())?.ok_or_else(|| {
                        anyhow!("block {} spends an output not in storage", height)
                    })?;
                    let entry: UtxoEntry = bincode::deserialize(old.value())?;
                    drop(old);
                    spent.push((input.commitment, entry));
                    let member = members
                        .remove(input.commitment.as_slice())?
                        .ok_or_else(|| {
                            anyhow!(
                                "output {} has no range-proof group",
                                hex::encode(input.commitment)
                            )
                        })?;
                    let (gid, idx): ([u8; 32], u32) = bincode::deserialize(member.value())?;
                    drop(member);
                    if !working.contains_key(&gid) {
                        let raw = groups
                            .get(gid.as_slice())?
                            .ok_or_else(|| anyhow!("missing group {}", hex::encode(gid)))?;
                        let group: StoredGroup = bincode::deserialize(raw.value())?;
                        drop(raw);
                        touched.push((gid, group.clone()));
                        working.insert(gid, group);
                    }
                    working
                        .get_mut(&gid)
                        .expect("inserted")
                        .spend(idx as usize)?;
                    spent_members.push((input.commitment, gid, idx));
                }
                for (gid, group) in &working {
                    if group.is_fully_spent() {
                        groups.remove(gid.as_slice())?;
                    } else {
                        groups.insert(gid.as_slice(), enc(group)?.as_slice())?;
                    }
                }

                // New outputs, their groups, and kernels.
                let mut created = Vec::new();
                let mut created_groups = Vec::new();
                let body_groups = batch.body.body.outputs.iter().map(|g| (g, false));
                let reward_group = batch.coinbase.iter().map(|c| (&c.outputs, true));
                for (group, coinbase) in body_groups.chain(reward_group) {
                    let stored_group = StoredGroup::from_group(group);
                    let gid = stored_group.id();
                    groups.insert(gid.as_slice(), enc(&stored_group)?.as_slice())?;
                    created_groups.push(gid);
                    for (idx, output) in group.outputs.iter().enumerate() {
                        let entry = UtxoEntry {
                            output_hash: output.metadata_hash(),
                            owner_key: output.owner_key,
                            recovery_commitment: output.recovery_commitment,
                            height,
                            coinbase,
                        };
                        utxos.insert(output.commitment.as_slice(), enc(&entry)?.as_slice())?;
                        members.insert(
                            output.commitment.as_slice(),
                            enc(&(gid, idx as u32))?.as_slice(),
                        )?;
                        created.push(output.commitment);
                    }
                }
                let mut new_kernels = Vec::new();
                for k in batch
                    .body
                    .body
                    .kernels
                    .iter()
                    .chain(batch.coinbase.as_ref().map(|c| &c.kernel))
                {
                    kernels.insert(k.id().as_slice(), enc(k)?.as_slice())?;
                    new_kernels.push(k.id());
                }

                let next = meta.advance(batch)?;
                let undo = BlockUndo {
                    spent,
                    created,
                    kernels: new_kernels,
                    prev: meta,
                    created_groups,
                    touched_groups: touched,
                    spent_members,
                };
                undo_table.insert(height, enc(&undo)?.as_slice())?;

                let mut header = batch.header();
                header.height = height;
                blocks.insert(height, enc(batch)?.as_slice())?;
                headers.insert(height, enc(&header)?.as_slice())?;
                meta = next;
            }

            // 3. The result must be exactly the caller's state.
            if meta != StateMeta::of(state) {
                bail!("commit_chain: stored diffs disagree with the supplied state");
            }
            meta_table.insert("state_meta", enc(&meta)?.as_slice())?;

            // 4. Bound the undo window (but keep what retained checkpoints need).
            let keep_from = state
                .height
                .saturating_sub(UNDO_KEEP)
                .min(finality.retain_from);
            let stale: Vec<u64> = undo_table
                .range(..keep_from)?
                .map(|e| e.map(|(k, _)| k.value()))
                .collect::<Result<_, _>>()?;
            for h in stale {
                undo_table.remove(h)?;
            }

            // 5. Verified sync headers below the new tip have been consumed.
            let mut sync = txn.open_table(SYNC_HEADERS)?;
            let applied: Vec<u64> = sync
                .range(..state.height)?
                .map(|e| e.map(|(k, _)| k.value()))
                .collect::<Result<_, _>>()?;
            for h in applied {
                sync.remove(h)?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    // ── Groups ──────────────────────────────────────────────────────────

    pub fn group_of(&self, commitment: &Point32) -> Result<Option<([u8; 32], u32, StoredGroup)>> {
        let txn = self.db.begin_read()?;
        let members = txn.open_table(MEMBERS)?;
        let Some(m) = members.get(commitment.as_slice())? else {
            return Ok(None);
        };
        let (gid, idx): ([u8; 32], u32) = bincode::deserialize(m.value())?;
        let groups = txn.open_table(GROUPS)?;
        let raw = groups
            .get(gid.as_slice())?
            .ok_or_else(|| anyhow!("dangling group reference"))?;
        Ok(Some((gid, idx, bincode::deserialize(raw.value())?)))
    }

    /// Every stored group (with at least one unspent member).
    pub fn groups(&self) -> Result<Vec<StoredGroup>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(GROUPS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            out.push(bincode::deserialize(entry?.1.value())?);
        }
        Ok(out)
    }

    /// Unspent outputs in commitment order, for wallets that cannot scan
    /// block bodies (a pruned node no longer has them). Returns the outputs
    /// with their UTXO records; `after` continues a previous page.
    pub fn unspent_outputs(
        &self,
        after: Option<Point32>,
        limit: usize,
    ) -> Result<Vec<(crate::core::mw::Output, UtxoEntry)>> {
        let txn = self.db.begin_read()?;
        let members = txn.open_table(MEMBERS)?;
        let groups = txn.open_table(GROUPS)?;
        let utxos = txn.open_table(UTXOS)?;
        let start: Vec<u8> = match after {
            // Exclusive: the next key after `after`.
            Some(c) => c.iter().copied().chain(std::iter::once(0u8)).collect(),
            None => Vec::new(),
        };
        let mut cache: HashMap<[u8; 32], StoredGroup> = HashMap::new();
        let mut out = Vec::new();
        for entry in members.range(start.as_slice()..)? {
            if out.len() >= limit {
                break;
            }
            let (k, v) = entry?;
            let commitment: Point32 = k
                .value()
                .try_into()
                .map_err(|_| anyhow!("corrupt member key"))?;
            let (gid, idx): ([u8; 32], u32) = bincode::deserialize(v.value())?;
            if !cache.contains_key(&gid) {
                let raw = groups
                    .get(gid.as_slice())?
                    .ok_or_else(|| anyhow!("dangling group reference"))?;
                cache.insert(gid, bincode::deserialize(raw.value())?);
            }
            let group = &cache[&gid];
            let output = match group.members.get(idx as usize) {
                Some(crate::core::mw::GroupMember::Unspent(o)) => o.clone(),
                _ => bail!("group member {} is not unspent", idx),
            };
            let record = utxos
                .get(commitment.as_slice())?
                .ok_or_else(|| anyhow!("member without a UTXO record"))?;
            out.push((output, bincode::deserialize(record.value())?));
        }
        Ok(out)
    }

    pub fn kernels(&self) -> Result<Vec<Kernel>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(KERNELS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            out.push(bincode::deserialize(entry?.1.value())?);
        }
        Ok(out)
    }

    // ── Snapshots, finality, pruning ────────────────────────────────────

    /// A snapshot at `checkpoint`, which must describe this chain and lie
    /// inside the undo window.
    pub fn export_snapshot(&self, current: &State, checkpoint: &Checkpoint) -> Result<Snapshot> {
        let h = checkpoint.mw_height;
        let state = self.state_at(current, h)?;
        let tip = self
            .load_header(h - 1)?
            .ok_or_else(|| anyhow!("no header at {}", h - 1))?;
        checkpoint.matches(&tip, state.depth)?;
        let parts = state.checkpoint_parts();
        if parts.root() != checkpoint.mw_state_root {
            bail!("derived state does not match the checkpoint");
        }

        // Groups as they were at `h`: undo later blocks' group changes.
        let mut groups: HashMap<[u8; 32], StoredGroup> =
            self.groups()?.into_iter().map(|g| (g.id(), g)).collect();
        {
            let txn = self.db.begin_read()?;
            let undo_table = txn.open_table(UNDO)?;
            for k in (h..current.height).rev() {
                let raw = undo_table
                    .get(k)?
                    .ok_or_else(|| anyhow!("no undo record for block {k}"))?;
                let undo: BlockUndo = bincode::deserialize(raw.value())?;
                for gid in &undo.created_groups {
                    groups.remove(gid);
                }
                for (gid, before) in undo.touched_groups {
                    groups.insert(gid, before);
                }
            }
        }
        let mut groups: Vec<StoredGroup> = groups.into_values().collect();
        groups.sort_by_key(|g| g.id());

        let kernels: Vec<Kernel> = self
            .kernels()?
            .into_iter()
            .filter(|k| state.kernels.contains(&k.id()))
            .collect();
        let first = h.saturating_sub(SNAPSHOT_HEADERS as u64);
        let headers = self.load_headers(first, h - first)?;
        let mut utxos: Vec<(Point32, UtxoEntry)> =
            state.utxos.iter().map(|(c, e)| (*c, *e)).collect();
        utxos.sort_by_key(|(c, _)| *c);
        Ok(Snapshot {
            checkpoint: checkpoint.clone(),
            headers,
            parts,
            mmr_peaks: mmr_peak_values(&state.chain_mmr.truncated(h - 1))?,
            utxos,
            groups,
            kernels,
            bonds: state.bonds.iter().map(|(id, e)| (*id, *e)).collect(),
        })
    }

    /// Initialises an empty database from a verified snapshot. `state` is
    /// what [`Snapshot::verify`] returned.
    pub fn import_snapshot(&self, snapshot: &Snapshot, state: &State) -> Result<()> {
        if self.load_meta()?.is_some() {
            bail!("refusing to import a snapshot into a non-empty database");
        }
        let h = snapshot.checkpoint.mw_height;
        let txn = self.db.begin_write()?;
        {
            let mut utxos = txn.open_table(UTXOS)?;
            for (c, e) in &snapshot.utxos {
                utxos.insert(c.as_slice(), enc(e)?.as_slice())?;
            }
            let mut kernels = txn.open_table(KERNELS)?;
            for k in &snapshot.kernels {
                kernels.insert(k.id().as_slice(), enc(k)?.as_slice())?;
            }
            let mut groups = txn.open_table(GROUPS)?;
            let mut members = txn.open_table(MEMBERS)?;
            for g in &snapshot.groups {
                let gid = g.id();
                groups.insert(gid.as_slice(), enc(g)?.as_slice())?;
                for (idx, o) in g.unspent() {
                    members.insert(o.commitment.as_slice(), enc(&(gid, idx as u32))?.as_slice())?;
                }
            }
            let mut headers = txn.open_table(HEADERS)?;
            for header in &snapshot.headers {
                headers.insert(header.height, enc(header)?.as_slice())?;
            }
            let mut meta = txn.open_table(META)?;
            meta.insert("state_meta", enc(&StateMeta::of(state))?.as_slice())?;
            let base = SnapshotBase {
                height: h,
                mmr_peaks: snapshot.mmr_peaks.clone(),
                checkpoint: snapshot.checkpoint.clone(),
            };
            meta.insert("base", enc(&base)?.as_slice())?;
            let finality = FinalityInfo {
                floor: h,
                checkpoint_id: Some(snapshot.checkpoint.id()),
                retain_from: h,
                pruned_below: h,
            };
            meta.insert("finality", enc(&finality)?.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Deletes block bodies below `height` (never above the floor).
    pub fn prune_bodies_below(&self, height: u64) -> Result<u64> {
        let mut finality = self.finality()?;
        let height = height.min(finality.floor);
        let txn = self.db.begin_write()?;
        let removed;
        {
            let mut blocks = txn.open_table(BATCHES)?;
            let doomed: Vec<u64> = blocks
                .range(..height)?
                .map(|e| e.map(|(k, _)| k.value()))
                .collect::<Result<_, _>>()?;
            removed = doomed.len() as u64;
            for h in doomed {
                blocks.remove(h)?;
            }
            finality.pruned_below = finality.pruned_below.max(height);
            txn.open_table(META)?
                .insert("finality", enc(&finality)?.as_slice())?;
        }
        txn.commit()?;
        Ok(removed)
    }

    // ── Sync resume ─────────────────────────────────────────────────────

    pub fn save_sync_headers(&self, headers: &[BatchHeader]) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(SYNC_HEADERS)?;
            for h in headers {
                table.insert(h.height, enc(h)?.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Verified headers from `start`, consecutive and linked, up to `count`.
    pub fn load_sync_headers(&self, start: u64, count: u64) -> Result<Vec<BatchHeader>> {
        let mut out: Vec<BatchHeader> = Vec::new();
        for h in load_header_range(&self.db, SYNC_HEADERS, start, count)? {
            let linked = match out.last() {
                None => h.height == start,
                Some(prev) => {
                    h.height == prev.height + 1 && h.prev_header_hash == prev.extension.final_hash
                }
            };
            if !linked {
                break;
            }
            out.push(h);
        }
        Ok(out)
    }

    pub fn clear_sync_headers(&self) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(SYNC_HEADERS)?;
            let all: Vec<u64> = table
                .iter()?
                .map(|e| e.map(|(k, _)| k.value()))
                .collect::<Result<_, _>>()?;
            for h in all {
                table.remove(h)?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    // ── Address book ────────────────────────────────────────────────────

    pub fn save_peers(&self, addrs: &[String]) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(PEERS)?;
            for a in addrs.iter().take(MAX_PEERS_STORED) {
                table.insert(a.as_str(), [].as_slice())?;
            }
            while table.len()? > MAX_PEERS_STORED as u64 {
                let first = table.first()?.map(|(k, _)| k.value().to_string());
                match first {
                    Some(k) => {
                        table.remove(k.as_str())?;
                    }
                    None => break,
                }
            }
        }
        txn.commit()?;
        Ok(())
    }

    pub fn load_peers(&self) -> Result<Vec<String>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PEERS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (k, _) = entry?;
            out.push(k.value().to_string());
        }
        Ok(out)
    }
}

#[cfg(all(test, feature = "fast-mining"))]
mod tests {
    use super::*;
    use crate::core::mw::{
        build_transaction, scan_output, Payment, Spendable, StealthAddress, Transaction, WalletKeys,
    };
    use crate::core::state::apply_batch;
    use crate::core::template::build_template;
    use crate::core::types::COINBASE_MATURITY;

    fn mine(
        state: &mut State,
        ts: &mut Vec<u64>,
        txs: &[Transaction],
        to: &StealthAddress,
    ) -> Batch {
        let b = build_template(state, ts, txs, to, None)
            .unwrap()
            .mine_blocking();
        apply_batch(state, &b, ts).unwrap();
        ts.push(b.timestamp);
        b
    }

    struct Built {
        batches: Vec<Batch>,
        states: Vec<State>,
        ts: Vec<u64>,
    }

    /// A chain whose block after maturity spends the first coinbase (so
    /// diffs include spends and group pruning), then `extra` empty blocks.
    fn chain_with_spend(extra: usize) -> Built {
        let keys = WalletKeys::random();
        let other = WalletKeys::random().address();
        let mut state = State::genesis();
        apply_batch(&mut state, Batch::genesis(), &[]).unwrap();
        let mut batches = vec![Batch::genesis().clone()];
        let mut states = vec![state.clone()];
        let mut ts = vec![Batch::genesis().timestamp];
        let mut coin = None;
        for i in 0..=COINBASE_MATURITY {
            let to = if i == 0 { keys.address() } else { other };
            let b = mine(&mut state, &mut ts, &[], &to);
            if i == 0 {
                let out = &b.coinbase.as_ref().unwrap().outputs.outputs[0];
                let owned = scan_output(&keys, out).unwrap();
                coin = Some(Spendable {
                    commitment: out.commitment,
                    value: owned.value,
                    blinding: owned.blinding,
                    owner_secret: owned.owner_secret,
                });
            }
            batches.push(b);
            states.push(state.clone());
        }
        let tx = build_transaction(
            &[coin.unwrap()],
            &[Payment {
                to: other,
                value: 7,
            }],
            &keys.address(),
            100_000,
            state.height,
        )
        .unwrap()
        .tx;
        batches.push(mine(&mut state, &mut ts, &[tx], &other));
        states.push(state.clone());
        for _ in 0..extra {
            batches.push(mine(&mut state, &mut ts, &[], &other));
            states.push(state.clone());
        }
        Built {
            batches,
            states,
            ts,
        }
    }

    fn same(a: &State, b: &State) -> bool {
        a.state_root() == b.state_root()
            && StateMeta::of(a) == StateMeta::of(b)
            && a.utxos == b.utxos
            && a.chain_mmr.root(true) == b.chain_mmr.root(true)
    }

    fn group_digest(s: &Storage) -> Vec<[u8; 32]> {
        let mut ids: Vec<[u8; 32]> = s
            .groups()
            .unwrap()
            .iter()
            .map(|g| crate::core::types::hash(&bincode::serialize(g).unwrap()))
            .collect();
        ids.sort();
        ids
    }

    fn checkpoint_for(s: &Storage, state: &State, height: u64) -> Checkpoint {
        let st = s.state_at(state, height).unwrap();
        Checkpoint::new(
            &s.load_header(height - 1).unwrap().unwrap(),
            st.depth,
            [0; 32],
        )
    }

    #[test]
    fn incremental_commits_reload_to_the_same_state() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let c = chain_with_spend(2);
        for (h, b) in c.batches.iter().enumerate() {
            storage
                .commit_chain(h as u64, std::slice::from_ref(b), &c.states[h])
                .unwrap();
        }
        let loaded = storage.load_state().unwrap().unwrap();
        assert!(same(&loaded, c.states.last().unwrap()));
        loaded.verify_supply().unwrap();
        for h in 1..c.states.len() {
            assert!(
                same(
                    &storage.state_at(&loaded, h as u64).unwrap(),
                    &c.states[h - 1]
                ),
                "height {h}"
            );
        }
    }

    #[test]
    fn groups_track_spends_and_reorgs_restore_them() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let a = chain_with_spend(1);
        let tip = a.states.last().unwrap();
        storage.commit_chain(0, &a.batches, tip).unwrap();

        // Every unspent output sits in exactly one stored group; the spent
        // coinbase's single-output group is gone.
        let groups = storage.groups().unwrap();
        let unspent: usize = groups.iter().map(|g| g.unspent().count()).sum();
        assert_eq!(unspent, tip.utxos.len());
        for c in tip.utxos.keys() {
            let (_, _, g) = storage.group_of(c).unwrap().unwrap();
            assert!(g.verify());
        }
        let spent = a.batches[1].coinbase.as_ref().unwrap().outputs.outputs[0].commitment;
        assert!(storage.group_of(&spent).unwrap().is_none());
        assert!(groups.iter().all(|g| !g.is_fully_spent()));
        let before = group_digest(&storage);

        // Replace the chain with an unrelated one and back: identical groups.
        let b = chain_with_spend(3);
        storage
            .commit_chain(1, &b.batches[1..], b.states.last().unwrap())
            .unwrap();
        assert!(same(
            &storage.load_state().unwrap().unwrap(),
            b.states.last().unwrap()
        ));
        storage.commit_chain(1, &a.batches[1..], tip).unwrap();
        assert_eq!(group_digest(&storage), before);
        assert!(same(&storage.load_state().unwrap().unwrap(), tip));
    }

    #[test]
    fn snapshots_round_trip_and_continue() {
        let dir = tempfile::tempdir().unwrap();
        let full = Storage::open(&dir.path().join("full")).unwrap();
        let mut c = chain_with_spend(2);
        let tip = c.states.last().unwrap().clone();
        full.commit_chain(0, &c.batches, &tip).unwrap();

        // At the tip, and at an older height (groups and kernels rewound).
        for h in [tip.height, tip.height - 3] {
            let cp = checkpoint_for(&full, &tip, h);
            let snap = full.export_snapshot(&tip, &cp).unwrap();
            let state = snap.verify(&cp.id()).unwrap();
            assert!(same(&state, &c.states[h as usize - 1]), "height {h}");
        }

        // Import at the tip into a fresh node and keep going on both.
        let cp = checkpoint_for(&full, &tip, tip.height);
        let snap = full.export_snapshot(&tip, &cp).unwrap();
        let state = snap.verify(&cp.id()).unwrap();
        let light = Storage::open(&dir.path().join("light")).unwrap();
        light.import_snapshot(&snap, &state).unwrap();
        assert!(
            light.import_snapshot(&snap, &state).is_err(),
            "only into an empty database"
        );
        let reloaded = light.load_state().unwrap().unwrap();
        assert!(same(&reloaded, &tip));

        let mut st = tip.clone();
        let payout = WalletKeys::random().address();
        for _ in 0..3 {
            let b = mine(&mut st, &mut c.ts, &[], &payout);
            let h = st.height - 1;
            full.commit_chain(h, std::slice::from_ref(&b), &st).unwrap();
            light
                .commit_chain(h, std::slice::from_ref(&b), &st)
                .unwrap();
        }
        let l = light.load_state().unwrap().unwrap();
        assert!(same(&l, &full.load_state().unwrap().unwrap()));
        assert!(same(&l, &st));
        // The light node cannot rewrite below its base.
        assert!(light.commit_chain(cp.mw_height - 1, &[], &st).is_err());
        // But it can serve a snapshot at its own newer checkpoints.
        let cp2 = checkpoint_for(&light, &l, l.height);
        light
            .export_snapshot(&l, &cp2)
            .unwrap()
            .verify(&cp2.id())
            .unwrap();
    }

    #[test]
    fn tampered_snapshots_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let c = chain_with_spend(1);
        let tip = c.states.last().unwrap();
        s.commit_chain(0, &c.batches, tip).unwrap();
        let cp = checkpoint_for(&s, tip, tip.height);
        let good = s.export_snapshot(tip, &cp).unwrap();
        good.verify(&cp.id()).unwrap();
        assert!(good.verify(&[0; 32]).is_err(), "untrusted checkpoint");

        let mut t = good.clone();
        t.groups.pop();
        assert!(t.verify(&cp.id()).is_err(), "missing range proof");
        let mut t = good.clone();
        t.kernels[0].fee += 1;
        assert!(t.verify(&cp.id()).is_err(), "kernel signature");
        let mut t = good.clone();
        t.kernels.pop();
        assert!(t.verify(&cp.id()).is_err(), "missing kernel");
        let mut t = good.clone();
        t.parts.supply += 1;
        assert!(t.verify(&cp.id()).is_err(), "supply");
        let mut t = good.clone();
        t.utxos[0].1.height += 1;
        assert!(t.verify(&cp.id()).is_err(), "UTXO record");
        let mut t = good.clone();
        if let Some(crate::core::mw::GroupMember::Unspent(o)) = t.groups[0]
            .members
            .iter_mut()
            .find(|m| matches!(m, crate::core::mw::GroupMember::Unspent(_)))
        {
            o.payload[3] ^= 1;
        }
        assert!(t.verify(&cp.id()).is_err(), "scanning data");
        let mut t = good.clone();
        t.mmr_peaks[0][0] ^= 1;
        assert!(t.verify(&cp.id()).is_err(), "MMR");
        let mut t = good;
        t.headers.remove(0);
        assert!(t.verify(&cp.id()).is_err(), "headers");
    }

    #[test]
    fn floor_blocks_deep_rewrites_and_bodies_can_be_pruned() {
        let dir = tempfile::tempdir().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let c = chain_with_spend(3);
        let tip = c.states.last().unwrap();
        s.commit_chain(0, &c.batches, tip).unwrap();
        let floor = tip.height - 2;
        let cp = checkpoint_for(&s, tip, floor);
        s.set_finality(&FinalityInfo {
            floor,
            checkpoint_id: Some(cp.id()),
            retain_from: floor,
            pruned_below: 0,
        })
        .unwrap();

        assert!(s
            .commit_chain(floor - 1, &c.batches[floor as usize - 1..], tip)
            .is_err());
        s.commit_chain(floor, &c.batches[floor as usize..], tip)
            .unwrap();

        assert_eq!(s.prune_bodies_below(u64::MAX).unwrap(), floor);
        assert!(s.load_batch(floor - 1).unwrap().is_none());
        assert!(s.load_batch(floor).unwrap().is_some());
        assert_eq!(s.finality().unwrap().pruned_below, floor);
        assert!(s.load_batches(0, 10, usize::MAX).unwrap().is_empty());
        let reloaded = s.load_state().unwrap().unwrap();
        assert!(same(&reloaded, tip));
        s.export_snapshot(tip, &cp)
            .unwrap()
            .verify(&cp.id())
            .unwrap();
    }

    #[test]
    fn corrupted_utxo_table_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let c = chain_with_spend(0);
        storage
            .commit_chain(0, &c.batches, c.states.last().unwrap())
            .unwrap();
        let txn = storage.db.begin_write().unwrap();
        {
            let mut t = txn.open_table(UTXOS).unwrap();
            let bogus = UtxoEntry {
                output_hash: [0; 32],
                owner_key: [1; 32],
                recovery_commitment: [0; 32],
                height: 1,
                coinbase: false,
            };
            t.insert([9u8; 32].as_slice(), enc(&bogus).unwrap().as_slice())
                .unwrap();
        }
        txn.commit().unwrap();
        let err = storage.load_state().unwrap_err().to_string();
        assert!(err.contains("corrupt"), "{err}");
    }

    #[test]
    fn inconsistent_commits_are_refused_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let a = chain_with_spend(0);
        let tip = a.states.last().unwrap();
        storage.commit_chain(0, &a.batches, tip).unwrap();
        let b = chain_with_spend(0);
        assert!(storage.commit_chain(1, &b.batches[1..], tip).is_err());
        assert!(storage.commit_chain(0, &a.batches[..2], tip).is_err());
        assert!(same(&storage.load_state().unwrap().unwrap(), tip));
    }

    #[test]
    fn sync_headers_persist_until_applied() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let a = chain_with_spend(2);
        let headers: Vec<BatchHeader> = a
            .batches
            .iter()
            .enumerate()
            .map(|(h, b)| {
                let mut x = b.header();
                x.height = h as u64;
                x
            })
            .collect();
        storage.save_sync_headers(&headers[1..]).unwrap();
        assert_eq!(
            storage.load_sync_headers(1, 100).unwrap().len(),
            headers.len() - 1
        );
        storage
            .commit_chain(0, &a.batches[..3], &a.states[2])
            .unwrap();
        assert!(storage.load_sync_headers(1, 100).unwrap().is_empty());
        assert_eq!(
            storage.load_sync_headers(3, 100).unwrap().len(),
            headers.len() - 3
        );
        storage.clear_sync_headers().unwrap();
        assert!(storage.load_sync_headers(3, 100).unwrap().is_empty());
    }

    #[test]
    fn peers_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        storage
            .save_peers(&["/ip4/1.2.3.4/tcp/1".to_string()])
            .unwrap();
        assert_eq!(
            storage.load_peers().unwrap(),
            vec!["/ip4/1.2.3.4/tcp/1".to_string()]
        );
    }
}
