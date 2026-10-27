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
//! | `bonds` | bond id | `BondEntry` of a bond that can still sign |
//! | `relay` | midstate height | `RelayEntry` of the midstate relay's chain |
//! | `meta` | `state_meta` / `base` / `finality` | [`StateMeta`] / [`SnapshotBase`] / [`FinalityInfo`] |
//! | `sync_headers` | height | verified headers of an unfinished sync |
//! | `peers` | multiaddr | empty |
//!
//! Every chain mutation goes through [`Storage::commit_chain`], one atomic
//! transaction whose result is cross-checked against the caller's state.

use crate::core::anchor::Checkpoint;
use crate::core::bond::BondSet;
use crate::core::mmr::{MerkleMountainRange, UtxoAccumulator};
use crate::core::mw::crypto::{compress, decompress, scalar_from_bytes, Point32, Scalar32};
use crate::core::mw::{Kernel, StoredGroup};
use crate::core::relay::{Relay, RelayEntry};
use crate::core::scan::{ScanBlock, ScanRun};
use crate::core::snapshot::{mmr_from_peaks, mmr_peak_values, Snapshot, SNAPSHOT_HEADERS};
use crate::core::state::{calculate_target, calculate_work};
use crate::core::types::{utxo_leaf, BlockEffects, UtxoEntry};
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
/// The bond set: every registered bond that can still sign. Blocks change
/// it by the diffs in their undo records, so it is never copied whole.
const BONDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("bonds");
/// The midstate relay's window, by midstate height. Changed by the diffs in
/// undo records, like the bond set.
const RELAY: TableDefinition<u64, &[u8]> = TableDefinition::new("relay");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
/// Each block's signer (bond id; empty if unsigned). Never pruned: the
/// fork-choice window needs signers after their bodies are gone.
const SIGNERS: TableDefinition<u64, &[u8]> = TableDefinition::new("signers");
/// Work fork choice has withheld (the work cap and the per-bond cap), summed
/// to each block. A missing entry is 0. An entry written before a cap existed
/// leaves that cap out, which is harmless: fork choice only compares branches
/// that share every entry below the point where they part.
const CAPPED: TableDefinition<u64, &[u8]> = TableDefinition::new("capped");
/// What each block was allowed to mint: the scheduled reward less whatever
/// the per-bond cap tapered away (`bond::capped_subsidy`). Recorded from the
/// release that introduced the taper on, which is before the switch that
/// activates it, so every block that ever withheld anything has an entry; a
/// height with none predates that and withheld nothing.
const SUBSIDY: TableDefinition<u64, &[u8]> = TableDefinition::new("subsidy");
/// Cumulative proof of work of the chain up to and including each block, so
/// finality can compare a checkpoint's claimed work without summing headers.
const DEPTHS: TableDefinition<u64, &[u8]> = TableDefinition::new("depths");
const SYNC_HEADERS: TableDefinition<u64, &[u8]> = TableDefinition::new("sync_headers");
const PEERS: TableDefinition<&str, &[u8]> = TableDefinition::new("peers");

/// Undo records always kept (at least); more if a retained checkpoint needs them.
pub const UNDO_KEEP: u64 = 1_200;
const MAX_PEERS_STORED: usize = 500;
/// The value an address saved as proven carries (`Storage::save_peers`).
const PROVEN_PEER: &[u8] = &[1];

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
        }
    }

    /// The scalars after `batch` (at `self.height`): the same updates
    /// `apply_batch` makes, for blocks already validated.
    /// `subsidy` is what the block was allowed to mint: the scheduled reward,
    /// less whatever the per-bond cap tapered away (`bond::capped_subsidy`).
    /// It must be the figure `state::apply_batch` arrived at, or a chain
    /// restored from this metadata carries a different supply — and supply is
    /// part of the state root.
    pub fn advance(&self, batch: &Batch, subsidy: u64) -> Result<Self> {
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
            subsidy
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
    /// What it changed in the bond set.
    pub effects: BlockEffects,
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

fn signer_to_log(signer: Option<[u8; 32]>) -> Vec<u8> {
    signer.map_or_else(Vec::new, |id| id.to_vec())
}

fn signer_from_log(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

/// The bond set as a table holds it.
fn read_bonds(table: &impl ReadableTable<&'static [u8], &'static [u8]>) -> Result<BondSet> {
    let mut bonds = BondSet::default();
    for entry in table.iter()? {
        let (k, v) = entry?;
        let id: [u8; 32] = k
            .value()
            .try_into()
            .map_err(|_| anyhow!("corrupt bond key"))?;
        bonds.insert(id, bincode::deserialize(v.value())?);
    }
    Ok(bonds)
}

/// The midstate relay as a table holds it. An empty table (a database from
/// before the relay) is the relay's genesis.
fn read_relay(table: &impl ReadableTable<u64, &'static [u8]>) -> Result<Relay> {
    let mut entries: Vec<RelayEntry> = Vec::new();
    for entry in table.iter()? {
        let (_, v) = entry?;
        entries.push(bincode::deserialize(v.value())?);
    }
    if entries.is_empty() {
        return Ok(Relay::genesis());
    }
    Relay::from_entries(entries).context("the stored midstate relay is corrupt")
}

/// Applies a block's bond diff to an in-memory set.
fn apply_bond_effects(bonds: &mut BondSet, effects: &BlockEffects) {
    for (id, _) in &effects.bonds_removed {
        bonds.remove(id);
    }
    for (id, entry) in &effects.bonds_added {
        bonds.insert(*id, *entry);
    }
}

/// Takes a block's bond diff back off an in-memory set.
fn undo_bond_effects(bonds: &mut BondSet, effects: &BlockEffects) {
    for (id, _) in &effects.bonds_added {
        bonds.remove(id);
    }
    for (id, entry) in &effects.bonds_removed {
        bonds.insert(*id, *entry);
    }
}

/// The signer of a stored block body (for blocks stored before the signer log).
fn signer_of_block(bytes: &[u8]) -> Result<Option<[u8; 32]>> {
    let batch: Batch = bincode::deserialize(bytes)?;
    Ok(batch.miner.map(|m| m.bond_id))
}

/// The signer of block `h`: from the signer log, else from its body. Neither
/// means the database is corrupt.
fn logged_signer(
    log: &impl ReadableTable<u64, &'static [u8]>,
    blocks: &impl ReadableTable<u64, &'static [u8]>,
    h: u64,
) -> Result<Option<[u8; 32]>> {
    if let Some(v) = log.get(h)? {
        return Ok(signer_from_log(v.value()));
    }
    match blocks.get(h)? {
        Some(v) => signer_of_block(v.value()),
        None => bail!(
            "the signer of block {} is missing; the database is corrupt",
            h
        ),
    }
}

/// `(height, work)` of each block in `range`, oldest first, from its stored
/// header: what the fork-choice work window (`bond::cap_work`) is rebuilt
/// from. Like the signer window, it decides the chain weight the next block
/// must claim, so a missing header is an error, never a gap.
fn header_works(
    headers: &impl ReadableTable<u64, &'static [u8]>,
    range: std::ops::Range<u64>,
) -> Result<Vec<(u64, u128)>> {
    let mut out = Vec::with_capacity(range.end.saturating_sub(range.start) as usize);
    for entry in headers.range(range.clone())? {
        let (k, v) = entry?;
        let header: BatchHeader = bincode::deserialize(v.value())?;
        out.push((k.value(), calculate_work(&header.target)));
    }
    if out.len() as u64 != range.end.saturating_sub(range.start) {
        bail!(
            "headers {}..{} are incomplete; the database is corrupt",
            range.start,
            range.end
        );
    }
    Ok(out)
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
            txn.open_table(SIGNERS)?;
            txn.open_table(CAPPED)?;
            txn.open_table(SUBSIDY)?;
            txn.open_table(DEPTHS)?;
            txn.open_table(BONDS)?;
            txn.open_table(RELAY)?;
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

    /// The scan data (`core/scan.rs`) of up to `count` consecutive stored
    /// blocks from `start`, as [`Self::load_batches`] reads the blocks, with
    /// `byte_limit` on the scan data's encoded size. `None` if there is no
    /// block at `start`.
    pub fn load_scan_run(
        &self,
        start: u64,
        count: u64,
        byte_limit: usize,
    ) -> Result<Option<ScanRun>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BATCHES)?;
        let mut run: Option<ScanRun> = None;
        let mut bytes = 0usize;
        for (expect, entry) in (start..).zip(table.range(start..start.saturating_add(count))?) {
            let (k, v) = entry?;
            if k.value() != expect {
                break; // pruned gap
            }
            let batch: Batch = bincode::deserialize(v.value())?;
            let scan = ScanBlock::of(&batch);
            let size = ScanRun::size_of(&scan);
            let run = run.get_or_insert_with(|| ScanRun {
                prev: batch.prev_header_hash,
                blocks: Vec::new(),
            });
            if !run.blocks.is_empty() && bytes + size > byte_limit {
                break;
            }
            bytes += size;
            run.blocks.push(scan);
        }
        Ok(run)
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

    /// Cumulative proof of work of the stored chain up to and including the
    /// block at `height`, if this database recorded it (blocks stored before
    /// the table existed, and blocks below a snapshot base other than its
    /// tip, did not).
    pub fn depth_after(&self, height: u64) -> Result<Option<u128>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(DEPTHS)?;
        let value = table.get(height)?;
        Ok(match value {
            Some(v) => Some(bincode::deserialize(v.value())?),
            None => None,
        })
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
        let bonds = read_bonds(&txn.open_table(BONDS)?)?;
        let relay = read_relay(&txn.open_table(RELAY)?)?;

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
            bonds,
            relay,
            recent_signers: Default::default(),
            signer_counts: Default::default(),
            work_floor: Default::default(),
            effects: Default::default(),
            capped: 0,
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
        state.capped = self.capped_before(state.height)?;
        self.rebuild_fork_choice_windows(&mut state)?;
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
            undo_bond_effects(&mut state.bonds, &undo.effects);
            state
                .relay
                .revert_change(&undo.effects.relay_removed, &undo.effects.relay_added);
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
        state.capped = self.capped_before(height)?;
        self.rebuild_fork_choice_windows(&mut state)?;
        Ok(state)
    }

    /// Refills the fork-choice windows (`bond::credit_work`) from the stored
    /// blocks just below `state`: signers from the signer log, work from the
    /// headers. The windows decide the chain weight the next block must
    /// claim, so they are consensus: a signer or header that cannot be found
    /// is an error, never a guess.
    fn rebuild_fork_choice_windows(&self, state: &mut State) -> Result<()> {
        let end = state.height;
        let start = end.saturating_sub(crate::core::bond::CAP_WINDOW as u64);
        let txn = self.db.begin_read()?;
        let log = txn.open_table(SIGNERS)?;
        let blocks = txn.open_table(BATCHES)?;
        let mut signers = Vec::with_capacity((end - start) as usize);
        for h in start..end {
            signers.push(logged_signer(&log, &blocks, h)?);
        }
        crate::core::bond::rebuild_signer_window(state, signers);
        let floor_start = end.saturating_sub(crate::core::bond::WORK_CAP_WINDOW as u64);
        let works = header_works(&txn.open_table(HEADERS)?, floor_start..end)?;
        crate::core::bond::rebuild_work_floor(state, works);
        Ok(())
    }

    /// The fork-choice work window (`bond::cap_work`) a block at `height`
    /// is weighed against, from the stored headers below it.
    pub fn work_floor_before(&self, height: u64) -> Result<im::Vector<(u64, u128)>> {
        let start = height.saturating_sub(crate::core::bond::WORK_CAP_WINDOW as u64);
        let txn = self.db.begin_read()?;
        let mut floor = im::Vector::new();
        for (h, work) in header_works(&txn.open_table(HEADERS)?, start..height)? {
            crate::core::bond::cap_work(&mut floor, h, work);
        }
        Ok(floor)
    }

    /// Work fork choice withheld from blocks `0..height`.
    fn capped_before(&self, height: u64) -> Result<u128> {
        let Some(last) = height.checked_sub(1) else {
            return Ok(0);
        };
        let txn = self.db.begin_read()?;
        let table = txn.open_table(CAPPED)?;
        Ok(match table.get(last)? {
            Some(v) => bincode::deserialize(v.value())?,
            None => 0,
        })
    }

    /// What the block at `height` minted: the scheduled reward, less whatever
    /// the per-bond cap withheld and burned. `None` for a block committed
    /// before this was recorded -- every one of those predates the taper, so
    /// it minted the whole scheduled reward.
    pub fn subsidy_at(&self, height: u64) -> Result<Option<u64>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(SUBSIDY)?;
        Ok(match table.get(height)? {
            Some(v) => Some(bincode::deserialize(v.value())?),
            None => None,
        })
    }

    /// Replaces every block at or above `first_height` with `batches`, whose
    /// application yields `state`. The blocks must already be validated, and
    /// `effects` holds what applying each one changed in the bond set (each
    /// state's [`State::effects`] as it was applied).
    pub fn commit_chain(
        &self,
        first_height: u64,
        batches: &[Batch],
        effects: &[Arc<BlockEffects>],
        state: &State,
    ) -> Result<()> {
        if first_height + batches.len() as u64 != state.height {
            bail!(
                "commit_chain: {} blocks from {} do not end at state height {}",
                batches.len(),
                first_height,
                state.height
            );
        }
        if effects.len() != batches.len() {
            bail!(
                "commit_chain: {} blocks but {} sets of effects",
                batches.len(),
                effects.len()
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
            let mut signer_log = txn.open_table(SIGNERS)?;
            let mut capped_table = txn.open_table(CAPPED)?;
            let mut subsidy_table = txn.open_table(SUBSIDY)?;
            let mut depth_table = txn.open_table(DEPTHS)?;
            let mut bond_table = txn.open_table(BONDS)?;
            let mut relay_table = txn.open_table(RELAY)?;
            if relay_table.is_empty()? {
                // A new database: the relay starts at its root.
                let root = RelayEntry::root();
                relay_table.insert(root.height, enc(&root)?.as_slice())?;
            }

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
                for (id, _) in &undo.effects.bonds_added {
                    bond_table.remove(id.as_slice())?;
                }
                for (id, entry) in &undo.effects.bonds_removed {
                    bond_table.insert(id.as_slice(), enc(entry)?.as_slice())?;
                }
                for e in &undo.effects.relay_added {
                    relay_table.remove(e.height)?;
                }
                for e in &undo.effects.relay_removed {
                    relay_table.insert(e.height, enc(e)?.as_slice())?;
                }
                blocks.remove(h)?;
                headers.remove(h)?;
                signer_log.remove(h)?;
                capped_table.remove(h)?;
                subsidy_table.remove(h)?;
                depth_table.remove(h)?;
                meta = undo.prev;
            }

            // The bond set below the first new block, advanced block by block
            // with the blocks' own diffs, for the fork-choice weights below.
            let mut bonds = read_bonds(&bond_table)?;

            // The fork-choice windows below the first new block, rebuilt as the
            // node rebuilds its own, so each block is weighed as the node did.
            let mut recent: im::Vector<Option<[u8; 32]>> = im::Vector::new();
            let mut counts: im::HashMap<[u8; 32], u32> = im::HashMap::new();
            let window_start = first_height.saturating_sub(crate::core::bond::CAP_WINDOW as u64);
            for h in window_start..first_height {
                let signer = logged_signer(&signer_log, &blocks, h)?;
                crate::core::bond::credit_in_window(
                    &mut recent,
                    &mut counts,
                    &bonds,
                    h,
                    signer,
                    0,
                    0,
                );
            }
            let mut floor: im::Vector<(u64, u128)> = im::Vector::new();
            let floor_start =
                first_height.saturating_sub(crate::core::bond::WORK_CAP_WINDOW as u64);
            for (h, work) in header_works(&headers, floor_start..first_height)? {
                crate::core::bond::cap_work(&mut floor, h, work);
            }
            let mut capped: u128 = match first_height.checked_sub(1) {
                Some(last) => match capped_table.get(last)? {
                    Some(v) => bincode::deserialize(v.value())?,
                    None => 0,
                },
                None => 0,
            };

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

                let block_effects: &BlockEffects = &effects[i];
                apply_bond_effects(&mut bonds, block_effects);
                for (id, _) in &block_effects.bonds_removed {
                    bond_table.remove(id.as_slice())?;
                }
                for (id, entry) in &block_effects.bonds_added {
                    bond_table.insert(id.as_slice(), enc(entry)?.as_slice())?;
                }
                for e in &block_effects.relay_removed {
                    relay_table.remove(e.height)?;
                }
                for e in &block_effects.relay_added {
                    relay_table.insert(e.height, enc(e)?.as_slice())?;
                }
                let signer = batch.miner.as_ref().map(|auth| auth.bond_id);
                let work = calculate_work(&batch.target);
                let creditable = crate::core::bond::cap_work(&mut floor, height, work);
                let credited = crate::core::bond::credit_in_window(
                    &mut recent,
                    &mut counts,
                    &bonds,
                    height,
                    signer,
                    creditable,
                    batch.timestamp,
                );
                // What the block was allowed to mint, by the rule
                // `state::apply_batch` applied when it accepted the block:
                // the scheduled reward, tapered once its signer is over cap
                // for the window. `credit_in_window` has just counted this
                // block, so `counts[signer]` is `n`.
                let subsidy = crate::core::bond::subsidy_for(
                    signer,
                    &counts,
                    &bonds,
                    height,
                    batch.timestamp,
                );
                let next = meta.advance(batch, subsidy)?;
                capped = capped.saturating_add(work - credited);
                if batch.chain_weight != next.depth.saturating_sub(capped) {
                    bail!(
                        "commit_chain: block {} claims chain weight {}, the replay gives {}",
                        height,
                        batch.chain_weight,
                        next.depth.saturating_sub(capped)
                    );
                }
                signer_log.insert(height, signer_to_log(signer).as_slice())?;
                capped_table.insert(height, enc(&capped)?.as_slice())?;
                subsidy_table.insert(height, enc(&subsidy)?.as_slice())?;
                depth_table.insert(height, enc(&next.depth)?.as_slice())?;
                let undo = BlockUndo {
                    spent,
                    created,
                    kernels: new_kernels,
                    prev: meta,
                    created_groups,
                    touched_groups: touched,
                    spent_members,
                    effects: block_effects.clone(),
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
            if capped != state.capped {
                bail!(
                    "commit_chain: replayed fork-choice weight disagrees with the supplied state"
                );
            }
            if bonds.root() != state.bonds.root() || bond_table.len()? != state.bonds.len() as u64 {
                bail!("commit_chain: stored bond diffs disagree with the supplied state");
            }
            let relay_tip = match relay_table.last()? {
                Some((_, v)) => Some(bincode::deserialize::<RelayEntry>(v.value())?),
                None => None,
            };
            if relay_tip.as_ref() != Some(state.relay.tip())
                || relay_table.len()? != state.relay.len() as u64
            {
                bail!("commit_chain: stored relay diffs disagree with the supplied state");
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
            relay: state.relay.entries().copied().collect(),
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
            let mut signers = txn.open_table(SIGNERS)?;
            for header in &snapshot.headers {
                headers.insert(header.height, enc(header)?.as_slice())?;
                // The fork-choice window below the base (the snapshot
                // carries at least `CAP_WINDOW` headers).
                signers.insert(header.height, signer_to_log(header.signer).as_slice())?;
            }
            txn.open_table(DEPTHS)?.insert(
                h - 1,
                enc(&snapshot.checkpoint.mw_cumulative_work)?.as_slice(),
            )?;
            txn.open_table(CAPPED)?
                .insert(h - 1, enc(&state.capped)?.as_slice())?;
            let mut bonds = txn.open_table(BONDS)?;
            for (id, entry) in state.bonds.iter() {
                bonds.insert(id.as_slice(), enc(entry)?.as_slice())?;
            }
            let mut relay = txn.open_table(RELAY)?;
            for e in state.relay.entries() {
                relay.insert(e.height, enc(e)?.as_slice())?;
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

    /// Replaces the saved address book with `proven` (`network::addrbook`):
    /// addresses where a midwimble peer was reached. Saving used to only add,
    /// so an address once written (a midstate node's, say) stayed for good.
    pub fn save_peers(&self, proven: &[String]) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(PEERS)?;
            let old: Vec<String> = table
                .iter()?
                .map(|e| e.map(|(k, _)| k.value().to_string()))
                .collect::<std::result::Result<_, _>>()?;
            for k in &old {
                table.remove(k.as_str())?;
            }
            for a in proven.iter().take(MAX_PEERS_STORED) {
                table.insert(a.as_str(), PROVEN_PEER)?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// The saved address book: each address, with whether it was proven.
    /// Books saved before addresses were checked come back unproven.
    pub fn load_peers(&self) -> Result<Vec<(String, bool)>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PEERS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            out.push((k.value().to_string(), v.value() == PROVEN_PEER));
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

    /// A producer signing with its own devnet bond, registered in its first block.
    fn devnet_bond(seed: &[u8], target: &[u8; 32]) -> crate::core::bond::MinerBond {
        devnet_bonds(&[seed], target).remove(0)
    }

    fn genesis_lock() -> u64 {
        crate::core::bond::est_midstate_height(crate::core::types::GENESIS_TIMESTAMP)
            + crate::core::bond::MAX_BOND_HORIZON / 2
    }

    /// Producers whose bonds share one stand-in midstate (so the headers
    /// their blocks relay agree), locked for a long time.
    fn devnet_bonds(seeds: &[&[u8]], target: &[u8; 32]) -> Vec<crate::core::bond::MinerBond> {
        let specs: Vec<(&[u8], u64)> = seeds.iter().map(|s| (*s, genesis_lock())).collect();
        bonds_until(&specs, target)
    }

    /// [`devnet_bonds`] locked until the given midstate heights.
    fn bonds_until(specs: &[(&[u8], u64)], target: &[u8; 32]) -> Vec<crate::core::bond::MinerBond> {
        use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
        let secrets: Vec<Scalar> = specs
            .iter()
            .map(|(seed, _)| Scalar::from_bytes_mod_order(crate::core::types::hash(seed)))
            .collect();
        let bonds: Vec<([u8; 32], u64, [u8; 32])> = specs
            .iter()
            .zip(&secrets)
            .map(|((seed, until), secret)| {
                (
                    RistrettoPoint::mul_base(secret).compress().to_bytes(),
                    *until,
                    crate::core::types::hash(seed),
                )
            })
            .collect();
        let (registrations, headers) = crate::core::bond::devnet_registrations(&bonds, target);
        registrations
            .into_iter()
            .zip(secrets)
            .map(|(registration, secret)| crate::core::bond::MinerBond {
                secret,
                bond_id: registration.bond_id(),
                registration: Some(registration),
                midstate: Some(headers.clone()),
                co_bonds: Vec::new(),
            })
            .collect()
    }

    /// Mines a block signed by `bond` and commits it, as the node does.
    fn mine_signed(
        storage: &Storage,
        state: &mut State,
        ts: &mut Vec<u64>,
        to: &StealthAddress,
        bond: &crate::core::bond::MinerBond,
    ) {
        // On schedule, so difficulty holds at the genesis target and a
        // block's work is large enough for the cap to withhold most of it.
        let on_schedule = crate::core::types::GENESIS_TIMESTAMP + 60 * state.height;
        mine_signed_at(storage, state, ts, to, bond, on_schedule);
    }

    /// [`mine_signed`], stamped `timestamp`.
    fn mine_signed_at(
        storage: &Storage,
        state: &mut State,
        ts: &mut Vec<u64>,
        to: &StealthAddress,
        bond: &crate::core::bond::MinerBond,
        timestamp: u64,
    ) {
        let (template, _) = crate::core::template::build_template_bonded(
            state,
            ts,
            &[],
            &[(to.clone(), 1)],
            [0; 32],
            Some(timestamp),
            Some(bond),
        )
        .unwrap();
        let b = template.mine_blocking();
        apply_batch(state, &b, ts).unwrap();
        ts.push(b.timestamp);
        storage
            .commit_chain(
                state.height - 1,
                std::slice::from_ref(&b),
                std::slice::from_ref(&state.effects),
                state,
            )
            .unwrap();
    }

    fn fresh(dir: &std::path::Path) -> (Storage, State, Vec<u64>) {
        let storage = Storage::open(dir).unwrap();
        let mut state = State::genesis();
        apply_batch(&mut state, Batch::genesis(), &[]).unwrap();
        storage
            .commit_chain(
                0,
                std::slice::from_ref(Batch::genesis()),
                std::slice::from_ref(&state.effects),
                &state,
            )
            .unwrap();
        (storage, state, vec![Batch::genesis().timestamp])
    }

    /// The testnet's failure: a lone producer, one full window after a restart,
    /// had its next block refused by storage. It must mine straight through.
    #[test]
    fn a_lone_bond_mines_past_a_full_window_and_through_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (storage, mut state, mut ts) = fresh(dir.path());
        let to = WalletKeys::random().address();
        let bond = devnet_bond(b"lone", &state.target);
        for _ in 0..2 * crate::core::bond::CAP_WINDOW {
            mine_signed(&storage, &mut state, &mut ts, &to, &bond);
        }
        assert_eq!(state.capped, 0, "a lone producer is never capped");
        drop(storage);

        let storage = Storage::open(dir.path()).unwrap();
        let mut loaded = storage.load_state().unwrap().unwrap();
        assert_eq!((loaded.depth, loaded.capped), (state.depth, state.capped));
        assert_eq!(loaded.signer_counts, state.signer_counts);
        for _ in 0..3 {
            mine_signed(&storage, &mut loaded, &mut ts, &to, &bond);
        }
        assert_eq!(loaded.capped, 0);
    }

    /// Bonds come and go by diffs: a bond that expires is removed from the
    /// table and its undo record brings it back, a restart reloads exactly
    /// the set, and no undo record carries a copy of the whole set.
    #[test]
    fn bond_diffs_persist_and_rewind() {
        use crate::core::bond::{est_midstate_height, min_remaining_bond_lock};
        let dir = tempfile::tempdir().unwrap();
        let (storage, mut state, mut ts) = fresh(dir.path());
        let to = WalletKeys::random().address();
        let t0 = crate::core::state::current_timestamp();
        let mut bonds = bonds_until(
            &[
                (
                    b"lasting",
                    est_midstate_height(t0) + crate::core::bond::MAX_BOND_HORIZON / 2,
                ),
                (
                    b"brief",
                    est_midstate_height(t0 + 300) + min_remaining_bond_lock(t0 + 300),
                ),
            ],
            &state.target,
        );
        let (lasting, brief) = (bonds.remove(0), bonds.remove(0));
        let mut at = |state: &mut State, bond: &crate::core::bond::MinerBond, t: u64| {
            let (template, _) = crate::core::template::build_template_bonded(
                state,
                &ts,
                &[],
                &[(to, 1)],
                [0; 32],
                Some(t),
                Some(bond),
            )
            .unwrap();
            let b = template.mine_blocking();
            apply_batch(state, &b, &ts).unwrap();
            ts.push(b.timestamp);
            storage
                .commit_chain(
                    state.height - 1,
                    std::slice::from_ref(&b),
                    std::slice::from_ref(&state.effects),
                    state,
                )
                .unwrap();
            state.clone()
        };
        at(&mut state, &lasting, t0 + 60);
        let registered = at(&mut state, &brief, t0 + 120);
        at(&mut state, &lasting, t0 + 240);
        let before_expiry = at(&mut state, &lasting, t0 + 400);
        let expired = at(&mut state, &lasting, t0 + 500);
        assert!(registered.bonds.contains_key(&brief.bond_id));
        assert!(before_expiry.bonds.contains_key(&brief.bond_id));
        assert!(!expired.bonds.contains_key(&brief.bond_id));

        // A restart reloads exactly the set, commitment included.
        let loaded = storage.load_state().unwrap().unwrap();
        assert_eq!(loaded.bonds, expired.bonds);
        assert_eq!(loaded.state_root(), expired.state_root());
        // Rewinding in memory brings the expired bond back.
        let rewound = storage.state_at(&loaded, before_expiry.height).unwrap();
        assert_eq!(rewound.bonds, before_expiry.bonds);
        // Undo records hold diffs, not the set.
        let txn = storage.db.begin_read().unwrap();
        let undo: BlockUndo = bincode::deserialize(
            txn.open_table(UNDO)
                .unwrap()
                .get(expired.height - 1)
                .unwrap()
                .unwrap()
                .value(),
        )
        .unwrap();
        assert_eq!(undo.effects.bonds_removed.len(), 1);
        assert!(undo.effects.bonds_added.is_empty());
        drop(txn);

        // Taking the expiring block back off the chain restores the bond in
        // the table too.
        storage
            .commit_chain(before_expiry.height, &[], &[], &before_expiry)
            .unwrap();
        let loaded = storage.load_state().unwrap().unwrap();
        assert_eq!(loaded.bonds, before_expiry.bonds);
        assert!(loaded.bonds.contains_key(&brief.bond_id));
    }

    /// Two bonds, one far over its cap: storage replays the same weight the
    /// node computed, and a restart or a rewind restores it.
    #[test]
    fn storage_weighs_over_cap_blocks_exactly_as_the_node_does() {
        let dir = tempfile::tempdir().unwrap();
        let (storage, mut state, mut ts) = fresh(dir.path());
        let to = WalletKeys::random().address();
        let mut bonds = devnet_bonds(&[b"bond a", b"bond b"], &state.target);
        let (a, b) = (bonds.remove(0), bonds.remove(0));
        mine_signed(&storage, &mut state, &mut ts, &to, &a);
        mine_signed(&storage, &mut state, &mut ts, &to, &b);
        let mut history = Vec::new();
        for _ in 0..crate::core::bond::CAP_WINDOW {
            mine_signed(&storage, &mut state, &mut ts, &to, &a);
            history.push((state.height, state.capped));
        }
        assert!(state.capped > 0, "bond a went over its cap");
        assert!(state.weight() < state.depth);
        drop(storage);

        let storage = Storage::open(dir.path()).unwrap();
        let mut loaded = storage.load_state().unwrap().unwrap();
        assert_eq!((loaded.depth, loaded.capped), (state.depth, state.capped));
        for &(height, capped) in &history {
            assert_eq!(
                storage.state_at(&loaded, height).unwrap().capped,
                capped,
                "height {height}"
            );
        }
        mine_signed(&storage, &mut loaded, &mut ts, &to, &b);
        mine_signed(&storage, &mut loaded, &mut ts, &to, &a);
    }

    /// Every committed block records what it was allowed to mint, so the
    /// explorer can say what a block withheld without re-deriving the window
    /// from its signers. The record follows the chain through a restart, and
    /// a height the chain never reached simply has none.
    #[test]
    fn storage_records_what_each_block_minted() {
        let dir = tempfile::tempdir().unwrap();
        let (storage, mut state, mut ts) = fresh(dir.path());
        let to = WalletKeys::random().address();
        let mut bonds = devnet_bonds(&[b"solo"], &state.target);
        let bond = bonds.remove(0);
        let mut minted = Vec::new();
        for _ in 0..4 {
            mine_signed(&storage, &mut state, &mut ts, &to, &bond);
            let height = state.height - 1;
            minted.push((height, crate::core::types::block_reward(height)));
        }
        for &(height, expected) in &minted {
            assert_eq!(
                storage.subsidy_at(height).unwrap(),
                Some(expected),
                "height {height}"
            );
        }
        drop(storage);

        let storage = Storage::open(dir.path()).unwrap();
        for &(height, expected) in &minted {
            assert_eq!(
                storage.subsidy_at(height).unwrap(),
                Some(expected),
                "after a restart, height {height}"
            );
        }
        assert_eq!(storage.subsidy_at(state.height + 50).unwrap(), None);
    }

    /// One cheap block (its parent stamped four hours late, which doubles
    /// the next target) caps every block after it at a quarter above its work
    /// until it leaves the work window. Storage replays the same weight the
    /// node computed, and a restart or a rewind restores it.
    #[test]
    fn storage_weighs_the_work_cap_exactly_as_the_node_does() {
        use crate::core::bond::{WORK_CAP_HEADROOM, WORK_CAP_WINDOW};
        let dir = tempfile::tempdir().unwrap();
        let (storage, mut state, mut ts) = fresh(dir.path());
        let to = WalletKeys::random().address();
        let bond = devnet_bond(b"work cap", &state.target);
        // Enough blocks that the timestamp floor is a median, so the block
        // after the late one may go back on schedule.
        for _ in 0..12 {
            mine_signed(&storage, &mut state, &mut ts, &to, &bond);
        }
        assert_eq!(state.capped, 0, "steady difficulty is never capped");
        let full = calculate_work(&state.target);
        let late = crate::core::types::GENESIS_TIMESTAMP + 60 * state.height + 4 * 3600;
        mine_signed_at(&storage, &mut state, &mut ts, &to, &bond, late);
        let cheap = calculate_work(&state.target);
        let cap = cheap + cheap / WORK_CAP_HEADROOM;
        assert!(
            cap < full,
            "the cheap block ({cheap}) caps a full one ({full})"
        );
        mine_signed(&storage, &mut state, &mut ts, &to, &bond);
        assert_eq!(calculate_work(&state.target), full, "back on schedule");

        let before = state.capped;
        let mut history = Vec::new();
        for _ in 0..WORK_CAP_WINDOW {
            mine_signed(&storage, &mut state, &mut ts, &to, &bond);
            history.push((state.height, state.capped));
        }
        assert_eq!(
            state.capped - before,
            (full - cap) * WORK_CAP_WINDOW as u128
        );
        let after = state.capped;
        mine_signed(&storage, &mut state, &mut ts, &to, &bond);
        assert_eq!(state.capped, after, "the cheap block has left the window");
        drop(storage);

        let storage = Storage::open(dir.path()).unwrap();
        let mut loaded = storage.load_state().unwrap().unwrap();
        assert_eq!((loaded.depth, loaded.capped), (state.depth, state.capped));
        assert_eq!(loaded.work_floor, state.work_floor);
        for &(height, capped) in &history {
            assert_eq!(
                storage.state_at(&loaded, height).unwrap().capped,
                capped,
                "height {height}"
            );
        }
        let rewound = storage.state_at(&loaded, history[0].0).unwrap();
        assert_eq!(rewound.work_floor.front().map(|&(_, w)| w), Some(cheap));
        mine_signed(&storage, &mut loaded, &mut ts, &to, &bond);
        assert_eq!(loaded.capped, after);
    }

    /// The work window crosses a snapshot exactly: a node started from one
    /// that carries only the window's headers, while a cheap block is still
    /// in the window, caps the next block just as the full node does.
    #[test]
    fn snapshots_carry_the_work_window() {
        use crate::core::bond::WORK_CAP_WINDOW;
        let dir = tempfile::tempdir().unwrap();
        let (full, mut state, mut ts) = fresh(&dir.path().join("full"));
        let to = WalletKeys::random().address();
        let bond = devnet_bond(b"work window", &state.target);
        for _ in 0..WORK_CAP_WINDOW + 6 {
            mine_signed(&full, &mut state, &mut ts, &to, &bond);
        }
        let late = crate::core::types::GENESIS_TIMESTAMP + 60 * state.height + 4 * 3600;
        mine_signed_at(&full, &mut state, &mut ts, &to, &bond, late);
        for _ in 0..3 {
            mine_signed(&full, &mut state, &mut ts, &to, &bond);
        }
        let before = state.capped;
        assert!(before > 0, "the cheap block caps the blocks after it");

        let cp = checkpoint_for(&full, &state, state.height);
        let snap = full.export_snapshot(&state, &cp).unwrap();
        assert_eq!(snap.headers.len(), crate::core::snapshot::SNAPSHOT_HEADERS);
        assert!(
            (snap.headers[0].height as usize) > 0,
            "the chain is longer than the snapshot"
        );
        let restored = snap.verify(&cp.id()).unwrap();
        assert_eq!(restored.work_floor, state.work_floor);
        let light = Storage::open(&dir.path().join("light")).unwrap();
        light.import_snapshot(&snap, &restored).unwrap();
        let mut loaded = light.load_state().unwrap().unwrap();
        assert_eq!(loaded.work_floor, state.work_floor);

        let (template, _) = crate::core::template::build_template_bonded(
            &loaded,
            &ts,
            &[],
            &[(to, 1)],
            [0; 32],
            Some(crate::core::types::GENESIS_TIMESTAMP + 60 * loaded.height),
            Some(&bond),
        )
        .unwrap();
        let block = template.mine_blocking();
        apply_batch(&mut loaded, &block, &ts).unwrap();
        apply_batch(&mut state, &block, &ts).unwrap();
        light
            .commit_chain(
                loaded.height - 1,
                std::slice::from_ref(&block),
                std::slice::from_ref(&loaded.effects),
                &loaded,
            )
            .unwrap();
        assert!(state.capped > before, "still capped");
        assert_eq!(
            (loaded.weight(), loaded.capped),
            (state.weight(), state.capped)
        );
    }

    /// A snapshot carries what the next blocks' claimed chain weights depend
    /// on: the work the cap withheld (the trusted depth less the weight the
    /// tip header claims) and the signer window (from the headers). A node
    /// that starts from one weighs new blocks exactly as a full node does.
    #[test]
    fn snapshots_carry_the_fork_choice_window() {
        let dir = tempfile::tempdir().unwrap();
        let (full, mut state, mut ts) = fresh(&dir.path().join("full"));
        let to = WalletKeys::random().address();
        let mut bonds = devnet_bonds(&[b"bond a", b"bond b"], &state.target);
        let (a, b) = (bonds.remove(0), bonds.remove(0));
        mine_signed(&full, &mut state, &mut ts, &to, &a);
        mine_signed(&full, &mut state, &mut ts, &to, &b);
        for _ in 0..crate::core::bond::CAP_WINDOW {
            mine_signed(&full, &mut state, &mut ts, &to, &a);
        }
        assert!(state.capped > 0, "bond a went over its cap");

        let cp = checkpoint_for(&full, &state, state.height);
        let snap = full.export_snapshot(&state, &cp).unwrap();
        assert!(snap.headers.len() >= crate::core::bond::CAP_WINDOW);
        let restored = snap.verify(&cp.id()).unwrap();
        assert_eq!(
            (restored.depth, restored.capped),
            (state.depth, state.capped)
        );
        assert_eq!(restored.recent_signers, state.recent_signers);
        assert_eq!(restored.signer_counts, state.signer_counts);
        assert_eq!(restored.work_floor, state.work_floor);

        let light = Storage::open(&dir.path().join("light")).unwrap();
        light.import_snapshot(&snap, &restored).unwrap();
        let mut loaded = light.load_state().unwrap().unwrap();
        assert_eq!((loaded.depth, loaded.capped), (state.depth, state.capped));
        assert_eq!(loaded.recent_signers, state.recent_signers);
        assert_eq!(loaded.work_floor, state.work_floor);

        // New blocks, over the cap and under it, apply on both with the same
        // claimed weights, and storage replays them from the seeded window.
        for bond in [&a, &b, &a] {
            let (template, _) = crate::core::template::build_template_bonded(
                &loaded,
                &ts,
                &[],
                &[(to, 1)],
                [0; 32],
                Some(crate::core::types::GENESIS_TIMESTAMP + 60 * loaded.height),
                Some(bond),
            )
            .unwrap();
            let block = template.mine_blocking();
            apply_batch(&mut loaded, &block, &ts).unwrap();
            apply_batch(&mut state, &block, &ts).unwrap();
            ts.push(block.timestamp);
            light
                .commit_chain(
                    loaded.height - 1,
                    std::slice::from_ref(&block),
                    std::slice::from_ref(&loaded.effects),
                    &loaded,
                )
                .unwrap();
            assert_eq!(
                (loaded.weight(), loaded.capped),
                (state.weight(), state.capped)
            );
        }
        let reloaded = light.load_state().unwrap().unwrap();
        assert_eq!(reloaded.capped, state.capped);

        // A snapshot without the whole window is refused.
        let mut short = snap.clone();
        short.headers.remove(0);
        assert!(
            short.verify(&cp.id()).is_err(),
            "too few headers for the window"
        );
    }

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

    /// What applying each block changed, from the states after them.
    fn fx(states: &[State]) -> Vec<Arc<BlockEffects>> {
        states.iter().map(|s| s.effects.clone()).collect()
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
                .commit_chain(
                    h as u64,
                    std::slice::from_ref(b),
                    std::slice::from_ref(&c.states[h].effects),
                    &c.states[h],
                )
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
        storage
            .commit_chain(0, &a.batches, &fx(&a.states), tip)
            .unwrap();

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
            .commit_chain(
                1,
                &b.batches[1..],
                &fx(&b.states[1..]),
                b.states.last().unwrap(),
            )
            .unwrap();
        assert!(same(
            &storage.load_state().unwrap().unwrap(),
            b.states.last().unwrap()
        ));
        storage
            .commit_chain(1, &a.batches[1..], &fx(&a.states[1..]), tip)
            .unwrap();
        assert_eq!(group_digest(&storage), before);
        assert!(same(&storage.load_state().unwrap().unwrap(), tip));
    }

    #[test]
    fn snapshots_round_trip_and_continue() {
        let dir = tempfile::tempdir().unwrap();
        let full = Storage::open(&dir.path().join("full")).unwrap();
        let mut c = chain_with_spend(2);
        let tip = c.states.last().unwrap().clone();
        full.commit_chain(0, &c.batches, &fx(&c.states), &tip)
            .unwrap();

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
            full.commit_chain(
                h,
                std::slice::from_ref(&b),
                std::slice::from_ref(&st.effects),
                &st,
            )
            .unwrap();
            light
                .commit_chain(
                    h,
                    std::slice::from_ref(&b),
                    std::slice::from_ref(&st.effects),
                    &st,
                )
                .unwrap();
        }
        let l = light.load_state().unwrap().unwrap();
        assert!(same(&l, &full.load_state().unwrap().unwrap()));
        assert!(same(&l, &st));
        // The light node cannot rewrite below its base.
        assert!(light.commit_chain(cp.mw_height - 1, &[], &[], &st).is_err());
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
        s.commit_chain(0, &c.batches, &fx(&c.states), tip).unwrap();
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
        s.commit_chain(0, &c.batches, &fx(&c.states), tip).unwrap();
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
            .commit_chain(
                floor - 1,
                &c.batches[floor as usize - 1..],
                &fx(&c.states[floor as usize - 1..]),
                tip
            )
            .is_err());
        s.commit_chain(
            floor,
            &c.batches[floor as usize..],
            &fx(&c.states[floor as usize..]),
            tip,
        )
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
            .commit_chain(0, &c.batches, &fx(&c.states), c.states.last().unwrap())
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
        storage
            .commit_chain(0, &a.batches, &fx(&a.states), tip)
            .unwrap();
        let b = chain_with_spend(0);
        assert!(storage
            .commit_chain(1, &b.batches[1..], &fx(&b.states[1..]), tip)
            .is_err());
        assert!(storage
            .commit_chain(0, &a.batches[..2], &fx(&a.states[..2]), tip)
            .is_err());
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
            .commit_chain(0, &a.batches[..3], &fx(&a.states[..3]), &a.states[2])
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
        // A book saved by an older version: added to, never trimmed, and
        // unchecked.
        {
            let txn = storage.db.begin_write().unwrap();
            {
                let mut table = txn.open_table(PEERS).unwrap();
                table
                    .insert("/ip4/9.9.9.9/tcp/9333", [].as_slice())
                    .unwrap();
            }
            txn.commit().unwrap();
        }
        assert_eq!(
            storage.load_peers().unwrap(),
            vec![("/ip4/9.9.9.9/tcp/9333".to_string(), false)]
        );
        // Saving replaces it.
        storage
            .save_peers(&["/ip4/1.2.3.4/tcp/1".to_string()])
            .unwrap();
        assert_eq!(
            storage.load_peers().unwrap(),
            vec![("/ip4/1.2.3.4/tcp/1".to_string(), true)]
        );
        storage.save_peers(&[]).unwrap();
        assert!(storage.load_peers().unwrap().is_empty());
    }
}

/// Bonded mining on the production build's constants (test builds start it
/// at `u64::MAX`): blocks built from templates and applied with their proof
/// of work taken as checked.
#[cfg(all(test, not(feature = "fast-mining")))]
mod bonded_era_tests {
    use super::*;
    use crate::core::mw::WalletKeys;
    use crate::core::state::{apply_batch, apply_batch_skip_pow, current_timestamp};
    use crate::core::template::build_template_relayed;
    use crate::core::types::compute_header_hash;

    /// While no bond can sign, blocks are unsigned and count for a sliver.
    /// Storage replays exactly that as it commits them (it checks each
    /// block's claimed weight), and a reload weighs the chain the same.
    #[test]
    fn storage_weighs_unsigned_blocks_as_the_node_does() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let mut state = State::genesis();
        apply_batch(&mut state, Batch::genesis(), &[]).unwrap();
        storage
            .commit_chain(
                0,
                std::slice::from_ref(Batch::genesis()),
                std::slice::from_ref(&state.effects),
                &state,
            )
            .unwrap();
        let to = WalletKeys::random().address();
        let mut ts = vec![current_timestamp() - 3_600];
        for _ in 0..5 {
            let at = ts.last().unwrap() + 60;
            let (t, _) =
                build_template_relayed(&state, &ts, &[], &[(to, 1)], [0; 32], Some(at), None, None)
                    .unwrap();
            assert!(t.batch.miner.is_none());
            let mut header = t.batch.header();
            header.height = state.height;
            apply_batch_skip_pow(&mut state, &t.batch, &ts, compute_header_hash(&header)).unwrap();
            ts.push(t.batch.timestamp);
            storage
                .commit_chain(
                    state.height - 1,
                    std::slice::from_ref(&t.batch),
                    std::slice::from_ref(&state.effects),
                    &state,
                )
                .unwrap();
        }
        assert!(state.capped > 0, "all but a sliver of each block withheld");
        drop(storage);
        let loaded = Storage::open(dir.path())
            .unwrap()
            .load_state()
            .unwrap()
            .unwrap();
        assert_eq!(
            (loaded.depth, loaded.capped, loaded.weight()),
            (state.depth, state.capped, state.weight())
        );
    }
}
