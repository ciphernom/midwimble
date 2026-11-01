//! The burn tracker (`GET /explorer/burn`): what the over-cap taper has kept
//! from being minted since the mainnet switch, in total, over time and bond
//! by bond.
//!
//! From the switch (`bond::EARLY_BONDS_UNTIL`), a block whose signer has
//! signed more than its cap of the fork-choice window mints only `cap / n`
//! of its scheduled subsidy (`bond::capped_subsidy`). The rest is never
//! minted by anyone. Unsigned blocks are never tapered.
//!
//! Every figure here is the one each coinbase in the explorer shows: the
//! block's scheduled reward (`types::block_reward`, slow start included) less
//! what storage recorded it as minting when consensus applied it
//! (`Storage::subsidy_at`). Nothing re-derives the taper. The total is then
//! checked against the chain's own supply accounting, which grows by exactly
//! what each block mints, so the schedule to date less the supply is
//! everything ever withheld.
//!
//! The tracker reads headers, the signer log and the subsidy record, which
//! pruning keeps, so a pruned node still counts every block. It reads each
//! block once, keeps 24 bytes of it (about 13 MB a year of blocks), drops
//! what a reorg replaced, and rebuilds its report only when the tip moves.

use super::{internal, unix_now, ApiError, SharedIndex};
use crate::core::bond::{signer_cap, CAP_WINDOW, EARLY_BONDS_UNTIL};
use crate::core::types::{block_reward, issued_before, State, MAX_SUPPLY};
use crate::node::NodeHandle;
use crate::storage::Storage;
use axum::body::Bytes;
use axum::extract::State as AxState;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

/// Blocks of margin read below the first block found stamped at or after the
/// switch. Timestamps are only roughly ordered, so a block a little below it
/// may be stamped past the switch too; a node refuses blocks stamped more
/// than 15 minutes ahead of its clock, so a day of blocks is plenty.
const SWITCH_MARGIN: u64 = 24 * 60;

/// Blocks read from storage per transaction while catching up.
const READ_CHUNK: u64 = 4096;

/// Hashes kept of the newest rows, to spot a reorg by: as deep as the
/// explorer's own index unwinds one. A deeper reorg rebuilds the rows.
const REORG_HASHES: usize = 2048;

const DAY: u64 = 24 * 60 * 60;

/// The leaderboard's periods, by how far back from the tip's timestamp each
/// reaches (`all` is everything since the switch).
const PERIODS: [(&str, u64); 3] = [("all", u64::MAX), ("week", 7 * DAY), ("day", DAY)];

/// A row's `minted` when this node keeps no record of the block (below a
/// checkpoint it synced from).
const UNKNOWN: u64 = u64::MAX;
/// A row's `signer` when nobody signed the block.
const UNSIGNED: u32 = u32::MAX;

/// One block, as the tracker counts it. Its height is its place in the rows,
/// and its scheduled subsidy follows from the height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Row {
    timestamp: u64,
    /// What consensus let it mint, or [`UNKNOWN`].
    minted: u64,
    /// Its signer's place in [`BurnIndex::ids`], or [`UNSIGNED`].
    signer: u32,
}

/// What "about 13 MB a year" rests on: 525,600 blocks of this.
const _: () = assert!(std::mem::size_of::<Row>() == 24);

impl Row {
    /// Whether the taper could apply to it: stamped at or after the switch,
    /// the test consensus applies (`bond::subsidy_for`).
    fn counted(&self) -> bool {
        self.timestamp >= EARLY_BONDS_UNTIL
    }
}

/// Sums over some blocks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Tally {
    blocks: u64,
    signed: u64,
    /// Blocks that withheld anything: their signer was over its cap.
    tapered: u64,
    /// Scheduled, minted and withheld cover the blocks with a record only,
    /// so minted / scheduled stays a like-for-like ratio.
    scheduled: u64,
    minted: u64,
    withheld: u64,
    /// Blocks this node has no subsidy record for.
    unknown: u64,
}

impl Tally {
    /// Counts a block that was scheduled `scheduled` and minted `minted`.
    fn add(&mut self, scheduled: u64, minted: u64, signed: bool) {
        self.blocks += 1;
        self.signed += u64::from(signed);
        if minted == UNKNOWN {
            self.unknown += 1;
            return;
        }
        // The explorer's coinbase figure: scheduled less minted.
        let withheld = scheduled.saturating_sub(minted);
        self.scheduled += scheduled;
        self.minted += minted;
        self.withheld += withheld;
        self.tapered += u64::from(withheld > 0);
    }

    fn json(&self) -> Value {
        json!({
            "blocks": self.blocks,
            "signed": self.signed,
            "tapered": self.tapered,
            "scheduled": self.scheduled,
            "minted": self.minted,
            "withheld": self.withheld,
            "unknown": self.unknown,
        })
    }
}

/// One bond's sums, per period, and its run of over-cap blocks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct BondTally {
    periods: [Tally; 3],
    /// Its latest blocks in a row (its own, whoever signed in between) that
    /// withheld something.
    streak: u64,
    longest_streak: u64,
    last_signed: u64,
}

/// Everything the report is built from, summed in one pass over the rows.
#[derive(Debug, Default)]
struct Sums {
    network: [Tally; 3],
    /// Period start times, for the page to say what each covers.
    since: [u64; 3],
    /// By signer index.
    bonds: HashMap<u32, BondTally>,
    /// By UTC day (its first second) and by thousand blocks (its first
    /// height).
    days: BTreeMap<u64, Tally>,
    kblocks: BTreeMap<u64, Tally>,
    first_counted: Option<u64>,
}

/// Sums `rows`, the blocks from height `start` on, counting only those
/// stamped at or after the switch, with each period reaching back from
/// `tip_timestamp` and each block's subsidy from `scheduled`.
fn sum(rows: &[Row], start: u64, tip_timestamp: u64, scheduled: impl Fn(u64) -> u64) -> Sums {
    let mut s = Sums::default();
    for (i, (_, span)) in PERIODS.iter().enumerate() {
        s.since[i] = if *span == u64::MAX {
            EARLY_BONDS_UNTIL
        } else {
            tip_timestamp.saturating_sub(*span).max(EARLY_BONDS_UNTIL)
        };
    }
    for (i, row) in rows.iter().enumerate().filter(|(_, r)| r.counted()) {
        let height = start + i as u64;
        let offered = scheduled(height);
        let signed = row.signer != UNSIGNED;
        s.first_counted.get_or_insert(height);
        let within: [bool; 3] = std::array::from_fn(|p| {
            PERIODS[p].1 == u64::MAX || row.timestamp.saturating_add(PERIODS[p].1) > tip_timestamp
        });
        for p in (0..PERIODS.len()).filter(|p| within[*p]) {
            s.network[p].add(offered, row.minted, signed);
        }
        s.days
            .entry(row.timestamp / DAY * DAY)
            .or_default()
            .add(offered, row.minted, signed);
        s.kblocks
            .entry(height / 1000 * 1000)
            .or_default()
            .add(offered, row.minted, signed);
        if signed {
            let b = s.bonds.entry(row.signer).or_default();
            for p in (0..PERIODS.len()).filter(|p| within[*p]) {
                b.periods[p].add(offered, row.minted, true);
            }
            if row.minted != UNKNOWN && row.minted < offered {
                b.streak += 1;
                b.longest_streak = b.longest_streak.max(b.streak);
            } else {
                b.streak = 0;
            }
            b.last_signed = height;
        }
    }
    s
}

/// Each bond's leaderboard place per period: most withheld first, then most
/// blocks, then by id so equal bonds always come out in the same order.
/// Bonds that signed nothing in a period have no place in it.
fn ranks(bonds: &HashMap<u32, BondTally>, ids: &[[u8; 32]]) -> HashMap<u32, [Option<u64>; 3]> {
    let mut out: HashMap<u32, [Option<u64>; 3]> = bonds.keys().map(|i| (*i, [None; 3])).collect();
    for p in 0..PERIODS.len() {
        let mut order: Vec<(u32, &Tally)> = bonds
            .iter()
            .map(|(i, b)| (*i, &b.periods[p]))
            .filter(|(_, t)| t.blocks > 0)
            .collect();
        order.sort_by(|(ia, a), (ib, b)| {
            b.withheld
                .cmp(&a.withheld)
                .then(b.blocks.cmp(&a.blocks))
                .then(ids[*ia as usize].cmp(&ids[*ib as usize]))
        });
        for (rank, (i, _)) in order.into_iter().enumerate() {
            out.get_mut(&i).expect("every bond has an entry")[p] = Some(rank as u64 + 1);
        }
    }
    out
}

/// The chain a report was built for: its height, tip hash, and how far the
/// rows had read.
type ReportKey = (u64, [u8; 32], u64);

/// The tracker's state: one row per block from a little before the switch.
#[derive(Default)]
pub struct BurnIndex {
    /// The height of `rows[0]`; the rows are consecutive from it.
    start: u64,
    rows: Vec<Row>,
    /// The hashes of the newest [`REORG_HASHES`] rows, oldest first.
    hashes: VecDeque<[u8; 32]>,
    /// Signers' bond ids by the index rows hold, and the way back.
    ids: Vec<[u8; 32]>,
    index: HashMap<[u8; 32], u32>,
    /// The last report, and the chain it was built for.
    cached: Option<(ReportKey, Arc<Report>)>,
}

/// A built report: its JSON once, served as is to every request until the
/// tip moves.
pub struct Report {
    json: Value,
    body: Bytes,
    /// Where each bond is in `json["bonds"]`.
    bonds: HashMap<[u8; 32], usize>,
}

/// The lowest height in `1..tip` whose stored header is stamped at or after
/// the switch, by bisection, or `tip` if there is none yet. Timestamps are
/// only roughly ordered, which [`SWITCH_MARGIN`] covers; a height with no
/// stored header (below a checkpoint) counts as before the switch.
fn first_past_switch(storage: &Storage, tip: u64) -> anyhow::Result<u64> {
    let (mut lo, mut hi) = (1u64, tip.max(1));
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let past = storage
            .load_header(mid)?
            .is_some_and(|h| h.timestamp >= EARLY_BONDS_UNTIL);
        if past {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Ok(lo)
}

impl BurnIndex {
    /// The height after the last row.
    fn end(&self) -> u64 {
        self.start + self.rows.len() as u64
    }

    fn signer(&mut self, id: Option<[u8; 32]>) -> u32 {
        let Some(id) = id else { return UNSIGNED };
        *self.index.entry(id).or_insert_with(|| {
            self.ids.push(id);
            (self.ids.len() - 1) as u32
        })
    }

    /// Brings the rows level with the blocks stored below `tip`: drops any
    /// the chain no longer has (above its tip, or replaced by a reorg), then
    /// reads the new ones.
    fn sync(&mut self, storage: &Storage, tip: u64) -> anyhow::Result<()> {
        while !self.rows.is_empty() {
            let Some(hash) = self.hashes.back().copied() else {
                // Replaced deeper than the hashes kept: start again.
                *self = Self::default();
                break;
            };
            let last = self.end() - 1;
            if last < tip
                && storage
                    .load_header(last)?
                    .is_some_and(|h| h.extension.final_hash == hash)
            {
                break;
            }
            self.rows.pop();
            self.hashes.pop_back();
        }
        if self.rows.is_empty() {
            self.start = first_past_switch(storage, tip)?
                .saturating_sub(SWITCH_MARGIN)
                .max(1);
            self.hashes.clear();
        }
        while self.end() < tip {
            let next = self.end();
            let records = storage.block_records(next, (tip - next).min(READ_CHUNK))?;
            let Some(first) = records.first() else {
                if !self.rows.is_empty() {
                    break; // not committed yet: the next sync reads it
                }
                // Nothing stored here: below a checkpoint. Look further up.
                self.start = next.saturating_add(READ_CHUNK);
                continue;
            };
            if first.height != next {
                if !self.rows.is_empty() {
                    break; // a gap above the rows: wait for storage
                }
                self.start = first.height;
            }
            for r in records {
                let signer = self.signer(r.signer);
                self.rows.push(Row {
                    timestamp: r.timestamp,
                    minted: r.minted.unwrap_or(UNKNOWN),
                    signer,
                });
                self.hashes.push_back(r.hash);
                if self.hashes.len() > REORG_HASHES {
                    self.hashes.pop_front();
                }
            }
        }
        Ok(())
    }

    /// The report for the chain at `state`, built at most once per tip.
    fn report(
        &mut self,
        storage: &Storage,
        state: &State,
        now: u64,
    ) -> anyhow::Result<Arc<Report>> {
        self.sync(storage, state.height)?;
        let key = (state.height, state.header_hash, self.end());
        if let Some((k, report)) = &self.cached {
            if *k == key {
                return Ok(report.clone());
            }
        }
        let report = Arc::new(self.build(state, now));
        self.cached = Some((key, report.clone()));
        Ok(report)
    }

    /// The report's JSON, from the rows and the chain at `state`.
    fn build(&self, state: &State, now: u64) -> Report {
        let s = sum(&self.rows, self.start, state.timestamp, block_reward);
        let ranked = ranks(&s.bonds, &self.ids);
        let all = &s.network[0];

        // Complete when the rows reach from before the switch to the tip and
        // every counted block has a record. Then the sum of what the
        // coinbases withheld must be the chain's own figure: the schedule
        // less the supply.
        let covers_switch = self
            .rows
            .first()
            .is_some_and(|r| !r.counted() || self.start <= 1);
        let covers_tip = !self.rows.is_empty() && self.end() == state.height;
        let complete = covers_switch && covers_tip && all.unknown == 0;
        let scheduled_to_date = issued_before(state.height);
        let consensus_withheld = scheduled_to_date.saturating_sub(state.supply);
        let (burned, source) = if complete {
            (all.withheld, "blocks")
        } else {
            (consensus_withheld, "supply")
        };

        // Every bond that signed a counted block, then every other bond in
        // the set, so a registered bond that has not burned is listed too.
        let mut listed: Vec<([u8; 32], Option<u32>)> = s
            .bonds
            .keys()
            .map(|i| (self.ids[*i as usize], Some(*i)))
            .collect();
        for id in state.bonds.keys() {
            if !self.index.get(id).is_some_and(|i| s.bonds.contains_key(i)) {
                listed.push((*id, None));
            }
        }
        let unranked = [None; 3];
        let rank_of = |i: &Option<u32>| i.and_then(|i| ranked.get(&i)).unwrap_or(&unranked);
        listed.sort_by_key(|(id, i)| {
            let rank = rank_of(i)[0];
            (rank.is_none(), rank, *id)
        });
        let idle = BondTally::default();
        let bonds: Vec<Value> = listed
            .iter()
            .map(|(id, i)| {
                let b = i.and_then(|i| s.bonds.get(&i)).unwrap_or(&idle);
                let rank = rank_of(i);
                let entry = state.bonds.get(id);
                let mut v = json!({
                    "bond_id": hex::encode(id),
                    "registered": entry.is_some(),
                    "eligible": entry.is_some_and(|e| e.eligible_at(now)),
                    "window_signed": state.signer_counts.get(id).copied().unwrap_or(0),
                    "streak": b.streak,
                    "longest_streak": b.longest_streak,
                    "last_signed": (b.periods[0].blocks > 0).then_some(b.last_signed),
                });
                for (p, (name, _)) in PERIODS.iter().enumerate() {
                    let mut t = b.periods[p].json();
                    t["rank"] = json!(rank[p]);
                    v[*name] = t;
                }
                v
            })
            .collect();
        let positions = listed
            .iter()
            .enumerate()
            .map(|(n, (id, _))| (*id, n))
            .collect();

        let mut periods = json!({});
        for (p, (name, _)) in PERIODS.iter().enumerate() {
            let mut t = s.network[p].json();
            t["since"] = json!(s.since[p]);
            // What the bonds' rows add up to: the whole of the period's burn,
            // since an unsigned block is never tapered. Published so anyone
            // can see the leaderboard and the total agree.
            t["bonds_withheld"] =
                json!(s.bonds.values().map(|b| b.periods[p].withheld).sum::<u64>());
            periods[*name] = t;
        }
        let series = |m: &BTreeMap<u64, Tally>, key: &str| -> Vec<Value> {
            m.iter()
                .map(|(first, t)| {
                    let mut v = t.json();
                    v[key] = json!(first);
                    v
                })
                .collect()
        };

        let json = json!({
            "switch": EARLY_BONDS_UNTIL,
            "active": all.blocks > 0,
            "tip": state.height,
            "tip_timestamp": state.timestamp,
            "first_height": s.first_counted,
            "indexed_from": (!self.rows.is_empty()).then_some(self.start),
            "complete": complete,
            "max_supply": MAX_SUPPLY,
            "supply": state.supply,
            "scheduled_to_date": scheduled_to_date,
            // The banner's figure: the coinbases' sum when this node holds
            // every one of them, else the chain's own accounting, which is
            // exact anyway.
            "burned": burned,
            "burned_source": source,
            "effective_max_supply": MAX_SUPPLY.saturating_sub(burned),
            "consensus": {
                "withheld": consensus_withheld,
                "matches": complete && consensus_withheld == all.withheld,
            },
            "window": {
                "size": CAP_WINDOW,
                "filled": state.recent_signers.len(),
                "cap": signer_cap(&state.bonds, now),
                "eligible": state.bonds.values().filter(|e| e.eligible_at(now)).count(),
            },
            "periods": periods,
            "series": {
                "days": series(&s.days, "day"),
                "kblocks": series(&s.kblocks, "from"),
            },
            "bonds": bonds,
        });
        let body = Bytes::from(serde_json::to_vec(&json).expect("a JSON value serialises"));
        Report {
            json,
            body,
            bonds: positions,
        }
    }
}

impl Report {
    /// What the bond page shows: this bond's row (or `null` if it has not
    /// signed since the switch and is not registered), the network's totals
    /// to set it against, and how many bonds the leaderboard ranks.
    fn bond(&self, id: &[u8; 32]) -> Value {
        let ranked = self.json["bonds"].as_array().map_or(0, |b| {
            b.iter().filter(|b| !b["all"]["rank"].is_null()).count()
        });
        json!({
            "active": self.json["active"],
            "switch": self.json["switch"],
            "complete": self.json["complete"],
            "periods": self.json["periods"],
            "window": self.json["window"],
            "ranked": ranked,
            "bond": self.bonds.get(id).map(|&i| self.json["bonds"][i].clone()),
        })
    }
}

/// Syncs the tracker and returns its report for the chain `node` is on.
fn current(index: &SharedIndex, node: &NodeHandle) -> anyhow::Result<Arc<Report>> {
    let mut idx = index
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let state = node.state();
    idx.burn.report(node.storage(), &state, unix_now())
}

/// `GET /explorer/burn`: the whole report, as served to the burn tracker.
pub async fn burn(
    AxState(node): AxState<NodeHandle>,
    Extension(index): Extension<SharedIndex>,
) -> Result<Response, ApiError> {
    let report = tokio::task::spawn_blocking(move || current(&index, &node))
        .await
        .map_err(internal)?
        .map_err(internal)?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        report.body.clone(),
    )
        .into_response())
}

/// The burn figures `GET /explorer/bond/{id}` carries.
pub(super) async fn for_bond(
    node: NodeHandle,
    index: SharedIndex,
    id: [u8; 32],
) -> Result<Value, ApiError> {
    let report = tokio::task::spawn_blocking(move || current(&index, &node))
        .await
        .map_err(internal)?
        .map_err(internal)?;
    Ok(report.bond(&id))
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = EARLY_BONDS_UNTIL;

    /// A block `secs` after the switch, signed by bond `signer` (0 for
    /// unsigned; bond `n` is index `n - 1`, id `[n; 32]`), minting `minted`
    /// of a 1,000-unit subsidy.
    fn row(secs: i64, signer: u32, minted: Option<u64>) -> Row {
        Row {
            timestamp: (S as i64 + secs) as u64,
            minted: minted.unwrap_or(UNKNOWN),
            signer: signer.checked_sub(1).unwrap_or(UNSIGNED),
        }
    }

    fn ids() -> Vec<[u8; 32]> {
        (1..=8).map(|n| [n; 32]).collect()
    }

    fn sum_of(rows: &[Row], start: u64) -> Sums {
        sum(rows, start, rows.last().unwrap().timestamp, |_| 1000)
    }

    #[test]
    fn only_blocks_stamped_from_the_switch_count() {
        let rows = [
            row(-120, 1, Some(1000)),
            row(-60, 1, Some(1000)),
            row(0, 1, Some(400)),
            // Stamped back before the switch, as median-time-past allows:
            // consensus never tapers it, so neither does the tracker.
            row(-1, 1, Some(1000)),
            row(60, 1, Some(250)),
        ];
        let s = sum_of(&rows, 1);
        let all = s.network[0];
        assert_eq!((all.blocks, all.tapered), (2, 2));
        assert_eq!((all.scheduled, all.minted, all.withheld), (2000, 650, 1350));
        assert_eq!(s.first_counted, Some(3));
    }

    /// The leaderboard adds up to the network total in every period:
    /// unsigned blocks are never tapered, so every withheld unit has a
    /// signer. The day and week reach back from the tip's timestamp.
    #[test]
    fn bonds_add_up_to_the_network_in_every_period() {
        let day = DAY as i64;
        let rows = [
            row(0, 1, Some(100)),               // 8 days before the tip
            row(6 * day, 2, Some(1000)),        // 2 days before
            row(6 * day + 60, 1, Some(500)),    // 2 days before
            row(7 * day + 3600, 0, Some(1000)), // unsigned, in the day
            row(8 * day - 60, 1, Some(200)),    // in the day
            row(8 * day, 2, Some(900)),         // the tip
        ];
        let s = sum_of(&rows, 10);
        for (p, (name, _)) in PERIODS.iter().enumerate() {
            let bonds: u64 = s.bonds.values().map(|b| b.periods[p].withheld).sum();
            assert_eq!(bonds, s.network[p].withheld, "period {name}");
        }
        assert_eq!(s.network[0].withheld, 900 + 500 + 800 + 100);
        assert_eq!(
            s.network[1].blocks, 5,
            "the week leaves out the first block"
        );
        assert_eq!(s.network[1].withheld, 500 + 800 + 100);
        assert_eq!(
            s.network[2].blocks, 3,
            "the day: the unsigned block, 14 and 15"
        );
        assert_eq!(s.network[2].withheld, 800 + 100);
        assert_eq!((s.network[0].signed, s.network[2].signed), (5, 2));
        assert_eq!(s.since[2], rows[5].timestamp - DAY);
        assert_eq!(s.since[0], S, "all-time starts at the switch");
        let r = ranks(&s.bonds, &ids());
        assert_eq!(r[&0], [Some(1), Some(1), Some(1)]);
        assert_eq!(r[&1], [Some(2), Some(2), Some(2)]);
    }

    /// A streak is a bond's own consecutive over-cap blocks, whoever signed
    /// in between; one block minted in full ends it.
    #[test]
    fn a_streak_counts_a_bonds_own_over_cap_blocks_in_a_row() {
        let rows = [
            row(0, 1, Some(600)),
            row(60, 1, Some(500)),
            row(120, 2, Some(1000)),
            row(180, 1, Some(400)),
            row(240, 1, Some(1000)),
            row(300, 1, Some(900)),
            row(360, 2, Some(1000)),
            row(420, 1, Some(800)),
        ];
        let s = sum_of(&rows, 1);
        let b = s.bonds[&0];
        assert_eq!((b.streak, b.longest_streak, b.last_signed), (2, 3, 8));
        let other = s.bonds[&1];
        assert_eq!((other.streak, other.longest_streak), (0, 0));
        assert_eq!(other.periods[0].tapered, 0);
    }

    /// A block this node has no record for is counted, but kept out of the
    /// sums, so minted / scheduled compares like with like.
    #[test]
    fn an_unrecorded_block_is_counted_but_not_guessed() {
        let rows = [row(0, 1, None), row(60, 1, Some(250))];
        let s = sum_of(&rows, 1);
        let t = s.network[0];
        assert_eq!((t.blocks, t.unknown), (2, 1));
        assert_eq!((t.scheduled, t.minted, t.withheld), (1000, 250, 750));
    }

    #[test]
    fn series_bucket_by_utc_day_and_thousand_blocks() {
        let day = DAY as i64;
        let rows = [
            row(0, 1, Some(500)),
            row(60, 1, Some(500)),
            row(day, 1, Some(1000)),
        ];
        let s = sum_of(&rows, 999);
        let days: Vec<(u64, u64)> = s.days.iter().map(|(d, t)| (*d, t.withheld)).collect();
        let switch_day = S / DAY * DAY;
        assert_eq!(days, vec![(switch_day, 1000), (switch_day + DAY, 0)]);
        let k: Vec<(u64, u64)> = s.kblocks.iter().map(|(h, t)| (*h, t.blocks)).collect();
        assert_eq!(k, vec![(0, 1), (1000, 2)]);
    }

    /// Ties go to more blocks, then to the lower id, so the order is stable
    /// whatever order the bonds were first seen in.
    #[test]
    fn ranks_are_by_withheld_then_blocks_then_id() {
        let rows = [
            row(0, 3, Some(500)),
            row(60, 2, Some(500)),
            row(120, 2, Some(1000)),
            row(180, 1, Some(500)),
            row(240, 4, Some(1000)),
        ];
        let s = sum_of(&rows, 1);
        let r = ranks(&s.bonds, &ids());
        assert_eq!(r[&1][0], Some(1), "bond 2: 500 withheld over two blocks");
        assert_eq!(r[&0][0], Some(2), "bond 1: 500 over one block, lower id");
        assert_eq!(r[&2][0], Some(3));
        assert_eq!(r[&3][0], Some(4), "minted in full: last");
    }

    /// On a real database: the tracker reads what storage holds, and when a
    /// reorg rewrites the top of the chain it drops the rows that were
    /// replaced and reads their replacements, so it never counts a block
    /// that is no longer on the chain.
    #[cfg(feature = "fast-mining")]
    #[test]
    fn a_reorg_replaces_the_rows_it_rewrote() {
        use crate::core::mw::WalletKeys;
        use crate::core::state::{apply_batch, current_timestamp};
        use crate::core::template::build_template;
        use crate::core::types::Batch;

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
        let mut ts = vec![Batch::genesis().timestamp];
        // Stamped an hour back from now, so past the switch and never ahead of
        // the clock.
        let t0 = current_timestamp() - 3600;
        let mine = |state: &mut State, ts: &mut Vec<u64>, to: &WalletKeys| -> (Batch, State) {
            let at = t0 + state.height;
            let b = build_template(state, ts, &[], &to.address(), Some(at))
                .unwrap()
                .mine_blocking();
            apply_batch(state, &b, ts).unwrap();
            ts.push(b.timestamp);
            (b, state.clone())
        };
        let commit = |from: u64, blocks: &[(Batch, State)]| {
            let batches: Vec<Batch> = blocks.iter().map(|(b, _)| b.clone()).collect();
            let effects: Vec<_> = blocks.iter().map(|(_, s)| s.effects.clone()).collect();
            storage
                .commit_chain(from, &batches, &effects, &blocks.last().unwrap().1)
                .unwrap();
        };
        let stored = |range: std::ops::RangeInclusive<u64>| -> Vec<[u8; 32]> {
            range
                .map(|h| {
                    storage
                        .load_header(h)
                        .unwrap()
                        .unwrap()
                        .extension
                        .final_hash
                })
                .collect()
        };

        let (a, b) = (WalletKeys::random(), WalletKeys::random());
        let shared: Vec<_> = (0..4).map(|_| mine(&mut state, &mut ts, &a)).collect();
        commit(1, &shared);
        let (mut state_b, mut ts_b) = (state.clone(), ts.clone());
        let branch_a: Vec<_> = (0..4).map(|_| mine(&mut state, &mut ts, &a)).collect();
        commit(5, &branch_a);

        let mut index = BurnIndex::default();
        let report = index.report(&storage, &state, current_timestamp()).unwrap();
        assert_eq!((index.start, index.end()), (1, 9), "blocks 1..=8");
        assert_eq!(Vec::from(index.hashes.clone()), stored(1..=8));
        assert_eq!(report.json["periods"]["all"]["blocks"], 8);
        assert_eq!(report.json["complete"], true);
        assert_eq!(report.json["consensus"]["matches"], true);

        // A longer branch from block 5 replaces 5..=8.
        let branch_b: Vec<_> = (0..5).map(|_| mine(&mut state_b, &mut ts_b, &b)).collect();
        commit(5, &branch_b);
        let report = index
            .report(&storage, &state_b, current_timestamp())
            .unwrap();
        assert_eq!((index.start, index.end()), (1, 10));
        assert_eq!(
            Vec::from(index.hashes.clone()),
            stored(1..=9),
            "the new branch's"
        );
        assert_eq!(report.json["tip"], 10);
        assert_eq!(report.json["periods"]["all"]["blocks"], 9);
        // Unsigned blocks are never tapered: all of it was minted.
        assert_eq!(report.json["burned"], 0);
        assert_eq!(
            report.json["periods"]["all"]["minted"],
            report.json["periods"]["all"]["scheduled"]
        );

        // Deeper than the hashes kept, it starts again rather than guess.
        index.hashes.clear();
        let report = index
            .report(&storage, &state_b, current_timestamp())
            .unwrap();
        assert_eq!((index.start, index.end()), (1, 10));
        assert_eq!(report.json["periods"]["all"]["blocks"], 9);
    }
}
