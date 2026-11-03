//! Orphaning over-cap blocks: where a producer builds when the tip is a run
//! of other producers' over-cap blocks.
//!
//! Past its cap a bond's blocks stay valid, but each adds only a sliver of
//! its work to fork choice (`bond::credit_in_window`): one block counted in
//! full outweighs up to `OVER_CAP_WORK_DIVISOR - 1` of them. So when the
//! blocks at the tip are other producers' over-cap blocks, a producer whose
//! own block would count in full can build on the last block before them
//! instead of on the tip. If it finds that block, its chain is the heavier
//! one and every node follows it: the over-cap blocks are orphaned, so they
//! pay their producer nothing, their room goes to a block that counts, and
//! their transactions go back to the mempool (the replacement carries what
//! it can of them again).
//!
//! This turns the per-bond cap from a limit on what a producer's blocks
//! weigh into a limit on what they earn: past its bonds' share of the window,
//! a producer's hashrate finds blocks that others replace. A producer that
//! wants its blocks kept bonds enough to cover them.
//!
//! Nothing here changes consensus: fork choice has always taken the heavier
//! chain. This only decides where a producer builds. It builds past a run
//! only when its block there would count in full and outweigh the whole run,
//! never past a block that counted in full, never past a block one of its own
//! bonds signed (orphaning that would throw away its own pay), and never more
//! than [`MAX_ORPHAN_DEPTH`] blocks back.

use super::bond::{sliver, MinerBond};
use super::mw::{PayoutReceipt, StealthAddress, Transaction};
use super::relay::RelayFeed;
use super::state::{apply_body, calculate_work};
use super::template::{
    build_template_relayed, select_transactions, transaction_budget, BlockTemplate,
};
use super::types::{BatchHeader, State};
use std::collections::HashSet;

/// The most blocks one block of a producer's replaces: a hundred, about an
/// hour and forty minutes of blocks. Deeper runs are left alone: the
/// replacement would outweigh them just the same, but replacing history that
/// old surprises the people who saw it confirmed, and their own wallets would
/// have to rescan it.
pub const MAX_ORPHAN_DEPTH: u64 = 100;

/// Whether a block that added `credited` to its chain's weight, with `work`
/// behind it, counted in full: not an over-cap block or an unsigned one,
/// which add only a [`sliver`] of their work.
///
/// A full-weight block is credited all its work as far as the work cap
/// allows (`bond::cap_work`), which holds it to a quarter above the week's
/// lowest; only a chain whose work rose more than a thousandfold within the
/// week could credit a full-weight block so little that it looks like a
/// sliver here. A block whose work is one is its own sliver: fork choice
/// weighs it the same over its cap or not, so it counts in full.
pub fn full_weight(credited: u128, work: u128) -> bool {
    credited > sliver(work) || credited == work
}

/// Whether the block `header` counted in full, given the chain's weight
/// before it.
pub fn counted_in_full(header: &BatchHeader, weight_before: u128) -> bool {
    full_weight(
        header.chain_weight.saturating_sub(weight_before),
        calculate_work(&header.target),
    )
}

/// How many blocks from `from` on counted in full, of consecutive `headers`
/// (oldest first). Each block's weight is measured from the header before it,
/// so the block below `from` must be in `headers` too (unless `from` is
/// genesis, whose chain weighed nothing before it).
///
/// These are a block's confirmations that cost something to undo: replacing
/// it means outweighing every full-weight block above it, which takes more
/// full-weight blocks, and so bonds. Over-cap blocks above it add next to
/// nothing, and a block that is itself over cap, with nothing but over-cap
/// blocks above it, has none: one full-weight block on the block below it
/// orphans it.
pub fn full_weight_blocks(headers: &[BatchHeader], from: u64) -> u64 {
    let mut before: Option<&BatchHeader> = None;
    let mut count = 0;
    for header in headers {
        let weight_before = match before {
            Some(b) if b.height + 1 == header.height => Some(b.chain_weight),
            _ if header.height == 0 => Some(0),
            _ => None,
        };
        if header.height >= from && weight_before.is_some_and(|w| counted_in_full(header, w)) {
            count += 1;
        }
        before = Some(header);
    }
    count
}

/// The run a producer signing with any bond `ours` names may orphan: how
/// many blocks at the end of `headers` are over-cap or unsigned blocks that
/// none of its bonds signed, up to `max_depth`.
///
/// `headers` are consecutive and oldest first, ending at the tip; the first
/// is only the reference the second's weight is measured from, so at most
/// `headers.len() - 1` blocks are counted. The run stops at the first block
/// that counted in full, or that one of `ours` signed, or where the headers
/// do not link.
pub fn orphanable_run(
    headers: &[BatchHeader],
    ours: impl Fn(&[u8; 32]) -> bool,
    max_depth: u64,
) -> u64 {
    let mut run = 0;
    for pair in headers.windows(2).rev() {
        let (below, block) = (&pair[0], &pair[1]);
        let linked = block.height == below.height + 1
            && block.prev_header_hash == below.extension.final_hash;
        if run >= max_depth
            || !linked
            || counted_in_full(block, below.chain_weight)
            || block.signer.as_ref().is_some_and(&ours)
        {
            break;
        }
        run += 1;
    }
    run
}

/// Where a producer builds instead of on the tip: on the last block before a
/// run of other producers' over-cap blocks.
#[derive(Clone, Debug)]
pub struct OrphanBase {
    /// The state after the last block before the run. A block built on it
    /// replaces the whole run.
    pub state: State,
    /// The timestamps of the blocks up to and including that one, oldest
    /// first, as many as a template needs (`types::DIFFICULTY_LOOKBACK`).
    pub timestamps: Vec<u64>,
    /// The tip the run ends at, and its chain's weight: a block built on
    /// [`OrphanBase::state`] has to outweigh it.
    pub tip: [u8; 32],
    pub tip_weight: u128,
    /// Who signed each block of the run, oldest first (`None`: unsigned).
    pub run_signers: Vec<Option<[u8; 32]>>,
    /// Transactions the run's blocks mined, as far as the producer saw them
    /// in its own pool. A block on the base carries again those that still
    /// apply there, so a reorganisation onto it delays them by a block
    /// rather than until someone rebroadcasts them.
    pub carried: Vec<Transaction>,
}

impl OrphanBase {
    /// The height of the block built on this base.
    pub fn height(&self) -> u64 {
        self.state.height
    }

    /// The hash of the block a block on this base builds on.
    pub fn parent(&self) -> [u8; 32] {
        self.state.header_hash
    }

    /// How many blocks a block on this base orphans.
    pub fn replaces(&self) -> u64 {
        self.run_signers.len() as u64
    }

    /// Whether one of `bond`'s bonds, its own or a co-bond, signed a block of
    /// the run.
    pub fn signed_by(&self, bond: &MinerBond) -> bool {
        let ours =
            |id: &[u8; 32]| *id == bond.bond_id || bond.co_bonds.iter().any(|c| c.bond_id == *id);
        self.run_signers.iter().flatten().any(ours)
    }
}

/// A template for a block on `base` that orphans its run, or `None` where a
/// producer signing with `bond` should build on the tip: it has no bond (an
/// unsigned block counts for a sliver), one of its bonds signed a block of the
/// run, its block on the base would count for only a sliver (its bonds are
/// over their cap there too) or would not outweigh the tip, or no template
/// can be built there at all.
///
/// `pool` is what the producer would mine on the tip (its mempool, valid
/// there). The run's own transactions are offered first
/// ([`OrphanBase::carried`]), and every transaction is checked again on the
/// base, where it may not apply yet: it may spend an output the run created,
/// or be time-locked past the base.
pub fn orphan_template(
    base: &OrphanBase,
    pool: &[Transaction],
    payouts: &[(StealthAddress, u64)],
    extra: [u8; 32],
    bond: Option<&MinerBond>,
    feed: Option<&RelayFeed>,
) -> Option<(BlockTemplate, Vec<(StealthAddress, PayoutReceipt)>)> {
    let bond = bond?;
    if base.run_signers.is_empty() || base.signed_by(bond) {
        return None;
    }
    let state = &base.state;
    let mut seen = HashSet::new();
    let candidates: Vec<Transaction> = base
        .carried
        .iter()
        .chain(pool)
        .filter(|tx| seen.insert(tx.hash()))
        .filter(|tx| tx.lock_height() <= state.height && apply_body(state, tx, None, 0).is_ok())
        .cloned()
        .collect();
    let budget = transaction_budget(state, payouts.len(), Some(bond), feed);
    let txs = select_transactions(&candidates, state.height, budget);
    let build = |txs: &[Transaction]| {
        build_template_relayed(
            state,
            &base.timestamps,
            txs,
            payouts,
            extra,
            None,
            Some(bond),
            feed,
        )
    };
    let (template, receipts) = build(&txs).or_else(|_| build(&[])).ok()?;
    let credited = template.batch.chain_weight.saturating_sub(state.weight());
    let counts = full_weight(credited, calculate_work(&template.batch.target));
    (counts && template.batch.chain_weight > base.tip_weight).then_some((template, receipts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::bond::OVER_CAP_WORK_DIVISOR;
    use crate::core::types::Extension;

    /// A target with 65,535 work, so a sliver is 63.
    fn target() -> [u8; 32] {
        let mut t = [0u8; 32];
        t[1] = 1;
        t
    }

    fn work() -> u128 {
        calculate_work(&target())
    }

    /// Consecutive headers from height 10, each adding the credit given and
    /// signed as given.
    fn chain(blocks: &[(u128, Option<u8>)]) -> Vec<BatchHeader> {
        let mut headers = vec![header(10, [0; 32], 1_000_000, None)];
        for (credit, signer) in blocks {
            let below = headers.last().unwrap();
            let (height, prev, weight) = (
                below.height + 1,
                below.extension.final_hash,
                below.chain_weight + credit,
            );
            headers.push(header(height, prev, weight, signer.map(|s| [s; 32])));
        }
        headers
    }

    fn header(
        height: u64,
        prev: [u8; 32],
        chain_weight: u128,
        signer: Option<[u8; 32]>,
    ) -> BatchHeader {
        BatchHeader {
            height,
            prev_midstate: [0; 32],
            post_tx_midstate: [0; 32],
            extension: Extension {
                nonce: 0,
                final_hash: crate::core::types::hash(&height.to_le_bytes()),
            },
            timestamp: 0,
            target: target(),
            state_root: [0; 32],
            prev_header_hash: prev,
            signer,
            chain_weight,
            aux_pow: None,
        }
    }

    #[test]
    fn a_sliver_is_never_full_weight_and_a_whole_block_is() {
        for w in [2, 16, 1_023, 1_024, 65_535, 1 << 40] {
            assert!(!full_weight(sliver(w), w), "work {w}");
            assert!(full_weight(w, w), "work {w}");
        }
        // The work cap credits a full-weight block a quarter above the
        // week's lowest: still nowhere near a sliver.
        assert!(full_weight(work() / 8, work()));
        assert_eq!(sliver(work()), work() / OVER_CAP_WORK_DIVISOR);
        // At a work of one, over its cap or not, a block adds the same one:
        // there is nothing to orphan it for.
        assert!(full_weight(1, 1));
    }

    #[test]
    fn the_run_is_the_other_producers_over_cap_blocks_at_the_tip() {
        let (full, light) = (work(), sliver(work()));
        let headers = chain(&[
            (full, Some(1)),
            (light, Some(2)),
            (light, Some(3)),
            (light, None),
        ]);
        let none = |_: &[u8; 32]| false;
        assert_eq!(orphanable_run(&headers, none, MAX_ORPHAN_DEPTH), 3);
        // Never past a block of one's own...
        let mine = |id: &[u8; 32]| *id == [3; 32];
        assert_eq!(orphanable_run(&headers, mine, MAX_ORPHAN_DEPTH), 1);
        // ...nor further back than asked...
        assert_eq!(orphanable_run(&headers, none, 2), 2);
        // ...nor past a full-weight block, which ends the run.
        let tip_full = chain(&[(light, Some(2)), (full, Some(1))]);
        assert_eq!(orphanable_run(&tip_full, none, MAX_ORPHAN_DEPTH), 0);
        // Headers that do not link end it too.
        let mut broken = headers.clone();
        broken[3].prev_header_hash = [9; 32];
        assert_eq!(orphanable_run(&broken, none, MAX_ORPHAN_DEPTH), 1);
        // A lone header has nothing to measure.
        assert_eq!(orphanable_run(&headers[..1], none, MAX_ORPHAN_DEPTH), 0);
    }

    #[test]
    fn only_full_weight_blocks_count_as_confirmations_that_cost_bonds() {
        let (full, light) = (work(), sliver(work()));
        let headers = chain(&[
            (full, Some(1)),
            (light, Some(2)),
            (full, Some(3)),
            (light, Some(2)),
        ]);
        // From block 11 (full) on: blocks 11 and 13.
        assert_eq!(full_weight_blocks(&headers, 11), 2);
        // An over-cap block with only over-cap blocks above it has none.
        assert_eq!(full_weight_blocks(&headers, 14), 0);
        // Without the header below it, a block's weight is unknown and it
        // is not counted.
        assert_eq!(full_weight_blocks(&headers[1..], 11), 1);
    }
}
