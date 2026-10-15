//! Headers-first synchronisation.
//!
//! From midstate `src/sync.rs`: `verify_header_chain` (sequential linkage,
//! median-time-past and ASERT target checks, then proof of work verified in
//! parallel), fork-point search against stored hashes, and a session that
//! walks `Headers → Batches`. Midstate's pipelined rebuild, prefetch buffers
//! and on-disk resume are left out; the session here is the simple core of
//! that design, and the node drives it (see `node.rs`).
//!
//! A session is dropped when its peer goes quiet, but never for the time
//! this node spends on its own work: a header's proof of work is a million
//! sequential hashes, so a chunk of headers can take minutes to verify on a
//! one-core machine, and that machine must still be able to sync
//! ([`SyncSession::timed_out`]). A dropped session stops its background
//! work, so retries do not pile up on the CPU.

use crate::core::simd_mining::{check_pow_chains_with, pow_seed, PowCheck};
use crate::core::state::{calculate_target, calculate_work, current_timestamp, validate_timestamp};
use crate::core::types::{compute_header_hash, MEDIAN_TIME_PAST_WINDOW};
use crate::core::{Batch, BatchHeader, State};
use anyhow::{bail, Context as _, Result};
use libp2p::request_response::OutboundRequestId;
use libp2p::PeerId;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A session whose peer sends nothing for this long is dropped (the default
/// for `NodeConfig::sync_timeout`). Our own work does not count.
pub const SYNC_TIMEOUT_SECS: u64 = 45;
/// The longest our own work on a session may run before the session is
/// dropped anyway: verifying one header chunk, deriving the fork state, or
/// applying one chunk of blocks. That work is bounded and takes well under
/// this even on slow hardware, so only a stuck task should reach it.
pub const LOCAL_WORK_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Headers asked for at a time. A chunk is verified in one go, so this also
/// bounds that work (about 25 s on one core with AVX2) and what a session
/// that ends early throws away. Peers serve any count up to
/// `MAX_GETHEADERS_COUNT`.
pub const HEADERS_PER_REQUEST: u64 = 1_000;
/// Refuse to reorganise away more than this many blocks.
pub const MAX_REORG_DEPTH: u64 = 1_000;
/// How far below our tip a new session starts asking for headers.
pub const INITIAL_STEP_BACK: u64 = 16;

/// Checks a run of consecutive headers.
///
/// `prior_timestamps` are the timestamps of the blocks just below
/// `headers[0]` (oldest first); the last one also fixes `headers[0]`'s
/// expected target. `parent_weight` is the chain weight of the block below
/// `headers[0]` (0 below genesis), and `work_floor` the fork-choice work
/// window after it (`bond::cap_work`; empty below genesis). The caller
/// checks that `headers[0]` links to its own chain.
///
/// Each header's claimed chain weight must have grown by what its block
/// could add: its work as far as the work cap allows, which the headers
/// themselves decide, or for a signed block the sliver an over-cap block
/// adds (`bond::credit_possible`). Which of those two is right depends on
/// the bond set, which headers do not carry, so applying the blocks settles
/// it: a block whose claim is wrong is invalid.
pub fn verify_header_chain(
    headers: &[BatchHeader],
    prior_timestamps: &[u64],
    parent_weight: u128,
    work_floor: &im::Vector<(u64, u128)>,
    check_pow: bool,
) -> Result<()> {
    verify_header_chain_with(
        headers,
        prior_timestamps,
        parent_weight,
        work_floor,
        check_pow,
        |_| true,
    )
}

/// [`verify_header_chain`], checking proof of work a piece at a time. Before
/// each piece, `proceed` is told how many headers it holds; returning `false`
/// abandons the verification, which then fails.
pub fn verify_header_chain_with(
    headers: &[BatchHeader],
    prior_timestamps: &[u64],
    parent_weight: u128,
    work_floor: &im::Vector<(u64, u128)>,
    check_pow: bool,
    mut proceed: impl FnMut(usize) -> bool,
) -> Result<()> {
    let Some(first) = headers.first() else {
        return Ok(());
    };
    let now = current_timestamp();

    let (mut weight, mut floor) = (parent_weight, work_floor.clone());
    for header in headers {
        let work = calculate_work(&header.target);
        let creditable = crate::core::bond::cap_work(&mut floor, header.height, work);
        let possible = header
            .chain_weight
            .checked_sub(weight)
            .is_some_and(|added| {
                crate::core::bond::credit_possible(creditable, header.signer.is_some(), added)
            });
        if !possible {
            bail!(
                "header {} claims a chain weight its block could not have added",
                header.height
            );
        }
        weight = header.chain_weight;
    }

    let expected_first_target = match (first.height, prior_timestamps.last()) {
        (0, _) => calculate_target(0, 0),
        (h, Some(ts)) => calculate_target(h, *ts),
        (_, None) => bail!("missing timestamps below height {}", first.height),
    };
    if first.target != expected_first_target {
        bail!("invalid difficulty target at height {}", first.height);
    }

    let mut window: VecDeque<u64> = prior_timestamps.iter().copied().collect();
    for (i, header) in headers.iter().enumerate() {
        if i > 0 {
            let prev = &headers[i - 1];
            if header.height != prev.height + 1 {
                bail!("header heights not consecutive at index {}", i);
            }
            if header.prev_header_hash != prev.extension.final_hash {
                bail!(
                    "header chain linkage broken at index {}: prev_header_hash mismatch",
                    i
                );
            }
            if header.prev_midstate != prev.post_tx_midstate {
                bail!(
                    "header chain linkage broken at index {}: prev_midstate mismatch",
                    i
                );
            }
            if header.target != calculate_target(prev.height + 1, prev.timestamp) {
                bail!("invalid difficulty target at height {}", header.height);
            }
        }
        if header.height > 0 {
            // `context` keeps the typed `TimestampError` reachable, so the
            // caller can tell a header from the future (not yet valid here)
            // from an invalid one.
            validate_timestamp(header.timestamp, window.make_contiguous(), now)
                .with_context(|| format!("header {}", header.height))?;
        }
        window.push_back(header.timestamp);
        while window.len() > MEDIAN_TIME_PAST_WINDOW {
            window.pop_front();
        }
    }

    if check_pow {
        let checked: Vec<&BatchHeader> = headers.iter().filter(|h| h.height > 0).collect();
        // Each header's chain seed and expected result: its own for native
        // blocks, its parent's for merged-mined ones.
        let mut jobs: Vec<(u64, [u8; 32], [u8; 32])> = Vec::with_capacity(checked.len());
        for h in &checked {
            let mining_hash = compute_header_hash(h);
            match &h.aux_pow {
                None => {
                    if h.extension.final_hash >= h.target {
                        bail!("proof of work invalid at height {}", h.height);
                    }
                    jobs.push((
                        h.height,
                        pow_seed(&mining_hash, h.extension.nonce),
                        h.extension.final_hash,
                    ));
                }
                Some(aux) => {
                    aux.check_claims(&mining_hash, &h.extension, &h.target)
                        .map_err(|e| anyhow::anyhow!("header {}: {}", h.height, e))?;
                    jobs.push((h.height, aux.pow_seed(&mining_hash), aux.final_hash));
                }
            }
        }
        // The first header alone, so a chunk whose first header is forged
        // costs one extension; then pieces wide enough to keep every thread
        // busy, small enough that an abandoned verification stops within
        // seconds.
        let chains: Vec<([u8; 32], [u8; 32])> = jobs.iter().map(|j| (j.1, j.2)).collect();
        match check_pow_chains_with(&chains, &mut proceed) {
            Ok(()) => {}
            Err(PowCheck::Bad(i)) => bail!("proof of work invalid at height {}", jobs[i].0),
            Err(PowCheck::Abandoned) => bail!("header verification abandoned"),
        }
    }
    Ok(())
}

/// Batch requests outstanding at once, across all serving peers.
pub const MAX_BATCH_REQUESTS_IN_FLIGHT: usize = 4;
/// How far past the apply cursor blocks may be requested.
pub const BATCH_LOOKAHEAD_BLOCKS: u64 = 64 * 8;
/// Cap on downloaded-but-unapplied blocks held in memory.
pub const MAX_BUFFER_BYTES: usize = 64 * 1024 * 1024;
pub const BATCH_REQUEST_TIMEOUT_SECS: u64 = 20;
/// Header chunks held while an earlier one is being verified.
pub const MAX_QUEUED_HEADER_CHUNKS: usize = 2;

/// Header download and verification, chunk by chunk.
pub struct HeaderSync {
    /// First height requested by this session.
    pub start: u64,
    /// Where the peer's chain leaves ours, once known.
    pub fork: Option<u64>,
    /// Last header received (the next chunk must link to it).
    pub tip: Option<BatchHeader>,
    /// Timestamps preceding the next chunk to verify (median-time-past window).
    pub window: VecDeque<u64>,
    /// Every header below this height is verified.
    pub verified_to: u64,
    /// The chain weight of the block below `verified_to`: what the peer's
    /// chain weighs as far as it is verified, and the weight the next chunk
    /// builds on. Fork choice compares it with ours.
    pub verified_weight: u128,
    /// The fork-choice work window after the block below `verified_to`
    /// (`bond::cap_work`), which the next chunk's claims are checked
    /// against.
    pub work_floor: im::Vector<(u64, u128)>,
    pub queue: VecDeque<Vec<BatchHeader>>,
    pub verifying: bool,
    pub next_fetch: u64,
    pub fetch_in_flight: bool,
    /// A fetch waits for the verification queue to drain.
    pub fetch_deferred: bool,
    /// The peer has no more headers.
    pub done: bool,
    /// Resuming: the first header returned must be this one.
    pub expect_overlap: Option<[u8; 32]>,
    pub resumed: bool,
    /// The outstanding header request, so its reply can be held to it.
    pub request: Option<OutboundRequestId>,
}

pub struct InFlight {
    pub peer: PeerId,
    pub count: u64,
    pub sent: Instant,
    /// The request, so its reply can be held to it.
    pub request: Option<OutboundRequestId>,
}

/// Downloaded blocks waiting for their turn to be applied.
pub struct Chunk {
    pub source: PeerId,
    pub batches: Vec<Batch>,
    pub headers: Vec<BatchHeader>,
    pub bytes: usize,
}

/// Block download (from any peer that has the blocks) and application.
pub struct BlockSync {
    pub fork: u64,
    /// State after `cursor` blocks; `None` while rebuilding or applying.
    pub candidate: Option<State>,
    pub timestamps: VecDeque<u64>,
    /// Next height to apply.
    pub cursor: u64,
    pub applying: bool,
    /// The fork-point state is being derived off-thread.
    pub rebuilding: bool,
    /// Applied blocks not yet committed (while a reorg is still lighter),
    /// and what applying each changed (`State::effects`).
    pub staged: Vec<Batch>,
    pub staged_effects: Vec<std::sync::Arc<crate::core::types::BlockEffects>>,
    /// Whether our chain has been replaced (always true for fast-forwards).
    pub committed: bool,
    pub buffer: BTreeMap<u64, Chunk>,
    pub buffered_bytes: usize,
    pub in_flight: HashMap<u64, InFlight>,
    /// Ranges to request again (timeouts, truncated or rejected responses).
    pub retry: VecDeque<(u64, u64)>,
    pub next_request: u64,
    /// Peers not to ask again this session.
    pub excluded: HashSet<PeerId>,
}

impl BlockSync {
    pub fn new(fork: u64, timestamps: VecDeque<u64>, committed: bool) -> Self {
        Self {
            fork,
            candidate: None,
            timestamps,
            cursor: fork,
            applying: false,
            rebuilding: false,
            staged: Vec::new(),
            staged_effects: Vec::new(),
            committed,
            buffer: BTreeMap::new(),
            buffered_bytes: 0,
            in_flight: HashMap::new(),
            retry: VecDeque::new(),
            next_request: fork,
            excluded: HashSet::new(),
        }
    }
}

pub struct SyncSession {
    pub id: u64,
    /// The peer whose chain we are adopting; headers come only from it.
    pub peer: PeerId,
    pub peer_height: u64,
    /// The chain weight the peer claimed when the session started
    /// (`State::weight`): what its headers must reach.
    pub peer_weight: u128,
    pub step_back: u64,
    /// When the peer last sent something useful, or our own work on the
    /// session last finished.
    pub last_progress: Instant,
    pub headers: HeaderSync,
    /// Starts once verified headers outweigh our chain from the fork.
    pub blocks: Option<BlockSync>,
    /// Set when the session ends, however it ends, so that its background
    /// work stops instead of competing with the next session's.
    pub cancel: Arc<AtomicBool>,
}

impl SyncSession {
    /// Whether to drop the session: its peer has sent nothing for `idle`.
    ///
    /// Time spent on our own work does not count against the peer: a header
    /// chunk can take minutes to verify on one core, and timing out partway
    /// through would restart the same chunk forever. That work has its own,
    /// much longer limit ([`LOCAL_WORK_TIMEOUT`]) in case a task is stuck.
    pub fn timed_out(&self, idle: Duration) -> bool {
        let limit = if self.busy() {
            LOCAL_WORK_TIMEOUT
        } else {
            idle
        };
        self.last_progress.elapsed() > limit
    }

    /// Whether this node is working on the session: verifying headers,
    /// deriving the fork state or applying blocks.
    pub fn busy(&self) -> bool {
        self.headers.verifying
            || self
                .blocks
                .as_ref()
                .is_some_and(|b| b.applying || b.rebuilding)
    }
}

impl Drop for SyncSession {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

// ── Accountability ──────────────────────────────────────────────────────────
//
// Claiming a heavier chain costs a peer nothing; following the claim costs us
// a session, and only one runs at a time. So a claim has to be backed: a peer
// whose session ends without headers that reach the weight it claimed, or
// that goes quiet, is struck and barred from starting another session for a
// while, longer each time, and banned at the third strike. A peer that merely
// could not serve us is barred for a while without a strike.

/// Sessions a peer may fail to back before it is banned.
pub const SYNC_STRIKES_TO_BAN: u32 = 3;
/// How long a peer is barred after its first strike, or after a session it
/// could not serve (`NodeConfig::sync_cooldown`). Each further strike
/// doubles it.
pub const SYNC_COOLDOWN_SECS: u64 = 30;
/// Peers whose record is kept.
const MAX_SYNC_RECORDS: usize = 4096;

/// What a session's end says about its peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blame {
    /// Nothing: the session finished, or showed that our chain had caught up.
    None,
    /// The peer could not serve us (it went away, is ahead of our clock, is
    /// on a fork we cannot follow), or our own side failed: no misbehaviour,
    /// but no immediate retry either.
    Pause,
    /// The peer claimed a heavier chain and did not back the claim.
    Strike,
}

/// Per-peer sync record: strikes, and until when a peer may not start a
/// session.
#[derive(Debug, Default)]
pub struct SyncRecord {
    peers: HashMap<PeerId, (u32, Instant)>,
}

impl SyncRecord {
    /// Records how a session with `peer` ended. Returns whether the peer is
    /// now to be banned.
    pub fn record(&mut self, peer: PeerId, blame: Blame, cooldown: Duration) -> bool {
        if blame == Blame::None {
            return false;
        }
        let now = Instant::now();
        if self.peers.len() >= MAX_SYNC_RECORDS && !self.peers.contains_key(&peer) {
            self.peers
                .retain(|_, (strikes, until)| *strikes > 0 || *until > now);
            if self.peers.len() >= MAX_SYNC_RECORDS {
                self.peers.clear();
            }
        }
        let (strikes, until) = self.peers.entry(peer).or_insert((0, now));
        match blame {
            Blame::None => {}
            Blame::Pause => *until = (*until).max(now + cooldown),
            Blame::Strike => {
                *strikes += 1;
                if *strikes >= SYNC_STRIKES_TO_BAN {
                    self.peers.remove(&peer);
                    return true;
                }
                *until = now + cooldown * 2u32.pow(*strikes - 1);
            }
        }
        false
    }

    /// Whether `peer` may not start a session now.
    pub fn barred(&self, peer: &PeerId) -> bool {
        self.peers
            .get(peer)
            .is_some_and(|(_, until)| *until > Instant::now())
    }

    pub fn strikes(&self, peer: &PeerId) -> u32 {
        self.peers.get(peer).map_or(0, |(strikes, _)| *strikes)
    }

    /// A session with `peer` brought us its chain: its record is clean.
    pub fn succeeded(&mut self, peer: &PeerId) {
        self.peers.remove(peer);
    }
}

/// Counters exposed for operators and tests.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct SyncStats {
    pub sessions: u64,
    pub resumed: u64,
    pub header_chunks_verified: u64,
    pub batch_chunks_applied: u64,
    /// Distinct peers that supplied applied blocks.
    pub batch_sources: usize,
}

#[cfg(all(test, feature = "fast-mining"))]
mod tests {
    use super::*;
    use crate::core::mw::WalletKeys;
    use crate::core::state::apply_batch;
    use crate::core::template::build_template;

    fn headers(n: usize) -> Vec<BatchHeader> {
        let payout = WalletKeys::random().address();
        let mut state = State::genesis();
        apply_batch(&mut state, Batch::genesis(), &[]).unwrap();
        let mut g = Batch::genesis().header();
        g.height = 0;
        let mut out = vec![g];
        let mut ts = vec![Batch::genesis().timestamp];
        for _ in 0..n {
            let b = build_template(&state, &ts, &[], &payout, None)
                .unwrap()
                .mine_blocking();
            let mut h = b.header();
            h.height = state.height;
            apply_batch(&mut state, &b, &ts).unwrap();
            ts.push(b.timestamp);
            out.push(h);
        }
        out
    }

    /// The work window after `hs`, as a node holding them computes it.
    fn floor_after(hs: &[BatchHeader]) -> im::Vector<(u64, u128)> {
        let mut floor = im::Vector::new();
        for h in hs {
            crate::core::bond::cap_work(&mut floor, h.height, calculate_work(&h.target));
        }
        floor
    }

    #[test]
    fn valid_chain_verifies_and_tampering_is_caught() {
        let hs = headers(6);
        let none = im::Vector::new();
        verify_header_chain(&hs, &[], 0, &none, true).unwrap();
        verify_header_chain(
            &hs[3..],
            &hs[..3].iter().map(|h| h.timestamp).collect::<Vec<_>>(),
            hs[2].chain_weight,
            &floor_after(&hs[..3]),
            true,
        )
        .unwrap();

        let mut bad = hs.clone();
        bad[4].extension.nonce ^= 1;
        assert!(verify_header_chain(&bad, &[], 0, &none, true).is_err());

        let mut relinked = hs.clone();
        relinked[5].prev_header_hash = [9; 32];
        assert!(verify_header_chain(&relinked, &[], 0, &none, false).is_err());

        let mut easier = hs.clone();
        easier[2].target = [0x01; 32];
        assert!(verify_header_chain(&easier, &[], 0, &none, false).is_err());
    }

    /// A header's chain weight can only grow by what its block could add,
    /// and the proof of work covers the claim.
    #[test]
    fn claimed_chain_weights_are_checked() {
        let hs = headers(4);
        let none = im::Vector::new();
        let work = calculate_work(&hs[2].target);
        assert_eq!(hs[2].chain_weight - hs[1].chain_weight, work);
        // From the wrong starting weight, or growing by anything else.
        let floor = floor_after(&hs[..1]);
        assert!(verify_header_chain(&hs[1..], &[hs[0].timestamp], 1, &floor, false).is_err());
        for claimed in [0, work + 1, work * 2, u128::MAX] {
            let mut lying = hs.clone();
            lying[2].chain_weight = lying[1].chain_weight.saturating_add(claimed);
            let err = verify_header_chain(&lying, &[], 0, &none, false).unwrap_err();
            assert!(err.to_string().contains("chain weight"), "{claimed}: {err}");
        }
        // A signer changes what is possible (see `bond::credit_possible`),
        // but the proof of work covers both fields: changing either, even to
        // something possible, is forgery.
        let mut signed = hs.clone();
        signed[2].signer = Some([7; 32]);
        verify_header_chain(&signed, &[], 0, &none, false).unwrap();
        assert!(verify_header_chain(&signed, &[], 0, &none, true).is_err());
    }

    /// The work window comes from the headers, so the work cap is checked
    /// exactly: after a cheaper block, the same headers' full-work claims
    /// are more than their blocks could add.
    #[test]
    fn claimed_weights_respect_the_work_cap() {
        let hs = headers(4);
        let (prior, parent) = ([hs[0].timestamp], hs[0].chain_weight);
        verify_header_chain(&hs[1..], &prior, parent, &floor_after(&hs[..1]), false).unwrap();
        let cheaper = im::vector![(0u64, calculate_work(&hs[1].target) / 2)];
        let err = verify_header_chain(&hs[1..], &prior, parent, &cheaper, false).unwrap_err();
        assert!(err.to_string().contains("chain weight"), "{err}");
    }

    #[test]
    fn verification_reports_its_pieces_and_can_be_abandoned() {
        let hs = headers(6);
        let mut seen = 0;
        verify_header_chain_with(&hs, &[], 0, &im::Vector::new(), true, |n| {
            seen += n;
            true
        })
        .unwrap();
        assert_eq!(seen, 6, "every header but genesis goes through a piece");
        let err =
            verify_header_chain_with(&hs, &[], 0, &im::Vector::new(), true, |_| false).unwrap_err();
        assert!(err.to_string().contains("abandoned"), "{err:#}");
    }

    fn session(verifying: bool, blocks: Option<BlockSync>, quiet_for: Duration) -> SyncSession {
        SyncSession {
            id: 1,
            peer: PeerId::random(),
            peer_height: 100,
            peer_weight: 100,
            step_back: INITIAL_STEP_BACK,
            last_progress: Instant::now() - quiet_for,
            headers: HeaderSync {
                start: 0,
                fork: None,
                tip: None,
                window: VecDeque::new(),
                verified_to: 0,
                verified_weight: 0,
                work_floor: im::Vector::new(),
                queue: VecDeque::new(),
                verifying,
                next_fetch: 0,
                fetch_in_flight: false,
                fetch_deferred: false,
                done: false,
                expect_overlap: None,
                resumed: false,
                request: None,
            },
            blocks,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    #[test]
    fn our_own_slow_work_does_not_time_out_a_session() {
        let idle = Duration::from_secs(SYNC_TIMEOUT_SECS);
        let minute = Duration::from_secs(60);
        // A quiet peer is dropped.
        assert!(session(false, None, minute).timed_out(idle));
        assert!(!session(false, None, Duration::ZERO).timed_out(idle));
        // A minute spent verifying headers, applying blocks or deriving the
        // fork state is ours, not the peer's.
        assert!(!session(true, None, minute).timed_out(idle));
        let mut applying = BlockSync::new(0, VecDeque::new(), true);
        applying.applying = true;
        assert!(!session(false, Some(applying), minute).timed_out(idle));
        let mut rebuilding = BlockSync::new(0, VecDeque::new(), false);
        rebuilding.rebuilding = true;
        assert!(!session(false, Some(rebuilding), minute).timed_out(idle));
        // A stuck task still ends the session eventually.
        let stuck = LOCAL_WORK_TIMEOUT + minute;
        assert!(session(true, None, stuck).timed_out(idle));
    }

    /// Unbacked claims are struck, barred for longer each time and banned at
    /// the third strike; pauses bar without striking; a finished session
    /// clears the record.
    #[test]
    fn peers_that_do_not_back_their_claims_are_struck_then_banned() {
        let cooldown = Duration::from_secs(30);
        let mut record = SyncRecord::default();
        let liar = PeerId::random();
        assert!(!record.barred(&liar));
        assert!(!record.record(liar, Blame::Strike, cooldown));
        assert!(record.barred(&liar));
        assert_eq!(record.strikes(&liar), 1);
        assert!(!record.record(liar, Blame::Strike, cooldown));
        let barred_for = record.peers[&liar].1 - Instant::now();
        assert!(
            barred_for > cooldown && barred_for <= cooldown * 2,
            "doubled"
        );
        assert!(
            record.record(liar, Blame::Strike, cooldown),
            "banned at the third"
        );
        assert_eq!(record.strikes(&liar), 0, "forgotten once banned");

        let slow = PeerId::random();
        for _ in 0..SYNC_STRIKES_TO_BAN + 1 {
            assert!(!record.record(slow, Blame::Pause, cooldown));
        }
        assert!(record.barred(&slow));
        assert_eq!(record.strikes(&slow), 0, "pauses are not strikes");
        assert!(!record.record(slow, Blame::None, Duration::ZERO));
        assert!(
            record.barred(&slow),
            "nothing lifts a bar early but success"
        );

        let honest = PeerId::random();
        record.record(honest, Blame::Strike, cooldown);
        record.succeeded(&honest);
        assert!(!record.barred(&honest));
        assert_eq!(record.strikes(&honest), 0);

        // Short cooldowns expire.
        let quick = PeerId::random();
        record.record(quick, Blame::Pause, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        assert!(!record.barred(&quick));
    }

    #[test]
    fn a_dropped_session_cancels_its_work() {
        let s = session(true, None, Duration::ZERO);
        let cancel = s.cancel.clone();
        assert!(!cancel.load(Ordering::Relaxed));
        drop(s);
        assert!(cancel.load(Ordering::Relaxed));
    }
}
