//! Headers-first synchronisation.
//!
//! From midstate `src/sync.rs`: `verify_header_chain` (sequential linkage,
//! median-time-past and ASERT target checks, then proof of work verified in
//! parallel), fork-point search against stored hashes, and a session that
//! walks `Headers → Batches`. Midstate's pipelined rebuild, prefetch buffers
//! and on-disk resume are left out; the session here is the simple core of
//! that design, and the node drives it (see `node.rs`).

use crate::core::simd_mining::{pow_seed, verify_pow_batch};
use crate::core::state::{calculate_target, calculate_work, current_timestamp, validate_timestamp};
use crate::core::types::{compute_header_hash, MEDIAN_TIME_PAST_WINDOW};
use crate::core::{Batch, BatchHeader, State};
use anyhow::{bail, Result};
use libp2p::PeerId;
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Instant;

pub const SYNC_TIMEOUT_SECS: u64 = 45;
/// Refuse to reorganise away more than this many blocks.
pub const MAX_REORG_DEPTH: u64 = 1_000;
/// How far below our tip a new session starts asking for headers.
pub const INITIAL_STEP_BACK: u64 = 16;

/// Checks a run of consecutive headers.
///
/// `prior_timestamps` are the timestamps of the blocks just below
/// `headers[0]` (oldest first); the last one also fixes `headers[0]`'s
/// expected target. The caller checks that `headers[0]` links to its own
/// chain.
pub fn verify_header_chain(
    headers: &[BatchHeader],
    prior_timestamps: &[u64],
    check_pow: bool,
) -> Result<()> {
    let Some(first) = headers.first() else {
        return Ok(());
    };
    let now = current_timestamp();

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
            validate_timestamp(header.timestamp, window.make_contiguous(), now)
                .map_err(|e| anyhow::anyhow!("header {}: {}", header.height, e))?;
        }
        window.push_back(header.timestamp);
        while window.len() > MEDIAN_TIME_PAST_WINDOW {
            window.pop_front();
        }
    }

    if check_pow {
        // Midstate's approach: rayon over SIMD-width chunks, each chunk
        // hashing all of its lanes' chains simultaneously.
        let lanes = crate::core::simd_mining::detected_level().lanes().max(1);
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
        let bad = jobs.par_chunks(lanes).find_map_any(|chunk| {
            let seeds: Vec<[u8; 32]> = chunk.iter().map(|j| j.1).collect();
            let finals = verify_pow_batch(&seeds);
            chunk
                .iter()
                .zip(finals)
                .find(|(j, f)| *f != j.2)
                .map(|(j, _)| j.0)
        });
        if let Some(height) = bad {
            bail!("proof of work invalid at height {}", height);
        }
    }
    Ok(())
}

/// Cumulative work of a run of headers.
pub fn headers_work(headers: &[BatchHeader]) -> u128 {
    headers.iter().fold(0u128, |acc, h| {
        acc.saturating_add(calculate_work(&h.target))
    })
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
    /// Work of verified headers from the fork.
    pub their_work: u128,
    /// Work of our own blocks from the fork.
    pub our_work: u128,
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
}

pub struct InFlight {
    pub peer: PeerId,
    pub count: u64,
    pub sent: Instant,
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
    /// Applied blocks not yet committed (while a reorg is still lighter).
    pub staged: Vec<Batch>,
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
    pub peer_depth: u128,
    pub step_back: u64,
    pub last_progress: Instant,
    pub headers: HeaderSync,
    /// Starts once verified headers outweigh our chain from the fork.
    pub blocks: Option<BlockSync>,
}

impl SyncSession {
    pub fn timed_out(&self) -> bool {
        self.last_progress.elapsed().as_secs() > SYNC_TIMEOUT_SECS
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

    #[test]
    fn valid_chain_verifies_and_tampering_is_caught() {
        let hs = headers(6);
        verify_header_chain(&hs, &[], true).unwrap();
        verify_header_chain(
            &hs[3..],
            &hs[..3].iter().map(|h| h.timestamp).collect::<Vec<_>>(),
            true,
        )
        .unwrap();
        assert!(headers_work(&hs) > 0);

        let mut bad = hs.clone();
        bad[4].extension.nonce ^= 1;
        assert!(verify_header_chain(&bad, &[], true).is_err());

        let mut relinked = hs.clone();
        relinked[5].prev_header_hash = [9; 32];
        assert!(verify_header_chain(&relinked, &[], false).is_err());

        let mut easier = hs.clone();
        easier[2].target = [0x01; 32];
        assert!(verify_header_chain(&easier, &[], false).is_err());
    }
}
