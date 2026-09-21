//! Consensus data structures.
//!
//! # Provenance
//!
//! From midstate `src/core/types.rs`: BLAKE3 helpers, the running `midstate`
//! hash chain, the `Extension` / `Batch` / `BatchHeader` layout,
//! `compute_header_hash`, the difficulty, timestamp and economic constants and
//! `block_reward`.
//!
//! Replaced: the commit/reveal `Transaction` enum, script predicates and
//! power-of-two coin ids. A batch now carries one aggregated MimbleWimble
//! transaction plus a coinbase.
//!
//! Removed: every historical activation height (V2, V4, commit-replay fix,
//! commit weight and its cap, timewarp fix). This is a new chain, so midstate's
//! latest rules are simply always on: domain-separated accumulators and a
//! 15-minute future-timestamp bound. The commit-weight bonus has no analogue
//! because there are no Commit transactions, so fork choice is plain
//! cumulative proof-of-work.

use super::bond::{BondEntry, BondRegistration, MinerAuth};
use super::auxpow::AuxPow;
use super::mmr::{MerkleMountainRange, UtxoAccumulator};
use super::mw::crypto::{self, Point32, Scalar32, IDENTITY};
use super::mw::{Coinbase, Transaction};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

// ── Hashing (midstate) ──────────────────────────────────────────────────────

/// BLAKE3 of a byte slice.
pub fn hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// BLAKE3(a ‖ b).
pub fn hash_concat(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(a);
    hasher.update(b);
    *hasher.finalize().as_bytes()
}

/// BLAKE3 over a domain label and length-prefixed parts. Used for every new
/// hash introduced by the MimbleWimble layer, so that no two purposes can
/// collide by construction.
pub fn hash_domain(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// Number of leading zero bits in a hash.
pub fn count_leading_zeros(hash: &[u8; 32]) -> u32 {
    let mut zeros = 0;
    for &byte in hash {
        if byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros();
            break;
        }
    }
    zeros
}

// ── Network identity and launch parameters ──────────────────────────────────

/// Compile-time hex decoding, so launch parameters read as the hex strings
/// they are announced as.
const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64, "a 32-byte hex string is 64 characters");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = hex_digit(b[2 * i]);
        let lo = hex_digit(b[2 * i + 1]);
        out[i] = hi * 16 + lo;
        i += 1;
    }
    out
}

const fn hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("not a hex digit"),
    }
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║ LAUNCH PARAMETERS                                                        ║
// ║                                                                          ║
// ║ Everything between the markers is written by                             ║
// ║ `scripts/set_launch_params.py` on launch day (see `docs/LAUNCH.md`).     ║
// ║ The values below are devnet placeholders: they carry midstate's own      ║
// ║ Bitcoin anchor and genesis target, so a build made from them is a        ║
// ║ devnet build and says so (`LAUNCH_PARAMETERS_SET`).                      ║
// ╚══════════════════════════════════════════════════════════════════════════╝
// @launch-params:begin

/// Distinguishes this network from midstate and from other deployments of
/// this code. Feeds the genesis midstate, every signed message, the merged-
/// mining commitment and the DHT rendezvous key.
pub const NETWORK_MAGIC: &[u8] = b"MIDWIMBLE_DEVNET_V1";

/// Bitcoin block anchoring the genesis. Its hash cannot be known before it is
/// mined, so a chain committing to it cannot have been started (or quietly
/// pre-mined) any earlier. **Pick a block mined after the code freeze.**
pub const BITCOIN_BLOCK_HASH: &str =
    "000000000000000000018f5ad5625d43356136c2e50c6dc18967a90a18f0af2e";
pub const BITCOIN_BLOCK_HEIGHT: u64 = 938708;
/// The anchor block's own timestamp. Genesis may not precede it.
pub const BITCOIN_BLOCK_TIME: u64 = 1_772_274_770;

/// Midstate block anchoring the genesis: midstate's tip at launch. Like the
/// Bitcoin anchor it cannot be known before it is mined, and it pins the
/// midstate chain that bonded mining is judged against. Placeholder: zeros.
pub const MIDSTATE_BLOCK_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
pub const MIDSTATE_BLOCK_HEIGHT: u64 = 0;

/// Mainnet genesis time; see [`GENESIS_TIMESTAMP`].
const LAUNCH_GENESIS_TIMESTAMP: u64 = 1_789_430_400; // 2026-09-15 00:00:00 UTC — placeholder

/// Mainnet genesis target; see [`GENESIS_TARGET`]. Placeholder: midstate's
/// genesis target, which is calibrated for one machine and is roughly four
/// orders of magnitude too easy for a network of merged miners.
const LAUNCH_GENESIS_TARGET: [u8; 32] =
    hex32("0011ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

/// False while the parameters above are placeholders. The node says so at
/// startup and `midwimble params` prints it, so a release built without
/// running the launch script cannot be mistaken for the real network.
pub const LAUNCH_PARAMETERS_SET: bool = false;

// @launch-params:end

/// Genesis cannot predate the Bitcoin block it commits to.
const _: () = assert!(LAUNCH_GENESIS_TIMESTAMP >= BITCOIN_BLOCK_TIME);

/// A build claiming real launch parameters must not carry the devnet
/// placeholder target (midstate's genesis target, 0x0011ff…) or anything
/// easier: it would open the chain with thousands of near-free blocks.
const _: () = assert!(
    !LAUNCH_PARAMETERS_SET || (LAUNCH_GENESIS_TARGET[0] == 0 && LAUNCH_GENESIS_TARGET[1] < 0x11)
);

const GENESIS_INSCRIPTION: &[u8] =
    b"midwimble: midstate consensus and networking, pluribit mimblewimble";

/// Stable 32-byte network identity (midstate `network_anchor`).
///
/// Midstate hashes only the Bitcoin anchor. The magic is mixed in here so that
/// this network's DHT rendezvous key differs from midstate's even though the
/// anchor block is the same; otherwise the two networks would discover each
/// other and waste every dial on a failed handshake.
pub fn network_anchor() -> [u8; 32] {
    hash_domain(
        b"midwimble.network-anchor.v1",
        &[BITCOIN_BLOCK_HASH.as_bytes(), NETWORK_MAGIC],
    )
}

// ── Timing and difficulty (midstate) ────────────────────────────────────────

pub const TARGET_BLOCK_TIME: u64 = 60;
/// ASERT half-life in seconds.
pub const ASERT_HALF_LIFE: i64 = 4 * 60 * 60;
/// Recent block timestamps kept by the node for median-time-past checks.
pub const DIFFICULTY_LOOKBACK: u64 = 60;
pub const MEDIAN_TIME_PAST_WINDOW: usize = 11;
/// Midstate's post-timewarp-fix bound, active from genesis here.
pub const MAX_FUTURE_BLOCK_TIME: u64 = 15 * 60;
pub const PRUNE_DEPTH: u64 = 1000;

/// ASERT is anchored to the genesis timestamp: difficulty follows the drift
/// between wall-clock time since genesis and `height × TARGET_BLOCK_TIME`.
///
/// **Set this to the actual launch time.** Midstate anchored to its Bitcoin
/// block's timestamp and launched immediately. A chain launched long after its
/// anchor would see a huge positive drift, clamp difficulty to the floor, and
/// mine thousands of near-free blocks until it caught up with the schedule.
/// Blocks cannot be mined before this instant (timestamps must exceed it).
#[cfg(not(feature = "fast-mining"))]
pub const GENESIS_TIMESTAMP: u64 = LAUNCH_GENESIS_TIMESTAMP;
#[cfg(feature = "fast-mining")]
pub const GENESIS_TIMESTAMP: u64 = 1_700_000_000;

/// The target block 1 must meet, and the reference point ASERT measures
/// every later target against.
///
/// Calibrate it on launch day from the midstate node's own `/state` target:
/// both chains run the same proof of work at the same 60-second spacing, so
/// `GENESIS_TARGET = midstate_target / expected_merge_mining_share`. Too easy
/// and the first hours produce thousands of near-free blocks while ASERT
/// catches up; too hard only makes early blocks slow, which the slow start
/// makes harmless. Err on the side of too hard.
#[cfg(not(feature = "fast-mining"))]
pub const GENESIS_TARGET: [u8; 32] = LAUNCH_GENESIS_TARGET;
#[cfg(feature = "fast-mining")]
pub const GENESIS_TARGET: [u8; 32] = {
    let mut t = [0xffu8; 32];
    t[0] = 0x0f;
    t
};

/// Sequential BLAKE3 iterations per proof-of-work attempt (midstate).
#[cfg(not(feature = "fast-mining"))]
pub const EXTENSION_ITERATIONS: u64 = 1_000_000;
#[cfg(feature = "fast-mining")]
pub const EXTENSION_ITERATIONS: u64 = 100;

// ── Economics ───────────────────────────────────────────────────────────────

pub const BLOCKS_PER_YEAR: u64 = 365 * 24 * 3600 / TARGET_BLOCK_TIME;

/// Base units in one coin: amounts carry 8 decimal places.
pub const COIN: u64 = 100_000_000;

/// Every coin that will ever exist: 1,000,000.00000000, reached exactly.
pub const MAX_SUPPLY: u64 = 1_000_000 * COIN;

/// Blocks per era; the reward halves at each multiple of this height.
///
/// 2,100,000 × 60 s = 126,000,000 s, the same wall-clock era as Bitcoin's
/// 210,000 × 600 s. ASERT is anchored to the genesis timestamp rather than a
/// sliding window, so the chain tracks that schedule instead of drifting ahead
/// of it: halvings land within a day or so of `GENESIS_TIMESTAMP + k ×
/// 126,000,000 s` as long as the hashrate stays within a few dozen times its
/// launch calibration.
pub const HALVING_INTERVAL: u64 = 2_100_000;

/// Slow start: the reward climbs linearly from ~0 to [`INITIAL_REWARD`] over
/// the first 30 days.
///
/// Launch day is when the least is known about the chain and when whoever
/// happens to hold hashrate — or has quietly pre-mined against a published
/// genesis — can take the most. Ramping the reward makes that window close to
/// worthless (day one pays about 5.7 coins rather than 343) and buys the time
/// difficulty discovery, merged-mining integration and word of mouth all need.
/// A plain proof-of-work chain pays for this in early security; a merge-mined
/// one does not, because its hashrate comes from midstate at nearly no extra
/// cost to the miner.
#[cfg(not(feature = "fast-mining"))]
pub const SLOW_START_BLOCKS: u64 = 30 * 24 * 60;
#[cfg(feature = "fast-mining")]
pub const SLOW_START_BLOCKS: u64 = 0;

/// Era-0 reward once the slow start is over: 0.23932616 coins.
///
/// The smallest reward whose schedule reaches [`MAX_SUPPLY`]; the 0.034 coins
/// it overshoots by are trimmed off the final blocks, so issuance stops at
/// exactly 1,000,000.00000000 rather than approaching it.
pub const INITIAL_REWARD: u64 = 23_932_616;

/// A slow start that outlasted its own era would make the schedule
/// meaningless, and the closed form below assumes it does not.
const _: () = assert!(SLOW_START_BLOCKS < HALVING_INTERVAL);

/// The emission curve: a linear slow start, then halvings, then a hard cap.
///
/// Defined by its *running total* rather than by a per-block formula. The
/// cumulative form has a closed form at every height, which makes three
/// things true that matter more than elegance:
///
/// * the cap is exact by construction — the last block to mint pays whatever
///   is left rather than a full reward, and every block after it pays nothing;
/// * any node can check a claimed supply at any height in microseconds, so a
///   snapshot or checkpoint cannot smuggle in coins the schedule never
///   allowed (see `core/snapshot.rs`);
/// * `block_reward` is just the difference between two neighbouring totals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Emission {
    pub initial_reward: u64,
    pub halving_interval: u64,
    pub slow_start: u64,
    pub max_supply: u64,
}

/// The schedule this build enforces.
pub const EMISSION: Emission = Emission {
    initial_reward: INITIAL_REWARD,
    halving_interval: HALVING_INTERVAL,
    slow_start: SLOW_START_BLOCKS,
    max_supply: MAX_SUPPLY,
};

/// Mainnet's schedule, whatever features this build carries. Tests assert the
/// real curve's properties even when compiled with `fast-mining`.
pub const MAINNET_EMISSION: Emission = Emission {
    initial_reward: 23_932_616,
    halving_interval: 2_100_000,
    slow_start: 30 * 24 * 60,
    max_supply: 1_000_000 * COIN,
};

impl Emission {
    /// Issuance scheduled for blocks `1..height`, before the cap applies.
    /// Genesis (height 0) mints nothing.
    fn scheduled_before(&self, height: u64) -> u128 {
        let last = match height.checked_sub(1) {
            None | Some(0) => return 0,
            Some(h) => h as u128,
        };
        let reward = self.initial_reward as u128;
        let ramp = self.slow_start as u128;
        let interval = self.halving_interval as u128;

        // Slow start: after m blocks, reward·m(m+1)/2·ramp coins, so each
        // block pays about reward·h/ramp and the ramp's last block pays the
        // full reward.
        let m = last.min(ramp);
        let mut total = if ramp == 0 {
            0
        } else {
            reward * m * (m + 1) / (2 * ramp)
        };
        // The rest of era 0.
        if last > ramp {
            total += (last.min(interval - 1) - ramp) * reward;
        }
        // Eras 1, 2, …: [k·interval, (k+1)·interval) paying reward >> k.
        let mut k = 1u32;
        while k < 64 {
            let start = k as u128 * interval;
            if start > last {
                break;
            }
            let era_reward = reward >> k;
            if era_reward == 0 {
                break;
            }
            let end = last.min(start + interval - 1);
            total += (end - start + 1) * era_reward;
            k += 1;
        }
        total
    }

    /// Coins in existence with `height` as the next block's height — that is,
    /// after every block below `height` has been applied. A chain state's
    /// `supply` field always equals this.
    pub fn issued_before(&self, height: u64) -> u64 {
        self.scheduled_before(height)
            .min(self.max_supply as u128) as u64
    }

    /// What the block at `height` may mint.
    pub fn block_reward(&self, height: u64) -> u64 {
        if height == 0 {
            return 0;
        }
        self.issued_before(height.saturating_add(1)) - self.issued_before(height)
    }

    /// Height of the last block that mints anything, if the cap is ever
    /// reached. Everything above it pays fees only.
    pub fn final_reward_height(&self) -> Option<u64> {
        let (mut lo, mut hi) = (1u64, 64u64.saturating_mul(self.halving_interval));
        if self.issued_before(hi.saturating_add(1)) < self.max_supply {
            return None;
        }
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.issued_before(mid.saturating_add(1)) >= self.max_supply {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        Some(lo)
    }
}

/// What the block at `height` may mint, under this build's schedule.
pub fn block_reward(height: u64) -> u64 {
    EMISSION.block_reward(height)
}

/// The supply a state whose next block is `height` must have.
pub fn issued_before(height: u64) -> u64 {
    EMISSION.issued_before(height)
}

// ── Amounts ─────────────────────────────────────────────────────────────────

/// Formats base units as coins, e.g. `23_932_616` → `"0.23932616"`.
pub fn format_amount(units: u64) -> String {
    format!("{}.{:08}", units / COIN, units % COIN)
}

/// Parses an amount written in coins, e.g. `"0.239"` → `23_900_000` units.
pub fn parse_amount(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if whole.is_empty() && frac.is_empty() {
        anyhow::bail!("empty amount");
    }
    if !whole.bytes().chain(frac.bytes()).all(|c| c.is_ascii_digit()) {
        anyhow::bail!("'{s}' is not an amount in coins (digits and one '.')");
    }
    if frac.len() > 8 {
        anyhow::bail!("amounts carry at most 8 decimal places");
    }
    let scale = 10u64.pow(8 - frac.len() as u32);
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse()? };
    let frac: u64 = if frac.is_empty() { 0 } else { frac.parse()? };
    let units = whole
        .checked_mul(COIN)
        .and_then(|u| u.checked_add(frac * scale))
        .ok_or_else(|| anyhow::anyhow!("amount out of range"))?;
    if units > MAX_SUPPLY {
        anyhow::bail!(
            "{s} is more than the whole {} coin supply (amounts are in coins, not base units)",
            MAX_SUPPLY / COIN
        );
    }
    Ok(units)
}

/// Blocks before a coinbase output may be spent (pluribit's rule; midstate had
/// none). Protects against reorgs invalidating chains of spends that descend
/// from a reorged-away reward.
#[cfg(not(feature = "fast-mining"))]
pub const COINBASE_MATURITY: u64 = 100;
#[cfg(feature = "fast-mining")]
pub const COINBASE_MATURITY: u64 = 3;

// ── Block limits ────────────────────────────────────────────────────────────

/// Weights follow Grin: an output (with its share of a range proof) costs far
/// more to verify and store than an input or kernel.
pub const INPUT_WEIGHT: u64 = 1;
pub const OUTPUT_WEIGHT: u64 = 21;
pub const KERNEL_WEIGHT: u64 = 3;
/// Roughly 1,900 outputs, under a second of range-proof verification on
/// several cores, and well below the 10 MB network message cap.
pub const MAX_BLOCK_WEIGHT: u64 = 40_000;
/// Relay limit for one transaction.
pub const MAX_TX_WEIGHT: u64 = 10_000;
/// Minimum relay fee per weight unit (local policy, not consensus).
///
/// 100 units puts an ordinary one-input, two-output payment at 4,600 base
/// units (0.000046 coins) and a full block of spam at 0.04 coins. It is a
/// tenth of what this code inherited, because the supply it is denominated
/// against is about a tenth the size: the point is to keep the floor where it
/// was *relative to the coin*, which for a privacy chain matters twice over —
/// every payment anyone is willing to make also enlarges the anonymity set.
pub const MIN_FEE_PER_WEIGHT: u64 = 100;

// ── UTXO records ────────────────────────────────────────────────────────────

/// What consensus remembers about an unspent output.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct UtxoEntry {
    /// `Output::metadata_hash`: commits the leaf to the whole output
    /// (scanning data included), so snapshots cannot alter it.
    pub output_hash: [u8; 32],
    pub owner_key: Point32,
    /// See `core/recovery.rs`; committed so checkpoints carry it.
    pub recovery_commitment: [u8; 32],
    pub height: u64,
    pub coinbase: bool,
}

/// Leaf committed into the UTXO accumulator. Covers every field of the entry,
/// so the state root commits to owner keys and maturity data too.
pub fn utxo_leaf(commitment: &Point32, entry: &UtxoEntry) -> [u8; 32] {
    hash_domain(
        b"midwimble.utxo-leaf.v1",
        &[
            commitment,
            &entry.output_hash,
            &entry.owner_key,
            &entry.recovery_commitment,
            &entry.height.to_le_bytes(),
            &[entry.coinbase as u8],
        ],
    )
}

/// The inputs of a state root.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateRootParts {
    pub utxo_root: [u8; 32],
    pub kernel_root: [u8; 32],
    pub chain_mmr_root: [u8; 32],
    pub kernel_excess_sum: Point32,
    pub total_kernel_offset: Scalar32,
    pub supply: u64,
    /// Commitment to the registered bond set ([`bonds_root`]).
    pub bonds_root: [u8; 32],
}

impl StateRootParts {
    pub fn root(&self) -> [u8; 32] {
        hash_domain(
            b"midwimble.state-root.v1",
            &[
                &self.utxo_root,
                &self.kernel_root,
                &self.chain_mmr_root,
                &self.kernel_excess_sum,
                &self.total_kernel_offset,
                &self.supply.to_le_bytes(),
                &self.bonds_root,
            ],
        )
    }
}

// ── Global state ────────────────────────────────────────────────────────────

/// Chain state after `height` blocks (so `height` is also the height of the
/// next block). Every collection is persistent (`im`), making clones O(1),
/// which midstate relies on for candidate states and the reorg cache.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    /// Running hash over every applied block (midstate).
    pub mw_midstate: [u8; 32],
    /// Unspent outputs keyed by commitment.
    pub utxos: im::HashMap<Point32, UtxoEntry>,
    /// Sparse Merkle tree over [`utxo_leaf`]s.
    pub utxo_set: UtxoAccumulator,
    /// Sparse Merkle tree over every kernel id ever mined (never pruned).
    pub kernels: UtxoAccumulator,
    /// Σ of every kernel excess, coinbase included.
    pub kernel_excess_sum: Point32,
    /// Σ of every block's Pedersen offset.
    pub total_kernel_offset: Scalar32,
    /// Coins minted so far.
    pub supply: u64,
    /// Cumulative proof-of-work.
    pub depth: u128,
    /// Target the next block must meet.
    pub target: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    /// Append-only log of block hashes, for light-client proofs (midstate).
    #[serde(default)]
    pub chain_mmr: MerkleMountainRange,
    /// `extension.final_hash` of the tip.
    pub header_hash: [u8; 32],
    /// Registered mining bonds, by bond id (`core/bond.rs`).
    #[serde(default)]
    pub bonds: im::HashMap<[u8; 32], BondEntry>,
}

impl State {
    /// The state before genesis is applied.
    pub fn genesis() -> Self {
        let anchor = network_anchor();
        let initial = hash_domain(
            b"midwimble.genesis.v1",
            &[
                &anchor,
                &BITCOIN_BLOCK_HEIGHT.to_le_bytes(),
                MIDSTATE_BLOCK_HASH.as_bytes(),
                &MIDSTATE_BLOCK_HEIGHT.to_le_bytes(),
                GENESIS_INSCRIPTION,
            ],
        );
        Self {
            mw_midstate: initial,
            bonds: im::HashMap::new(),
            utxos: im::HashMap::new(),
            utxo_set: UtxoAccumulator::new(),
            kernels: UtxoAccumulator::new(),
            kernel_excess_sum: IDENTITY,
            total_kernel_offset: [0u8; 32],
            supply: 0,
            depth: 0,
            target: GENESIS_TARGET,
            height: 0,
            timestamp: GENESIS_TIMESTAMP,
            chain_mmr: MerkleMountainRange::new(),
            header_hash: initial,
        }
    }

    /// Commitment to everything consensus tracks. Computed after a block's
    /// body is applied but before its own hash joins `chain_mmr`, exactly as
    /// midstate does.
    pub fn state_root(&self) -> [u8; 32] {
        self.root_parts().root()
    }

    /// The parts the tip block's header committed to: the same as
    /// [`State::root_parts`] but with the chain MMR before the tip's own hash
    /// was appended. These hash to a checkpoint's `mw_state_root`.
    pub fn checkpoint_parts(&self) -> StateRootParts {
        let mut parts = self.root_parts();
        parts.chain_mmr_root = self
            .chain_mmr
            .truncated(self.height.saturating_sub(1))
            .root(true);
        parts
    }

    /// The pieces [`State::state_root`] hashes (what recovery claims carry).
    pub fn root_parts(&self) -> StateRootParts {
        StateRootParts {
            utxo_root: self.utxo_set.root(true),
            bonds_root: bonds_root(&self.bonds),
            kernel_root: self.kernels.root(true),
            chain_mmr_root: self.chain_mmr.root(true),
            kernel_excess_sum: self.kernel_excess_sum,
            total_kernel_offset: self.total_kernel_offset,
            supply: self.supply,
        }
    }

    /// Rebuilds the `#[serde(skip)]` accumulator caches. Must follow every
    /// deserialization (see midstate `storage.rs::deserialize_state`).
    pub fn rebuild_caches(&mut self) {
        self.utxo_set.rebuild_tree(true);
        self.kernels.rebuild_tree(true);
    }

    /// MimbleWimble's whole-chain audit: the unspent set, minus everything
    /// ever minted, must equal the sum of every kernel excess plus the total
    /// offset. A node that fast-syncs a UTXO set can run this to confirm no
    /// coins were created from nothing, without any spent history.
    ///
    /// ```text
    ///   Σ C_utxo − supply·G = Σ E_all + (Σ o)·H
    /// ```
    pub fn verify_supply(&self) -> anyhow::Result<()> {
        let utxos = crypto::sum_points(self.utxos.keys())?;
        let excess = crypto::decompress(&self.kernel_excess_sum)
            .ok_or_else(|| anyhow::anyhow!("corrupt kernel excess sum"))?;
        let offset = crypto::scalar_from_bytes(&self.total_kernel_offset)
            .ok_or_else(|| anyhow::anyhow!("corrupt total offset"))?;
        let lhs = utxos - curve25519_dalek::scalar::Scalar::from(self.supply) * crypto::gen_g();
        let rhs = excess + offset * crypto::gen_h();
        if lhs != rhs {
            anyhow::bail!("supply audit failed: unspent outputs do not match kernels and supply");
        }
        Ok(())
    }

    pub fn header(&self) -> BatchHeader {
        BatchHeader {
            height: self.height,
            prev_midstate: [0u8; 32],
            post_tx_midstate: self.mw_midstate,
            extension: Extension {
                nonce: 0,
                final_hash: self.header_hash,
            },
            timestamp: self.timestamp,
            target: self.target,
            state_root: self.state_root(),
            prev_header_hash: [0u8; 32],
            aux_pow: None,
        }
    }
}

// ── Blocks (midstate layout) ────────────────────────────────────────────────

/// Proof of sequential work: `final_hash = H^N(H(header_hash ‖ nonce))`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Extension {
    pub nonce: u64,
    pub final_hash: [u8; 32],
}

/// A block. Midstate calls these batches, and the name is kept so the ported
/// sync and network code reads the same.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Batch {
    pub prev_midstate: [u8; 32],
    pub prev_header_hash: [u8; 32],
    /// Every included transaction, aggregated into one (canonical order,
    /// summed offsets). Midstate's `transactions: Vec<Transaction>`.
    pub body: Transaction,
    /// Present exactly when the block has something to claim (reward + fees).
    pub coinbase: Option<Coinbase>,
    pub extension: Extension,
    pub timestamp: u64,
    pub target: [u8; 32],
    pub state_root: [u8; 32],
    /// Merged-mining proof. When present, `extension` holds the block id
    /// (`auxpow::aux_block_id`) and the work lives in the parent block.
    #[serde(default)]
    pub aux_pow: Option<AuxPow>,
    /// Bond registrations (`core/bond.rs`): a block producer registers its
    /// own bond in the first block it mines. At most one per block.
    #[serde(default)]
    pub registrations: Vec<BondRegistration>,
    /// Bonded-mining authorisation, required from `bond::BONDED_MINING_FROM`.
    #[serde(default)]
    pub miner: Option<MinerAuth>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchHeader {
    pub height: u64,
    pub prev_midstate: [u8; 32],
    pub post_tx_midstate: [u8; 32],
    pub extension: Extension,
    pub timestamp: u64,
    pub target: [u8; 32],
    pub state_root: [u8; 32],
    pub prev_header_hash: [u8; 32],
    /// Merged-mining proof (not part of the mining hash, which it proves).
    #[serde(default)]
    pub aux_pow: Option<AuxPow>,
}

/// The hash miners grind on (midstate, unchanged).
pub fn compute_header_hash(header: &BatchHeader) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&header.prev_header_hash);
    hasher.update(&header.post_tx_midstate);
    hasher.update(&header.state_root);
    hasher.update(&header.timestamp.to_le_bytes());
    hasher.update(&header.target);
    *hasher.finalize().as_bytes()
}

/// Folds a block's contents into the running midstate.
///
/// Midstate folded each transaction, then each coinbase coin, then the state
/// root. Here the body is one aggregate, so it is one fold, and the hashes
/// cover the full serialization (signatures and proofs included), so the
/// proof-of-work commits to every byte of the block.
pub fn fold_midstate(
    prev_midstate: &[u8; 32],
    body: &Transaction,
    coinbase: Option<&Coinbase>,
    state_root: &[u8; 32],
) -> [u8; 32] {
    let mut m = hash_concat(prev_midstate, &body.hash());
    if let Some(cb) = coinbase {
        m = hash_concat(&m, &cb.hash());
    }
    hash_concat(&m, state_root)
}

/// [`fold_block`] without the miner's authorisation: what a bonded miner
/// signs over. Registrations fold in after midstate's own items.
pub fn fold_unsigned(prev_midstate: &[u8; 32], batch: &Batch) -> [u8; 32] {
    let m = fold_midstate(
        prev_midstate,
        &batch.body,
        batch.coinbase.as_ref(),
        &batch.state_root,
    );
    if batch.registrations.is_empty() {
        m
    } else {
        hash_concat(&m, &registrations_hash(&batch.registrations))
    }
}

/// Folds a whole block into the running midstate: midstate's fold, then the
/// block's bond registrations, then its miner authorisation. The mining hash
/// covers the result, so the proof of work commits to every byte of the
/// block, signature included. Blocks with neither fold exactly as before.
pub fn fold_block(prev_midstate: &[u8; 32], batch: &Batch) -> [u8; 32] {
    let unsigned = fold_unsigned(prev_midstate, batch);
    match &batch.miner {
        Some(auth) => hash_concat(&unsigned, &auth.hash()),
        None => unsigned,
    }
}

pub fn registrations_hash(registrations: &[BondRegistration]) -> [u8; 32] {
    let bytes = bincode::serialize(registrations).expect("registrations serialize");
    hash_domain(b"midwimble.registrations.v1", &[&bytes])
}

/// Commitment to the registered bond set: every entry, in bond-id order.
pub fn bonds_root(bonds: &im::HashMap<[u8; 32], BondEntry>) -> [u8; 32] {
    let mut ids: Vec<&[u8; 32]> = bonds.keys().collect();
    ids.sort();
    let mut h = blake3::Hasher::new();
    h.update(b"midwimble.bonds.v1");
    for id in ids {
        let e = &bonds[id];
        h.update(id);
        h.update(&e.mining_key);
        h.update(&e.value.to_le_bytes());
        h.update(&e.bonded_until.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

impl Batch {
    /// Header derived from the full batch; `height` is left for the caller.
    pub fn header(&self) -> BatchHeader {
        BatchHeader {
            height: 0,
            prev_header_hash: self.prev_header_hash,
            prev_midstate: self.prev_midstate,
            post_tx_midstate: fold_block(&self.prev_midstate, self),
            extension: self.extension.clone(),
            timestamp: self.timestamp,
            target: self.target,
            state_root: self.state_root,
            aux_pow: self.aux_pow.clone(),
        }
    }

    pub fn weight(&self) -> u64 {
        self.body.weight()
            + self.coinbase.as_ref().map_or(0, Coinbase::weight)
            + self.registrations.iter().map(BondRegistration::weight).sum::<u64>()
    }

    /// The canonical genesis block: no transactions, no reward.
    ///
    /// Midstate hardcodes a genesis nonce mined offline. Genesis here is built
    /// locally from constants and never needs to meet the target (it is
    /// recognised by hash), so there is nothing to mine before launch.
    pub fn genesis() -> &'static Batch {
        static GENESIS: OnceLock<Batch> = OnceLock::new();
        GENESIS.get_or_init(|| {
            let state = State::genesis();
            let mut after = state.clone();
            after.height = 0;
            let state_root = after.state_root();
            let body = Transaction::empty();
            let header = BatchHeader {
                height: 0,
                prev_header_hash: state.header_hash,
                prev_midstate: state.mw_midstate,
                post_tx_midstate: fold_midstate(&state.mw_midstate, &body, None, &state_root),
                extension: Extension {
                    nonce: 0,
                    final_hash: [0u8; 32],
                },
                timestamp: state.timestamp,
                target: state.target,
                state_root,
                aux_pow: None,
            };
            let extension = super::extension::create_extension(compute_header_hash(&header), 0);
            Batch {
                registrations: Vec::new(),
                miner: None,
                prev_midstate: state.mw_midstate,
                prev_header_hash: state.header_hash,
                body,
                coinbase: None,
                extension,
                timestamp: state.timestamp,
                target: state.target,
                state_root,
                aux_pow: None,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_domain_separates_parts() {
        assert_ne!(
            hash_domain(b"d", &[b"ab", b"c"]),
            hash_domain(b"d", &[b"a", b"bc"])
        );
        assert_ne!(hash_domain(b"d1", &[b"x"]), hash_domain(b"d2", &[b"x"]));
    }

    #[test]
    fn network_anchor_differs_from_midstate() {
        assert_ne!(network_anchor(), hash(BITCOIN_BLOCK_HASH.as_bytes()));
    }

    /// The properties the schedule is chosen for, checked against mainnet's
    /// parameters even when this build carries `fast-mining`.
    #[test]
    fn mainnet_emission_reaches_the_cap_exactly() {
        let e = MAINNET_EMISSION;
        let end = e.final_reward_height().expect("the cap is reached");
        assert_eq!(e.issued_before(end + 1), MAX_SUPPLY);
        assert_eq!(e.block_reward(end + 1), 0);
        assert!(e.block_reward(end) > 0);
        // Genesis mints nothing, and nothing mints after the cap.
        assert_eq!(e.block_reward(0), 0);
        assert_eq!(e.issued_before(0), 0);
        assert_eq!(e.block_reward(u64::MAX), 0);
        assert_eq!(e.issued_before(u64::MAX), MAX_SUPPLY);
        // ~95 years: long enough that fees, not issuance, are the endgame.
        assert!((49_000_000..51_000_000).contains(&end), "ends at {end}");
    }

    #[test]
    fn mainnet_emission_shape() {
        let e = MAINNET_EMISSION;
        // The ramp rises every block, never reverses, and ends at the full
        // reward, which then holds until the first halving.
        assert!(e.block_reward(1) > 0);
        for h in 1..e.slow_start {
            assert!(
                e.block_reward(h + 1) >= e.block_reward(h),
                "ramp dips at {h}"
            );
        }
        assert_eq!(e.block_reward(e.slow_start), e.initial_reward);
        assert_eq!(e.block_reward(e.slow_start + 1), e.initial_reward);
        assert_eq!(e.block_reward(e.halving_interval - 1), e.initial_reward);
        // Halvings land on the era boundaries.
        for k in 1..20u32 {
            let h = k as u64 * e.halving_interval;
            assert_eq!(e.block_reward(h), e.initial_reward >> k, "era {k}");
            assert_eq!(e.block_reward(h - 1), e.initial_reward >> (k - 1));
        }
        // Half of everything inside the first era, as intended.
        let era_one = e.issued_before(e.halving_interval);
        assert!(era_one > MAX_SUPPLY / 2 - MAX_SUPPLY / 200);
        assert!(era_one < MAX_SUPPLY / 2);
        // The first month is worth about half a percent of the supply.
        let month = e.issued_before(e.slow_start + 1);
        assert!(month < MAX_SUPPLY / 150, "slow start minted {month}");
    }

    /// `issued_before` is the running total of `block_reward`; consensus
    /// relies on the two never disagreeing.
    #[test]
    fn issuance_is_the_running_total_of_the_rewards() {
        for e in [MAINNET_EMISSION, EMISSION] {
            let mut running: u128 = 0;
            let probes = (0..2_000).chain([
                e.slow_start.saturating_sub(1),
                e.slow_start,
                e.slow_start + 1,
                e.halving_interval - 2,
                e.halving_interval - 1,
                e.halving_interval,
                e.halving_interval + 1,
                2 * e.halving_interval,
            ]);
            for h in probes {
                running = e.issued_before(h) as u128 + e.block_reward(h) as u128;
                assert_eq!(running, e.issued_before(h + 1) as u128, "height {h}");
            }
            let _ = running;
            // Never more than the cap, at any height.
            assert!(e.issued_before(u64::MAX) <= e.max_supply);
        }
    }

    #[test]
    fn amounts_round_trip() {
        assert_eq!(format_amount(INITIAL_REWARD), "0.23932616");
        assert_eq!(format_amount(0), "0.00000000");
        assert_eq!(format_amount(MAX_SUPPLY), "1000000.00000000");
        assert_eq!(parse_amount("0.23932616").unwrap(), INITIAL_REWARD);
        assert_eq!(parse_amount("1").unwrap(), COIN);
        assert_eq!(parse_amount(" 1.5 ").unwrap(), 150_000_000);
        assert_eq!(parse_amount(".5").unwrap(), 50_000_000);
        assert_eq!(parse_amount("0.00000001").unwrap(), 1);
        for bad in ["", "1.234567891", "-1", "1e8", "1.2.3", "abc", "1000001"] {
            assert!(parse_amount(bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn genesis_is_deterministic_and_empty() {
        let g = Batch::genesis();
        assert!(g.body.is_empty());
        assert!(g.coinbase.is_none());
        assert_eq!(g.prev_midstate, State::genesis().mw_midstate);
        assert_eq!(
            g.header().post_tx_midstate,
            Batch::genesis().header().post_tx_midstate
        );
    }

    #[test]
    fn empty_state_passes_supply_audit() {
        State::genesis().verify_supply().unwrap();
    }
}
