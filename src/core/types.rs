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

// ── Network identity ────────────────────────────────────────────────────────

/// Distinguishes this network from midstate and from other deployments of
/// this code. Feeds the genesis midstate, every signed message, and the DHT
/// rendezvous key. **Change it for each network you launch.**
pub const NETWORK_MAGIC: &[u8] = b"MIDWIMBLE_DEVNET_V1";

/// Bitcoin block anchoring the genesis (midstate's anchor; replace at launch
/// with a recent block to prove the chain was not premined before it).
pub const BITCOIN_BLOCK_HASH: &str =
    "000000000000000000018f5ad5625d43356136c2e50c6dc18967a90a18f0af2e";
pub const BITCOIN_BLOCK_HEIGHT: u64 = 938708;

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
pub const GENESIS_TIMESTAMP: u64 = 1_789_430_400; // 2026-09-15 00:00:00 UTC — devnet placeholder
#[cfg(feature = "fast-mining")]
pub const GENESIS_TIMESTAMP: u64 = 1_700_000_000;

/// Midstate's genesis target (calibrated for ~60 s blocks on its reference
/// hardware with the SIMD miner).
#[cfg(not(feature = "fast-mining"))]
pub const GENESIS_TARGET: [u8; 32] = {
    let mut t = [0xffu8; 32];
    t[0] = 0x00;
    t[1] = 0x11;
    t
};
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
/// Midstate's initial reward (2^30), halving yearly to a floor of 1.
pub const INITIAL_REWARD: u64 = 1_073_741_824;

pub fn block_reward(height: u64) -> u64 {
    let halvings = height / BLOCKS_PER_YEAR;
    INITIAL_REWARD >> halvings.min(30)
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
pub const MIN_FEE_PER_WEIGHT: u64 = 1_000;

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
                GENESIS_INSCRIPTION,
            ],
        );
        Self {
            mw_midstate: initial,
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
    /// Required on every block except genesis.
    pub coinbase: Option<Coinbase>,
    pub extension: Extension,
    pub timestamp: u64,
    pub target: [u8; 32],
    pub state_root: [u8; 32],
    /// Merged-mining proof. When present, `extension` holds the block id
    /// (`auxpow::aux_block_id`) and the work lives in the parent block.
    #[serde(default)]
    pub aux_pow: Option<AuxPow>,
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

impl Batch {
    /// Header derived from the full batch; `height` is left for the caller.
    pub fn header(&self) -> BatchHeader {
        BatchHeader {
            height: 0,
            prev_header_hash: self.prev_header_hash,
            prev_midstate: self.prev_midstate,
            post_tx_midstate: fold_midstate(
                &self.prev_midstate,
                &self.body,
                self.coinbase.as_ref(),
                &self.state_root,
            ),
            extension: self.extension.clone(),
            timestamp: self.timestamp,
            target: self.target,
            state_root: self.state_root,
            aux_pow: self.aux_pow.clone(),
        }
    }

    pub fn weight(&self) -> u64 {
        self.body.weight() + self.coinbase.as_ref().map_or(0, Coinbase::weight)
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

    #[test]
    fn block_reward_schedule() {
        assert_eq!(block_reward(0), INITIAL_REWARD);
        assert_eq!(block_reward(BLOCKS_PER_YEAR), INITIAL_REWARD / 2);
        assert_eq!(block_reward(u64::MAX), 1);
        // Total issuance fits comfortably inside the 64-bit range proofs.
        let total: u128 = (0..=30u32)
            .map(|h| (INITIAL_REWARD >> h) as u128 * BLOCKS_PER_YEAR as u128)
            .sum();
        assert!(total < (1u128 << 63));
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
