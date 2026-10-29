//! Bonded proof of work: recognising a midstate mining bond
//! (`docs/BONDED_POW.md`).
//!
//! A bond is an ordinary midstate coin locked by a P2SH script that commits
//! to a midwimble mining key and an unlock height. Midstate needs no consensus
//! change to hold one — its script VM already has the timelock and signature
//! opcodes — and never learns what the coin is for. Midwimble recognises a
//! bond by the exact script template below and proves that it exists with an
//! SMT inclusion proof against a midstate header.
//!
//! A registered bond authorises the blocks its key signs
//! (`check_miner_authorization`); from `BONDED_MINING_FROM` a block must be
//! signed whenever a registered bond could sign it, and an unsigned block
//! counts for only a sliver of its work (`credit_in_window`). Fork choice
//! caps how much work any one bond's blocks add (`credit_work`), so a
//! producer's capacity scales with the bonds behind it, co-bonds included.
//! Fork choice also caps the work any one block adds, at a quarter above the
//! lowest block of the week before (`cap_work`), so hashrate alone cannot
//! stand in for bonds.
//!
//! The header a bond is proven against must be on the midstate relay's chain
//! (`core/relay.rs`): consensus's own view of midstate, fed by blocks. A bond
//! whose header a heavier midstate branch replaces is revoked.
//!
//! A network may open with an early phase ([`EARLY_BONDS_UNTIL`]): blocks
//! stamped before it accept a smaller bond with a shorter lock, so it can
//! start as a testnet anyone can mine and become mainnet in place. From then
//! on only bonds meeting the full minimums count.
//!
//! A month after that ([`BOND_RETARGET_FROM`]) what a *new* bond must lock
//! starts following midwimble's own difficulty: one doubling of the bond per
//! [`WORK_DOUBLINGS_PER_BOND_DOUBLING`] doublings of work since genesis, up
//! to [`MAX_MINING_BOND`] ([`registration_min_bond`]). The retarget is a
//! gate on registration only — [`eligible`] keeps asking every bond the
//! launch minimum and nothing more — so a bond already locked is never
//! stranded by it, and the stock reprices as locks run out rather than all
//! at once.

use super::anchor::HeaderLink;
use super::auxpow::midstate_coin_id;
use super::mmr::{verify_utxo_proof, UtxoAccumulator, UtxoProof};
use super::mw::crypto::{schnorr_sign, schnorr_verify, SchnorrSig};
use super::relay::{MidstateHeaders, Relay};
use super::state::calculate_work;
use super::types::{
    compute_header_hash, fold_unsigned, hash, hash_concat, hash_domain, Batch, BatchHeader,
    NETWORK_MAGIC,
};
use anyhow::{anyhow, bail, Result};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use serde::{Deserialize, Serialize};

/// Midstate opcodes the template uses (midstate `src/core/script.rs`).
const OP_PUSH_DATA: u8 = 0x01;
const OP_DROP: u8 = 0x10;
const OP_CHECKSIGVERIFY: u8 = 0x32;
const OP_CHECKTIMEVERIFY: u8 = 0x33;

/// Midstate heights at which its UTXO hashing and state-root preimage changed.
const MIDSTATE_V2_ACTIVATION_HEIGHT: u64 = 100_000;
const MIDSTATE_V4_ACTIVATION_HEIGHT: u64 = 163_675;

/// Smallest bond that grants eligibility once the early phase is over, in
/// midstate base units: 2^37 (128 gMDS) on mainnet. A launch parameter, so a
/// testnet can set it low enough that testers risk nothing
/// (`types::LAUNCH_MIN_MINING_BOND`). What a block needs is
/// [`min_mining_bond`] at its timestamp.
pub const MIN_MINING_BOND: u64 = super::types::LAUNCH_MIN_MINING_BOND;

/// How many midstate blocks a bond must stay locked beyond the height it is
/// judged at (30 days on mainnet), once the early phase is over. This *is*
/// the unbonding delay: a bond stops counting this long before its owner can
/// spend it, so neither chain has to track an unbonding state. Also a launch
/// parameter, so a testnet's bonds free up in a day or two. What a block
/// needs is [`min_remaining_bond_lock`] at its timestamp.
pub const MIN_REMAINING_BOND_LOCK: u64 = super::types::LAUNCH_MIN_REMAINING_BOND_LOCK;

/// End of the network's early phase, as a block timestamp; zero if it had
/// none. Blocks stamped before it take [`EARLY_MIN_MINING_BOND`] locked for
/// [`EARLY_MIN_REMAINING_BOND_LOCK`] instead, so a network can open as a
/// testnet, cheap for anyone to mine, and become mainnet without a restart:
/// from this moment the bonds that cannot meet the full minimums stop
/// counting, and leave the bond set with the first block that cannot be
/// stamped before it (`types::LAUNCH_EARLY_BONDS_UNTIL`).
pub const EARLY_BONDS_UNTIL: u64 = super::types::LAUNCH_EARLY_BONDS_UNTIL;

/// Smallest bond during the early phase (`types::LAUNCH_EARLY_MIN_MINING_BOND`).
pub const EARLY_MIN_MINING_BOND: u64 = super::types::LAUNCH_EARLY_MIN_MINING_BOND;

/// The unbonding delay during the early phase
/// (`types::LAUNCH_EARLY_MIN_REMAINING_BOND_LOCK`).
pub const EARLY_MIN_REMAINING_BOND_LOCK: u64 =
    super::types::LAUNCH_EARLY_MIN_REMAINING_BOND_LOCK;

/// The minimums a bond must meet to authorise a block: the full ones and,
/// for blocks stamped before `early_until`, an early phase's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BondRules {
    pub min_bond: u64,
    pub min_lock: u64,
    /// End of the early phase, as a block timestamp; zero for none.
    pub early_until: u64,
    pub early_min_bond: u64,
    pub early_min_lock: u64,
}

/// This network's rules, from its launch parameters.
pub const BOND_RULES: BondRules = BondRules {
    min_bond: MIN_MINING_BOND,
    min_lock: MIN_REMAINING_BOND_LOCK,
    early_until: EARLY_BONDS_UNTIL,
    early_min_bond: EARLY_MIN_MINING_BOND,
    early_min_lock: EARLY_MIN_REMAINING_BOND_LOCK,
};

impl BondRules {
    pub fn in_early_phase(&self, block_timestamp: u64) -> bool {
        block_timestamp < self.early_until
    }

    pub fn min_bond_at(&self, block_timestamp: u64) -> u64 {
        if self.in_early_phase(block_timestamp) {
            self.early_min_bond
        } else {
            self.min_bond
        }
    }

    pub fn min_lock_at(&self, block_timestamp: u64) -> u64 {
        if self.in_early_phase(block_timestamp) {
            self.early_min_lock
        } else {
            self.min_lock
        }
    }

    /// Whether a bond of `value` locked until midstate height `bonded_until`
    /// may authorise a block stamped `block_timestamp`: see
    /// [`Bond::eligible_at`].
    pub fn eligible(&self, value: u64, bonded_until: u64, block_timestamp: u64) -> bool {
        value >= self.min_bond_at(block_timestamp)
            && bonded_until
                >= est_midstate_height(block_timestamp)
                    .saturating_add(self.min_lock_at(block_timestamp))
    }

    /// Whether the early phase asks less than the full rules, never more.
    /// Then a bond's eligibility only ever runs down as time passes, which
    /// is what lets the bond set forget a bond for good
    /// ([`BondSet::prune_expired`]). `types.rs` refuses to build a network
    /// whose rules break it.
    pub const fn early_phase_asks_less(&self) -> bool {
        self.early_min_bond <= self.min_bond && self.early_min_lock <= self.min_lock
    }
}

const _: () = assert!(BOND_RULES.early_phase_asks_less());

/// Whether a block stamped `block_timestamp` falls in the early phase.
pub fn in_early_phase(block_timestamp: u64) -> bool {
    BOND_RULES.in_early_phase(block_timestamp)
}

/// Smallest bond that can authorise a block stamped `block_timestamp`.
pub fn min_mining_bond(block_timestamp: u64) -> u64 {
    BOND_RULES.min_bond_at(block_timestamp)
}

/// Midstate blocks a bond must still be locked for to authorise a block
/// stamped `block_timestamp`.
pub fn min_remaining_bond_lock(block_timestamp: u64) -> u64 {
    BOND_RULES.min_lock_at(block_timestamp)
}

// ── Bond-size retarget ──────────────────────────────────────────────────────

/// How long after the early phase ends the bond-size retarget begins (30
/// days). Until then a registration needs only [`min_mining_bond`], so the
/// retarget cannot move the bar out from under a network that has only just
/// opened: every bond registered in the first month is priced at the launch
/// minimum, and keeps that price for as long as it stays locked.
pub const BOND_RETARGET_DELAY: u64 = 30 * 24 * 60 * 60;

/// First block timestamp whose registrations are priced by the retarget
/// ([`registration_min_bond`]): one month after [`EARLY_BONDS_UNTIL`].
pub const BOND_RETARGET_FROM: u64 = EARLY_BONDS_UNTIL.saturating_add(BOND_RETARGET_DELAY);

/// Doublings of midwimble's work per block that raise the minimum a *new*
/// bond must lock by one doubling: at four, midwimble's hashrate has to rise
/// 16-fold to double the bond.
///
/// Genesis was targeted at a hundredth of midstate's hashrate, so full
/// merged-mining adoption is around 100× — six doublings, one step. That
/// leaves the second step for growth beyond midstate's own hashrate, which
/// is the point at which midwimble, not midstate, is why the hashrate is
/// there. A faster setting would spend both steps on adoption alone and
/// leave the retarget pinned at its ceiling with nothing left to say.
pub const WORK_DOUBLINGS_PER_BOND_DOUBLING: u32 = 4;

/// How far the retarget may raise the minimum above the launch minimum, in
/// doublings: 2^37 → 2^39 (128 → 512 gMDS) on mainnet.
///
/// The ceiling is what keeps the flywheel from eating its own float. At the
/// cap's [`CAP_K`] eligible bonds, a 2^37 minimum locks about 4.4% of
/// midstate's terminal supply, 2^38 about 9% and 2^39 about 17.5%. Against
/// what midstate has actually *minted* so far those figures are roughly
/// three times larger, and that is the number that binds in the early years:
/// the retarget is indexed to midwimble's difficulty, which can rise faster
/// than midstate's supply grows. Two steps is the usable range.
pub const MAX_BOND_DOUBLINGS: u32 = 2;

/// The largest minimum the retarget can ask for: the launch minimum shifted
/// up by [`MAX_BOND_DOUBLINGS`]. Still a power of two, so still a midstate
/// coin value.
pub const MAX_MINING_BOND: u64 = MIN_MINING_BOND << MAX_BOND_DOUBLINGS;

/// The ceiling has to fit in the width of a coin value, so that
/// [`registration_min_bond`] can shift without overflowing.
const _: () = assert!(MIN_MINING_BOND.leading_zeros() > MAX_BOND_DOUBLINGS);
/// A retarget that could ask *less* than [`min_mining_bond`] would be inert,
/// because [`eligible`] still holds every bond to that minimum.
const _: () = assert!(MAX_MINING_BOND >= MIN_MINING_BOND);
/// The retarget begins after the early phase, never during it: an early
/// network is being bootstrapped, not priced.
const _: () = assert!(BOND_RETARGET_FROM >= EARLY_BONDS_UNTIL);

/// Whole doublings of work per block between `midwimble_target` and the
/// target midwimble launched at; negative if midwimble is easier than it
/// launched.
///
/// Whole doublings, because a midstate coin's value is a power of two and so
/// the minimum bond can only move in doublings: there is no point measuring
/// the input more finely than the output can be set. It also makes the step
/// coarse — a 16× move in hashrate — which is far larger than anything
/// ASERT's retarget does block to block, so the figure is stable without
/// needing to be averaged.
pub fn work_doublings_since_genesis(midwimble_target: &[u8; 32]) -> i32 {
    fn bits(target: &[u8; 32]) -> i32 {
        // `max(1)` only guards `ilog2`: a target of zero is not a valid one.
        calculate_work(target).max(1).ilog2() as i32
    }
    bits(midwimble_target) - bits(&super::types::GENESIS_TARGET)
}

/// Smallest bond a *registration* carried by a block with this target and
/// timestamp may lock: [`min_mining_bond`] doubled once per
/// [`WORK_DOUBLINGS_PER_BOND_DOUBLING`] doublings of midwimble's work since
/// genesis, up to [`MAX_MINING_BOND`].
///
/// This is the retarget, and it is deliberately only a gate on *new* bonds.
/// A bond already in the set is judged by [`eligible`] alone, which asks the
/// launch minimum and nothing more, so raising this bar never strands a bond
/// anyone has already locked. The retarget controls the inflow; the stock
/// follows it within one unbonding delay, because a bond's eligibility runs
/// out with its lock ([`MIN_REMAINING_BOND_LOCK`]) and re-locking it is a
/// fresh registration at whatever the bar is then. Same shape as difficulty
/// steering hashrate: the lever acts on the margin and the stock converges.
///
/// Keeping it out of [`eligible`] is also what preserves the invariant the
/// bond set is built on — that a bond's eligibility only ever runs down as
/// time passes ([`BondSet::prune_expired`] forgets a bond for good). A
/// minimum that could fall would let a forgotten bond qualify again.
pub fn registration_min_bond(midwimble_target: &[u8; 32], block_timestamp: u64) -> u64 {
    let floor = min_mining_bond(block_timestamp);
    if block_timestamp < BOND_RETARGET_FROM {
        return floor;
    }
    let steps = (work_doublings_since_genesis(midwimble_target)
        / WORK_DOUBLINGS_PER_BOND_DOUBLING as i32)
        .clamp(0, MAX_BOND_DOUBLINGS as i32) as u32;
    floor << steps
}

/// The locking script of a mining bond:
///
/// ```text
/// PUSH_DATA <mining key>    DROP              binds the key into the address
/// PUSH_INT  <bonded_until>  CHECKTIMEVERIFY   unspendable below that height
/// PUSH_DATA <owner key>     CHECKSIGVERIFY    only the owner can spend it
/// PUSH_INT  1
/// ```
///
/// Spent with one witness item, the owner's signature. The mining key plays
/// no part in execution, but a midstate address is the hash of its script, so
/// the address — and with it the coin id — commits to the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondScript {
    pub mining_key: [u8; 32],
    pub bonded_until: u64,
    pub owner_pk: [u8; 32],
}

fn push_data(bc: &mut Vec<u8>, data: &[u8]) {
    bc.push(OP_PUSH_DATA);
    bc.extend_from_slice(&(data.len() as u16).to_le_bytes());
    bc.extend_from_slice(data);
}

/// Midstate's minimal little-endian integer encoding (`script::from_u64`).
fn int_bytes(v: u64) -> Vec<u8> {
    let b = v.to_le_bytes();
    let mut len = 8;
    while len > 1 && b[len - 1] == 0 {
        len -= 1;
    }
    b[..len].to_vec()
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn op(&mut self, want: u8) -> Result<()> {
        if self.bytes.get(self.at) != Some(&want) {
            bail!("not a mining bond script");
        }
        self.at += 1;
        Ok(())
    }

    fn push(&mut self) -> Result<&'a [u8]> {
        self.op(OP_PUSH_DATA)?;
        let len = self
            .bytes
            .get(self.at..self.at + 2)
            .ok_or_else(|| anyhow!("truncated bond script"))?;
        let len = u16::from_le_bytes([len[0], len[1]]) as usize;
        self.at += 2;
        let data = self
            .bytes
            .get(self.at..self.at + len)
            .ok_or_else(|| anyhow!("truncated bond script"))?;
        self.at += len;
        Ok(data)
    }

    fn push32(&mut self) -> Result<[u8; 32]> {
        self.push()?
            .try_into()
            .map_err(|_| anyhow!("bond script key is not 32 bytes"))
    }
}

impl BondScript {
    pub fn to_bytecode(&self) -> Vec<u8> {
        let mut bc = Vec::with_capacity(83);
        push_data(&mut bc, &self.mining_key);
        bc.push(OP_DROP);
        push_data(&mut bc, &int_bytes(self.bonded_until));
        bc.push(OP_CHECKTIMEVERIFY);
        push_data(&mut bc, &self.owner_pk);
        bc.push(OP_CHECKSIGVERIFY);
        push_data(&mut bc, &int_bytes(1));
        bc
    }

    /// Recognises exactly the template. Any other script — including this one
    /// with extra opcodes or an integer written non-minimally — is not a bond,
    /// so every bond has one encoding and one address.
    pub fn parse(bytecode: &[u8]) -> Result<Self> {
        let mut r = Reader {
            bytes: bytecode,
            at: 0,
        };
        let mining_key = r.push32()?;
        r.op(OP_DROP)?;
        let until = r.push()?;
        if until.is_empty() || until.len() > 8 {
            bail!("bond lock height is not a u64");
        }
        let mut le = [0u8; 8];
        le[..until.len()].copy_from_slice(until);
        let bonded_until = u64::from_le_bytes(le);
        r.op(OP_CHECKTIMEVERIFY)?;
        let owner_pk = r.push32()?;
        r.op(OP_CHECKSIGVERIFY)?;
        let parsed = Self {
            mining_key,
            bonded_until,
            owner_pk,
        };
        // Re-encoding catches everything else at once: a missing or different
        // final push, trailing bytes, and non-minimal integers.
        if parsed.to_bytecode() != bytecode {
            bail!("not the canonical mining bond encoding");
        }
        Ok(parsed)
    }

    /// The midstate address holding the bond: the hash of its script.
    pub fn address(&self) -> [u8; 32] {
        hash(&self.to_bytecode())
    }
}

/// A midstate coin locked by a bond script.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondCoin {
    pub script: BondScript,
    pub value: u64,
    pub salt: [u8; 32],
}

impl BondCoin {
    /// The midstate coin id, which also serves as the bond's id: unique per
    /// coin, so one bond cannot be counted twice.
    pub fn coin_id(&self) -> [u8; 32] {
        midstate_coin_id(&self.script.address(), self.value, &self.salt)
    }
}

/// What a midstate header's `state_root` commits to (midstate
/// `core/state.rs`, state-root validation):
///
/// ```text
/// state_root = H( H( H(coins, commitments), chain_mmr ), burned_wots )
/// ```
///
/// The chain MMR root is the one from *before* the block appended itself, and
/// the burned-WOTS term exists from V4 activation onwards. A proof server that
/// returned the node's current roots instead would hand out proofs that match
/// no header at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MidstateRoots {
    /// UTXO SMT root after the block's transactions and coinbase.
    pub coins: [u8; 32],
    pub commitments: [u8; 32],
    /// Chain MMR root before the block itself was appended.
    pub chain_mmr: [u8; 32],
    /// Present exactly when the header is at or above V4 activation.
    pub burned_wots: Option<[u8; 32]>,
}

impl MidstateRoots {
    /// The `state_root` a midstate header at `height` carries for these roots.
    pub fn state_root(&self, height: u64) -> Result<[u8; 32]> {
        let smt = hash_concat(&self.coins, &self.commitments);
        let root = hash_concat(&smt, &self.chain_mmr);
        match (height >= MIDSTATE_V4_ACTIVATION_HEIGHT, self.burned_wots) {
            (true, Some(burned)) => Ok(hash_concat(&root, &burned)),
            (false, None) => Ok(root),
            _ => bail!("burned-WOTS root does not fit a header at height {height}"),
        }
    }
}

/// Evidence that a bond coin was unspent in the midstate state committed by
/// one particular header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondProof {
    pub coin: BondCoin,
    /// Height of the midstate header the proof is against.
    pub midstate_height: u64,
    pub roots: MidstateRoots,
    pub smt: UtxoProof,
}

/// A bond proven to exist, unspent, at a midstate height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bond {
    pub id: [u8; 32],
    pub mining_key: [u8; 32],
    pub value: u64,
    pub bonded_until: u64,
    pub proven_at: u64,
}

impl BondProof {
    /// Checks the bond coin is in the UTXO set that the midstate header at
    /// `midstate_height` commits to with `header_state_root`. Obtaining that
    /// header — and knowing it is the one midwimble consensus agreed on — is
    /// the caller's job.
    pub fn verify(&self, header_state_root: &[u8; 32]) -> Result<Bond> {
        if self.midstate_height < MIDSTATE_V2_ACTIVATION_HEIGHT {
            bail!("bonds are only recognised against midstate's V2 state");
        }
        if self.roots.state_root(self.midstate_height)? != *header_state_root {
            bail!("roots do not match the midstate header's state root");
        }
        let id = self.coin.coin_id();
        if !verify_utxo_proof(&id, &self.smt, &self.roots.coins, true) {
            bail!("bond coin is not in midstate's UTXO set at that height");
        }
        Ok(Bond {
            id,
            mining_key: self.coin.script.mining_key,
            value: self.coin.value,
            bonded_until: self.coin.script.bonded_until,
            proven_at: self.midstate_height,
        })
    }
}

/// Midstate's genesis time. Its ASERT, like midwimble's, is anchored here, so
/// its height tracks `(t − genesis) / 60` — running ahead of that by
/// `240 · log2(hashrate / calibration)` blocks, never behind it for long.
const MIDSTATE_GENESIS_TIMESTAMP: u64 = 1_772_274_770;

/// Pads the clock estimate of midstate's height by seven days, more than
/// midstate's lead over its schedule at any plausible hashrate (about 3,500
/// blocks at today's roughly 28,000 times its calibration).
pub const CLOCK_MARGIN: u64 = 7 * 24 * 60;

/// Midstate's height as judged from a midwimble block's timestamp, estimated
/// high on purpose: an error can only retire a bond early, never let it mine
/// after it could have been spent. Deterministic from midwimble's own chain,
/// so a stalled or unreachable midstate never stops a bonded miner.
pub fn est_midstate_height(timestamp: u64) -> u64 {
    timestamp.saturating_sub(MIDSTATE_GENESIS_TIMESTAMP) / 60 + CLOCK_MARGIN
}

impl Bond {
    /// Version-1 eligibility for a block with this timestamp: at least
    /// [`min_mining_bond`], and still locked for at least
    /// [`min_remaining_bond_lock`] beyond the estimated midstate height (the
    /// early phase's minimums before [`EARLY_BONDS_UNTIL`], the full ones
    /// from it). Nothing can spend a bond before its lock height, so the
    /// proof it was registered with keeps holding until then. The value is a
    /// gate, never a weight: a bigger bond buys no more mining power.
    ///
    /// Once false, never true again at a later timestamp: the estimated
    /// height only rises, and the early minimums are at most the full ones
    /// (checked at compile time, [`BondRules::early_phase_asks_less`]).
    pub fn eligible_at(&self, block_timestamp: u64) -> bool {
        eligible(self.value, self.bonded_until, block_timestamp)
    }
}

fn eligible(value: u64, bonded_until: u64, block_timestamp: u64) -> bool {
    BOND_RULES.eligible(value, bonded_until, block_timestamp)
}

// ── Registration ─────────────────────────────────────────────────────────────

/// A registration's header must be buried under a day of work, measured in
/// blocks of the *registering midwimble block's own target*.
///
/// The headers above it are the relay's, so they are midstate's chain as far
/// as consensus knows it, and a bond on a branch that loses is revoked. The
/// burial guards the time in between: hijacking the relay long enough to
/// register a bond costs at least a day of midwimble's entire network's work,
/// on top of outweighing what honest producers relay, however midstate's
/// block reward has decayed.
pub const REGISTRATION_WORK_BLOCKS: u128 = 24 * 60;

/// No header counts for more than 1/60 of the requirement, so a burial needs
/// at least 60 headers' worth of real work. Without the cap, one improbably
/// lucky hash on a very hard target could stand in for the day.
pub const REGISTRATION_MIN_HEADERS: u128 = 60;

/// The work a registration in a block with this target must show.
pub fn registration_work(midwimble_target: &[u8; 32]) -> u128 {
    calculate_work(midwimble_target).saturating_mul(REGISTRATION_WORK_BLOCKS)
}

/// The most any one header above a bond's header is credited with, towards a
/// registration in a block with this target.
pub fn registration_cap(midwimble_target: &[u8; 32]) -> u128 {
    (registration_work(midwimble_target) / REGISTRATION_MIN_HEADERS).max(1)
}

/// Work the headers `above` a bond's header are credited with, towards a
/// registration in a block with `midwimble_target` (for tools that hold the
/// headers themselves; consensus counts the relay's).
pub fn credited_work(above: &[HeaderLink], midwimble_target: &[u8; 32]) -> u128 {
    let cap = registration_cap(midwimble_target);
    above.iter().fold(0u128, |sum, h| {
        sum.saturating_add(calculate_work(&h.target).min(cap))
    })
}

/// A bond proof, to be checked against the midstate relay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondRegistration {
    pub proof: BondProof,
}

impl BondRegistration {
    /// Verifies a registration in a block with `midwimble_target`, against
    /// the relay as that block leaves it: the proof's header is on the
    /// relay's chain, the proof rebuilds its state root, and the headers
    /// relayed above it carry a day of work at the block's target. Returns
    /// the entry the bond set gains, which records the header it was proven
    /// against.
    ///
    /// Nothing here hashes a chain: the relay's headers had their proof of
    /// work checked once, when they were relayed.
    pub fn verify(&self, relay: &Relay, midwimble_target: &[u8; 32]) -> Result<BondEntry> {
        let height = self.proof.midstate_height;
        let header = relay.get(height).filter(|e| !e.is_root()).ok_or_else(|| {
            anyhow!(
                "the bond's midstate header (height {height}) is not on the relay's chain: relay it first"
            )
        })?;
        let bond = self.proof.verify(&header.state_root)?;
        let required = registration_work(midwimble_target);
        let credited = relay.credited_above(height, registration_cap(midwimble_target));
        if credited < required {
            bail!(
                "{credited} units of relayed midstate work above the bond's header; a block at this target requires {required}"
            );
        }
        Ok(BondEntry {
            mining_key: bond.mining_key,
            value: bond.value,
            bonded_until: bond.bonded_until,
            proven_height: height,
            proven_hash: header.hash,
        })
    }
}

// ── Bonded mining in consensus ──────────────────────────────────────────────

/// First height whose block must be authorised by a registered, eligible
/// bond whenever one could sign it ([`any_can_sign`]). Genesis is fixed data
/// that nobody mines, so bonded mining begins with the first mined block.
///
/// While no registered bond can sign (before the first registration, or if
/// every bond has lapsed) a block may be unsigned, and fork choice credits
/// it with only the over-cap sliver ([`credit_in_window`]): enough to keep
/// the chain, and the midstate relay with it, moving until a bond registers,
/// never enough to win against signed blocks.
#[cfg(not(feature = "fast-mining"))]
pub const BONDED_MINING_FROM: u64 = 1;
/// Test builds: an authorisation is optional, but checked in full whenever a
/// block carries one. Temporary, until the node, pool and merge miner sign
/// their templates and the integration tests mine bonded blocks.
#[cfg(feature = "fast-mining")]
pub const BONDED_MINING_FROM: u64 = u64::MAX;

/// A block carries at most one registration. A producer registers its own
/// bond in the first block it mines, and the cap bounds how much
/// verification any one block can demand.
pub const MAX_REGISTRATIONS_PER_BLOCK: usize = 1;

/// Registration weight: 256 units for the ~8 KB proof, in line with what
/// transaction data weighs per byte.
const REGISTRATION_WEIGHT: u64 = 256;

/// A registered bond as the chain's state holds it, keyed by bond id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondEntry {
    pub mining_key: [u8; 32],
    pub value: u64,
    pub bonded_until: u64,
    /// The relay entry the bond was proven against: if a heavier midstate
    /// branch replaces it, the bond is revoked.
    pub proven_height: u64,
    pub proven_hash: [u8; 32],
}

impl BondEntry {
    /// See [`Bond::eligible_at`].
    pub fn eligible_at(&self, block_timestamp: u64) -> bool {
        eligible(self.value, self.bonded_until, block_timestamp)
    }
}

/// The leaf a bond contributes to the bond set's commitment: every field of
/// its entry, under its id.
pub fn bond_leaf(id: &[u8; 32], entry: &BondEntry) -> [u8; 32] {
    hash_domain(
        b"midwimble.bond-leaf.v1",
        &[
            id,
            &entry.mining_key,
            &entry.value.to_le_bytes(),
            &entry.bonded_until.to_le_bytes(),
            &entry.proven_height.to_le_bytes(),
            &entry.proven_hash,
        ],
    )
}

/// The registered bonds, by bond id, with a sparse Merkle commitment kept up
/// to date as bonds come and go, so the state root never re-sorts the set.
///
/// The set holds only bonds that can still authorise a block: before each
/// block is applied, bonds no longer eligible at the earliest timestamp it
/// (or any later block) may carry are removed ([`BondSet::prune_expired`]).
/// Serialised as its entries alone; the commitment is rebuilt on load.
#[derive(Clone, Debug, Default)]
pub struct BondSet {
    entries: im::HashMap<[u8; 32], BondEntry>,
    leaves: UtxoAccumulator,
}

impl PartialEq for BondSet {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}

impl Eq for BondSet {}

impl Serialize for BondSet {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut entries: Vec<(&[u8; 32], &BondEntry)> = self.entries.iter().collect();
        entries.sort_by_key(|(id, _)| **id);
        entries.serialize(s)
    }
}

impl<'de> Deserialize<'de> for BondSet {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let entries = Vec::<([u8; 32], BondEntry)>::deserialize(d)?;
        let len = entries.len();
        let set: BondSet = entries.into_iter().collect();
        if set.len() != len {
            return Err(serde::de::Error::custom("duplicate bond id"));
        }
        Ok(set)
    }
}

impl FromIterator<([u8; 32], BondEntry)> for BondSet {
    fn from_iter<I: IntoIterator<Item = ([u8; 32], BondEntry)>>(iter: I) -> Self {
        let mut set = BondSet::default();
        for (id, entry) in iter {
            set.insert(id, entry);
        }
        set
    }
}

impl BondSet {
    pub fn get(&self, id: &[u8; 32]) -> Option<&BondEntry> {
        self.entries.get(id)
    }

    pub fn contains_key(&self, id: &[u8; 32]) -> bool {
        self.entries.contains_key(id)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 32], &BondEntry)> {
        self.entries.iter()
    }

    pub fn keys(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.entries.keys()
    }

    pub fn values(&self) -> impl Iterator<Item = &BondEntry> {
        self.entries.values()
    }

    /// Adds or replaces a bond, returning the entry it replaced.
    pub fn insert(&mut self, id: [u8; 32], entry: BondEntry) -> Option<BondEntry> {
        let old = self.entries.insert(id, entry);
        if let Some(old) = &old {
            self.leaves.remove(&bond_leaf(&id, old), true);
        }
        self.leaves.insert(bond_leaf(&id, &entry), true);
        old
    }

    pub fn remove(&mut self, id: &[u8; 32]) -> Option<BondEntry> {
        let old = self.entries.remove(id)?;
        self.leaves.remove(&bond_leaf(id, &old), true);
        Some(old)
    }

    /// The commitment the state root carries.
    pub fn root(&self) -> [u8; 32] {
        self.leaves.root(true)
    }

    /// Removes every bond that is not eligible at `earliest_timestamp`, the
    /// smallest timestamp the next block may carry, and returns them in id
    /// order. Timestamps must exceed the median of the last eleven, and that
    /// median never falls, so no later block on this chain could be
    /// authorised by them either (eligibility only runs down with time, the
    /// end of the early phase included: see [`Bond::eligible_at`]): removing
    /// them changes nothing but the size of the set. Early-phase bonds below
    /// the full minimums leave at the first block that cannot be stamped
    /// before [`EARLY_BONDS_UNTIL`].
    pub fn prune_expired(&mut self, earliest_timestamp: u64) -> Vec<([u8; 32], BondEntry)> {
        let mut expired: Vec<([u8; 32], BondEntry)> = self
            .entries
            .iter()
            .filter(|(_, e)| !e.eligible_at(earliest_timestamp))
            .map(|(id, e)| (*id, *e))
            .collect();
        expired.sort_by_key(|(id, _)| *id);
        for (id, _) in &expired {
            self.remove(id);
        }
        expired
    }

    /// Removes every bond proven against a midstate header above `height`,
    /// and returns them in id order: a heavier branch from `height` replaced
    /// those headers, so their coins are no longer known to exist.
    pub fn revoke_above(&mut self, height: u64) -> Vec<([u8; 32], BondEntry)> {
        let mut revoked: Vec<([u8; 32], BondEntry)> = self
            .entries
            .iter()
            .filter(|(_, e)| e.proven_height > height)
            .map(|(id, e)| (*id, *e))
            .collect();
        revoked.sort_by_key(|(id, _)| *id);
        for (id, _) in &revoked {
            self.remove(id);
        }
        revoked
    }
}

impl BondRegistration {
    /// The bond's id: its midstate coin id.
    pub fn bond_id(&self) -> [u8; 32] {
        self.proof.coin.coin_id()
    }

    /// Whether the bond, once registered, could sign a block stamped
    /// `block_timestamp` ([`Bond::eligible_at`]).
    pub fn eligible_at(&self, block_timestamp: u64) -> bool {
        let coin = &self.proof.coin;
        eligible(coin.value, coin.script.bonded_until, block_timestamp)
    }

    /// Checks a registration against the midstate headers carried with it
    /// (a bond file's): they link and carry valid proof of work, and the
    /// proof rebuilds the state root of its header among them. Returns the
    /// work credited above that header at `midwimble_target`. What the chain
    /// accepts is decided against its relay ([`BondRegistration::verify`]);
    /// this catches a bad file before it costs a block.
    pub fn check_carried(
        &self,
        carried: &MidstateHeaders,
        midwimble_target: &[u8; 32],
    ) -> Result<u128> {
        let index = self
            .proof
            .midstate_height
            .checked_sub(carried.start)
            .map(|i| i as usize)
            .filter(|i| *i < carried.headers.len())
            .ok_or_else(|| {
                anyhow!("the carried midstate headers do not include the proof's header")
            })?;
        carried.verify()?;
        self.proof.verify(&carried.headers[index].state_root)?;
        Ok(credited_work(
            &carried.headers[index + 1..],
            midwimble_target,
        ))
    }

    pub fn weight(&self) -> u64 {
        REGISTRATION_WEIGHT
    }
}

/// A block's bonded-mining authorisation: the bond it is mined under, and
/// that bond's mining-key signature over [`authorization_message`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinerAuth {
    pub bond_id: [u8; 32],
    pub signature: SchnorrSig,
}

impl MinerAuth {
    pub fn hash(&self) -> [u8; 32] {
        hash_domain(
            b"midwimble.miner-auth.v1",
            &[&self.bond_id, &self.signature.e, &self.signature.s],
        )
    }
}

/// What a bonded miner signs for `batch` on a chain whose midstate is
/// `prev_midstate`: the mining hash the block would have without its
/// authorisation (and without its signer, which the authorisation names).
/// The signature covers every other byte of the block, the chain weight its
/// header claims included, and the proof of work then covers the signature
/// and the signer, so a found block cannot be re-attributed to another bond.
/// Merged mining keeps that property, because the midstate parent commits to
/// the full mining hash.
pub fn authorization_message(prev_midstate: &[u8; 32], batch: &Batch) -> [u8; 32] {
    let header = BatchHeader {
        height: 0,
        prev_header_hash: batch.prev_header_hash,
        prev_midstate: *prev_midstate,
        post_tx_midstate: fold_unsigned(prev_midstate, batch),
        extension: batch.extension.clone(),
        timestamp: batch.timestamp,
        target: batch.target,
        state_root: batch.state_root,
        signer: None,
        chain_weight: batch.chain_weight,
        aux_pow: None,
    };
    hash_domain(
        b"midwimble.block-authorisation.v1",
        &[&compute_header_hash(&header), NETWORK_MAGIC],
    )
}

/// Checks `batch`'s authorisation against the bond set, which already
/// includes any registration the block itself carries.
pub fn check_miner_authorization(
    bonds: &BondSet,
    prev_midstate: &[u8; 32],
    batch: &Batch,
) -> Result<()> {
    let auth = batch
        .miner
        .as_ref()
        .ok_or_else(|| anyhow!("block is not authorised by a mining bond"))?;
    let bond = bonds.get(&auth.bond_id).ok_or_else(|| {
        anyhow!(
            "block is mined under an unregistered bond {}",
            hex::encode(auth.bond_id)
        )
    })?;
    if !bond.eligible_at(batch.timestamp) {
        bail!(
            "bond {} is not eligible at this block's time (too small, or its lock ends too soon)",
            hex::encode(auth.bond_id)
        );
    }
    let message = authorization_message(prev_midstate, batch);
    if !schnorr_verify(&bond.mining_key, &message, &auth.signature) {
        bail!("the block's miner signature does not verify under its bond's mining key");
    }
    Ok(())
}

/// What a block producer needs in order to mine under a bond.
#[derive(Clone)]
pub struct MinerBond {
    pub secret: Scalar,
    pub bond_id: [u8; 32],
    /// The bond's registration, carried in this producer's blocks until the
    /// chain has it.
    pub registration: Option<BondRegistration>,
    /// Midstate headers from the proof's header through its burial, relayed
    /// by this producer's blocks where the relay lacks them.
    pub midstate: Option<MidstateHeaders>,
    /// Bonds others locked naming this producer's mining key. Blocks are
    /// signed with whichever bond has the most fork-choice quota left.
    pub co_bonds: Vec<CoBond>,
}

/// A bond someone else locked naming this producer's mining key. They keep
/// the coin, which only their owner key can spend; the producer signs with it.
#[derive(Clone, Debug)]
pub struct CoBond {
    pub bond_id: [u8; 32],
    /// Carried in this producer's blocks, one a block, until the chain has it.
    pub registration: Option<BondRegistration>,
    /// As [`MinerBond::midstate`].
    pub midstate: Option<MidstateHeaders>,
}

impl std::fmt::Debug for MinerBond {
    /// Never prints the secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MinerBond")
            .field("bond_id", &hex::encode(self.bond_id))
            .field("registered_here", &self.registration.is_some())
            .finish_non_exhaustive()
    }
}

impl MinerBond {
    /// The bond to sign the next block with: of this producer's own bond and
    /// its co-bonds, the registered, eligible one with the most fork-choice
    /// quota left (`signer_cap`), the producer's own on ties.
    pub fn choose_signer(
        &self,
        bonds: &BondSet,
        counts: &im::HashMap<[u8; 32], u32>,
        block_timestamp: u64,
    ) -> [u8; 32] {
        self.signer_for(bonds, counts, block_timestamp)
            .unwrap_or(self.bond_id)
    }

    /// [`MinerBond::choose_signer`] among only the bonds that can sign now:
    /// `None` when none of this producer's bonds is registered and eligible.
    pub fn signer_for(
        &self,
        bonds: &BondSet,
        counts: &im::HashMap<[u8; 32], u32>,
        block_timestamp: u64,
    ) -> Option<[u8; 32]> {
        let key = self.mining_key();
        std::iter::once(self.bond_id)
            .chain(self.co_bonds.iter().map(|c| c.bond_id))
            .filter(|id| {
                bonds
                    .get(id)
                    .is_some_and(|e| e.mining_key == key && e.eligible_at(block_timestamp))
            })
            .min_by_key(|id| counts.get(id).copied().unwrap_or(0))
    }

    pub fn mining_key(&self) -> [u8; 32] {
        RistrettoPoint::mul_base(&self.secret).compress().to_bytes()
    }

    pub fn sign(&self, message: &[u8; 32]) -> SchnorrSig {
        schnorr_sign(&self.secret, message)
    }
}

/// Test-build bonds on a stand-in midstate (`relay::devnet`): each coin is
/// locked, one header commits to all of them, and enough headers bury it to
/// register at `midwimble_target` (with a quarter to spare, should the target
/// harden). Returns each bond's registration and the headers, from the relay's
/// root on, that a block relays so the registrations verify. Bonds that are to
/// share a chain must come from one call: separate calls mine competing
/// branches of the same relay root.
///
/// Fast-mining builds only: the headers are mined with short extensions,
/// which a real network could never accept.
#[cfg(feature = "fast-mining")]
pub fn devnet_registrations(
    bonds: &[([u8; 32], u64, [u8; 32])],
    midwimble_target: &[u8; 32],
) -> (Vec<BondRegistration>, MidstateHeaders) {
    let mut midstate = super::relay::devnet::DevnetMidstate::new();
    let coins: Vec<BondCoin> = bonds
        .iter()
        .map(|&(mining_key, bonded_until, salt)| BondCoin {
            script: BondScript {
                mining_key,
                bonded_until,
                owner_pk: hash(b"test bond owner"),
            },
            value: MIN_MINING_BOND,
            salt,
        })
        .collect();
    for coin in &coins {
        midstate.lock(coin);
    }
    midstate.mine(1);
    let registrations: Vec<BondRegistration> = coins
        .iter()
        .map(|coin| BondRegistration {
            proof: midstate.prove(coin),
        })
        .collect();
    let required = registration_work(midwimble_target);
    let per = calculate_work(&midstate.target).min(registration_cap(midwimble_target));
    let burial = (required + required / 4).div_ceil(per.max(1)) as u64 + 1;
    midstate.mine(burial);
    (registrations, midstate.mined.clone())
}

/// [`devnet_registrations`] for one bond.
#[cfg(feature = "fast-mining")]
pub fn devnet_registration(
    mining_key: [u8; 32],
    bonded_until: u64,
    salt: [u8; 32],
    midwimble_target: &[u8; 32],
) -> (BondRegistration, MidstateHeaders) {
    let (mut registrations, headers) =
        devnet_registrations(&[(mining_key, bonded_until, salt)], midwimble_target);
    (registrations.remove(0), headers)
}

// ── The producer's bond file and midstate RPC parsing ──────────────────────

/// What a block producer keeps on disk (`midwimble node --mining-bond`): the
/// mining secret and, as `midwimble bond register` fills them in, the bond
/// coin, the proof taken against midstate's tip, and the finished
/// registration. Guard it like a wallet key: whoever holds it can mine as the
/// bond (though never spend it; that takes the owner's midstate key).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BondFile {
    /// Mining secret, hex. Empty in a co-bond file.
    #[serde(default)]
    pub secret: String,
    /// A co-bond file's mining key, hex: the key of the producer (pool) the
    /// bond is locked to. The file holds no secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mining_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coin: Option<BondCoin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<BondProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration: Option<BondRegistration>,
    /// Midstate headers from the relay's tip when the registration was made
    /// (or the proof's header, if the relay had it) through the proof's
    /// burial. A producer relays whatever the chain still lacks of them, so a
    /// bond can be registered without a midstate node feeding the relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub midstate_headers: Option<MidstateHeaders>,
}

impl BondFile {
    pub fn generate() -> Self {
        Self {
            secret: hex::encode(super::mw::crypto::random_scalar().to_bytes()),
            ..Self::default()
        }
    }

    pub fn secret(&self) -> Result<Scalar> {
        let bytes: [u8; 32] = hex::decode(&self.secret)?
            .try_into()
            .map_err(|_| anyhow!("bond file secret must be 32 bytes"))?;
        super::mw::crypto::scalar_from_bytes(&bytes)
            .ok_or_else(|| anyhow!("bond file secret is not a canonical scalar"))
    }

    pub fn mining_key(&self) -> Result<[u8; 32]> {
        if let Some(key) = &self.mining_pubkey {
            let bytes: [u8; 32] = hex::decode(key)?
                .try_into()
                .map_err(|_| anyhow!("mining_pubkey must be 32 bytes"))?;
            if curve25519_dalek::ristretto::CompressedRistretto(bytes)
                .decompress()
                .is_none()
            {
                bail!("mining_pubkey is not a valid mining key");
            }
            return Ok(bytes);
        }
        Ok(RistrettoPoint::mul_base(&self.secret()?)
            .compress()
            .to_bytes())
    }

    /// A co-bond file: the bond will name `mining_key`, someone else's.
    pub fn co_bond(mining_key: [u8; 32]) -> Self {
        Self {
            mining_pubkey: Some(hex::encode(mining_key)),
            ..Self::default()
        }
    }

    /// What a producer adds with `--co-bond`. Needs a finished registration.
    pub fn co_bond_entry(&self) -> Result<CoBond> {
        let registration = self.registration.clone().ok_or_else(|| {
            anyhow!("this co-bond is not registered yet: finish `midwimble bond register` first")
        })?;
        if registration.proof.coin.script.mining_key != self.mining_key()? {
            bail!("this file's mining key is not the registered bond's");
        }
        Ok(CoBond {
            bond_id: registration.bond_id(),
            registration: Some(registration),
            midstate: self.midstate_headers.clone(),
        })
    }

    /// What the node mines with. Needs a finished registration.
    pub fn miner_bond(&self) -> Result<MinerBond> {
        if self.mining_pubkey.is_some() {
            bail!("this is a co-bond file: its producer adds it with --co-bond, alongside their own --mining-bond");
        }
        let registration = self.registration.clone().ok_or_else(|| {
            anyhow!("this bond is not registered yet: finish `midwimble bond register` first")
        })?;
        let bond = MinerBond {
            co_bonds: Vec::new(),
            secret: self.secret()?,
            bond_id: registration.bond_id(),
            registration: Some(registration),
            midstate: self.midstate_headers.clone(),
        };
        let registered_key = bond
            .registration
            .as_ref()
            .unwrap()
            .proof
            .coin
            .script
            .mining_key;
        if bond.mining_key() != registered_key {
            bail!("this file's secret is not the registered bond's mining key");
        }
        Ok(bond)
    }
}

/// One header of midstate's `GET /headers` response, as a link plus the hash
/// of the header before it.
pub fn header_link_from_json(h: &serde_json::Value) -> Result<(HeaderLink, [u8; 32])> {
    use super::auxpow::bytes32;
    let u64_of = |v: &serde_json::Value| {
        v.as_u64()
            .ok_or_else(|| anyhow!("midstate header field is not a u64"))
    };
    let link = HeaderLink {
        post_tx_midstate: bytes32(&h["post_tx_midstate"])?,
        state_root: bytes32(&h["state_root"])?,
        timestamp: u64_of(&h["timestamp"])?,
        target: bytes32(&h["target"])?,
        nonce: u64_of(&h["extension"]["nonce"])?,
        final_hash: bytes32(&h["extension"]["final_hash"])?,
    };
    Ok((link, bytes32(&h["prev_header_hash"])?))
}

/// A bond proof from midstate's `GET /utxo_proof/:coin_id` response.
pub fn bond_proof_from_json(coin: BondCoin, v: &serde_json::Value) -> Result<BondProof> {
    use super::auxpow::bytes32;
    if let Some(e) = v.get("error") {
        bail!("midstate refused the proof: {e}");
    }
    let roots = MidstateRoots {
        coins: bytes32(&v["coins_root"])?,
        commitments: bytes32(&v["commitments_root"])?,
        chain_mmr: bytes32(&v["chain_mmr_root"])?,
        burned_wots: match &v["burned_wots_root"] {
            serde_json::Value::Null => None,
            b => Some(bytes32(b)?),
        },
    };
    Ok(BondProof {
        coin,
        midstate_height: v["height"]
            .as_u64()
            .ok_or_else(|| anyhow!("proof has no height"))?,
        roots,
        smt: serde_json::from_value(v["proof"].clone())?,
    })
}

// --- Fork-choice cap (co-bonded mining) -------------------------------------

/// Over any `CAP_WINDOW` blocks, one bond adds full work to fork choice for at
/// most `signer_cap` of them. Blocks beyond that stay valid and pay, but add
/// only `1 / OVER_CAP_WORK_DIVISOR` of their work, so a chain outweighs another
/// only with enough bonds behind its hashrate: a pool's capacity scales with
/// the bonds co-signed to its mining key.
#[cfg(not(feature = "fast-mining"))]
pub const CAP_WINDOW: usize = 24 * 60;
/// Test and devnet builds use a small window, so the cap is reachable.
#[cfg(feature = "fast-mining")]
pub const CAP_WINDOW: usize = 16;
/// With at least this many eligible bonds, each may sign `1 / CAP_K` of the
/// window at full weight; with fewer, they share it equally.
///
/// 360 divides the window exactly: four full-weight blocks a bond a day. A
/// pool with a share `s` of the hashrate then needs about `360 × s` bonds (108
/// at 30%), so the capital behind block production grows with the hashrate it
/// covers, while a miner with less than 1/360 of it needs only its one bond.
#[cfg(not(feature = "fast-mining"))]
pub const CAP_K: usize = 360;
#[cfg(feature = "fast-mining")]
pub const CAP_K: usize = 4;
pub const OVER_CAP_WORK_DIVISOR: u128 = 1024;
/// Fork choice credits a block with at most a quarter more than the lowest
/// work among its chain's previous `WORK_CAP_WINDOW` blocks (`cap_work`).
///
/// The per-bond cap counts blocks, not work. Without this, an attacker with
/// `r` times the honest hashrate could let ASERT raise its private chain's
/// difficulty, which takes hours, and then fill each quota slot with `r` times
/// the work of an honest block: a day-long rewrite would need about `1/r` of
/// the bonds. A fork younger than the window inherits its floor from the
/// history it shares with the honest chain, so extra hashrate buys it no
/// weight: outweighing the honest chain takes more full-weight blocks, and so
/// more bonds. Honest growth faster than a quarter in a window is credited
/// late, and alike on every branch that shares the window.
#[cfg(not(feature = "fast-mining"))]
pub const WORK_CAP_WINDOW: usize = 7 * 24 * 60;
/// Test and devnet builds use four signer windows, so a test can reach the
/// cap and see a low block leave the window.
#[cfg(feature = "fast-mining")]
pub const WORK_CAP_WINDOW: usize = 4 * CAP_WINDOW;
/// The cap is the window's lowest work plus `1 / WORK_CAP_HEADROOM` of it.
pub const WORK_CAP_HEADROOM: u128 = 4;
/// How far past the block's estimated midstate height a registration may lock
/// its coin, so a forged registration expires instead of holding a quota slot
/// forever.
pub const MAX_BOND_HORIZON: u64 = 365 * 24 * 60;

/// Full-weight blocks one bond may sign per `CAP_WINDOW`: an equal share among
/// the bonds eligible at `block_timestamp`, never below `1 / CAP_K`. Counting
/// registered bonds rather than recent signers keeps an attacker's private
/// chain, where only the attacker signs, under the same cap.
pub fn signer_cap(bonds: &BondSet, block_timestamp: u64) -> usize {
    let eligible = bonds
        .values()
        .filter(|e| e.eligible_at(block_timestamp))
        .count();
    CAP_WINDOW.div_ceil(eligible.clamp(1, CAP_K))
}

/// The coinbase subsidy a signed block may mint: the whole `reward` while its
/// bond has signed at most `cap` of the last [`CAP_WINDOW`] blocks, and
/// `reward × cap / n` (rounded down) once it has signed `n > cap` of them,
/// this block included.
///
/// This is the pay-side of the test fork choice already applies to work: the
/// same `n > signer_cap` that drops an over-cap block to a [`sliver`]
/// ([`credit_in_window`]) tapers what it may mint, so a producer earns the
/// full reward only by spreading its hashrate over enough bonds. The curve is
/// smooth — at `n == cap + 1` the loss is one part in `n`, so there is no
/// cliff to stop mining at, or to switch keys to dodge.
///
/// The withheld part is **not** redistributed: it is never minted at all, so
/// the chain's supply ends below the emission schedule by the sum of every
/// block's withholding. Callers leave unsigned blocks and blocks stamped
/// before [`EARLY_BONDS_UNTIL`] untapered.
///
/// Integer maths throughout, in `u128` so the product cannot overflow: a
/// signed over-cap block has `n >= 2`, so the division is always defined.
pub fn capped_subsidy(reward: u64, n: usize, cap: usize) -> u64 {
    if n <= cap {
        return reward;
    }
    ((reward as u128 * cap as u128) / n as u128) as u64
}

/// What the block at `height` may mint, which is the whole of the taper rule
/// in one place: the scheduled reward for an unsigned block or one stamped
/// before the mainnet switch, and [`capped_subsidy`] of it for a signed block
/// from the switch on.
///
/// `counts` must be the signer window **with this block already counted**, as
/// [`credit_in_window`] leaves it, so `counts[signer]` is `n`; `bonds` is the
/// set as the block leaves it, the same one the cap was taken against. Three
/// places have to agree on this figure exactly -- the node applying a block,
/// storage replaying one, and a producer's template paying its own coinbase --
/// and a disagreement is a chain split, so they all call this rather than
/// keeping a copy of the rule.
pub fn subsidy_for(
    signer: Option<[u8; 32]>,
    counts: &im::HashMap<[u8; 32], u32>,
    bonds: &BondSet,
    height: u64,
    block_timestamp: u64,
) -> u64 {
    let reward = super::types::block_reward(height);
    match signer {
        Some(id) if block_timestamp >= EARLY_BONDS_UNTIL => {
            let n = counts.get(&id).copied().unwrap_or(0) as usize;
            capped_subsidy(reward, n, signer_cap(bonds, block_timestamp))
        }
        _ => reward,
    }
}

/// Whether any registered bond could sign a block timestamped
/// `block_timestamp`. From [`BONDED_MINING_FROM`] a block must be signed
/// exactly when one could.
pub fn any_can_sign(bonds: &BondSet, block_timestamp: u64) -> bool {
    bonds.values().any(|e| e.eligible_at(block_timestamp))
}

/// What fork choice credits an over-cap or unsigned block: a sliver of its
/// work, never zero, so a longer chain is always a heavier one.
pub fn sliver(work: u128) -> u128 {
    (work / OVER_CAP_WORK_DIVISOR).max(1)
}

/// Records a block in the fork-choice windows and returns the work it adds to
/// its chain's weight: its work as far as [`cap_work`] allows, all of that
/// while the bond has signed at most `signer_cap` of the last `CAP_WINDOW`
/// blocks, this one included, and a sliver beyond (never zero, so a longer
/// chain is always a heavier one). From [`BONDED_MINING_FROM`] an unsigned
/// block adds only the sliver. `state.height` is the block's own height.
pub fn credit_work(
    state: &mut super::types::State,
    signer: Option<[u8; 32]>,
    work: u128,
    block_timestamp: u64,
) -> u128 {
    let work = cap_work(&mut state.work_floor, state.height, work);
    credit_in_window(
        &mut state.recent_signers,
        &mut state.signer_counts,
        &state.bonds,
        state.height,
        signer,
        work,
        block_timestamp,
    )
}

/// The work fork choice may credit the block at `height`: at most the lowest
/// work among the previous `WORK_CAP_WINDOW` blocks plus a quarter of it.
/// Then adds the block's own work to the window.
///
/// `floor` holds `(height, work)` pairs from the window, oldest first, with
/// work strictly rising: each is a block no later block has undercut, so the
/// front is the window's minimum and every update is amortised O(1). It is
/// left holding exactly the window the next block will see, so a window
/// rebuilt from stored blocks is identical. An empty window (before genesis)
/// caps nothing. Storage replays blocks through this on its own copy and must
/// weigh each one exactly as the node did.
pub fn cap_work(floor: &mut im::Vector<(u64, u128)>, height: u64, work: u128) -> u128 {
    fn keep_window_of(floor: &mut im::Vector<(u64, u128)>, height: u64) {
        let oldest = height.saturating_sub(WORK_CAP_WINDOW as u64);
        while floor.front().is_some_and(|&(h, _)| h < oldest) {
            floor.pop_front();
        }
    }
    keep_window_of(floor, height);
    let credited = match floor.front() {
        Some(&(_, low)) => work.min(low.saturating_add(low / WORK_CAP_HEADROOM)),
        None => work,
    };
    while floor.back().is_some_and(|&(_, w)| w >= work) {
        floor.pop_back();
    }
    floor.push_back((height, work));
    keep_window_of(floor, height + 1);
    credited
}

/// The per-bond half of [`credit_work`], on a bare window, for the block at
/// `height`. Storage replays blocks onto its own records and must weigh each
/// one exactly as the node did.
pub fn credit_in_window(
    recent: &mut im::Vector<Option<[u8; 32]>>,
    counts: &mut im::HashMap<[u8; 32], u32>,
    bonds: &BondSet,
    height: u64,
    signer: Option<[u8; 32]>,
    work: u128,
    block_timestamp: u64,
) -> u128 {
    recent.push_back(signer);
    if let Some(id) = signer {
        let count = counts.get(&id).copied().unwrap_or(0);
        counts.insert(id, count + 1);
    }
    while recent.len() > CAP_WINDOW {
        if let Some(Some(old)) = recent.pop_front() {
            match counts.get(&old).copied() {
                Some(count) if count > 1 => {
                    counts.insert(old, count - 1);
                }
                _ => {
                    counts.remove(&old);
                }
            }
        }
    }
    match signer {
        Some(id)
            if counts.get(&id).copied().unwrap_or(0) as usize
                > signer_cap(bonds, block_timestamp) =>
        {
            sliver(work)
        }
        None if height >= BONDED_MINING_FROM => sliver(work),
        _ => work,
    }
}

/// Whether the block at `height` could add `credited` to its chain's weight,
/// given `creditable`, its work as far as the work cap allows ([`cap_work`]):
/// for a signed block, all of that or the sliver an over-cap block adds; for
/// an unsigned one, the sliver from [`BONDED_MINING_FROM`] and all of it
/// before ([`credit_in_window`]). Headers-first sync checks claimed chain
/// weights with this (the work window is in the headers; the bond set is
/// not, so which of a signed block's two is right is settled when the block
/// is applied).
pub fn credit_possible(creditable: u128, signed: bool, height: u64, credited: u128) -> bool {
    match (signed, height >= BONDED_MINING_FROM) {
        (true, _) => credited == creditable || credited == sliver(creditable),
        (false, true) => credited == sliver(creditable),
        (false, false) => credited == creditable,
    }
}

/// Rebuilds the window from the signers of the blocks before `state`, oldest
/// first (storage does this after loading or rewinding).
pub fn rebuild_signer_window(
    state: &mut super::types::State,
    signers: impl IntoIterator<Item = Option<[u8; 32]>>,
) {
    state.recent_signers = im::Vector::new();
    state.signer_counts = im::HashMap::new();
    for signer in signers {
        credit_in_window(
            &mut state.recent_signers,
            &mut state.signer_counts,
            &state.bonds,
            0,
            signer,
            0,
            0,
        );
    }
}

/// Rebuilds the work window from the `(height, work)` of the blocks before
/// `state`, oldest first (storage does this after loading or rewinding, and
/// snapshots after verifying). The window decides the chain weight the next
/// block must claim, so every block in it must be given: storage and
/// snapshots keep a full window of headers.
pub fn rebuild_work_floor(
    state: &mut super::types::State,
    works: impl IntoIterator<Item = (u64, u128)>,
) {
    state.work_floor = im::Vector::new();
    for (height, work) in works {
        cap_work(&mut state.work_floor, height, work);
    }
}

/// The cheap, stateful checks on a block's registrations, run before any
/// header's proof of work: not already registered, at least
/// [`registration_min_bond`] for the block's target and time, eligible at
/// the block's time (a bond that could never sign is not worth the space,
/// and one already pruned could otherwise come back), and locked no further
/// out than `MAX_BOND_HORIZON`.
///
/// The bond minimum is the block's own retargeted one, not the launch
/// minimum: this is the only place the retarget applies, which is what
/// leaves every bond already in the set priced as it was registered.
pub fn precheck_registrations(
    bonds: &BondSet,
    registrations: &[BondRegistration],
    midwimble_target: &[u8; 32],
    block_timestamp: u64,
) -> Result<()> {
    let horizon = est_midstate_height(block_timestamp).saturating_add(MAX_BOND_HORIZON);
    let min_bond = registration_min_bond(midwimble_target, block_timestamp);
    for registration in registrations {
        let id = registration.bond_id();
        if bonds.contains_key(&id) {
            bail!("bond {} is already registered", hex::encode(id));
        }
        let (value, bonded_until) = (
            registration.proof.coin.value,
            registration.proof.coin.script.bonded_until,
        );
        if value < min_bond {
            bail!(
                "bond {} locks {} units; a mining bond is at least {}{}",
                hex::encode(id),
                value,
                min_bond,
                if min_bond > min_mining_bond(block_timestamp) {
                    " at this block's difficulty"
                } else if EARLY_BONDS_UNTIL > 0 && !in_early_phase(block_timestamp) {
                    " now that the early phase is over"
                } else {
                    ""
                }
            );
        }
        if bonded_until > horizon {
            bail!(
                "bond {} is locked until midstate height {}; a registration may lock at most to {}",
                hex::encode(id),
                bonded_until,
                horizon
            );
        }
        if !eligible(value, bonded_until, block_timestamp) {
            bail!(
                "bond {} is not eligible at this block's time: its lock ends too soon",
                hex::encode(id)
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod cap_tests {
    use super::*;

    fn eligible_bond() -> BondEntry {
        BondEntry {
            mining_key: [0u8; 32],
            value: MIN_MINING_BOND,
            bonded_until: u64::MAX,
            proven_height: 0,
            proven_hash: [0; 32],
        }
    }

    /// A signed block adds all its work or, over its cap, a sliver; an
    /// unsigned one adds all of it before bonded mining begins and only the
    /// sliver after: nothing else.
    #[test]
    fn possible_credits() {
        let work = 1u128 << 40;
        let sliver = work / OVER_CAP_WORK_DIVISOR;
        let (bonded, before) = (BONDED_MINING_FROM, BONDED_MINING_FROM - 1);
        for h in [bonded, before] {
            assert!(credit_possible(work, true, h, work));
            assert!(credit_possible(work, true, h, sliver));
            for other in [0, sliver - 1, sliver + 1, work - 1, work + 1] {
                assert!(!credit_possible(work, true, h, other), "{other}");
                assert!(!credit_possible(work, false, h, other), "{other}");
            }
        }
        assert!(credit_possible(work, false, before, work));
        assert!(!credit_possible(work, false, before, sliver));
        assert!(credit_possible(work, false, bonded, sliver));
        assert!(
            !credit_possible(work, false, bonded, work),
            "an unsigned block counts for a sliver once bonded mining begins"
        );
        // Tiny work: the sliver is never zero, so a longer chain is heavier.
        assert!(credit_possible(1, true, bonded, 1));
        assert!(!credit_possible(1, true, bonded, 0));
        assert!(credit_possible(1, false, bonded, 1));
    }

    /// The same rule as the block's own weighing: an unsigned block in the
    /// bonded era is credited the sliver, before it all its work.
    #[test]
    fn unsigned_blocks_count_for_a_sliver_once_bonded_mining_begins() {
        let none = BondSet::default();
        let work = 1u128 << 30;
        for (height, expected) in [
            (BONDED_MINING_FROM, sliver(work)),
            (BONDED_MINING_FROM - 1, work),
        ] {
            let (mut recent, mut counts) = (im::Vector::new(), im::HashMap::new());
            let credited = credit_in_window(&mut recent, &mut counts, &none, height, None, work, 0);
            assert_eq!(credited, expected, "height {height}");
            assert!(credit_possible(work, false, height, credited));
            assert_eq!(recent.back(), Some(&None), "recorded as unsigned");
            assert!(counts.is_empty());
        }
        // Who could sign decides whether a block may be unsigned.
        let t = 1_800_000_000;
        let mut bonds = BondSet::default();
        assert!(!any_can_sign(&bonds, t));
        let edge = est_midstate_height(t) + min_remaining_bond_lock(t);
        bonds.insert(
            [7; 32],
            BondEntry {
                bonded_until: edge,
                ..eligible_bond()
            },
        );
        assert!(any_can_sign(&bonds, t));
        assert!(
            !any_can_sign(&bonds, t + 24 * 60 * 60),
            "a day later its lock is too short to sign"
        );
    }

    /// Revocation removes exactly the bonds proven above the fork.
    #[test]
    fn revocation_removes_bonds_proven_above_a_fork() {
        let at = |h: u64| BondEntry {
            proven_height: h,
            ..eligible_bond()
        };
        let mut set: BondSet = (0..10).map(|i| (bond_id(i), at(100 + i as u64))).collect();
        let revoked = set.revoke_above(104);
        let ids: Vec<[u8; 32]> = revoked.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, (5..10).map(bond_id).collect::<Vec<_>>());
        assert_eq!(set.len(), 5);
        assert!(set.revoke_above(104).is_empty());
    }

    /// A distinct bond id for each `i`, beyond the 256 a repeated byte allows.
    fn bond_id(i: usize) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&(i as u64).to_le_bytes());
        id
    }

    #[test]
    fn cap_is_an_equal_share_never_below_one_kth() {
        let mut bonds = BondSet::default();
        assert_eq!(
            signer_cap(&bonds, 0),
            CAP_WINDOW,
            "a lone producer is uncapped"
        );
        for i in 0..3 {
            bonds.insert(bond_id(i), eligible_bond());
        }
        assert_eq!(signer_cap(&bonds, 0), CAP_WINDOW.div_ceil(3));
        for i in 3..CAP_K + 10 {
            bonds.insert(bond_id(i), eligible_bond());
        }
        assert_eq!(signer_cap(&bonds, 0), CAP_WINDOW.div_ceil(CAP_K));
        assert_eq!(
            CAP_WINDOW % CAP_K,
            0,
            "K divides the window, so the cap is exact"
        );

        // Expired and undersized bonds do not dilute the cap.
        let mut few = BondSet::default();
        few.insert([1; 32], eligible_bond());
        few.insert(
            [2; 32],
            BondEntry {
                bonded_until: 0,
                ..eligible_bond()
            },
        );
        few.insert(
            [3; 32],
            BondEntry {
                value: min_mining_bond(0) / 2,
                ..eligible_bond()
            },
        );
        assert_eq!(signer_cap(&few, 0), CAP_WINDOW);
    }

    /// A lone producer's window is all its own blocks, and that is its cap:
    /// it must never be weighed down by itself (the bug that stopped the
    /// testnet's only miner one window after a restart).
    #[test]
    fn a_lone_producer_is_never_capped() {
        let mut state = super::super::types::State::genesis();
        state.bonds.insert([1; 32], eligible_bond());
        let work = 1u128 << 40;
        for _ in 0..3 * CAP_WINDOW {
            assert_eq!(credit_work(&mut state, Some([1; 32]), work, 0), work);
        }
        assert_eq!(state.signer_counts[&[1; 32]] as usize, CAP_WINDOW);
        // A window rebuilt full of its blocks (a restart) still credits in full.
        let signers = vec![Some([1u8; 32]); CAP_WINDOW];
        rebuild_signer_window(&mut state, signers);
        assert_eq!(credit_work(&mut state, Some([1; 32]), work, 0), work);
    }

    /// The pay-side of the cap: inside it a block mints the whole reward,
    /// past it the subsidy falls away as `cap / n`. The step at the boundary
    /// is one part in `n`, so there is no cliff to stop mining at.
    #[test]
    fn the_subsidy_tapers_only_past_the_cap() {
        let reward = 23_932_616u64;
        // At the cap and under it, the block mints everything.
        assert_eq!(capped_subsidy(reward, 1, 36), reward);
        assert_eq!(capped_subsidy(reward, 35, 36), reward);
        assert_eq!(capped_subsidy(reward, 36, 36), reward);
        // One past it: a slope, not a cliff — less than 1/36 is withheld.
        let just_over = capped_subsidy(reward, 37, 36);
        assert_eq!(just_over, (reward as u128 * 36 / 37) as u64);
        assert!(just_over < reward && just_over > reward - reward / 36);
        // Far past it, pay falls off with the overshoot. The bond that signed
        // 1,387 of the last 1,440 against a cap of 36 keeps about 2.6%.
        assert_eq!(capped_subsidy(reward, 72, 36), reward / 2);
        assert_eq!(
            capped_subsidy(reward, 1_387, 36),
            (reward as u128 * 36 / 1_387) as u64
        );
        assert!(capped_subsidy(reward, 1_387, 36) * 38 < reward);
    }

    /// Integer maths, rounded down, and never a panic. What the rounding
    /// leaves behind is simply not minted: nobody is paid it.
    #[test]
    fn the_taper_rounds_down_and_never_overflows() {
        assert_eq!(capped_subsidy(10, 4, 3), 7); // 7.5 floors to 7
        assert_eq!(capped_subsidy(1, 2, 1), 0); // a whole block's reward withheld
        assert_eq!(capped_subsidy(0, 1_000, 1), 0); // after the last coin is issued
                                                    // The product is taken in u128, so the largest reward cannot wrap.
        assert_eq!(capped_subsidy(u64::MAX, 2, 1), u64::MAX / 2);
    }

    /// The whole rule, as the node, storage and a producer's template all
    /// now read it. Only a signed block, past its cap, stamped from the
    /// switch on, mints less than the schedule.
    #[test]
    fn the_taper_only_bites_on_a_signed_over_cap_block_after_the_switch() {
        let mut bonds = BondSet::default();
        bonds.insert([1; 32], eligible_bond());
        bonds.insert([2; 32], eligible_bond());
        let switch = EARLY_BONDS_UNTIL;
        let cap = signer_cap(&bonds, switch);
        let height = 1;
        let full = super::super::types::block_reward(height);

        let mut over = im::HashMap::new();
        over.insert([1u8; 32], (cap + 1) as u32);

        // Stamped a second before the switch, an over-cap bond still mints
        // the lot: the rule is not live yet.
        assert_eq!(
            subsidy_for(Some([1; 32]), &over, &bonds, height, switch - 1),
            full
        );
        // From the switch it keeps cap/n.
        let tapered = subsidy_for(Some([1; 32]), &over, &bonds, height, switch);
        assert_eq!(tapered, capped_subsidy(full, cap + 1, cap));
        assert!(tapered < full);
        // An unsigned block is never tapered, whatever the window holds.
        assert_eq!(subsidy_for(None, &over, &bonds, height, switch), full);
        // Nor is a bond still inside its cap.
        let mut inside = im::HashMap::new();
        inside.insert([2u8; 32], cap as u32);
        assert_eq!(
            subsidy_for(Some([2; 32]), &inside, &bonds, height, switch),
            full
        );
    }

    /// A lone producer fills the window with its own blocks and is still
    /// inside its cap, so it is never tapered — the same reason it is never
    /// weighed down (`a_lone_producer_is_never_capped`). This is why the
    /// taper barely bites in the first window after the switch.
    #[test]
    fn a_lone_producer_mints_in_full() {
        let mut bonds = BondSet::default();
        bonds.insert([1; 32], eligible_bond());
        let cap = signer_cap(&bonds, 0);
        assert_eq!(cap, CAP_WINDOW);
        assert_eq!(capped_subsidy(23_932_616, CAP_WINDOW, cap), 23_932_616);
    }

    #[test]
    fn a_bond_past_its_cap_adds_a_sliver_until_its_blocks_age_out() {
        let mut state = super::super::types::State::genesis();
        state.bonds.insert([1; 32], eligible_bond());
        state.bonds.insert([2; 32], eligible_bond());
        let cap = signer_cap(&state.bonds, 0);
        assert_eq!(cap, CAP_WINDOW / 2);
        let work = 1u128 << 40;

        for _ in 0..cap {
            assert_eq!(credit_work(&mut state, Some([1; 32]), work, 0), work);
        }
        assert_eq!(
            credit_work(&mut state, Some([1; 32]), work, 0),
            work / OVER_CAP_WORK_DIVISOR
        );

        // Bond 2 fills the rest of the window.
        for _ in 0..CAP_WINDOW - cap - 1 {
            assert_eq!(credit_work(&mut state, Some([2; 32]), work, 0), work);
        }
        assert_eq!(state.recent_signers.len(), CAP_WINDOW);
        assert_eq!(state.signer_counts[&[1; 32]] as usize, cap + 1);

        // Two more blocks evict two of bond 1's: it is back under its cap.
        credit_work(&mut state, None, work, 0);
        credit_work(&mut state, None, work, 0);
        assert_eq!(state.signer_counts[&[1; 32]] as usize, cap - 1);
        assert_eq!(credit_work(&mut state, Some([1; 32]), work, 0), work);
        assert!(
            !state.signer_counts.contains_key(&[0; 32]),
            "unsigned blocks count for nobody"
        );

        // Rebuilding from the same signers reproduces the window exactly.
        let signers: Vec<_> = state.recent_signers.iter().copied().collect();
        let mut rebuilt = super::super::types::State::genesis();
        rebuilt.bonds = state.bonds.clone();
        rebuild_signer_window(&mut rebuilt, signers);
        assert_eq!(rebuilt.recent_signers, state.recent_signers);
        assert_eq!(rebuilt.signer_counts, state.signer_counts);
    }

    /// Appends `n` blocks of `work` to `state`, signed in turn by `signers`,
    /// keeping the books `apply_batch` keeps.
    fn extend(state: &mut super::super::types::State, signers: &[[u8; 32]], n: usize, work: u128) {
        for i in 0..n {
            let credited = credit_work(state, Some(signers[i % signers.len()]), work, 0);
            state.depth += work;
            state.capped += work - credited;
            state.height += 1;
        }
    }

    #[test]
    fn a_low_block_caps_credit_for_exactly_one_window() {
        let mut floor = im::Vector::new();
        let work = 1u128 << 40;
        assert_eq!(
            cap_work(&mut floor, 0, work),
            work,
            "an empty window caps nothing"
        );
        for h in 1..10 {
            assert_eq!(cap_work(&mut floor, h, work), work);
        }
        // A quarter over the floor is the most a block can count for.
        assert_eq!(cap_work(&mut floor, 10, 4 * work), work + work / 4);
        // One block at half the work...
        assert_eq!(cap_work(&mut floor, 11, work / 2), work / 2);
        // ...caps every block after it while it is in the window, and no longer.
        let window = WORK_CAP_WINDOW as u64;
        for h in 12..12 + window {
            assert_eq!(
                cap_work(&mut floor, h, work),
                work / 2 + work / 8,
                "height {h}"
            );
        }
        assert_eq!(cap_work(&mut floor, 12 + window, work), work);
    }

    #[test]
    fn the_floor_is_the_lowest_work_of_the_window_before() {
        // Work wandering within a factor of two, over two windows and more.
        let n = 2 * WORK_CAP_WINDOW + 50;
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let works: Vec<u128> = (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (1u128 << 40) + u128::from(x % 4096) * (1 << 28)
            })
            .collect();
        let mut floor = im::Vector::new();
        for (h, &work) in works.iter().enumerate() {
            let credited = cap_work(&mut floor, h as u64, work);
            if h % 7 == 0 || h + 8 > n {
                let low = works[h.saturating_sub(WORK_CAP_WINDOW)..h].iter().min();
                let expected = low.map_or(work, |&l| work.min(l + l / WORK_CAP_HEADROOM));
                assert_eq!(credited, expected, "height {h}");
            }
        }
        // The window rebuilt from stored blocks (a restart) is the same window.
        let mut state = super::super::types::State::genesis();
        rebuild_work_floor(
            &mut state,
            (n - WORK_CAP_WINDOW..n).map(|h| (h as u64, works[h])),
        );
        assert_eq!(state.work_floor, floor);
    }

    /// What the per-bond cap alone missed. It counts blocks, so an attacker
    /// with ten times the honest hashrate could let difficulty climb tenfold
    /// and sign a day with a fifth of the honest bonds: each of its four
    /// blocks a bond a day would carry ten blocks' work. Against the work cap
    /// it loses. A chain with more full-weight blocks still wins, and that
    /// takes bonds.
    #[test]
    fn hashrate_cannot_stand_in_for_bonds() {
        let d = 1u128 << 40;
        let honest: Vec<[u8; 32]> = (0..CAP_K).map(bond_id).collect();
        let few: Vec<[u8; 32]> = (CAP_K..CAP_K + CAP_K.div_ceil(5)).map(bond_id).collect();
        let many: Vec<[u8; 32]> = (2 * CAP_K..3 * CAP_K + 1).map(bond_id).collect();
        let mut shared = super::super::types::State::genesis();
        for id in honest.iter().chain(&few).chain(&many) {
            shared.bonds.insert(*id, eligible_bond());
        }
        let share = CAP_WINDOW / CAP_K;
        assert_eq!(signer_cap(&shared.bonds, 0), share);

        // A week of history at honest difficulty, every block within its share.
        extend(&mut shared, &honest, WORK_CAP_WINDOW, d);
        assert_eq!(shared.capped, 0);
        let mut honest_day = shared.clone();
        extend(&mut honest_day, &honest, CAP_WINDOW, d);
        assert_eq!(honest_day.capped, 0, "the honest day counts in full");

        let mut rich = shared.clone();
        extend(&mut rich, &few, CAP_WINDOW, 10 * d);
        let slots = (share * few.len()) as u128;
        assert!(
            slots * 10 * d > CAP_WINDOW as u128 * d,
            "by block count alone it would win"
        );
        assert!(
            rich.weight() < honest_day.weight(),
            "ten times the hashrate buys no weight"
        );

        let mut bonded = shared.clone();
        extend(&mut bonded, &many, CAP_WINDOW + 1, d);
        assert!(
            bonded.weight() > honest_day.weight(),
            "more full-weight blocks still win"
        );
    }

    /// The commitment depends on the set alone, however it was reached, and
    /// pruning removes exactly the bonds that can no longer sign.
    #[test]
    fn the_bond_set_commits_to_its_entries_and_prunes_expired_bonds() {
        let t = 1_800_000_000;
        let lasting = |i: usize| {
            (
                bond_id(i),
                BondEntry {
                    bonded_until: u64::MAX,
                    ..eligible_bond()
                },
            )
        };
        let ending = |i: usize, until: u64| {
            (
                bond_id(i),
                BondEntry {
                    bonded_until: until,
                    ..eligible_bond()
                },
            )
        };
        let edge = est_midstate_height(t) + min_remaining_bond_lock(t);
        let mut set: BondSet = (0..20).map(lasting).collect();
        let reversed: BondSet = (0..20).rev().map(lasting).collect();
        assert_eq!(set.root(), reversed.root());
        let before = set.root();
        set.insert(ending(100, edge).0, ending(100, edge).1);
        set.insert(ending(101, edge - 1).0, ending(101, edge - 1).1);
        assert_ne!(set.root(), before);
        // Replacing an entry replaces its leaf.
        let mut replaced = set.clone();
        replaced.insert(
            bond_id(0),
            BondEntry {
                value: MIN_MINING_BOND * 2,
                ..eligible_bond()
            },
        );
        assert_ne!(replaced.root(), set.root());
        replaced.insert(bond_id(0), lasting(0).1);
        assert_eq!(replaced.root(), set.root());

        // At `t` the bond ending at the edge still signs; the one before it
        // cannot, now or ever again.
        let pruned = set.prune_expired(t);
        assert_eq!(pruned, vec![ending(101, edge - 1)]);
        assert!(set.contains_key(&bond_id(100)));
        let pruned = set.prune_expired(t + 60);
        assert_eq!(pruned, vec![ending(100, edge)]);
        assert_eq!(set.len(), 20);
        assert_eq!(
            set.root(),
            reversed.root(),
            "back to the lasting bonds alone"
        );

        // Round trip: entries only, commitment rebuilt.
        let bytes = bincode::serialize(&set).unwrap();
        let back: BondSet = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back, set);
        assert_eq!(back.root(), set.root());
        let twice = bincode::serialize(&vec![lasting(1), lasting(1)]).unwrap();
        assert!(bincode::deserialize::<BondSet>(&twice).is_err());
    }

    #[test]
    fn registrations_must_be_eligible_when_made() {
        let t = 1_800_000_000;
        let reg = |until: u64| BondRegistration {
            proof: BondProof {
                coin: BondCoin {
                    script: BondScript {
                        mining_key: [1; 32],
                        bonded_until: until,
                        owner_pk: [2; 32],
                    },
                    value: MIN_MINING_BOND,
                    salt: [3; 32],
                },
                midstate_height: 300_000,
                roots: MidstateRoots {
                    coins: [0; 32],
                    commitments: [0; 32],
                    chain_mmr: [0; 32],
                    burned_wots: None,
                },
                smt: UtxoAccumulator::from_set([[0; 32]], true)
                    .prove(&[0; 32], true)
                    .unwrap(),
            },
        };
        let edge = est_midstate_height(t) + min_remaining_bond_lock(t);
        let none = BondSet::default();
        precheck_registrations(&none, &[reg(edge)], &crate::core::types::GENESIS_TARGET, t).unwrap();
        let err = precheck_registrations(&none, &[reg(edge - 1)], &crate::core::types::GENESIS_TARGET, t).unwrap_err();
        assert!(err.to_string().contains("not eligible"), "{err}");
    }

    /// A bond whose value and lock come from the arguments, locked as long
    /// as wanted, with nothing else of note.
    fn entry(value: u64, bonded_until: u64) -> BondEntry {
        BondEntry {
            value,
            bonded_until,
            ..eligible_bond()
        }
    }

    /// The early phase: before `EARLY_BONDS_UNTIL` the early minimums
    /// decide, from it the full ones. An early bond that falls short of them
    /// stops counting exactly at the switch, leaves the set with the first
    /// block that cannot be stamped before it, and cannot be registered any
    /// more; a full bond carries on as if nothing happened.
    #[test]
    fn the_early_phase_ends_at_its_switch() {
        if EARLY_BONDS_UNTIL == 0 {
            // A launch without an early phase: the full minimums, always.
            for t in [0, 1_800_000_000, u64::MAX] {
                assert!(!in_early_phase(t));
                assert_eq!(min_mining_bond(t), MIN_MINING_BOND);
                assert_eq!(min_remaining_bond_lock(t), MIN_REMAINING_BOND_LOCK);
            }
            return;
        }
        let (last, first) = (EARLY_BONDS_UNTIL - 1, EARLY_BONDS_UNTIL);
        assert!(in_early_phase(last) && !in_early_phase(first));
        assert_eq!(min_mining_bond(last), EARLY_MIN_MINING_BOND);
        assert_eq!(min_mining_bond(first), MIN_MINING_BOND);
        assert_eq!(min_remaining_bond_lock(last), EARLY_MIN_REMAINING_BOND_LOCK);
        assert_eq!(min_remaining_bond_lock(first), MIN_REMAINING_BOND_LOCK);

        // Small but long-locked; full-sized but locked only as long as the
        // early phase asks; full on both counts.
        let small = entry(EARLY_MIN_MINING_BOND, u64::MAX);
        let short = entry(
            MIN_MINING_BOND,
            est_midstate_height(last) + EARLY_MIN_REMAINING_BOND_LOCK,
        );
        let full = entry(
            MIN_MINING_BOND,
            est_midstate_height(first) + MIN_REMAINING_BOND_LOCK,
        );
        for e in [&small, &short, &full] {
            assert!(e.eligible_at(last), "{e:?} counts in the early phase");
        }
        assert!(full.eligible_at(first));
        assert_eq!(
            small.eligible_at(first),
            EARLY_MIN_MINING_BOND >= MIN_MINING_BOND
        );
        assert_eq!(
            short.eligible_at(first),
            EARLY_MIN_REMAINING_BOND_LOCK >= MIN_REMAINING_BOND_LOCK
        );

        // The set: everything stays while the next block may still be
        // stamped before the switch; the short-falling bonds go once it
        // cannot.
        let mut set: BondSet = [(bond_id(1), small), (bond_id(2), short), (bond_id(3), full)]
            .into_iter()
            .collect();
        assert!(set.prune_expired(last).is_empty());
        let gone: Vec<[u8; 32]> = set
            .prune_expired(first)
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        let mut expected = Vec::new();
        if EARLY_MIN_MINING_BOND < MIN_MINING_BOND {
            expected.push(bond_id(1));
        }
        if EARLY_MIN_REMAINING_BOND_LOCK < MIN_REMAINING_BOND_LOCK {
            expected.push(bond_id(2));
        }
        expected.sort();
        assert_eq!(gone, expected);
        assert!(set.contains_key(&bond_id(3)));
        // Signing follows the same line: a lone early bond can sign the last
        // early block, and nothing can sign the first one after.
        let lone: BondSet = [(bond_id(1), small)].into_iter().collect();
        assert!(any_can_sign(&lone, last));
        assert_eq!(
            any_can_sign(&lone, first),
            EARLY_MIN_MINING_BOND >= MIN_MINING_BOND
        );

        // Registrations: an early bond registers until the switch, not after.
        if EARLY_MIN_MINING_BOND < MIN_MINING_BOND {
            let reg = BondRegistration {
                proof: BondProof {
                    coin: BondCoin {
                        script: BondScript {
                            mining_key: [1; 32],
                            bonded_until: est_midstate_height(first)
                                + MIN_REMAINING_BOND_LOCK,
                            owner_pk: [2; 32],
                        },
                        value: EARLY_MIN_MINING_BOND,
                        salt: [3; 32],
                    },
                    midstate_height: 300_000,
                    roots: MidstateRoots {
                        coins: [0; 32],
                        commitments: [0; 32],
                        chain_mmr: [0; 32],
                        burned_wots: None,
                    },
                    smt: UtxoAccumulator::from_set([[0; 32]], true)
                        .prove(&[0; 32], true)
                        .unwrap(),
                },
            };
            let none = BondSet::default();
            precheck_registrations(&none, std::slice::from_ref(&reg), &crate::core::types::GENESIS_TARGET, last).unwrap();
            let err = precheck_registrations(&none, &[reg], &crate::core::types::GENESIS_TARGET, first)
                .unwrap_err()
                .to_string();
            assert!(err.contains("early phase is over"), "{err}");
        }
    }

    /// Whether, under `rules`, some bond is eligible at a later moment but
    /// not at an earlier one, over a grid of sizes, locks and moments around
    /// the rules' switch: the one thing `prune_expired` may never meet.
    fn eligibility_comes_back(rules: &BondRules) -> Option<String> {
        let switch = rules.early_until.max(1_792_122_068);
        let times = [
            switch - 7 * 86_400,
            switch - 3_600,
            switch - 1,
            switch,
            switch + 1,
            switch + 3_600,
            switch + 40 * 86_400,
        ];
        let values = [
            rules.early_min_bond / 2,
            rules.early_min_bond,
            rules.min_bond / 2,
            rules.min_bond,
            rules.min_bond * 2,
        ];
        let base = est_midstate_height(switch);
        let locks = [
            base,
            base + rules.early_min_lock,
            base + rules.min_lock,
            base + rules.min_lock + 20 * 1_440,
            u64::MAX,
        ];
        for &value in &values {
            for &until in &locks {
                for (i, &earlier) in times.iter().enumerate() {
                    for &later in &times[i..] {
                        if rules.eligible(value, until, later)
                            && !rules.eligible(value, until, earlier)
                        {
                            return Some(format!(
                                "value {value}, locked until {until}: eligible at {later} but not at {earlier}"
                            ));
                        }
                    }
                }
            }
        }
        None
    }

    /// Eligibility never comes back: whatever a bond's size and lock, once
    /// it cannot sign at some time it cannot sign at any later one, across
    /// the switch too. `prune_expired` depends on it. It holds for this
    /// build's rules and for any whose early phase asks less; an early phase
    /// asking more would break it, which is why `types.rs` refuses one.
    #[test]
    fn eligibility_only_runs_down_with_time() {
        let switch = 1_793_404_800;
        let mainnet = BondRules {
            min_bond: 1 << 37,
            min_lock: 43_200,
            early_until: 0,
            early_min_bond: 1 << 37,
            early_min_lock: 43_200,
        };
        let early = BondRules {
            early_until: switch,
            early_min_bond: 1 << 24,
            early_min_lock: 2_880,
            ..mainnet
        };
        let smaller_only = BondRules {
            early_min_lock: 43_200,
            ..early
        };
        let shorter_only = BondRules {
            early_min_bond: 1 << 37,
            ..early
        };
        for rules in [BOND_RULES, mainnet, early, smaller_only, shorter_only] {
            assert!(rules.early_phase_asks_less());
            assert_eq!(eligibility_comes_back(&rules), None, "{rules:?}");
        }
        for wrong in [
            BondRules {
                early_min_bond: 1 << 38,
                ..early
            },
            BondRules {
                early_min_lock: 43_201,
                ..early
            },
        ] {
            assert!(!wrong.early_phase_asks_less());
            assert!(eligibility_comes_back(&wrong).is_some(), "{wrong:?}");
        }
    }

    /// The rules on their own: the early minimums decide before the switch
    /// and the full ones from it, whatever this build was launched with.
    #[test]
    fn bond_rules_switch_at_their_early_until() {
        let switch = 1_793_404_800;
        let rules = BondRules {
            min_bond: 1 << 37,
            min_lock: 43_200,
            early_until: switch,
            early_min_bond: 1 << 24,
            early_min_lock: 2_880,
        };
        assert!(rules.in_early_phase(switch - 1) && !rules.in_early_phase(switch));
        assert_eq!(rules.min_bond_at(switch - 1), 1 << 24);
        assert_eq!(rules.min_bond_at(switch), 1 << 37);
        assert_eq!(rules.min_lock_at(switch - 1), 2_880);
        assert_eq!(rules.min_lock_at(switch), 43_200);
        let lasting = u64::MAX;
        assert!(rules.eligible(1 << 24, lasting, switch - 1));
        assert!(!rules.eligible(1 << 24, lasting, switch), "too small from the switch");
        let early_lock = est_midstate_height(switch - 1) + 2_880;
        assert!(rules.eligible(1 << 37, early_lock, switch - 1));
        assert!(!rules.eligible(1 << 37, early_lock, switch), "too short from the switch");
        let full_lock = est_midstate_height(switch) + 43_200;
        assert!(rules.eligible(1 << 37, full_lock, switch - 1));
        assert!(rules.eligible(1 << 37, full_lock, switch));
        // Without an early phase the full rules hold from the start.
        let none = BondRules {
            early_until: 0,
            ..rules
        };
        assert!(!none.in_early_phase(0));
        assert!(!none.eligible(1 << 24, lasting, switch - 1));
        // This build's rules are what its launch parameters say.
        assert_eq!(BOND_RULES.min_bond, crate::core::types::LAUNCH_MIN_MINING_BOND);
        assert_eq!(BOND_RULES.early_until, crate::core::types::LAUNCH_EARLY_BONDS_UNTIL);
    }

    #[test]
    fn a_producer_signs_with_the_bond_that_has_the_most_quota_left() {
        let co = |id: [u8; 32]| CoBond {
            bond_id: id,
            registration: None,
            midstate: None,
        };
        let mut producer = MinerBond {
            secret: Scalar::from_bytes_mod_order([7u8; 32]),
            bond_id: [1; 32],
            registration: None,
            midstate: None,
            co_bonds: vec![co([2; 32]), co([3; 32])],
        };
        let mine = BondEntry {
            mining_key: producer.mining_key(),
            ..eligible_bond()
        };
        let mut bonds = BondSet::default();
        bonds.insert([1; 32], mine);
        bonds.insert([2; 32], mine);
        // Registered, but naming someone else's key: never this producer's to sign.
        bonds.insert(
            [3; 32],
            BondEntry {
                mining_key: [9; 32],
                ..eligible_bond()
            },
        );

        let mut counts = im::HashMap::new();
        assert_eq!(
            producer.choose_signer(&bonds, &counts, 0),
            [1; 32],
            "own bond on ties"
        );
        counts.insert([1; 32], 5);
        counts.insert([2; 32], 2);
        assert_eq!(producer.choose_signer(&bonds, &counts, 0), [2; 32]);
        counts.insert([2; 32], 9);
        assert_eq!(producer.choose_signer(&bonds, &counts, 0), [1; 32]);

        // An unregistered co-bond is skipped, however much quota it has.
        producer.co_bonds.push(co([4; 32]));
        counts.insert([1; 32], 100);
        assert_eq!(producer.choose_signer(&bonds, &counts, 0), [2; 32]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::mmr::UtxoAccumulator;

    /// A real midstate mainnet header, height 297691, checked against its
    /// predecessor's hash with the exact code the relay uses. Production
    /// builds only: it needs the real million-step extension.
    #[cfg(not(feature = "fast-mining"))]
    #[test]
    fn verifies_a_real_midstate_header() {
        let prev = [
            0, 0, 0, 69, 80, 103, 194, 112, 22, 147, 243, 28, 0, 248, 178, 198, 115, 71, 111, 209,
            96, 194, 254, 189, 159, 129, 242, 85, 223, 228, 248, 243,
        ];
        let mut target = [255u8; 32];
        target[..6].copy_from_slice(&[0, 0, 4, 193, 32, 127]);
        let link = HeaderLink {
            post_tx_midstate: [
                77, 173, 143, 201, 58, 55, 42, 180, 120, 49, 199, 104, 109, 234, 237, 174, 168, 31,
                199, 241, 102, 160, 92, 127, 150, 150, 136, 33, 175, 108, 75, 79,
            ],
            state_root: [
                84, 171, 15, 189, 239, 148, 177, 127, 181, 83, 162, 142, 181, 144, 7, 138, 72, 17,
                227, 169, 3, 9, 21, 136, 138, 20, 150, 166, 46, 120, 122, 200,
            ],
            timestamp: 1_789_993_393,
            target,
            nonce: 9_297_194_912_428,
            final_hash: [
                0, 0, 0, 102, 168, 40, 225, 155, 113, 82, 165, 33, 248, 48, 166, 12, 34, 149, 135,
                177, 254, 193, 74, 112, 88, 28, 39, 93, 45, 106, 77, 205,
            ],
        };
        use crate::core::relay::RelayHeaders;
        let relayed = |link: &HeaderLink| {
            RelayHeaders {
                prev,
                headers: vec![link.clone()],
            }
            .verify_pow(297_691)
        };
        relayed(&link).unwrap();
        let mut flipped = link.clone();
        flipped.state_root[31] ^= 1;
        assert!(relayed(&flipped).is_err());
    }

    fn script() -> BondScript {
        BondScript {
            mining_key: [0x11; 32],
            bonded_until: 400_000,
            owner_pk: [0x22; 32],
        }
    }

    /// Computed with an independent BLAKE3 (Python `blake3`) from the byte
    /// layout midstate's own `push_data`/`push_int` produce. Midstate's side
    /// (`script::compile_mining_bond`) carries the same vector.
    #[test]
    fn golden_vector() {
        let bc = script().to_bytecode();
        assert_eq!(
            hex::encode(&bc),
            "0120001111111111111111111111111111111111111111111111111111111111111111\
             10010300801a0633012000222222222222222222222222222222222222222222222222\
             22222222222222223201010001"
        );
        assert_eq!(
            hex::encode(script().address()),
            "22fd4a4255a093856e1b4a714deb228676742accbe4e3145a6fbcb50f757b67f"
        );
        let coin = BondCoin {
            script: script(),
            value: 1 << 34,
            salt: [0x33; 32],
        };
        assert_eq!(
            hex::encode(coin.coin_id()),
            "55bc6798dad6d8bdb3b69263e8509db120146acb61c3fb5cb4be37aee8226429"
        );
    }

    #[test]
    fn parser_accepts_only_the_template() {
        let bc = script().to_bytecode();
        assert_eq!(BondScript::parse(&bc).unwrap(), script());
        for until in [0u64, 1, 255, 256, u64::MAX] {
            let s = BondScript {
                bonded_until: until,
                ..script()
            };
            assert_eq!(BondScript::parse(&s.to_bytecode()).unwrap(), s);
        }
        // Trailing opcode.
        let mut extra = bc.clone();
        extra.push(OP_DROP);
        assert!(BondScript::parse(&extra).is_err());
        // Lock height padded to four bytes: executes the same on midstate, but
        // would give one bond two addresses.
        let mut padded = Vec::new();
        push_data(&mut padded, &[0x11; 32]);
        padded.push(OP_DROP);
        push_data(&mut padded, &[0x80, 0x1a, 0x06, 0x00]);
        // Everything after the lock-height push: 35 (key) + 1 (DROP) + 6.
        padded.extend_from_slice(&bc[42..]);
        assert_eq!(bc[42], OP_CHECKTIMEVERIFY);
        assert!(BondScript::parse(&padded).is_err());
        // Truncated, and a different final push.
        assert!(BondScript::parse(&bc[..bc.len() - 1]).is_err());
        let mut two = bc.clone();
        *two.last_mut().unwrap() = 2;
        assert!(BondScript::parse(&two).is_err());
        assert!(BondScript::parse(&[]).is_err());
    }

    /// Builds a midstate-shaped UTXO set holding the bond and returns a proof
    /// plus the header state root it must verify against.
    fn proven(coin: &BondCoin, height: u64) -> (BondProof, [u8; 32]) {
        let mut coins = UtxoAccumulator::new();
        for i in 0..50u8 {
            coins.insert(hash(&[i]), true);
        }
        coins.insert(coin.coin_id(), true);
        let roots = MidstateRoots {
            coins: coins.root(true),
            commitments: hash(b"commitments"),
            chain_mmr: hash(b"chain mmr before the block"),
            burned_wots: (height >= MIDSTATE_V4_ACTIVATION_HEIGHT).then(|| hash(b"burned")),
        };
        let proof = BondProof {
            coin: *coin,
            midstate_height: height,
            roots,
            smt: coins.prove(&coin.coin_id(), true).unwrap(),
        };
        let header_root = roots.state_root(height).unwrap();
        (proof, header_root)
    }

    fn coin() -> BondCoin {
        BondCoin {
            script: script(),
            value: MIN_MINING_BOND,
            salt: [0x33; 32],
        }
    }

    #[test]
    fn proof_verifies_against_the_header_root() {
        let (proof, root) = proven(&coin(), 300_000);
        let bond = proof.verify(&root).unwrap();
        assert_eq!(bond.id, coin().coin_id());
        assert_eq!(bond.mining_key, [0x11; 32]);
        assert_eq!(bond.proven_at, 300_000);
        // Before V4 the burned-WOTS term is absent, and must be.
        let (early, early_root) = proven(&coin(), 150_000);
        early.verify(&early_root).unwrap();
    }

    #[test]
    fn tampering_is_caught() {
        let (proof, root) = proven(&coin(), 300_000);
        // Another header.
        assert!(proof.verify(&hash(b"another header")).is_err());
        // Claiming a different mining key, value or owner changes the coin id,
        // so the SMT path no longer leads to the committed root.
        for tampered in [
            BondCoin {
                script: BondScript {
                    mining_key: [0x99; 32],
                    ..script()
                },
                ..coin()
            },
            BondCoin {
                value: MIN_MINING_BOND * 2,
                ..coin()
            },
            BondCoin {
                script: BondScript {
                    bonded_until: 900_000,
                    ..script()
                },
                ..coin()
            },
        ] {
            let mut forged = proof.clone();
            forged.coin = tampered;
            assert!(forged.verify(&root).is_err());
        }
        // A pre-V4 shape presented for a post-V4 header, and vice versa.
        let mut shape = proof.clone();
        shape.roots.burned_wots = None;
        assert!(shape.verify(&root).is_err());
        // Below V2 bonds are not recognised at all.
        let mut ancient = proof;
        ancient.midstate_height = 99_999;
        assert!(ancient.verify(&root).is_err());
    }

    /// The bond size and lock are launch parameters now, so a build can be
    /// given bad ones. These are the properties every build must keep, and
    /// the reason `types.rs` refuses the worst of them at compile time.
    #[test]
    fn bond_parameters_stay_usable() {
        for (bond, lock) in [
            (MIN_MINING_BOND, MIN_REMAINING_BOND_LOCK),
            (EARLY_MIN_MINING_BOND, EARLY_MIN_REMAINING_BOND_LOCK),
        ] {
            assert_eq!(
                bond.count_ones(),
                1,
                "a bond is one midstate coin, and coin values are powers of two"
            );
            assert!(bond >= 1 << 20, "a bond has to cost something");
            assert!(lock >= 24 * 60, "the unbonding delay must outlast a reorg");
        }
        assert!(
            BOND_RULES.early_phase_asks_less(),
            "the early phase asks less, never more"
        );
        // Eligibility follows whatever this build was given, both ways, in
        // whichever phase the moment falls (the day before the switch, if
        // there is one, and a moment after it).
        for t in [EARLY_BONDS_UNTIL.max(1_792_122_068) - 86_400, 1_800_000_000] {
            let bond = Bond {
                id: [0; 32],
                mining_key: [0x11; 32],
                value: min_mining_bond(t),
                bonded_until: est_midstate_height(t) + min_remaining_bond_lock(t),
                proven_at: 300_000,
            };
            assert!(bond.eligible_at(t));
            assert!(!bond.eligible_at(t + 60), "the lock runs down");
            assert!(!Bond {
                value: min_mining_bond(t) / 2,
                ..bond
            }
            .eligible_at(t));
        }
    }

    #[test]
    fn eligibility_is_a_gate() {
        let t = 1_800_000_000;
        let bond = Bond {
            id: [0; 32],
            mining_key: [0x11; 32],
            value: min_mining_bond(t),
            bonded_until: est_midstate_height(t) + min_remaining_bond_lock(t),
            proven_at: 300_000,
        };
        assert!(bond.eligible_at(t));
        // A minute later one more block of the lock has run down: that is how
        // a bond unbonds, with no state to track.
        assert!(!bond.eligible_at(t + 60));
        assert!(!Bond {
            value: min_mining_bond(t) / 2,
            ..bond
        }
        .eligible_at(t));
        // The clock runs a week ahead of midstate's nominal schedule.
        assert_eq!(
            est_midstate_height(MIDSTATE_GENESIS_TIMESTAMP),
            CLOCK_MARGIN
        );
    }

    /// Registrations against a relay of mined midstate headers, so these run
    /// with the test build's short extensions.
    #[cfg(feature = "fast-mining")]
    mod registration {
        use super::*;
        use crate::core::relay::devnet::DevnetMidstate;
        use crate::core::relay::{Relay, RelayHeaders};

        /// 3 units of work: a day is 4,320 units, capped at 72 a header.
        const MW_TARGET: [u8; 32] = {
            let mut t = [0; 32];
            t[0] = 0x40;
            t
        };

        /// A relay holding the stand-in's headers, and a registration for
        /// `coin()` proven at its first header.
        fn relayed(above: u64) -> (Relay, BondRegistration, DevnetMidstate) {
            let mut ms = DevnetMidstate::new();
            ms.lock(&coin());
            ms.mine(1);
            let registration = BondRegistration {
                proof: ms.prove(&coin()),
            };
            ms.mine(above);
            let mut relay = Relay::genesis();
            let run = ms.from_height(ms.mined.start);
            relay
                .extend(
                    &RelayHeaders {
                        prev: run.prev,
                        headers: run.headers,
                    },
                    crate::core::state::current_timestamp(),
                )
                .unwrap();
            (relay, registration, ms)
        }

        #[test]
        fn a_day_of_relayed_work_registers_the_bond() {
            assert_eq!(registration_work(&MW_TARGET), 4_320);
            // Each stand-in header is worth over 72 units: 60 are a day.
            let (relay, reg, _) = relayed(60);
            let entry = reg.verify(&relay, &MW_TARGET).unwrap();
            assert_eq!(entry.mining_key, [0x11; 32]);
            assert_eq!(entry.proven_height, reg.proof.midstate_height);
            assert_eq!(
                entry.proven_hash,
                relay.get(entry.proven_height).unwrap().hash
            );
        }

        #[test]
        fn less_than_a_day_does_not() {
            let (relay, reg, _) = relayed(59);
            let err = reg.verify(&relay, &MW_TARGET).unwrap_err().to_string();
            assert!(err.contains("units of relayed midstate work"), "{err}");
        }

        /// The yardstick is the registering block's own target: the same
        /// headers fall short once midwimble's hashrate has grown past what
        /// they carry (at 64 units a block, a day is more than 60 of them).
        #[test]
        fn the_bar_rises_with_midwimbles_hashrate() {
            let mut harder = MW_TARGET;
            harder[0] = 0x04;
            let (relay, reg, _) = relayed(60);
            assert!(
                registration_cap(&harder) > relay.tip().work,
                "each header now counts in full"
            );
            assert!(reg.verify(&relay, &harder).is_err());
        }

        /// The header must be on the relay's chain, and the proof must match
        /// its state root: a proof against any other header, a header the
        /// relay never saw, or the root, is refused.
        #[test]
        fn the_header_must_be_the_relays() {
            let (relay, reg, ms) = relayed(60);
            let mut elsewhere = reg.clone();
            elsewhere.proof.midstate_height += 1;
            assert!(elsewhere.verify(&relay, &MW_TARGET).is_err());
            let mut unseen = reg.clone();
            unseen.proof.midstate_height = ms.height() + 10;
            let err = unseen.verify(&relay, &MW_TARGET).unwrap_err().to_string();
            assert!(err.contains("not on the relay's chain"), "{err}");
            let mut at_root = reg.clone();
            at_root.proof.midstate_height = relay.base().height;
            assert!(at_root.verify(&relay, &MW_TARGET).is_err());
            // A coin the header's state does not hold.
            let mut forged = reg.clone();
            forged.proof.coin.value *= 2;
            assert!(forged.verify(&relay, &MW_TARGET).is_err());
        }
    }
}

#[cfg(test)]
mod retarget_tests {
    use super::*;
    use primitive_types::U256;

    /// A target carrying `doublings` more work per block than genesis: work
    /// is `U256::MAX / target`, so halving the target doubles the work.
    fn harder_by(doublings: u32) -> [u8; 32] {
        (U256::from_big_endian(&super::super::types::GENESIS_TARGET) >> doublings as usize)
            .to_big_endian()
    }

    /// The easiest target there is, so the least work a block can carry.
    const EASIEST: [u8; 32] = [0xff; 32];

    /// A moment the retarget is in force, and past any early phase.
    fn retargeting() -> u64 {
        BOND_RETARGET_FROM + 1
    }

    #[test]
    fn work_doublings_are_measured_against_genesis() {
        assert_eq!(
            work_doublings_since_genesis(&super::super::types::GENESIS_TARGET),
            0,
            "genesis is the zero point"
        );
        for d in 1..=12u32 {
            assert_eq!(
                work_doublings_since_genesis(&harder_by(d)),
                d as i32,
                "{d} halvings of the target is {d} doublings of work"
            );
        }
        assert!(
            work_doublings_since_genesis(&EASIEST) < 0,
            "a chain easier than it launched reads negative"
        );
    }

    /// Nothing changes until the retarget begins: a month of mainnet prices
    /// every bond at the launch minimum however the hashrate moves.
    #[test]
    fn the_retarget_is_inert_before_it_begins() {
        let before = BOND_RETARGET_FROM - 1;
        for d in [0, 4, 8, 64] {
            assert_eq!(
                registration_min_bond(&harder_by(d), before),
                min_mining_bond(before),
                "the retarget cannot bite at {before} (+{d} doublings)"
            );
        }
    }

    /// One doubling of the bond per `WORK_DOUBLINGS_PER_BOND_DOUBLING`
    /// doublings of work, and no partial steps in between.
    #[test]
    fn the_minimum_doubles_once_per_four_doublings_of_work() {
        let t = retargeting();
        let floor = min_mining_bond(t);
        let per = WORK_DOUBLINGS_PER_BOND_DOUBLING;
        for step in 0..=MAX_BOND_DOUBLINGS {
            for within in 0..per {
                let d = step * per + within;
                assert_eq!(
                    registration_min_bond(&harder_by(d), t),
                    floor << step,
                    "{d} doublings of work should ask {} units",
                    floor << step
                );
            }
        }
    }

    /// The ceiling holds however far midwimble's hashrate runs, and the
    /// floor holds however far it falls: the retarget only ever adds to what
    /// [`eligible`] already asks, so it can never strand a bond.
    #[test]
    fn the_retarget_stays_between_the_launch_minimum_and_the_ceiling() {
        let t = retargeting();
        for d in [0, 1, 7, 8, 9, 40, 100, 200] {
            let min = registration_min_bond(&harder_by(d), t);
            assert!(
                (min_mining_bond(t)..=MAX_MINING_BOND).contains(&min),
                "+{d} doublings asked {min}, outside [{}, {}]",
                min_mining_bond(t),
                MAX_MINING_BOND
            );
            assert_eq!(min.count_ones(), 1, "a bond is one midstate coin: {min}");
        }
        assert_eq!(
            registration_min_bond(&EASIEST, t),
            min_mining_bond(t),
            "an easier chain never asks less than the launch minimum"
        );
        assert_eq!(
            registration_min_bond(&harder_by(200), t),
            MAX_MINING_BOND,
            "the ceiling is the ceiling"
        );
        assert_eq!(
            registration_min_bond(&[0; 32], t),
            min_mining_bond(t),
            "a degenerate target reads as no work at all, which asks the \
             floor rather than the ceiling: the safe direction"
        );
    }

    /// The minimum only ever rises with the work, never falls with it.
    #[test]
    fn the_minimum_is_monotone_in_the_work() {
        let t = retargeting();
        let mut last = 0;
        for d in 0..=40u32 {
            let min = registration_min_bond(&harder_by(d), t);
            assert!(min >= last, "+{d} doublings dropped the minimum");
            last = min;
        }
    }

    fn registration(value: u64, bonded_until: u64) -> BondRegistration {
        BondRegistration {
            proof: BondProof {
                coin: BondCoin {
                    script: BondScript {
                        mining_key: [1; 32],
                        bonded_until,
                        owner_pk: [2; 32],
                    },
                    value,
                    salt: [3; 32],
                },
                midstate_height: 300_000,
                roots: MidstateRoots {
                    coins: [0; 32],
                    commitments: [0; 32],
                    chain_mmr: [0; 32],
                    burned_wots: None,
                },
                smt: UtxoAccumulator::from_set([[0; 32]], true)
                    .prove(&[0; 32], true)
                    .unwrap(),
            },
        }
    }

    /// Past the switch, a registration at the launch minimum is refused once
    /// the work has doubled the bar, and one at the new bar is taken.
    #[test]
    fn a_registration_under_the_retargeted_minimum_is_refused() {
        let t = retargeting();
        let target = harder_by(WORK_DOUBLINGS_PER_BOND_DOUBLING);
        let asked = registration_min_bond(&target, t);
        assert_eq!(asked, min_mining_bond(t) * 2, "one step up");
        let until = est_midstate_height(t) + min_remaining_bond_lock(t);
        let none = BondSet::default();

        let err = precheck_registrations(&none, &[registration(asked / 2, until)], &target, t)
            .unwrap_err()
            .to_string();
        assert!(err.contains("at least"), "{err}");
        assert!(err.contains("at this block's difficulty"), "{err}");

        precheck_registrations(&none, &[registration(asked, until)], &target, t)
            .expect("a bond at the retargeted minimum registers");
        // And the same bond would have been fine at genesis difficulty.
        precheck_registrations(
            &none,
            &[registration(asked / 2, until)],
            &super::super::types::GENESIS_TARGET,
            t,
        )
        .expect("the launch minimum still registers while the work has not moved");
    }

    /// The whole point of gating the retarget at registration: a bond locked
    /// under the old minimum keeps signing, and keeps counting towards the
    /// cap, after the bar has risen above it. The retarget prices the inflow
    /// and the stock follows as locks run out, rather than stranding coins
    /// their owners can no longer move.
    #[test]
    fn a_bond_registered_under_the_old_minimum_is_grandfathered() {
        let t = retargeting();
        let target = harder_by(MAX_BOND_DOUBLINGS * WORK_DOUBLINGS_PER_BOND_DOUBLING);
        assert_eq!(registration_min_bond(&target, t), MAX_MINING_BOND);

        let old = BondEntry {
            mining_key: [7; 32],
            value: min_mining_bond(t),
            bonded_until: u64::MAX,
            proven_height: 0,
            proven_hash: [0; 32],
        };
        assert!(
            old.value < registration_min_bond(&target, t),
            "the bar has risen above this bond"
        );
        assert!(
            old.eligible_at(t),
            "a bond already locked still authorises blocks"
        );

        let mut bonds = BondSet::default();
        bonds.insert([9; 32], old);
        assert_eq!(
            signer_cap(&bonds, t),
            signer_cap(&{
                let mut rich = BondSet::default();
                rich.insert([9; 32], BondEntry { value: MAX_MINING_BOND, ..old });
                rich
            }, t),
            "the cap counts bonds, not what they lock: an old bond is a full slot"
        );
        assert!(
            bonds.prune_expired(t).is_empty(),
            "and the retarget never prunes it"
        );
    }
}
