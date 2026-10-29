//! Midstate's header chain as midwimble consensus tracks it
//! (`docs/BONDED_POW.md`, "The midstate relay").
//!
//! A bond registration proves a coin against the state root of a midstate
//! header. Proof of work on that header is not enough on its own: anyone can
//! mine a private midstate fork whose state holds coins that were never
//! locked, and one such fork could back any number of bonds. So consensus
//! keeps its own view of midstate's chain, fed by block producers: the
//! heaviest chain of midstate headers that blocks have relayed, starting from
//! the midstate block the genesis commits to (`MIDSTATE_BLOCK_*`).
//!
//! * A block may relay a run of midstate headers ([`RelayHeaders`]) that
//!   extends the relay's tip, or that forks from a header in its window and
//!   outweighs everything it replaces. Each header must carry exactly the
//!   target midstate's own difficulty rule gives it ([`midstate_target`]), a
//!   timestamp at most [`RELAY_MAX_FUTURE`] past the relaying block's, and
//!   valid proof of work.
//! * A registration's header must be on the relay's chain, buried under the
//!   work the registration rule asks for (`bond::BondRegistration::verify`).
//! * When a heavier branch replaces relay headers, every bond proven against
//!   one of them is revoked: its coin is not known to exist any more.
//!
//! Keeping a fake bond therefore means keeping a fake midstate branch heavier
//! than the real one as producers relay it, which takes more than midstate's
//! whole hashrate for as long as the bond is to last.
//!
//! The relay keeps the last [`RELAY_WINDOW`] headers of its chain; nothing
//! older can be forked from or proven against. Each entry carries a digest
//! chained through every entry before it, and the state root commits to the
//! tip's, so the window is authenticated by one hash.
//!
//! Holding relayed headers to midstate's difficulty is what keeps the window
//! honest. Without it a producer could relay a long run of cheap headers and
//! push the real chain out of the window, after which it could never be
//! relayed again. With it a fake header costs what a real midstate block
//! costs, and more the further a fake branch runs ahead of real time: its
//! timestamps cannot pass the relaying block's by more than
//! [`RELAY_MAX_FUTURE`], so midstate's rule doubles its difficulty every four
//! hours of blocks it gets ahead. Running a window's length ahead of the real
//! chain would take midstate's whole network years of work; a branch forked
//! inside the window has to outweigh the real chain from there instead,
//! which takes more than midstate's whole hashrate for up to two days.

use super::anchor::{link_mining_hash, HeaderLink};
use super::simd_mining::{check_pow_jobs, PowCheck, PowJob};
use super::state::{asert_target, calculate_work};
use super::types::{
    hash_domain, midstate_pow_algo_at, PowAlgo, MAX_FUTURE_BLOCK_TIME, MIDSTATE_BLOCK_HASH,
    MIDSTATE_BLOCK_HEIGHT, MIDSTATE_WALK_TARGET_SHIFT,
};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

/// Most midstate headers one block may relay: a day of midstate blocks.
/// Enough to catch up after a day without feeders, or to relay a launch's
/// first bond with its burial; each costs every node one extension.
pub const MAX_RELAY_HEADERS_PER_BLOCK: usize = 24 * 60;
/// Block weight of each relayed header (144 bytes), in line with what
/// transaction data weighs per byte.
pub const RELAY_WEIGHT_PER_HEADER: u64 = 4;
/// Midstate headers the relay keeps below its tip: two days. A registration's
/// header must be this recent, and no branch may fork from further back.
pub const RELAY_WINDOW: u64 = 2 * 24 * 60;
/// How far a relayed header's timestamp may be past the relaying block's:
/// twice the future limit each chain allows its own blocks, so a real header
/// relayed as soon as it is mined always fits whichever way the two clocks
/// differ, while a fake branch cannot claim time that has not passed.
pub const RELAY_MAX_FUTURE: u64 = 2 * MAX_FUTURE_BLOCK_TIME;

/// Midstate's genesis target and time, which its difficulty rule (the same
/// ASERT as midwimble's, anchored at midstate's genesis) is computed from.
#[cfg(not(feature = "fast-mining"))]
const MIDSTATE_ASERT_TARGET: [u8; 32] = {
    let mut t = [0xff; 32];
    t[0] = 0x00;
    t[1] = 0x11;
    t
};
#[cfg(not(feature = "fast-mining"))]
const MIDSTATE_ASERT_TIME: u64 = 1_772_274_770;

/// Test builds: the stand-in midstate's ([`devnet`]), whose headers are
/// timestamped on schedule ([`devnet_timestamp`]) and so all carry
/// [`DEVNET_TARGET`].
#[cfg(feature = "fast-mining")]
const MIDSTATE_ASERT_TARGET: [u8; 32] = DEVNET_TARGET;
#[cfg(feature = "fast-mining")]
const MIDSTATE_ASERT_TIME: u64 = DEVNET_EPOCH - 60 - 60 * MIDSTATE_BLOCK_HEIGHT;

/// About a thousand attempts a header: cheap with test extensions, and enough
/// work that sixty of them bury a test registration.
#[cfg(feature = "fast-mining")]
pub const DEVNET_TARGET: [u8; 32] = {
    let mut t = [0xff; 32];
    t[0] = 0x00;
    t[1] = 0x3f;
    t
};
/// When the stand-in midstate's chain reaches the relay's root: long before
/// any test chain's genesis, so its headers are never in a block's future.
#[cfg(feature = "fast-mining")]
pub const DEVNET_EPOCH: u64 = 1_600_000_000;

/// The stand-in midstate's timestamp for its header at `height`: one a
/// minute from the relay's root, exactly on schedule.
#[cfg(feature = "fast-mining")]
pub fn devnet_timestamp(height: u64) -> u64 {
    midstate_schedule(height)
}

/// The timestamp that puts midstate's header at `height` exactly on its
/// schedule: a header whose parent was stamped
/// `midstate_schedule(height - 1)` carries midstate's genesis target. Each
/// four hours earlier doubles its difficulty, each four hours later halves
/// it.
pub fn midstate_schedule(height: u64) -> u64 {
    MIDSTATE_ASERT_TIME.saturating_add(60u64.saturating_mul(height.saturating_add(1)))
}

/// The target midstate's difficulty rule gives its header at `height`, whose
/// parent is timestamped `parent_timestamp` (midstate checks exactly this:
/// `calculate_target(prev.height + 1, prev.timestamp)`), including its
/// difficulty reset from its switch to Midstate Walk.
pub fn midstate_target(height: u64, parent_timestamp: u64) -> [u8; 32] {
    let shift = match midstate_pow_algo_at(height) {
        PowAlgo::Walk => MIDSTATE_WALK_TARGET_SHIFT,
        PowAlgo::Blake3Chain => 0,
    };
    asert_target(
        &MIDSTATE_ASERT_TARGET,
        MIDSTATE_ASERT_TIME,
        height,
        parent_timestamp,
        shift,
    )
}

fn root_hash() -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(MIDSTATE_BLOCK_HASH, &mut out)
        .expect("MIDSTATE_BLOCK_HASH is 32 bytes of hex");
    out
}

/// A midstate header on the relay's chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEntry {
    /// Midstate height.
    pub height: u64,
    /// The header's final hash, which the next header links to.
    pub hash: [u8; 32],
    pub prev: [u8; 32],
    /// What bond proofs are checked against. Zero for the root, whose header
    /// fields are not known (only its hash is pinned).
    pub state_root: [u8; 32],
    pub timestamp: u64,
    /// Work its target claims, and the chain's total from the root.
    pub work: u128,
    pub chain_work: u128,
    /// Commits to this entry and, through the previous digest, every entry
    /// before it back to the root.
    pub digest: [u8; 32],
}

impl RelayEntry {
    /// The midstate block the genesis commits to. Only its hash is pinned, so
    /// nothing can be proven against it; it is where relaying starts.
    pub fn root() -> Self {
        let hash = root_hash();
        Self {
            height: MIDSTATE_BLOCK_HEIGHT,
            hash,
            prev: [0; 32],
            state_root: [0; 32],
            timestamp: 0,
            work: 0,
            chain_work: 0,
            digest: hash_domain(
                b"midwimble.relay-root.v1",
                &[&hash, &MIDSTATE_BLOCK_HEIGHT.to_le_bytes()],
            ),
        }
    }

    pub fn is_root(&self) -> bool {
        *self == Self::root()
    }

    /// The entry `link` makes on top of this one.
    fn next(&self, link: &HeaderLink, work: u128) -> Self {
        let mut e = Self {
            height: self.height + 1,
            hash: link.final_hash,
            prev: self.hash,
            state_root: link.state_root,
            timestamp: link.timestamp,
            work,
            chain_work: self.chain_work.saturating_add(work),
            digest: [0; 32],
        };
        e.digest = e.digest_after(&self.digest);
        e
    }

    fn digest_after(&self, prev_digest: &[u8; 32]) -> [u8; 32] {
        hash_domain(
            b"midwimble.relay-entry.v1",
            &[
                prev_digest,
                &self.height.to_le_bytes(),
                &self.hash,
                &self.prev,
                &self.state_root,
                &self.timestamp.to_le_bytes(),
                &self.work.to_le_bytes(),
                &self.chain_work.to_le_bytes(),
            ],
        )
    }
}

/// Midstate headers a block relays: the relay entry the first builds on,
/// then each header building on the one before.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayHeaders {
    pub prev: [u8; 32],
    pub headers: Vec<HeaderLink>,
}

impl RelayHeaders {
    pub fn weight(&self) -> u64 {
        RELAY_WEIGHT_PER_HEADER.saturating_mul(self.headers.len() as u64)
    }

    /// What a block's fold commits to.
    pub fn hash(&self) -> [u8; 32] {
        let bytes = bincode::serialize(self).expect("relay headers serialize");
        hash_domain(b"midwimble.relay-headers.v1", &[&bytes])
    }

    /// Every header's proof of work: the expensive half of the checks, run
    /// once [`Relay::extend`] has accepted the run. The first header is
    /// checked alone and the rest in parallel batches, so a forged run costs
    /// one extension to reject.
    ///
    /// `first_height` is the midstate height of the first header (one above
    /// the relay entry `prev` names): each header is checked with the proof
    /// of work midstate requires at its height ([`midstate_pow_algo_at`]).
    pub fn verify_pow(&self, first_height: u64) -> Result<()> {
        let mut prev = self.prev;
        let mut jobs = Vec::with_capacity(self.headers.len());
        for (i, link) in self.headers.iter().enumerate() {
            jobs.push(PowJob {
                algo: midstate_pow_algo_at(first_height + i as u64),
                mining_hash: link_mining_hash(prev, link),
                nonce: link.nonce,
                final_hash: link.final_hash,
            });
            prev = link.final_hash;
        }
        match check_pow_jobs(&jobs) {
            Ok(()) => Ok(()),
            Err(PowCheck::Bad(i)) => bail!("relayed midstate header {i} fails its proof of work"),
            Err(PowCheck::Abandoned) => bail!("relay verification abandoned"),
        }
    }
}

/// What relaying changed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayChange {
    /// New entries, lowest first.
    pub added: Vec<RelayEntry>,
    /// Entries replaced by a heavier branch, then entries that left the
    /// window.
    pub removed: Vec<RelayEntry>,
    /// When a branch was replaced, the height it forked from: every entry
    /// above it is new.
    pub fork_from: Option<u64>,
}

/// The relay's chain: the last [`RELAY_WINDOW`] midstate headers of the
/// heaviest chain relayed so far, by height.
#[derive(Clone, Debug)]
pub struct Relay {
    entries: im::OrdMap<u64, RelayEntry>,
    heights: im::HashMap<[u8; 32], u64>,
}

impl PartialEq for Relay {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}

impl Eq for Relay {}

impl Default for Relay {
    fn default() -> Self {
        Self::genesis()
    }
}

impl Serialize for Relay {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let entries: Vec<&RelayEntry> = self.entries.values().collect();
        entries.serialize(s)
    }
}

impl<'de> Deserialize<'de> for Relay {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let entries = Vec::<RelayEntry>::deserialize(d)?;
        Relay::from_entries(entries).map_err(serde::de::Error::custom)
    }
}

impl Relay {
    /// The relay before anything is relayed: the root alone.
    pub fn genesis() -> Self {
        let root = RelayEntry::root();
        Self {
            entries: im::OrdMap::unit(root.height, root),
            heights: im::HashMap::unit(root.hash, root.height),
        }
    }

    /// Rebuilds a relay from its entries, lowest first, checking that they
    /// form one chain: consecutive heights, each linked to the one below, its
    /// work added, and its digest chained from the one below. Only the first
    /// entry is taken as given; a caller that knows the commitment
    /// ([`Relay::commitment`]) authenticates all of it by comparing.
    pub fn from_entries(entries: Vec<RelayEntry>) -> Result<Self> {
        let first = *entries
            .first()
            .ok_or_else(|| anyhow!("a relay has at least one entry"))?;
        if entries.len() as u64 > RELAY_WINDOW + 1 {
            bail!("a relay holds at most {} entries", RELAY_WINDOW + 1);
        }
        let mut relay = Self {
            entries: im::OrdMap::new(),
            heights: im::HashMap::new(),
        };
        relay.insert(first);
        for pair in entries.windows(2) {
            let (below, e) = (&pair[0], &pair[1]);
            if e.height != below.height + 1
                || e.prev != below.hash
                || e.chain_work != below.chain_work.saturating_add(e.work)
                || e.digest != e.digest_after(&below.digest)
            {
                bail!(
                    "relay entries do not form a chain at midstate height {}",
                    e.height
                );
            }
            if relay.heights.contains_key(&e.hash) {
                bail!("relay entry {} appears twice", hex::encode(e.hash));
            }
            relay.insert(*e);
        }
        Ok(relay)
    }

    fn insert(&mut self, e: RelayEntry) {
        self.entries.insert(e.height, e);
        self.heights.insert(e.hash, e.height);
    }

    fn remove(&mut self, height: u64) -> Option<RelayEntry> {
        let e = self.entries.remove(&height)?;
        self.heights.remove(&e.hash);
        Some(e)
    }

    pub fn tip(&self) -> &RelayEntry {
        self.entries
            .values()
            .next_back()
            .expect("a relay is never empty")
    }

    /// The lowest entry kept.
    pub fn base(&self) -> &RelayEntry {
        self.entries
            .values()
            .next()
            .expect("a relay is never empty")
    }

    pub fn get(&self, height: u64) -> Option<&RelayEntry> {
        self.entries.get(&height)
    }

    pub fn by_hash(&self, hash: &[u8; 32]) -> Option<&RelayEntry> {
        self.heights.get(hash).and_then(|h| self.entries.get(h))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries lowest first.
    pub fn entries(&self) -> impl Iterator<Item = &RelayEntry> {
        self.entries.values()
    }

    /// What the state root commits to: the tip's digest, which chains
    /// through every entry.
    pub fn commitment(&self) -> [u8; 32] {
        self.tip().digest
    }

    /// Work credited above the entry at `height`, towards a registration:
    /// each header counts for at most `cap`.
    pub fn credited_above(&self, height: u64, cap: u128) -> u128 {
        self.entries
            .range(height.saturating_add(1)..)
            .fold(0u128, |sum, (_, e)| sum.saturating_add(e.work.min(cap)))
    }

    /// Applies the headers relayed by a block timestamped `block_timestamp`,
    /// after the cheap checks: each builds on the one before, the first on an
    /// entry of this relay; each carries the target midstate's difficulty
    /// rule gives it and meets that target, and is timestamped no more than
    /// [`RELAY_MAX_FUTURE`] past the block; and a run that forks below the
    /// tip is new and outweighs the branch it replaces. Proof of work is left
    /// to [`RelayHeaders::verify_pow`]. On error the relay is unchanged.
    ///
    /// The root's own header fields are not known, only its hash, so its
    /// child's target cannot be recomputed and is taken as claimed: one
    /// header, whose work still counts only as far as its proof of work.
    pub fn extend(&mut self, relayed: &RelayHeaders, block_timestamp: u64) -> Result<RelayChange> {
        let n = relayed.headers.len();
        if n == 0 {
            bail!("a block that relays midstate headers relays at least one");
        }
        if n > MAX_RELAY_HEADERS_PER_BLOCK {
            bail!("a block relays at most {MAX_RELAY_HEADERS_PER_BLOCK} midstate headers, not {n}");
        }
        let base = *self.by_hash(&relayed.prev).ok_or_else(|| {
            anyhow!(
                "relayed headers build on {}, which is not on the relay's chain",
                hex::encode(relayed.prev)
            )
        })?;
        let tip = *self.tip();
        if base.height < tip.height {
            let replaced = self.get(base.height + 1).expect("entries are consecutive");
            if relayed.headers[0].final_hash == replaced.hash {
                bail!("relayed headers repeat the relay's own chain");
            }
        }
        let latest = block_timestamp.saturating_add(RELAY_MAX_FUTURE);
        let mut added = Vec::with_capacity(n);
        let mut last = base;
        for (i, link) in relayed.headers.iter().enumerate() {
            if link.final_hash >= link.target {
                bail!("relayed midstate header {i} misses its own target");
            }
            if link.timestamp > latest {
                bail!(
                    "relayed midstate header {i} is timestamped {}, more than {RELAY_MAX_FUTURE}s past the block relaying it",
                    link.timestamp
                );
            }
            if !last.is_root() && link.target != midstate_target(last.height + 1, last.timestamp) {
                bail!(
                    "relayed midstate header {i} (height {}) does not carry the target midstate's difficulty rule gives it",
                    last.height + 1
                );
            }
            let work = calculate_work(&link.target);
            let entry = last.next(link, work);
            if self
                .heights
                .get(&entry.hash)
                .is_some_and(|h| *h <= base.height)
            {
                bail!("relayed midstate header {i} is already on the relay's chain");
            }
            added.push(entry);
            last = entry;
        }
        if base.height < tip.height && last.chain_work <= tip.chain_work {
            bail!(
                "a relayed branch from midstate height {} must outweigh the one it replaces",
                base.height
            );
        }
        let mut removed: Vec<RelayEntry> = Vec::new();
        for h in base.height + 1..=tip.height {
            removed.extend(self.remove(h));
        }
        let fork_from = (!removed.is_empty()).then_some(base.height);
        for e in &added {
            self.insert(*e);
        }
        let keep_from = self.tip().height.saturating_sub(RELAY_WINDOW);
        let stale: Vec<u64> = self.entries.range(..keep_from).map(|(h, _)| *h).collect();
        for h in stale {
            removed.extend(self.remove(h));
        }
        Ok(RelayChange {
            added,
            removed,
            fork_from,
        })
    }

    /// Replays a change (storage and in-memory rewinds use these).
    pub fn apply_change(&mut self, removed: &[RelayEntry], added: &[RelayEntry]) {
        for e in removed {
            self.remove(e.height);
        }
        for e in added {
            self.insert(*e);
        }
    }

    /// Takes a change back.
    pub fn revert_change(&mut self, removed: &[RelayEntry], added: &[RelayEntry]) {
        for e in added {
            self.remove(e.height);
        }
        for e in removed {
            self.insert(*e);
        }
    }
}

/// A run of midstate headers from a midstate node or a bond file, with the
/// height of the first: material for blocks to relay.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MidstateHeaders {
    /// Midstate height of the first header.
    pub start: u64,
    /// The hash of the header before the first.
    pub prev: [u8; 32],
    pub headers: Vec<HeaderLink>,
}

impl MidstateHeaders {
    /// Checks each header meets its own target, links to the one before,
    /// and has valid proof of work.
    pub fn verify(&self) -> Result<()> {
        for (i, link) in self.headers.iter().enumerate() {
            if link.final_hash >= link.target {
                bail!(
                    "midstate header {} misses its own target",
                    self.start + i as u64
                );
            }
        }
        RelayHeaders {
            prev: self.prev,
            headers: self.headers.clone(),
        }
        .verify_pow(self.start)
    }
}

/// Midstate headers a producer has to relay, by height, merged from its
/// sources (a midstate node, bond files). Not consensus: it only proposes
/// what a template relays, and consensus checks it.
#[derive(Clone, Debug, Default)]
pub struct RelayFeed {
    /// height -> (hash of the header below, header)
    headers: std::collections::BTreeMap<u64, ([u8; 32], HeaderLink)>,
}

/// Headers a feed keeps above the relay's tip.
const FEED_AHEAD: u64 = 2 * MAX_RELAY_HEADERS_PER_BLOCK as u64;

impl RelayFeed {
    /// Adds a run of headers. Where a height is already held, `replace`
    /// decides which wins (a live midstate node's view should; a bond file's
    /// should not).
    pub fn add(&mut self, run: &MidstateHeaders, replace: bool) {
        let mut prev = run.prev;
        for (i, link) in run.headers.iter().enumerate() {
            let height = run.start + i as u64;
            if replace || !self.headers.contains_key(&height) {
                self.headers.insert(height, (prev, link.clone()));
            }
            prev = link.final_hash;
        }
    }

    pub fn len(&self) -> usize {
        self.headers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// The highest height held.
    pub fn tip_height(&self) -> Option<u64> {
        self.headers.keys().next_back().copied()
    }

    /// Forgets headers the relay no longer needs (below its window) and any
    /// far beyond what blocks could relay soon.
    pub fn prune(&mut self, relay: &Relay) {
        let below = relay.base().height;
        self.headers = self.headers.split_off(&below);
        let above = relay.tip().height.saturating_add(FEED_AHEAD);
        self.headers.split_off(&(above + 1));
    }

    /// What a block on `relay` could relay from this feed: the run that
    /// extends the relay's tip, or else a run that forks from an entry in
    /// its window and differs from the relay there. Consensus decides
    /// whether a fork outweighs what it replaces; this only proposes it.
    pub fn next_for(&self, relay: &Relay) -> Option<RelayHeaders> {
        let tip = relay.tip();
        let start = match self.headers.get(&(tip.height + 1)) {
            Some((prev, _)) if *prev == tip.hash => tip.height + 1,
            _ => {
                // The highest height where the feed branches off the relay.
                let base = relay.base().height;
                (base + 1..=tip.height).rev().find(|h| {
                    match (self.headers.get(h), relay.get(h - 1), relay.get(*h)) {
                        (Some((prev, link)), Some(below), Some(ours)) => {
                            *prev == below.hash && link.final_hash != ours.hash
                        }
                        _ => false,
                    }
                })?
            }
        };
        let (prev, _) = self.headers.get(&start)?;
        let mut run = RelayHeaders {
            prev: *prev,
            headers: Vec::new(),
        };
        let mut expect = *prev;
        for (_, (below, link)) in self.headers.range(start..) {
            if *below != expect || run.headers.len() == MAX_RELAY_HEADERS_PER_BLOCK {
                break;
            }
            expect = link.final_hash;
            run.headers.push(link.clone());
        }
        (!run.headers.is_empty()).then_some(run)
    }
}

/// A stand-in midstate for test builds: bond coins in a UTXO tree, and
/// headers mined with short extensions on top of the relay's root.
#[cfg(feature = "fast-mining")]
pub mod devnet {
    use super::*;
    use crate::core::bond::{BondCoin, BondProof, MidstateRoots};
    use crate::core::extension::create_extension_with;
    use crate::core::mmr::UtxoAccumulator;
    use crate::core::types::hash;

    /// Headers mined on top of the relay root, with a UTXO set of coins.
    #[derive(Clone, Debug)]
    pub struct DevnetMidstate {
        coins: UtxoAccumulator,
        /// Every header mined so far, from the root's child.
        pub mined: MidstateHeaders,
        /// The roots each header committed to, by height.
        roots: Vec<(u64, MidstateRoots)>,
        pub target: [u8; 32],
    }

    impl Default for DevnetMidstate {
        fn default() -> Self {
            Self::new()
        }
    }

    impl DevnetMidstate {
        pub fn new() -> Self {
            let root = RelayEntry::root();
            let mut coins = UtxoAccumulator::new();
            for i in 0..8u8 {
                coins.insert(hash(&[i, 0xb0]), true);
            }
            Self {
                coins,
                mined: MidstateHeaders {
                    start: root.height + 1,
                    prev: root.hash,
                    headers: Vec::new(),
                },
                roots: Vec::new(),
                target: DEVNET_TARGET,
            }
        }

        /// Puts a coin in the UTXO set the next header commits to.
        pub fn lock(&mut self, coin: &BondCoin) {
            self.coins.insert(coin.coin_id(), true);
        }

        pub fn height(&self) -> u64 {
            self.mined.start + self.mined.headers.len() as u64 - 1
        }

        /// Mines `n` headers, each committing to the current coins.
        pub fn mine(&mut self, n: u64) {
            for _ in 0..n {
                let height = self.mined.start + self.mined.headers.len() as u64;
                let roots = MidstateRoots {
                    coins: self.coins.root(true),
                    commitments: hash(b"devnet commitments"),
                    chain_mmr: hash(&height.to_le_bytes()),
                    burned_wots: Some(hash(b"devnet burned")),
                };
                let prev = self
                    .mined
                    .headers
                    .last()
                    .map_or(self.mined.prev, |h| h.final_hash);
                let mut link = HeaderLink {
                    post_tx_midstate: hash(&[&height.to_le_bytes()[..], b"devnet"].concat()),
                    state_root: roots
                        .state_root(height)
                        .expect("devnet heights are past V4"),
                    timestamp: devnet_timestamp(height),
                    target: self.target,
                    nonce: 0,
                    final_hash: [0; 32],
                };
                let mining = link_mining_hash(prev, &link);
                let algo = midstate_pow_algo_at(height);
                loop {
                    let fin = create_extension_with(algo, mining, link.nonce).final_hash;
                    if fin < link.target {
                        link.final_hash = fin;
                        break;
                    }
                    link.nonce += 1;
                }
                self.mined.headers.push(link);
                self.roots.push((height, roots));
            }
        }

        /// A proof that `coin` is unspent at the latest header.
        pub fn prove(&self, coin: &BondCoin) -> BondProof {
            let (height, roots) = *self.roots.last().expect("mine a header first");
            BondProof {
                coin: *coin,
                midstate_height: height,
                roots,
                smt: self
                    .coins
                    .prove(&coin.coin_id(), true)
                    .expect("the coin is locked"),
            }
        }

        /// Headers from `start` on.
        pub fn from_height(&self, start: u64) -> MidstateHeaders {
            let skip = start.saturating_sub(self.mined.start) as usize;
            let prev = match skip {
                0 => self.mined.prev,
                k => self.mined.headers[k - 1].final_hash,
            };
            MidstateHeaders {
                start: self.mined.start + skip as u64,
                prev,
                headers: self.mined.headers[skip.min(self.mined.headers.len())..].to_vec(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::hash;
    use primitive_types::U256;

    /// A block timestamp no relayed header in these tests is ahead of.
    const LATER: u64 = u64::MAX / 4;

    fn on_schedule(height: u64) -> u64 {
        midstate_schedule(height)
    }

    /// A header at `height` on `prev`, timestamped `ts`, carrying `target`
    /// and a final hash that meets it. `extend` does not check proof of work
    /// (that is `verify_pow`'s half), so none is done.
    fn link(prev: [u8; 32], height: u64, ts: u64, target: [u8; 32], salt: u8) -> HeaderLink {
        let seed = hash(&[&prev[..], &height.to_le_bytes(), &[salt]].concat());
        let below = U256::from_big_endian(&seed) % U256::from_big_endian(&target);
        HeaderLink {
            post_tx_midstate: hash(&[&seed[..], b"post"].concat()),
            state_root: hash(&[&seed[..], b"root"].concat()),
            timestamp: ts,
            target,
            nonce: 0,
            final_hash: below.to_big_endian(),
        }
    }

    /// `n` headers on `base`, each timestamped `ts(height)` and carrying the
    /// target midstate's rule gives it.
    fn run_with(base: &RelayEntry, n: usize, salt: u8, ts: impl Fn(u64) -> u64) -> RelayHeaders {
        let mut headers: Vec<HeaderLink> = Vec::new();
        let (mut prev, mut prev_ts) = (base.hash, base.timestamp);
        for i in 0..n {
            let height = base.height + 1 + i as u64;
            if i == 0 && base.is_root() {
                prev_ts = ts(height - 1);
            }
            let l = link(
                prev,
                height,
                ts(height),
                midstate_target(height, prev_ts),
                salt,
            );
            (prev, prev_ts) = (l.final_hash, l.timestamp);
            headers.push(l);
        }
        RelayHeaders {
            prev: base.hash,
            headers,
        }
    }

    fn run(base: &RelayEntry, n: usize, salt: u8) -> RelayHeaders {
        run_with(base, n, salt, on_schedule)
    }

    fn work_on_schedule() -> u128 {
        calculate_work(&MIDSTATE_ASERT_TARGET)
    }

    #[test]
    fn runs_extend_the_tip_and_commit_to_everything() {
        let mut relay = Relay::genesis();
        let root = relay.commitment();
        let a = run(&RelayEntry::root(), 5, 1);
        let change = relay.extend(&a, LATER).unwrap();
        assert_eq!(change.added.len(), 5);
        assert!(change.removed.is_empty() && change.fork_from.is_none());
        assert_eq!(relay.tip().height, MIDSTATE_BLOCK_HEIGHT + 5);
        assert_eq!(relay.tip().chain_work, 5 * work_on_schedule());
        assert_ne!(relay.commitment(), root);
        // Rebuilt from its entries, it is the same relay; tampered, it is not.
        let entries: Vec<RelayEntry> = relay.entries().copied().collect();
        assert_eq!(Relay::from_entries(entries.clone()).unwrap(), relay);
        let mut bad = entries.clone();
        bad[3].state_root[0] ^= 1;
        assert!(Relay::from_entries(bad).is_err());
        // Serialised as entries; deserialising checks them.
        let back: Relay = bincode::deserialize(&bincode::serialize(&relay).unwrap()).unwrap();
        assert_eq!(back, relay);

        // Continuing from the tip works; from nowhere, or repeating, does not.
        let b = run(relay.tip(), 2, 2);
        relay.clone().extend(&b, LATER).unwrap();
        let mut nowhere = b.clone();
        nowhere.prev = [9; 32];
        assert!(relay.clone().extend(&nowhere, LATER).is_err());
        let again = RelayHeaders {
            prev: a.prev,
            headers: a.headers[..2].to_vec(),
        };
        assert!(relay.clone().extend(&again, LATER).is_err());
        // A header that misses its own target.
        let mut missed = b.clone();
        missed.headers[1].final_hash = [0xff; 32];
        assert!(relay.clone().extend(&missed, LATER).is_err());
    }

    #[test]
    fn heavier_branches_replace_lighter_ones_and_say_where() {
        let mut relay = Relay::genesis();
        let root = RelayEntry::root();
        relay.extend(&run(&root, 6, 1), LATER).unwrap();
        let fork_at = *relay.get(root.height + 2).unwrap();
        let before = relay.clone();
        // Same length, same work: not heavier.
        let level = run(&fork_at, 4, 7);
        assert!(relay.clone().extend(&level, LATER).is_err());
        // One more header outweighs it (every header follows midstate's
        // difficulty, so on schedule they all weigh the same).
        let heavy = run(&fork_at, 5, 8);
        let change = relay.extend(&heavy, LATER).unwrap();
        assert_eq!(change.fork_from, Some(root.height + 2));
        assert_eq!(change.removed.len(), 4);
        assert_eq!(relay.tip().height, root.height + 7);
        assert_eq!(
            relay.get(root.height + 3).unwrap().hash,
            heavy.headers[0].final_hash
        );
        // Undoing the change restores the relay exactly.
        let mut undone = relay.clone();
        undone.revert_change(&change.removed, &change.added);
        assert_eq!(undone, before);
        let mut redone = before.clone();
        redone.apply_change(&change.removed, &change.added);
        assert_eq!(redone, relay);
    }

    #[test]
    fn the_window_is_kept_and_burial_is_capped() {
        let mut relay = Relay::genesis();
        let root = RelayEntry::root();
        // Fill past the window in a few blocks' worth of runs.
        let mut total = 0;
        while total <= RELAY_WINDOW + 10 {
            let n = (RELAY_WINDOW as usize + 20 - total as usize).min(MAX_RELAY_HEADERS_PER_BLOCK);
            let r = run(relay.tip(), n, (total % 251) as u8);
            let change = relay.extend(&r, LATER).unwrap();
            total += n as u64;
            assert_eq!(relay.len() as u64, (total + 1).min(RELAY_WINDOW + 1));
            if total > RELAY_WINDOW {
                assert!(!change.removed.is_empty(), "old entries leave the window");
            }
        }
        assert_eq!(relay.base().height, relay.tip().height - RELAY_WINDOW);
        assert!(relay.get(root.height).is_none());
        // From the window's lowest entry, nothing below it.
        let h = relay.base().height;
        assert_eq!(
            relay.credited_above(h, u128::MAX),
            RELAY_WINDOW as u128 * work_on_schedule()
        );
        assert_eq!(relay.credited_above(h, 0), 0);
        let from_old = run(&root, 1, 99);
        assert!(
            relay.clone().extend(&from_old, LATER).is_err(),
            "the root is out of the window"
        );
    }

    #[test]
    fn a_feed_proposes_the_run_the_relay_needs() {
        let root = RelayEntry::root();
        let mut relay = Relay::genesis();
        let chain = run(&root, 8, 1);
        let feed_run = MidstateHeaders {
            start: root.height + 1,
            prev: root.hash,
            headers: chain.headers.clone(),
        };
        let mut feed = RelayFeed::default();
        feed.add(&feed_run, true);
        let first = feed.next_for(&relay).unwrap();
        assert_eq!(first, chain);
        relay
            .extend(
                &RelayHeaders {
                    prev: chain.prev,
                    headers: chain.headers[..3].to_vec(),
                },
                LATER,
            )
            .unwrap();
        let rest = feed.next_for(&relay).unwrap();
        assert_eq!(rest.headers, chain.headers[3..].to_vec());
        relay.extend(&rest, LATER).unwrap();
        assert!(feed.next_for(&relay).is_none(), "nothing left to relay");

        // A heavier (longer) branch in the feed is proposed from where it
        // branches off.
        let fork_at = *relay.get(root.height + 5).unwrap();
        let branch = run(&fork_at, 4, 5);
        feed.add(
            &MidstateHeaders {
                start: root.height + 6,
                prev: fork_at.hash,
                headers: branch.headers.clone(),
            },
            true,
        );
        let proposed = feed.next_for(&relay).unwrap();
        assert_eq!(proposed, branch);
        relay.extend(&proposed, LATER).unwrap();
        feed.prune(&relay);
        assert!(feed.next_for(&relay).is_none());
    }

    /// Every relayed header must carry exactly the target midstate's own
    /// rule gives it: neither an easier one (a cheap header) nor a harder
    /// one. Only the root's child, whose parent's timestamp is not known, is
    /// taken as claimed.
    #[test]
    fn relayed_headers_carry_midstates_difficulty() {
        let mut relay = Relay::genesis();
        let root = RelayEntry::root();
        // The root's child may claim any target; the next must follow it.
        let mut child = run(&root, 2, 1);
        let easy = [0xff; 32];
        child.headers[0] = link(
            root.hash,
            root.height + 1,
            on_schedule(root.height + 1),
            easy,
            1,
        );
        child.headers[1] = link(
            child.headers[0].final_hash,
            root.height + 2,
            on_schedule(root.height + 2),
            midstate_target(root.height + 2, on_schedule(root.height + 1)),
            1,
        );
        relay.extend(&child, LATER).unwrap();
        assert_eq!(
            relay.get(root.height + 1).unwrap().work,
            calculate_work(&easy)
        );

        let tip = *relay.tip();
        let good = run(&tip, 3, 2);
        relay.clone().extend(&good, LATER).unwrap();
        let wanted = U256::from_big_endian(&good.headers[1].target);
        for (claimed, what) in [(wanted << 4, "easier"), (wanted >> 1, "harder")] {
            let mut bad = good.clone();
            let h = tip.height + 2;
            let l = link(
                bad.headers[0].final_hash,
                h,
                on_schedule(h),
                claimed.to_big_endian(),
                3,
            );
            bad.headers[1] = l;
            bad.headers.truncate(2);
            let err = relay.clone().extend(&bad, LATER).unwrap_err().to_string();
            assert!(err.contains("difficulty rule"), "{what}: {err}");
        }
    }

    /// Midstate's difficulty reset at its switch to Midstate Walk, mirrored:
    /// on schedule, the last BLAKE3-chain header carries the genesis target
    /// and the first Walk header that target times `2^MIDSTATE_WALK_TARGET_SHIFT`.
    #[test]
    fn midstates_walk_difficulty_reset_is_mirrored() {
        use crate::core::types::{
            MIDSTATE_WALK_ACTIVATION_HEIGHT as SWITCH, MIDSTATE_WALK_TARGET_SHIFT,
        };
        let before = midstate_target(SWITCH - 1, midstate_schedule(SWITCH - 2));
        let after = midstate_target(SWITCH, midstate_schedule(SWITCH - 1));
        assert_eq!(before, MIDSTATE_ASERT_TARGET);
        assert_eq!(
            U256::from_big_endian(&after),
            U256::from_big_endian(&MIDSTATE_ASERT_TARGET) << (MIDSTATE_WALK_TARGET_SHIFT as usize)
        );
    }

    /// A relayed header may be timestamped at most RELAY_MAX_FUTURE past the
    /// block relaying it, root's child included.
    #[test]
    fn relayed_headers_cannot_claim_time_that_has_not_passed() {
        let mut relay = Relay::genesis();
        relay
            .extend(&run(&RelayEntry::root(), 3, 1), LATER)
            .unwrap();
        let tip = *relay.tip();
        let block = tip.timestamp + 600;
        let latest = block + RELAY_MAX_FUTURE;
        let at = |last: u64| {
            move |h: u64| {
                if h == tip.height + 2 {
                    last
                } else {
                    tip.timestamp + 60 * (h - tip.height)
                }
            }
        };
        relay
            .clone()
            .extend(&run_with(&tip, 2, 2, at(latest)), block)
            .unwrap();
        let err = relay
            .clone()
            .extend(&run_with(&tip, 2, 2, at(latest + 1)), block)
            .unwrap_err()
            .to_string();
        assert!(err.contains("past the block"), "{err}");
    }

    /// Test builds: proof of work on the stand-in midstate's mined headers.
    #[cfg(feature = "fast-mining")]
    #[test]
    fn relayed_headers_need_their_proof_of_work() {
        let mut ms = devnet::DevnetMidstate::new();
        ms.mine(5);
        let run = ms.from_height(ms.mined.start);
        let mined = RelayHeaders {
            prev: run.prev,
            headers: run.headers,
        };
        Relay::genesis().extend(&mined, LATER).unwrap();
        mined.verify_pow(run.start).unwrap();
        // A forged proof of work passes the cheap checks and fails the
        // expensive one.
        let mut forged = mined.clone();
        forged.headers[3].nonce += 1;
        Relay::genesis().extend(&forged, LATER).unwrap();
        assert!(forged.verify_pow(run.start).is_err());
    }

    /// Test builds: a run across midstate's switch to Midstate Walk. Below
    /// it headers carry the BLAKE3 chain, from it the Walk, and each is
    /// refused if checked as if it sat on the other side.
    #[cfg(feature = "fast-mining")]
    #[test]
    fn relayed_headers_switch_to_the_walk_with_midstate() {
        use crate::core::types::MIDSTATE_WALK_ACTIVATION_HEIGHT as SWITCH;
        let mut ms = devnet::DevnetMidstate::new();
        ms.mine(SWITCH - ms.mined.start + 3);
        let run = ms.from_height(ms.mined.start);
        let relayed = RelayHeaders {
            prev: run.prev,
            headers: run.headers.clone(),
        };
        let mut relay = Relay::genesis();
        relay.extend(&relayed, LATER).unwrap();
        relayed.verify_pow(run.start).unwrap();
        assert_eq!(relay.tip().height, SWITCH + 2);
        // Labelled one height lower, the last chain header is checked with
        // the Walk and the first Walk header with the chain: both fail.
        let around = ms.from_height(SWITCH - 1);
        let two = RelayHeaders {
            prev: around.prev,
            headers: around.headers[..2].to_vec(),
        };
        two.verify_pow(SWITCH - 1).unwrap();
        assert!(two.verify_pow(SWITCH).is_err());
        assert!(two.verify_pow(SWITCH - 2).is_err());
    }

    /// Real midstate headers (`testdata/midstate-headers.txt`, from a mainnet
    /// node), checked against midstate's real rule: production builds only.
    #[cfg(not(feature = "fast-mining"))]
    mod real {
        use super::*;

        struct Real {
            height: u64,
            prev: [u8; 32],
            link: HeaderLink,
        }

        fn real_headers() -> Vec<Real> {
            let h32 = |s: &str| -> [u8; 32] {
                let mut out = [0u8; 32];
                hex::decode_to_slice(s, &mut out).unwrap();
                out
            };
            include_str!("testdata/midstate-headers.txt")
                .lines()
                .filter(|l| !l.starts_with('#'))
                .map(|l| {
                    let f: Vec<&str> = l.split_whitespace().collect();
                    Real {
                        height: f[0].parse().unwrap(),
                        prev: h32(f[2]),
                        link: HeaderLink {
                            post_tx_midstate: h32(f[3]),
                            state_root: h32(f[4]),
                            timestamp: f[1].parse().unwrap(),
                            target: h32(f[5]),
                            nonce: f[6].parse().unwrap(),
                            final_hash: h32(f[7]),
                        },
                    }
                })
                .collect()
        }

        /// A relay whose lowest entry is the first real header.
        fn relay_at(first: &Real) -> Relay {
            let work = calculate_work(&first.link.target);
            let entry = RelayEntry {
                height: first.height,
                hash: first.link.final_hash,
                prev: first.prev,
                state_root: first.link.state_root,
                timestamp: first.link.timestamp,
                work,
                chain_work: work,
                digest: hash(b"a real midstate header"),
            };
            Relay::from_entries(vec![entry]).unwrap()
        }

        #[test]
        fn real_headers_follow_midstates_rule_and_relay() {
            let real = real_headers();
            assert_eq!(real.len(), 200);
            for pair in real.windows(2) {
                assert_eq!(pair[1].height, pair[0].height + 1);
                assert_eq!(pair[1].prev, pair[0].link.final_hash);
                assert_eq!(
                    pair[1].link.target,
                    midstate_target(pair[1].height, pair[0].link.timestamp),
                    "height {}",
                    pair[1].height
                );
            }
            // The relay takes all of them, relayed as they would be.
            let mut relay = relay_at(&real[0]);
            let run = RelayHeaders {
                prev: real[0].link.final_hash,
                headers: real[1..].iter().map(|r| r.link.clone()).collect(),
            };
            let last = real.last().unwrap().link.timestamp;
            relay.extend(&run, last).unwrap();
            assert_eq!(relay.tip().hash, real.last().unwrap().link.final_hash);
            // Their proofs of work hold over midstate's header hash (a few:
            // each is a full extension).
            RelayHeaders {
                prev: run.prev,
                headers: run.headers[..3].to_vec(),
            }
            .verify_pow(real[1].height)
            .unwrap();
        }

        /// The attack this rule stops: a run of cheap headers pushing the
        /// real chain out of the window. A header carrying less than its
        /// rule's target is refused outright, and the cheapest run the rule
        /// allows, timestamped as late as a block may let it, costs more
        /// than midstate's whole network could mine in years.
        #[test]
        fn a_cheap_branch_cannot_push_the_real_chain_out() {
            let real = real_headers();
            let mut relay = relay_at(&real[0]);
            relay
                .extend(
                    &RelayHeaders {
                        prev: real[0].link.final_hash,
                        headers: real[1..].iter().map(|r| r.link.clone()).collect(),
                    },
                    LATER,
                )
                .unwrap();
            let tip = *relay.tip();

            // Sixteen times cheaper than the rule asks: refused at once.
            let fair = midstate_target(tip.height + 1, tip.timestamp);
            let cheap = (U256::from_big_endian(&fair) << 4).to_big_endian();
            let fake = RelayHeaders {
                prev: tip.hash,
                headers: vec![link(tip.hash, tip.height + 1, tip.timestamp + 60, cheap, 1)],
            };
            assert!(relay.clone().extend(&fake, tip.timestamp + 60).is_err());

            // The cheapest the rule allows: every header as late as allowed.
            let latest = tip.timestamp + 60 + RELAY_MAX_FUTURE;
            let (mut total, mut prev_ts) = (0u128, tip.timestamp);
            for k in 1..=RELAY_WINDOW + 1 {
                total += calculate_work(&midstate_target(tip.height + k, prev_ts));
                prev_ts = latest;
            }
            let blocks = total / tip.work;
            assert!(
                blocks > 365 * 1440,
                "pushing the window out costs {blocks} real midstate blocks' work"
            );
        }
    }
}
