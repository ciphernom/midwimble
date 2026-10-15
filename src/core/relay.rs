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
//!   outweighs everything it replaces. Each header must carry at least a
//!   sixteenth of a midwimble block's work and valid proof of work.
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

use super::anchor::{link_mining_hash, HeaderLink};
use super::simd_mining::{check_pow_chains, pow_seed, PowCheck};
use super::state::calculate_work;
use super::types::{hash_domain, MIDSTATE_BLOCK_HASH, MIDSTATE_BLOCK_HEIGHT};
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
/// A relayed header must claim at least this fraction of the relaying
/// block's work. Real midstate headers carry more than a midwimble block's
/// (midwimble's target is easier by its merged-mining share), so this only
/// stops headers made to be cheap: filling a block with them costs a
/// sixteenth of a midwimble block each.
pub const RELAY_MIN_WORK_DIVISOR: u128 = 16;

/// The least work a header relayed by a block with this target may claim.
pub fn relay_min_work(midwimble_target: &[u8; 32]) -> u128 {
    (calculate_work(midwimble_target) / RELAY_MIN_WORK_DIVISOR).max(1)
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
    pub fn verify_pow(&self) -> Result<()> {
        let mut prev = self.prev;
        let mut jobs = Vec::with_capacity(self.headers.len());
        for link in &self.headers {
            jobs.push((
                pow_seed(&link_mining_hash(prev, link), link.nonce),
                link.final_hash,
            ));
            prev = link.final_hash;
        }
        match check_pow_chains(&jobs) {
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

    /// Applies a block's relayed headers, after the cheap checks: each builds
    /// on the one before, the first on an entry of this relay; each claims at
    /// least `min_work` and meets its own target; and a run that forks below
    /// the tip is new and outweighs the branch it replaces. Proof of work is
    /// left to [`RelayHeaders::verify_pow`]. On error the relay is unchanged.
    pub fn extend(&mut self, relayed: &RelayHeaders, min_work: u128) -> Result<RelayChange> {
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
        let mut added = Vec::with_capacity(n);
        let mut last = base;
        for (i, link) in relayed.headers.iter().enumerate() {
            if link.final_hash >= link.target {
                bail!("relayed midstate header {i} misses its own target");
            }
            let work = calculate_work(&link.target);
            if work < min_work {
                bail!("relayed midstate header {i} claims less work than a relayed header must");
            }
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
        .verify_pow()
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
    use crate::core::extension::create_extension;
    use crate::core::mmr::UtxoAccumulator;
    use crate::core::types::hash;

    /// About a thousand attempts a header: cheap with test extensions, and
    /// well above what the relay asks of a test chain's headers.
    const DEVNET_TARGET: [u8; 32] = {
        let mut t = [0xff; 32];
        t[0] = 0x00;
        t[1] = 0x3f;
        t
    };

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
                    timestamp: 1_800_000_000 + 60 * height,
                    target: self.target,
                    nonce: 0,
                    final_hash: [0; 32],
                };
                let mining = link_mining_hash(prev, &link);
                loop {
                    let fin = create_extension(mining, link.nonce).final_hash;
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
    use crate::core::extension::create_extension;
    use crate::core::types::hash;

    /// Mines a run of `n` headers on `prev` at `target` (cheap with test
    /// extensions; the few the production build mines take a moment).
    fn run(prev: [u8; 32], n: usize, salt: u8, target: [u8; 32]) -> RelayHeaders {
        let mut headers: Vec<HeaderLink> = Vec::new();
        let mut last = prev;
        for i in 0..n {
            let mut link = HeaderLink {
                post_tx_midstate: hash(&[salt, i as u8]),
                state_root: hash(&[salt, i as u8, 1]),
                timestamp: 1_800_000_000 + i as u64,
                target,
                nonce: 0,
                final_hash: [0; 32],
            };
            let mining = link_mining_hash(last, &link);
            loop {
                let fin = create_extension(mining, link.nonce).final_hash;
                if fin < target {
                    link.final_hash = fin;
                    break;
                }
                link.nonce += 1;
            }
            last = link.final_hash;
            headers.push(link);
        }
        RelayHeaders { prev, headers }
    }

    const EASY: [u8; 32] = [0xff; 32];
    fn harder() -> [u8; 32] {
        let mut t = [0xff; 32];
        t[0] = 0x7f;
        t
    }

    #[test]
    fn runs_extend_the_tip_and_commit_to_everything() {
        let mut relay = Relay::genesis();
        let root = relay.commitment();
        let a = run(RelayEntry::root().hash, 5, 1, EASY);
        a.verify_pow().unwrap();
        let change = relay.extend(&a, 1).unwrap();
        assert_eq!(change.added.len(), 5);
        assert!(change.removed.is_empty() && change.fork_from.is_none());
        assert_eq!(relay.tip().height, MIDSTATE_BLOCK_HEIGHT + 5);
        assert_eq!(relay.tip().chain_work, 5 * calculate_work(&EASY));
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
        let b = run(relay.tip().hash, 2, 2, EASY);
        relay.clone().extend(&b, 1).unwrap();
        assert!(relay.clone().extend(&run([9; 32], 1, 3, EASY), 1).is_err());
        let again = RelayHeaders {
            prev: a.prev,
            headers: a.headers[..2].to_vec(),
        };
        assert!(relay.clone().extend(&again, 1).is_err());
        // Too little work, or a header that misses its own target.
        assert!(relay.clone().extend(&b, 2).is_err());
        let mut missed = b.clone();
        missed.headers[1].target = [0; 32];
        assert!(relay.clone().extend(&missed, 1).is_err());
        // A forged proof of work passes the cheap checks and fails the
        // expensive one.
        let mut forged = b.clone();
        forged.headers[1].nonce += 1;
        relay.clone().extend(&forged, 1).unwrap();
        assert!(forged.verify_pow().is_err());
    }

    #[test]
    fn heavier_branches_replace_lighter_ones_and_say_where() {
        let mut relay = Relay::genesis();
        let root = RelayEntry::root();
        relay.extend(&run(root.hash, 6, 1, EASY), 1).unwrap();
        let fork_at = relay.get(root.height + 2).unwrap().hash;
        let before = relay.clone();
        // Same length, same work: not heavier.
        let level = run(fork_at, 4, 7, EASY);
        assert!(relay.clone().extend(&level, 1).is_err());
        // Fewer but harder headers outweigh it.
        let heavy = run(fork_at, 3, 8, harder());
        let change = relay.extend(&heavy, 1).unwrap();
        assert_eq!(change.fork_from, Some(root.height + 2));
        assert_eq!(change.removed.len(), 4);
        assert_eq!(relay.tip().height, root.height + 5);
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

    /// Mines more than a window of headers: test builds only.
    #[cfg(feature = "fast-mining")]
    #[test]
    fn the_window_is_kept_and_burial_is_capped() {
        let mut relay = Relay::genesis();
        let root = RelayEntry::root();
        // Fill past the window in a few blocks' worth of runs.
        let mut prev = root.hash;
        let mut total = 0;
        while total <= RELAY_WINDOW + 10 {
            let n = (RELAY_WINDOW as usize + 20 - total as usize).min(MAX_RELAY_HEADERS_PER_BLOCK);
            let r = run(prev, n, (total % 251) as u8, EASY);
            prev = r.headers.last().unwrap().final_hash;
            let change = relay.extend(&r, 1).unwrap();
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
            RELAY_WINDOW as u128 * calculate_work(&EASY)
        );
        assert_eq!(relay.credited_above(h, 0), 0);
        let from_old = run(root.hash, 1, 99, EASY);
        assert!(
            relay.clone().extend(&from_old, 1).is_err(),
            "the root is out of the window"
        );
    }

    #[test]
    fn a_feed_proposes_the_run_the_relay_needs() {
        let root = RelayEntry::root();
        let mut relay = Relay::genesis();
        let chain = run(root.hash, 8, 1, EASY);
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
                1,
            )
            .unwrap();
        let rest = feed.next_for(&relay).unwrap();
        assert_eq!(rest.headers, chain.headers[3..].to_vec());
        relay.extend(&rest, 1).unwrap();
        assert!(feed.next_for(&relay).is_none(), "nothing left to relay");

        // A heavier branch in the feed is proposed from where it branches off.
        let fork_at = relay.get(root.height + 5).unwrap().hash;
        let branch = run(fork_at, 4, 5, harder());
        feed.add(
            &MidstateHeaders {
                start: root.height + 6,
                prev: fork_at,
                headers: branch.headers.clone(),
            },
            true,
        );
        let proposed = feed.next_for(&relay).unwrap();
        assert_eq!(proposed, branch);
        relay.extend(&proposed, 1).unwrap();
        feed.prune(&relay);
        assert!(feed.next_for(&relay).is_none());
    }
}
