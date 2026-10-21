//! The address book: where this node has found midwimble peers, and where it
//! has heard they might be.
//!
//! Midwimble and midstate nodes speak the same transports and often run side
//! by side, and both used to write down the address of every peer that
//! connected before knowing what it spoke. The address was saved, redialled
//! and handed on in peer exchange, so each network kept feeding its nodes
//! the other's. Midstate is the bigger network: its nodes crowded the book,
//! each was banned on sight and dialled again after every restart, and the
//! saved book never forgot one (saving only added). A failed dial, on the
//! other hand, erased an address for good, the operator's `--peer` included:
//! a node that started while its seed was restarting never dialled the seed
//! again. Between the two, nodes lost each other.
//!
//! Now:
//! * An address is *proven* once this node dialled it and the peer there
//!   identified itself as a midwimble node (identify lists our protocol).
//!   Only proven addresses are saved; the saved book is replaced, not added
//!   to.
//! * Addresses heard in peer exchange, or that a midwimble peer says it
//!   listens on, are kept unproven, dialled when the node needs peers, and
//!   dropped at their first failure.
//! * A proven address is dropped after [`PROVEN_FAILURES_TO_DROP`] failed
//!   dials in a row, so a peer restarting or a passing outage does not erase
//!   it; reaching it again clears the count.
//! * Pinned addresses (`--peer`) are never dropped: the node redials them
//!   whenever their peer is not connected.
//! * A peer found to be foreign, or banned, loses every address it has here.

use libp2p::{Multiaddr, PeerId};
use rand::seq::SliceRandom;
use std::collections::HashMap;

/// Failed dials in a row after which a proven address is dropped.
pub const PROVEN_FAILURES_TO_DROP: u32 = 5;
/// Addresses kept of each kind at most.
pub const MAX_PROVEN: usize = 500;
pub const MAX_HEARD: usize = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Heard,
    Proven,
}

#[derive(Clone, Debug)]
struct Entry {
    peer: PeerId,
    kind: Kind,
    failures: u32,
}

#[derive(Debug, Default)]
pub struct AddressBook {
    entries: HashMap<String, Entry>,
    pinned: Vec<(String, PeerId)>,
}

/// `addr` in canonical form, with the peer id it names. Addresses that name
/// no peer, or a browser transport, are not kept.
fn parse(addr: &str) -> Option<(String, PeerId)> {
    if addr.contains("/webrtc-direct") {
        return None;
    }
    let ma: Multiaddr = addr.parse().ok()?;
    let peer = super::extract_peer_id(&ma)?;
    Some((ma.to_string(), peer))
}

impl AddressBook {
    /// A book holding `saved` (from [`Self::to_save`] last session: each
    /// address with whether it was proven) and the operator's `pinned`
    /// addresses. A pinned address without a peer id is dialled once at
    /// startup by the network and not tracked here.
    pub fn new(saved: impl IntoIterator<Item = (String, bool)>, pinned: &[Multiaddr]) -> Self {
        let mut book = Self::default();
        for (addr, proven) in saved {
            if proven {
                book.proven(&addr);
            } else {
                book.heard(&addr);
            }
        }
        for addr in pinned {
            if let Some((a, peer)) = parse(&addr.to_string()) {
                if !book.pinned.iter().any(|(p, _)| *p == a) {
                    book.pinned.push((a, peer));
                }
            }
        }
        book
    }

    /// An address heard from a peer (PEX), not yet checked. Returns whether
    /// it was new.
    pub fn heard(&mut self, addr: &str) -> bool {
        let Some((addr, peer)) = parse(addr) else {
            return false;
        };
        if self.entries.contains_key(&addr) || self.count(Kind::Heard) >= MAX_HEARD {
            return false;
        }
        self.entries.insert(
            addr,
            Entry {
                peer,
                kind: Kind::Heard,
                failures: 0,
            },
        );
        true
    }

    /// This node reached a midwimble peer at `addr`.
    pub fn proven(&mut self, addr: &str) {
        let Some((addr, peer)) = parse(addr) else {
            return;
        };
        let room = self.count(Kind::Proven) < MAX_PROVEN;
        if let Some(e) = self.entries.get_mut(&addr) {
            if room {
                e.kind = Kind::Proven;
            }
            e.failures = 0;
            return;
        }
        if !room {
            return;
        }
        self.entries.insert(
            addr,
            Entry {
                peer,
                kind: Kind::Proven,
                failures: 0,
            },
        );
    }

    /// A dial to `addr` failed.
    pub fn dial_failed(&mut self, addr: &str) {
        let Some((addr, _)) = parse(addr) else { return };
        let drop = match self.entries.get_mut(&addr) {
            None => false,
            Some(e) if e.kind == Kind::Heard => true,
            Some(e) => {
                e.failures += 1;
                e.failures >= PROVEN_FAILURES_TO_DROP
            }
        };
        if drop {
            self.entries.remove(&addr);
        }
    }

    /// Drops every address of `peer` (pinned ones stay pinned). Returns how
    /// many there were.
    pub fn forget_peer(&mut self, peer: &PeerId) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, e| e.peer != *peer);
        before - self.entries.len()
    }

    /// The operator's `--peer` addresses, with their peer ids.
    pub fn pinned(&self) -> &[(String, PeerId)] {
        &self.pinned
    }

    /// Up to `n` addresses to dial, of peers `skip` lets through: proven
    /// ones first, with one place in three kept for an unproven one when
    /// there is any (so the book keeps learning), at random within each kind.
    pub fn pick(&self, n: usize, skip: impl Fn(&PeerId) -> bool) -> Vec<String> {
        let mut rng = rand::thread_rng();
        let mut of_kind = |kind: Kind| {
            let mut v: Vec<&str> = self
                .entries
                .iter()
                .filter(|(_, e)| e.kind == kind && !skip(&e.peer))
                .map(|(a, _)| a.as_str())
                .collect();
            v.shuffle(&mut rng);
            v
        };
        let (mut proven, mut heard) = (of_kind(Kind::Proven), of_kind(Kind::Heard));
        let heard_places = if heard.is_empty() { 0 } else { (n / 3).max(1) };
        let mut out: Vec<String> = Vec::with_capacity(n);
        let take_proven = n.saturating_sub(heard_places).min(proven.len());
        out.extend(proven.drain(..take_proven).map(String::from));
        let take_heard = (n - out.len()).min(heard.len());
        out.extend(heard.drain(..take_heard).map(String::from));
        let rest = (n - out.len()).min(proven.len());
        out.extend(proven.drain(..rest).map(String::from));
        out
    }

    /// The proven addresses, to save; the rest are relearned.
    pub fn to_save(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| e.kind == Kind::Proven)
            .map(|(a, _)| a.clone())
            .collect();
        out.sort();
        out
    }

    /// (proven, heard) addresses held.
    pub fn counts(&self) -> (usize, usize) {
        (self.count(Kind::Proven), self.count(Kind::Heard))
    }

    fn count(&self, kind: Kind) -> usize {
        self.entries.values().filter(|e| e.kind == kind).count()
    }

    #[cfg(test)]
    fn has(&self, addr: &str) -> bool {
        parse(addr).is_some_and(|(a, _)| self.entries.contains_key(&a))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(ip: &str, peer: &PeerId) -> String {
        format!("/ip4/{ip}/tcp/9433/p2p/{peer}")
    }

    #[test]
    fn heard_addresses_go_at_their_first_failure_proven_ones_hold_on() {
        let (a, b) = (PeerId::random(), PeerId::random());
        let mut book = AddressBook::default();
        assert!(book.heard(&addr("1.2.3.4", &a)));
        assert!(!book.heard(&addr("1.2.3.4", &a)), "already known");
        book.dial_failed(&addr("1.2.3.4", &a));
        assert!(!book.has(&addr("1.2.3.4", &a)));

        book.proven(&addr("5.6.7.8", &b));
        for _ in 1..PROVEN_FAILURES_TO_DROP {
            book.dial_failed(&addr("5.6.7.8", &b));
        }
        assert!(
            book.has(&addr("5.6.7.8", &b)),
            "a restart does not erase it"
        );
        // Reaching it again clears the count.
        book.proven(&addr("5.6.7.8", &b));
        for _ in 1..PROVEN_FAILURES_TO_DROP {
            book.dial_failed(&addr("5.6.7.8", &b));
        }
        assert!(book.has(&addr("5.6.7.8", &b)));
        book.dial_failed(&addr("5.6.7.8", &b));
        assert!(!book.has(&addr("5.6.7.8", &b)));
    }

    #[test]
    fn only_proven_addresses_are_saved() {
        let (a, b) = (PeerId::random(), PeerId::random());
        let mut book = AddressBook::default();
        book.heard(&addr("1.2.3.4", &a));
        book.proven(&addr("5.6.7.8", &b));
        // Hearing a proven address again does not demote it.
        book.heard(&addr("5.6.7.8", &b));
        assert_eq!(book.to_save(), vec![addr("5.6.7.8", &b)]);
        assert_eq!(book.counts(), (1, 1));
        // A heard address that proves itself is saved from then on.
        book.proven(&addr("1.2.3.4", &a));
        assert_eq!(book.counts(), (2, 0));

        // What was saved comes back proven; an old book's entries (saved
        // before addresses were checked) come back unproven.
        let reloaded = AddressBook::new(
            vec![(addr("5.6.7.8", &b), true), (addr("9.9.9.9", &a), false)],
            &[],
        );
        assert_eq!(reloaded.counts(), (1, 1));
        assert_eq!(reloaded.to_save(), vec![addr("5.6.7.8", &b)]);
    }

    #[test]
    fn a_foreign_or_banned_peer_loses_every_address() {
        let (foreign, other) = (PeerId::random(), PeerId::random());
        let mut book = AddressBook::default();
        book.proven(&addr("1.2.3.4", &foreign));
        book.heard(&format!("/ip4/1.2.3.4/udp/9333/quic-v1/p2p/{foreign}"));
        book.proven(&addr("5.6.7.8", &other));
        assert_eq!(book.forget_peer(&foreign), 2);
        assert_eq!(book.to_save(), vec![addr("5.6.7.8", &other)]);
        assert_eq!(book.counts(), (1, 0));
    }

    #[test]
    fn pinned_peers_are_never_dropped() {
        let seed = PeerId::random();
        let pinned: Multiaddr = addr("134.199.148.215", &seed).parse().unwrap();
        let no_id: Multiaddr = "/ip4/1.1.1.1/tcp/9433".parse().unwrap();
        let mut book = AddressBook::new(vec![], &[pinned.clone(), no_id, pinned.clone()]);
        assert_eq!(book.pinned(), &[(pinned.to_string(), seed)]);
        for _ in 0..10 {
            book.dial_failed(&pinned.to_string());
        }
        book.forget_peer(&seed);
        assert_eq!(book.pinned(), &[(pinned.to_string(), seed)]);
    }

    #[test]
    fn addresses_without_a_peer_id_or_for_browsers_are_not_kept() {
        let mut book = AddressBook::default();
        assert!(!book.heard("/ip4/1.2.3.4/tcp/9433"));
        assert!(!book.heard("not an address"));
        let p = PeerId::random();
        assert!(!book.heard(&format!(
            "/ip4/1.2.3.4/udp/9435/webrtc-direct/certhash/uEiCME0N0ArEqXME5vwQv0WoPnGThs9VE99aPVP7bGEQQPg/p2p/{p}"
        )));
        book.proven("/ip4/1.2.3.4/tcp/9433");
        assert_eq!(book.counts(), (0, 0));
    }

    #[test]
    fn the_book_stays_bounded() {
        let mut book = AddressBook::default();
        for i in 0..(MAX_HEARD + 50) {
            book.heard(&format!(
                "/ip4/1.2.{}.{}/tcp/9433/p2p/{}",
                i / 250,
                i % 250,
                PeerId::random()
            ));
        }
        for i in 0..(MAX_PROVEN + 50) {
            book.proven(&format!(
                "/ip4/5.6.{}.{}/tcp/9433/p2p/{}",
                i / 250,
                i % 250,
                PeerId::random()
            ));
        }
        assert_eq!(book.counts(), (MAX_PROVEN, MAX_HEARD));
    }

    #[test]
    fn picks_prefer_proven_peers_keep_a_place_for_unproven_and_skip_as_told() {
        let mut book = AddressBook::default();
        let proven: Vec<PeerId> = (0..5).map(|_| PeerId::random()).collect();
        let heard: Vec<PeerId> = (0..5).map(|_| PeerId::random()).collect();
        for (i, p) in proven.iter().enumerate() {
            book.proven(&addr(&format!("5.6.7.{i}"), p));
        }
        for (i, p) in heard.iter().enumerate() {
            book.heard(&addr(&format!("1.2.3.{i}"), p));
        }
        let of = |picks: &[String], peers: &[PeerId]| {
            picks
                .iter()
                .filter(|a| peers.iter().any(|p| a.ends_with(&p.to_string())))
                .count()
        };
        for _ in 0..20 {
            let picks = book.pick(3, |_| false);
            assert_eq!(picks.len(), 3);
            assert_eq!((of(&picks, &proven), of(&picks, &heard)), (2, 1));
        }
        // With every proven peer connected (skipped), unproven ones fill in.
        let picks = book.pick(3, |p| proven.contains(p));
        assert_eq!((of(&picks, &proven), of(&picks, &heard)), (0, 3));
        // With no unproven ones, proven ones take every place.
        let picks = book.pick(3, |p| heard.contains(p));
        assert_eq!((of(&picks, &proven), of(&picks, &heard)), (3, 0));
        // And never more than there are.
        assert_eq!(book.pick(30, |_| false).len(), 10);
        assert!(book.pick(3, |_| true).is_empty());
    }
}
