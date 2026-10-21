//! Bans that end.
//!
//! A node bans a peer when the peer shows it is broken or hostile: it relayed
//! an invalid block, answered a sync request with something else, claimed a
//! heavier chain three times without backing it. Bans used to last until the
//! node restarted. On a small network that turns one mistaken ban into a
//! partition: when the honest peer is the one everyone syncs from (a seed on
//! a slow link, say), each node that strikes it out stops talking to it for
//! days, and the chain splits along the bans.
//!
//! Now a ban ends. The first lasts the base duration the node gives
//! (`NodeConfig::ban_duration`, an hour by default), and each further ban of
//! the same peer doubles it, up to [`MAX_BAN`]; a peer's record is forgotten
//! [`FORGET_AFTER`] after its last ban ends. A hostile peer gets an hour, then
//! two, then four; an honest peer banned by mistake is heard again within the
//! hour, and the network heals.

use libp2p::PeerId;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// The longest a ban grows to by doubling. A longer base (an operator's
/// choice) is kept as it is.
pub const MAX_BAN: Duration = Duration::from_secs(24 * 3600);

/// How long after its last ban ends a peer's record is kept, so that a peer
/// banned again soon after gets a longer ban.
pub const FORGET_AFTER: Duration = Duration::from_secs(24 * 3600);

/// Records kept at most. Past this, ended records go first, then the
/// soonest to end.
pub const MAX_RECORDS: usize = 10_000;

#[derive(Clone, Debug)]
struct Record {
    /// `None`: banned for good (bans the node was started with).
    until: Option<Instant>,
    reason: String,
    times: u32,
}

/// A banned peer, as `/state` shows it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct BannedPeer {
    pub peer: String,
    pub reason: String,
    /// `None`: until the node restarts.
    pub seconds_left: Option<u64>,
}

#[derive(Debug, Default)]
pub struct Bans {
    records: HashMap<PeerId, Record>,
}

impl Bans {
    /// Bans `peer` for `base`, or longer if it was banned before: twice as
    /// long for each earlier ban still on record, up to [`MAX_BAN`]. Returns
    /// how long this ban lasts.
    pub fn ban(&mut self, peer: PeerId, reason: &str, base: Duration, now: Instant) -> Duration {
        self.gc(now);
        let times = match self.records.get(&peer) {
            Some(r) if r.until.is_none() => return Duration::MAX,
            Some(r) => r.times + 1,
            None => 1,
        };
        let length = escalate(base, times);
        self.records.insert(
            peer,
            Record {
                until: Some(now.checked_add(length).unwrap_or(now + MAX_BAN)),
                reason: reason.to_string(),
                times,
            },
        );
        length
    }

    /// Bans `peer` until the node restarts.
    pub fn ban_for_good(&mut self, peer: PeerId, reason: &str) {
        self.records.insert(
            peer,
            Record {
                until: None,
                reason: reason.to_string(),
                times: 1,
            },
        );
    }

    pub fn is_banned(&self, peer: &PeerId, now: Instant) -> bool {
        self.records
            .get(peer)
            .is_some_and(|r| r.until.map_or(true, |t| now < t))
    }

    /// Why `peer` is banned, if it is.
    pub fn reason(&self, peer: &PeerId, now: Instant) -> Option<&str> {
        self.is_banned(peer, now)
            .then(|| self.records[peer].reason.as_str())
    }

    /// The peers banned now, soonest to be heard again first.
    pub fn active(&self, now: Instant) -> Vec<BannedPeer> {
        let mut out: Vec<BannedPeer> = self
            .records
            .iter()
            .filter(|(p, _)| self.is_banned(p, now))
            .map(|(p, r)| BannedPeer {
                peer: p.to_string(),
                reason: r.reason.clone(),
                seconds_left: r.until.map(|t| t.saturating_duration_since(now).as_secs()),
            })
            .collect();
        out.sort_by(|a, b| {
            let left = |x: &BannedPeer| x.seconds_left.unwrap_or(u64::MAX);
            left(a).cmp(&left(b)).then_with(|| a.peer.cmp(&b.peer))
        });
        out
    }

    /// Drops records whose last ban ended [`FORGET_AFTER`] ago, and keeps
    /// the count under [`MAX_RECORDS`].
    fn gc(&mut self, now: Instant) {
        self.records.retain(|_, r| {
            r.until
                .map_or(true, |t| now < t.checked_add(FORGET_AFTER).unwrap_or(t))
        });
        if self.records.len() < MAX_RECORDS {
            return;
        }
        let mut by_end: Vec<(PeerId, Option<Instant>)> =
            self.records.iter().map(|(p, r)| (*p, r.until)).collect();
        // Ended first, then soonest to end; bans for good last.
        by_end.sort_by_key(|(_, until)| until.map_or((2, now), |t| ((now < t) as u8, t)));
        for (peer, _) in by_end
            .into_iter()
            .take(self.records.len() + 1 - MAX_RECORDS)
        {
            self.records.remove(&peer);
        }
    }
}

/// `base` doubled for each ban before this one, capped at [`MAX_BAN`]
/// unless `base` is longer still.
fn escalate(base: Duration, times: u32) -> Duration {
    let doubled = base
        .checked_mul(1u32 << (times - 1).min(20))
        .unwrap_or(Duration::MAX);
    doubled.min(MAX_BAN.max(base))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    #[test]
    fn a_ban_ends() {
        let (mut bans, peer, t0) = (Bans::default(), PeerId::random(), Instant::now());
        assert_eq!(bans.ban(peer, "relayed an invalid block", HOUR, t0), HOUR);
        assert!(bans.is_banned(&peer, t0));
        assert!(bans.is_banned(&peer, t0 + HOUR - Duration::from_secs(1)));
        assert_eq!(bans.reason(&peer, t0), Some("relayed an invalid block"));
        assert!(!bans.is_banned(&peer, t0 + HOUR));
        assert_eq!(bans.reason(&peer, t0 + HOUR), None);
        assert!(!bans.is_banned(&PeerId::random(), t0));
    }

    #[test]
    fn each_ban_of_the_same_peer_lasts_twice_as_long_up_to_a_day() {
        let (mut bans, peer, mut t) = (Bans::default(), PeerId::random(), Instant::now());
        let mut lengths = Vec::new();
        for _ in 0..8 {
            let length = bans.ban(peer, "timed out", HOUR, t);
            lengths.push(length.as_secs() / 3600);
            t += length;
            assert!(!bans.is_banned(&peer, t));
        }
        assert_eq!(lengths, [1, 2, 4, 8, 16, 24, 24, 24]);
        // A day after a ban ends, the peer starts again from the base.
        t += FORGET_AFTER;
        assert_eq!(bans.ban(peer, "timed out", HOUR, t), HOUR);
        // Other peers are not held to its record.
        assert_eq!(bans.ban(PeerId::random(), "timed out", HOUR, t), HOUR);
    }

    #[test]
    fn a_base_longer_than_a_day_is_kept() {
        let (mut bans, peer, t0) = (Bans::default(), PeerId::random(), Instant::now());
        let week = 7 * 24 * HOUR;
        assert_eq!(bans.ban(peer, "configured", week, t0), week);
        assert_eq!(bans.ban(peer, "configured", week, t0 + week), week);
    }

    #[test]
    fn bans_for_good_do_not_end() {
        let (mut bans, peer, t0) = (Bans::default(), PeerId::random(), Instant::now());
        bans.ban_for_good(peer, "configured");
        assert!(bans.is_banned(&peer, t0 + 1000 * HOUR));
        assert_eq!(bans.ban(peer, "again", HOUR, t0), Duration::MAX);
        assert_eq!(
            bans.active(t0),
            vec![BannedPeer {
                peer: peer.to_string(),
                reason: "configured".into(),
                seconds_left: None
            }]
        );
    }

    #[test]
    fn only_bans_in_force_are_listed_soonest_to_end_first() {
        let (mut bans, t0) = (Bans::default(), Instant::now());
        let (a, b, c) = (PeerId::random(), PeerId::random(), PeerId::random());
        bans.ban(a, "a", 2 * HOUR, t0);
        bans.ban(b, "b", HOUR, t0);
        bans.ban(c, "c", Duration::from_secs(60), t0);
        let listed = bans.active(t0 + Duration::from_secs(120));
        assert_eq!(
            listed,
            vec![
                BannedPeer {
                    peer: b.to_string(),
                    reason: "b".into(),
                    seconds_left: Some(3480)
                },
                BannedPeer {
                    peer: a.to_string(),
                    reason: "a".into(),
                    seconds_left: Some(7080)
                },
            ]
        );
    }

    #[test]
    fn records_stay_bounded_and_ended_ones_go_first() {
        let (mut bans, t0) = (Bans::default(), Instant::now());
        let ended = PeerId::random();
        bans.ban(ended, "old", Duration::from_secs(1), t0);
        let t1 = t0 + Duration::from_secs(2);
        let banned: Vec<PeerId> = (0..MAX_RECORDS + 10).map(|_| PeerId::random()).collect();
        for (i, p) in banned.iter().enumerate() {
            bans.ban(*p, "foreign", HOUR, t1 + Duration::from_millis(i as u64));
        }
        assert!(bans.records.len() <= MAX_RECORDS);
        assert!(!bans.records.contains_key(&ended));
        // Past the ended record, the bans soonest to end made room: the
        // newest are all still in force.
        let now = t1 + Duration::from_secs(20);
        assert!(banned
            .iter()
            .rev()
            .take(100)
            .all(|p| bans.is_banned(p, now)));
        assert!(!bans.records.contains_key(&banned[0]));
    }
}
