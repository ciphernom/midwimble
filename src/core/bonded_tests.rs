//! Bonded mining on the production build's own constants: from
//! `BONDED_MINING_FROM` a block must be signed exactly when a registered bond
//! could sign it, and an unsigned block counts for only the over-cap sliver.
//! Test builds start bonded mining at `u64::MAX`, so these run without
//! `fast-mining`: blocks are built from templates and applied with their
//! proof of work taken as checked (`apply_batch_skip_pow`).

use super::anchor::HeaderLink;
use super::bond::*;
use super::mmr::UtxoAccumulator;
use super::mw::WalletKeys;
use super::relay::{
    midstate_schedule, midstate_target, MidstateHeaders, Relay, RelayEntry, RelayHeaders,
    MAX_RELAY_HEADERS_PER_BLOCK,
};
use super::state::{
    apply_batch, apply_batch_skip_pow, apply_batch_trusted, calculate_work, current_timestamp,
};
use super::template::{build_template_relayed, BlockTemplate};
use super::types::*;
use anyhow::Result;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use primitive_types::U256;

/// Where the test chain's blocks are stamped from (the first a minute
/// later): the genesis schedule, so that ASERT keeps every target near the
/// genesis target and each block carries real work. A chain stamped days
/// behind its schedule falls to the easiest target, and a block's work of
/// one is its own sliver, so no test could tell a capped or unsigned block
/// from a full one. If the genesis lies ahead (a launch build, made before
/// mining opens), an hour ago instead: blocks from the future are refused.
fn chain_start() -> u64 {
    GENESIS_TIMESTAMP.min(current_timestamp() - 3_600)
}

/// A chain past genesis whose blocks are stamped from [`chain_start`]: the
/// timestamps given with each block decide its earliest stamp, so these
/// work whatever the build's genesis time is.
struct Chain {
    state: State,
    ts: Vec<u64>,
}

impl Chain {
    fn new() -> Self {
        let mut state = State::genesis();
        apply_batch(&mut state, Batch::genesis(), &[]).unwrap();
        assert!(
            state.height >= BONDED_MINING_FROM,
            "bonded mining has begun"
        );
        Self {
            state,
            ts: vec![chain_start()],
        }
    }

    fn next_stamp(&self) -> u64 {
        self.ts.last().unwrap() + 60
    }

    fn template(&self, bond: Option<&MinerBond>) -> Result<BlockTemplate> {
        let payout = WalletKeys::random().address();
        Ok(build_template_relayed(
            &self.state,
            &self.ts,
            &[],
            &[(payout, 1)],
            [0; 32],
            Some(self.next_stamp()),
            bond,
            None,
        )?
        .0)
    }

    fn try_apply(&self, batch: &Batch) -> Result<State> {
        let mut header = batch.header();
        header.height = self.state.height;
        let mut next = self.state.clone();
        apply_batch_skip_pow(&mut next, batch, &self.ts, compute_header_hash(&header))?;
        Ok(next)
    }

    fn apply(&mut self, batch: &Batch) {
        self.state = self.try_apply(batch).unwrap();
        self.ts.push(batch.timestamp);
    }

    /// [`Chain::apply`] for a block relaying stand-in midstate headers, whose
    /// proofs of work are not real: every rule but proofs and signatures in
    /// the block's contents is still checked, the miner's authorisation
    /// included.
    fn apply_trusted(&mut self, batch: &Batch) {
        let mut header = batch.header();
        header.height = self.state.height;
        let mut next = self.state.clone();
        apply_batch_trusted(&mut next, batch, &self.ts, compute_header_hash(&header)).unwrap();
        self.state = next;
        self.ts.push(batch.timestamp);
    }

    /// What the next block can add to the chain's weight, before any cap
    /// on its signer.
    fn creditable(&self) -> u128 {
        let mut floor = self.state.work_floor.clone();
        cap_work(
            &mut floor,
            self.state.height,
            calculate_work(&self.state.target),
        )
    }
}

/// A producer whose bond, locked until `until`, is keyed `seed`.
fn producer(seed: u8) -> (MinerBond, [u8; 32]) {
    let secret = Scalar::from_bytes_mod_order([seed; 32]);
    let key = RistrettoPoint::mul_base(&secret).compress().to_bytes();
    (
        MinerBond {
            co_bonds: Vec::new(),
            secret,
            bond_id: [seed; 32],
            registration: None,
            midstate: None,
        },
        key,
    )
}

/// A lock comfortably inside `MAX_BOND_HORIZON` and well past the minimum
/// remaining lock, for blocks stamped from [`chain_start`].
fn locked_long() -> u64 {
    est_midstate_height(chain_start()) + MAX_BOND_HORIZON / 2
}

/// Puts a bond straight into the chain's bond set, as if registered earlier.
fn with_bond(chain: &mut Chain, seed: u8, until: u64) -> MinerBond {
    let (bond, key) = producer(seed);
    chain.state.bonds.insert(
        bond.bond_id,
        BondEntry {
            mining_key: key,
            value: MIN_MINING_BOND,
            bonded_until: until,
            proven_height: 0,
            proven_hash: [0; 32],
        },
    );
    bond
}

/// `batch` stripped of its signature and claiming `weight`: the copy a
/// miner without a bond would make.
fn unsigned_copy(batch: &Batch, weight: u128) -> Batch {
    let mut copy = batch.clone();
    copy.miner = None;
    copy.chain_weight = weight;
    copy
}

/// A producer keyed `seed` whose bond coin is in a stand-in midstate's state
/// at height `proven`, and the registration proving it there.
fn proven_producer(seed: u8, proven: u64) -> (MinerBond, BondRegistration) {
    let (mut bond, key) = producer(seed);
    let coin = BondCoin {
        script: BondScript {
            mining_key: key,
            bonded_until: locked_long(),
            owner_pk: [2; 32],
        },
        value: MIN_MINING_BOND,
        salt: [seed; 32],
    };
    let mut coins = UtxoAccumulator::new();
    coins.insert(coin.coin_id(), true);
    let registration = BondRegistration {
        proof: BondProof {
            coin,
            midstate_height: proven,
            roots: MidstateRoots {
                coins: coins.root(true),
                commitments: hash(b"commitments"),
                chain_mmr: hash(b"chain"),
                burned_wots: Some(hash(b"burned")),
            },
            smt: coins.prove(&coin.coin_id(), true).unwrap(),
        },
    };
    bond.bond_id = registration.bond_id();
    bond.registration = Some(registration.clone());
    (bond, registration)
}

/// `count` stand-in midstate headers from the relay's root, the one at the
/// registration's height committing to its proof's roots. Each carries the
/// target midstate's rule gives it, stamped a month behind midstate's
/// schedule: far harder than a registration counts any one header for, and
/// never in a block's future. Their proofs of work are not real.
fn stand_in_headers(count: u64, registration: &BondRegistration) -> MidstateHeaders {
    let root = RelayEntry::root();
    let proof = &registration.proof;
    let stamp = |h: u64| midstate_schedule(h) - 30 * 24 * 3_600;
    let headers = (root.height + 1..=root.height + count)
        .map(|h| {
            let target = midstate_target(h, stamp(h - 1));
            let seed = hash(&h.to_le_bytes());
            HeaderLink {
                post_tx_midstate: hash(&[&seed[..], b"post"].concat()),
                state_root: if h == proof.midstate_height {
                    proof.roots.state_root(h).unwrap()
                } else {
                    hash(&[&seed[..], b"root"].concat())
                },
                timestamp: stamp(h),
                target,
                nonce: 0,
                final_hash: (U256::from_big_endian(&seed) % U256::from_big_endian(&target))
                    .to_big_endian(),
            }
        })
        .collect();
    MidstateHeaders {
        start: root.height + 1,
        prev: root.hash,
        headers,
    }
}

#[test]
fn while_no_bond_can_sign_blocks_are_unsigned_and_count_for_a_sliver() {
    let mut chain = Chain::new();
    assert!(chain.state.bonds.is_empty());
    for _ in 0..3 {
        let parent = chain.state.weight();
        let creditable = chain.creditable();
        assert!(
            sliver(creditable) < creditable,
            "the test chain's blocks carry real work (see chain_start)"
        );
        let t = chain.template(None).unwrap();
        assert!(t.batch.miner.is_none());
        assert_eq!(t.batch.chain_weight, parent + sliver(creditable));
        // Claiming the block's full work instead is refused.
        let greedy = unsigned_copy(&t.batch, parent + creditable);
        let err = chain.try_apply(&greedy).unwrap_err().to_string();
        assert!(err.contains("claims chain weight"), "{err}");
        chain.apply(&t.batch);
        assert_eq!(chain.state.weight(), parent + sliver(creditable));
    }
    // A producer whose bond is not on chain mines unsigned blocks too.
    let (bond, _) = producer(5);
    let t = chain.template(Some(&bond)).unwrap();
    assert!(t.batch.miner.is_none() && t.batch.registrations.is_empty());
    chain.apply(&t.batch);
}

#[test]
fn an_unsigned_block_is_refused_while_a_bond_could_sign() {
    let mut chain = Chain::new();
    let bond = with_bond(&mut chain, 7, locked_long());
    let parent = chain.state.weight();
    let creditable = chain.creditable();

    // Without a bond to sign with, there is no template...
    let err = chain.template(None).unwrap_err().to_string();
    assert!(err.contains("bonded mining is required"), "{err}");
    // ...and an unsigned copy of a signed block is refused, whatever weight
    // it claims.
    let signed = chain.template(Some(&bond)).unwrap().batch;
    assert_eq!(signed.miner.as_ref().unwrap().bond_id, bond.bond_id);
    for weight in [parent + sliver(creditable), parent + creditable] {
        let err = chain
            .try_apply(&unsigned_copy(&signed, weight))
            .unwrap_err()
            .to_string();
        assert!(err.contains("a registered bond could sign it"), "{err}");
    }
    // Signed, it counts in full.
    chain.apply(&signed);
    assert_eq!(chain.state.weight(), parent + creditable);

    // Another producer, not on chain, cannot mine while this bond can sign.
    let (stranger, _) = producer(8);
    assert!(chain.template(Some(&stranger)).is_err());
}

/// The freeze this rule prevents: every bond lapses, and the chain carries
/// on unsigned until one is registered again.
#[test]
fn when_the_last_bond_lapses_the_chain_carries_on() {
    let mut chain = Chain::new();
    // Eligible for blocks stamped up to about two minutes from the start.
    let start = chain.next_stamp();
    let until = est_midstate_height(start + 120) + MIN_REMAINING_BOND_LOCK;
    let bond = with_bond(&mut chain, 9, until);
    let signed = chain.template(Some(&bond)).unwrap();
    assert!(signed.batch.miner.is_some());
    chain.apply(&signed.batch);

    // Ten minutes on, it cannot sign, and nothing else can: its producer's
    // blocks are unsigned, and count for a sliver.
    chain.ts.push(start + 600);
    for _ in 0..4 {
        let t = chain.template(Some(&bond)).unwrap();
        assert!(t.batch.miner.is_none(), "unsigned once no bond can sign");
        let parent = chain.state.weight();
        let creditable = chain.creditable();
        chain.apply(&t.batch);
        assert_eq!(chain.state.weight(), parent + sliver(creditable));
    }
    assert!(
        chain.state.bonds.is_empty(),
        "the lapsed bond has left the set"
    );
}

/// A block that registers a bond is signed: the bond it adds could sign it.
/// Built on a relay holding a stand-in midstate header that proves the bond's
/// coin, buried under headers carrying midstate's difficulty.
#[test]
fn a_block_registering_a_bond_must_be_signed() {
    let mut chain = Chain::new();
    let (bond, registration) = proven_producer(11, RelayEntry::root().height + 1);
    let run = stand_in_headers(64, &registration);
    let mut relay = Relay::genesis();
    relay
        .extend(
            &RelayHeaders {
                prev: run.prev,
                headers: run.headers,
            },
            chain.next_stamp(),
        )
        .unwrap();
    chain.state.relay = relay;
    registration
        .verify(&chain.state.relay, &chain.state.target)
        .expect("buried under a day of work");

    let signed = chain.template(Some(&bond)).unwrap().batch;
    assert_eq!(signed.registrations.len(), 1);
    assert_eq!(signed.miner.as_ref().unwrap().bond_id, bond.bond_id);
    let parent = chain.state.weight();
    let err = chain
        .try_apply(&unsigned_copy(&signed, parent + sliver(chain.creditable())))
        .unwrap_err()
        .to_string();
    assert!(err.contains("a registered bond could sign it"), "{err}");
    chain.apply(&signed);
    assert!(chain.state.bonds.contains_key(&bond.bond_id));
}

/// The launch freeze, on the production rules: the first bond's proof is
/// further past the relay's tip than one block can relay. When every block
/// had to be signed, nothing could be mined, so nothing could relay what the
/// registration needed. Now unsigned blocks relay midstate a day at a time,
/// the block that registers the bond is signed by it, and from then on
/// blocks must be signed.
#[test]
fn a_relay_far_behind_catches_up_before_the_first_bond_registers() {
    let mut chain = Chain::new();
    let behind = MAX_RELAY_HEADERS_PER_BLOCK as u64 + 100;
    let (mut bond, registration) = proven_producer(13, RelayEntry::root().height + behind);
    let run = stand_in_headers(behind + 64, &registration);
    let tip = run.headers.last().unwrap().final_hash;
    bond.midstate = Some(run);

    let first = chain.template(Some(&bond)).unwrap().batch;
    assert!(first.miner.is_none() && first.registrations.is_empty());
    assert_eq!(
        first.relay.as_ref().unwrap().headers.len(),
        MAX_RELAY_HEADERS_PER_BLOCK
    );
    let parent = chain.state.weight();
    let creditable = chain.creditable();
    chain.apply_trusted(&first);
    assert_eq!(chain.state.weight(), parent + sliver(creditable));
    assert!(chain.state.bonds.is_empty());

    let second = chain.template(Some(&bond)).unwrap().batch;
    assert_eq!(second.registrations.len(), 1);
    assert_eq!(second.miner.as_ref().unwrap().bond_id, bond.bond_id);
    let parent = chain.state.weight();
    let creditable = chain.creditable();
    chain.apply_trusted(&second);
    assert_eq!(chain.state.weight(), parent + creditable);
    assert!(chain.state.bonds.contains_key(&bond.bond_id));
    assert_eq!(chain.state.relay.tip().hash, tip);

    let third = chain.template(Some(&bond)).unwrap().batch;
    assert!(third.miner.is_some());
    let err = chain
        .try_apply(&unsigned_copy(
            &third,
            chain.state.weight() + sliver(chain.creditable()),
        ))
        .unwrap_err()
        .to_string();
    assert!(err.contains("a registered bond could sign it"), "{err}");
}
