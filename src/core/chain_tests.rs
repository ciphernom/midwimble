//! End-to-end consensus tests on a real (fast-mining) chain.
//!
//! Run with `cargo test --features fast-mining`.

use super::mw::crypto::{random_scalar, Point32};
use super::mw::{
    build_transaction, scan_output, Context, Input, Kernel, KernelFeatures, Payment, Spendable,
    StealthAddress, Transaction, TxBody, WalletKeys,
};
use super::state::{apply_batch, apply_body, choose_best_state, validate_block_contents};
use super::template::{build_template, select_transactions};
use super::types::*;
use anyhow::Result;

struct TestChain {
    state: State,
    timestamps: Vec<u64>,
    blocks: Vec<Batch>,
}

impl TestChain {
    fn new() -> Self {
        let mut state = State::genesis();
        apply_batch(&mut state, Batch::genesis(), &[]).unwrap();
        Self {
            state,
            timestamps: vec![Batch::genesis().timestamp],
            blocks: vec![Batch::genesis().clone()],
        }
    }

    fn make_block(&self, txs: &[Transaction], payout: &StealthAddress) -> Result<Batch> {
        Ok(build_template(&self.state, &self.timestamps, txs, payout, None)?.mine_blocking())
    }

    fn apply(&mut self, batch: Batch) -> Result<()> {
        apply_batch(&mut self.state, &batch, &self.timestamps)?;
        self.timestamps.push(batch.timestamp);
        self.blocks.push(batch);
        Ok(())
    }

    fn mine(&mut self, txs: &[Transaction], payout: &StealthAddress) -> Result<()> {
        let batch = self.make_block(txs, payout)?;
        self.apply(batch)
    }
}

/// Minimal wallet: tracks spendable outputs by scanning blocks.
struct TestWallet {
    keys: WalletKeys,
    coins: Vec<(Spendable, bool, u64)>, // (coin, is_coinbase, height)
}

impl TestWallet {
    fn new() -> Self {
        Self {
            keys: WalletKeys::random(),
            coins: Vec::new(),
        }
    }

    fn address(&self) -> StealthAddress {
        self.keys.address()
    }

    fn scan(&mut self, batch: &Batch, height: u64) {
        let spent: Vec<Point32> = batch.body.input_commitments().copied().collect();
        self.coins
            .retain(|(c, _, _)| !spent.contains(&c.commitment));
        let body = batch.body.outputs().map(|o| (o, false));
        let cb = batch
            .coinbase
            .iter()
            .flat_map(|c| c.outputs.outputs.iter())
            .map(|o| (o, true));
        for (output, is_cb) in body.chain(cb) {
            if let Some(owned) = scan_output(&self.keys, output) {
                self.coins.push((
                    Spendable {
                        commitment: output.commitment,
                        value: owned.value,
                        blinding: owned.blinding,
                        owner_secret: owned.owner_secret,
                    },
                    is_cb,
                    height,
                ));
            }
        }
    }

    fn scan_chain(&mut self, chain: &TestChain) {
        self.coins.clear();
        for (h, b) in chain.blocks.iter().enumerate() {
            self.scan(b, h as u64);
        }
    }

    fn balance(&self) -> u64 {
        self.coins.iter().map(|(c, _, _)| c.value).sum()
    }

    fn spendable_at(&self, height: u64) -> Vec<Spendable> {
        self.coins
            .iter()
            .filter(|(_, cb, h)| !*cb || height >= h + COINBASE_MATURITY)
            .map(|(c, _, _)| c.clone())
            .collect()
    }
}

/// Mines a coinbase to `wallet` and enough further blocks to mature it.
fn funded_chain(wallet: &mut TestWallet) -> TestChain {
    let mut chain = TestChain::new();
    let miner = TestWallet::new();
    chain.mine(&[], &wallet.address()).unwrap();
    for _ in 0..COINBASE_MATURITY {
        chain.mine(&[], &miner.address()).unwrap();
    }
    wallet.scan_chain(&chain);
    chain
}

#[test]
fn mine_spend_receive_and_audit() {
    let mut alice = TestWallet::new();
    let mut bob = TestWallet::new();
    let mut miner = TestWallet::new();
    let mut chain = funded_chain(&mut alice);
    assert_eq!(alice.balance(), block_reward(1));

    let fee = 50_000;
    let h = chain.state.height;
    let tx = build_transaction(
        &alice.spendable_at(h),
        &[Payment {
            to: bob.address(),
            value: 1_000_000,
        }],
        &alice.address(),
        fee,
        h,
    )
    .unwrap()
    .tx;
    chain.mine(&[tx], &miner.address()).unwrap();

    alice.scan_chain(&chain);
    bob.scan_chain(&chain);
    miner.scan_chain(&chain);
    assert_eq!(bob.balance(), 1_000_000);
    assert_eq!(alice.balance(), block_reward(1) - 1_000_000 - fee);
    // The miner of the last block collected its reward plus the fee.
    let last = chain.blocks.last().unwrap();
    let last_cb: u64 = last
        .coinbase
        .as_ref()
        .unwrap()
        .outputs
        .outputs
        .iter()
        .filter_map(|o| scan_output(&miner.keys, o))
        .map(|o| o.value)
        .sum();
    assert_eq!(last_cb, block_reward(h) + fee);

    chain.state.verify_supply().unwrap();
    // The supply audit genuinely constrains: inflate supply and it fails.
    let mut cooked = chain.state.clone();
    cooked.supply += 1;
    assert!(cooked.verify_supply().is_err());
}

/// Pluribit's flaw at the consensus layer: Alice paid Bob, so she knows the
/// output's blinding factor, and tries to spend it with her own key.
#[test]
fn payer_cannot_spend_payment() {
    let mut alice = TestWallet::new();
    let mut bob = TestWallet::new();
    let mut chain = funded_chain(&mut alice);

    let h = chain.state.height;
    let pay = build_transaction(
        &alice.spendable_at(h),
        &[Payment {
            to: bob.address(),
            value: 5_000_000,
        }],
        &alice.address(),
        50_000,
        h,
    )
    .unwrap()
    .tx;
    chain.mine(&[pay], &alice.address()).unwrap();
    bob.scan_chain(&chain);
    let bobs = bob.coins[0].0.clone();

    // Alice kept the blinding she generated (her wallet saw it at creation).
    // Simulate that knowledge directly: it is Bob's blinding factor.
    let alice_forged_coin = Spendable {
        commitment: bobs.commitment,
        value: bobs.value,
        blinding: bobs.blinding,
        owner_secret: random_scalar(), // all she can do: a key of her own
    };
    let h = chain.state.height;
    let theft = build_transaction(
        &[alice_forged_coin],
        &[Payment {
            to: alice.address(),
            value: 4_000_000,
        }],
        &alice.address(),
        50_000,
        h,
    )
    .unwrap()
    .tx;
    // Statelessly the theft transaction is perfectly well formed...
    theft.validate(Context::Relay).unwrap();
    // ...but consensus checks the owner key recorded for Bob's output.
    let err = chain
        .make_block(&[theft], &alice.address())
        .unwrap_err()
        .to_string();
    assert!(err.contains("owner key"), "{err}");

    // Bob, holding b, can spend it.
    let h = chain.state.height;
    let legit = build_transaction(
        &[bobs],
        &[Payment {
            to: alice.address(),
            value: 1,
        }],
        &bob.address(),
        50_000,
        h,
    )
    .unwrap()
    .tx;
    chain.mine(&[legit], &bob.address()).unwrap();
}

#[test]
fn double_spend_is_rejected() {
    let mut alice = TestWallet::new();
    let bob = TestWallet::new();
    let carol = TestWallet::new();
    let mut chain = funded_chain(&mut alice);
    let h = chain.state.height;
    let coins = alice.spendable_at(h);
    let to_bob = build_transaction(
        &coins,
        &[Payment {
            to: bob.address(),
            value: 10,
        }],
        &alice.address(),
        50_000,
        h,
    )
    .unwrap()
    .tx;
    let to_carol = build_transaction(
        &coins,
        &[Payment {
            to: carol.address(),
            value: 10,
        }],
        &alice.address(),
        50_000,
        h,
    )
    .unwrap()
    .tx;

    // Both in one block: aggregation refuses.
    assert!(chain
        .make_block(&[to_bob.clone(), to_carol.clone()], &alice.address())
        .is_err());
    // The selector keeps only one of them.
    assert_eq!(
        select_transactions(&[to_bob.clone(), to_carol.clone()], h, MAX_BLOCK_WEIGHT).len(),
        1
    );

    chain.mine(&[to_bob], &alice.address()).unwrap();
    let err = chain
        .make_block(&[to_carol], &alice.address())
        .unwrap_err()
        .to_string();
    assert!(err.contains("not found or already spent"), "{err}");
}

#[test]
fn kernel_replay_is_rejected() {
    let mut alice = TestWallet::new();
    let bob = TestWallet::new();
    let chain = funded_chain(&mut alice);
    let h = chain.state.height;
    let tx = build_transaction(
        &alice.spendable_at(h),
        &[Payment {
            to: bob.address(),
            value: 10,
        }],
        &alice.address(),
        50_000,
        h,
    )
    .unwrap()
    .tx;

    // Pretend the same kernel had already been mined (as it would be if the
    // inputs were ever re-created and the transaction replayed).
    let mut replay_state = chain.state.clone();
    replay_state.kernels.insert(tx.body.kernels[0].id(), true);
    let err = apply_body(&replay_state, &tx, None, 0)
        .unwrap_err()
        .to_string();
    assert!(err.contains("already on chain"), "{err}");

    // Without the prior kernel the same body applies.
    apply_body(&chain.state, &tx, None, 0).unwrap();
}

#[test]
fn immature_coinbase_cannot_be_spent() {
    let mut alice = TestWallet::new();
    let mut chain = TestChain::new();
    chain.mine(&[], &alice.address()).unwrap();
    alice.scan_chain(&chain);
    let (coin, is_cb, created) = alice.coins[0].clone();
    assert!(is_cb);
    let h = chain.state.height;
    assert!(h < created + COINBASE_MATURITY);
    let tx = build_transaction(
        &[coin],
        &[Payment {
            to: alice.address(),
            value: 1,
        }],
        &alice.address(),
        50_000,
        h,
    )
    .unwrap()
    .tx;
    let err = chain
        .make_block(&[tx], &alice.address())
        .unwrap_err()
        .to_string();
    assert!(err.contains("immature"), "{err}");
}

#[test]
fn time_locked_transaction_waits() {
    let mut alice = TestWallet::new();
    let mut chain = funded_chain(&mut alice);
    let h = chain.state.height;
    let tx = build_transaction(
        &alice.spendable_at(h),
        &[Payment {
            to: alice.address(),
            value: 1,
        }],
        &alice.address(),
        50_000,
        h + 2,
    )
    .unwrap()
    .tx;
    assert!(select_transactions(std::slice::from_ref(&tx), h, MAX_BLOCK_WEIGHT).is_empty());
    let err = chain
        .make_block(std::slice::from_ref(&tx), &alice.address())
        .unwrap_err()
        .to_string();
    assert!(err.contains("time-locked"), "{err}");
    chain.mine(&[], &alice.address()).unwrap();
    chain.mine(&[], &alice.address()).unwrap();
    chain.mine(&[tx], &alice.address()).unwrap();
}

#[test]
fn block_level_tampering_is_rejected() {
    let mut chain = TestChain::new();
    let miner = TestWallet::new();
    let good = chain.make_block(&[], &miner.address()).unwrap();

    let mut bad_root = good.clone();
    bad_root.state_root[0] ^= 1;
    assert!(apply_batch(&mut chain.state.clone(), &bad_root, &chain.timestamps).is_err());

    let mut bad_pow = good.clone();
    bad_pow.extension.nonce ^= 1;
    assert!(apply_batch(&mut chain.state.clone(), &bad_pow, &chain.timestamps).is_err());

    let mut no_coinbase = good.clone();
    no_coinbase.coinbase = None;
    assert!(apply_batch(&mut chain.state.clone(), &no_coinbase, &chain.timestamps).is_err());

    let mut future = good.clone();
    future.timestamp = u64::MAX / 2;
    assert!(apply_batch(&mut chain.state.clone(), &future, &chain.timestamps).is_err());

    // A failed application leaves the state untouched.
    let before = chain.state.mw_midstate;
    let mut s = chain.state.clone();
    let _ = apply_batch(&mut s, &bad_root, &chain.timestamps);
    assert_eq!(s.mw_midstate, before);
    assert_eq!(s.height, chain.state.height);

    chain.apply(good).unwrap();
}

#[test]
fn overpaying_coinbase_is_rejected() {
    let mut chain = TestChain::new();
    let miner = TestWallet::new();
    let template =
        build_template(&chain.state, &chain.timestamps, &[], &miner.address(), None).unwrap();
    let mut batch = template.batch.clone();
    batch.coinbase =
        Some(super::mw::build_coinbase(&[(miner.address(), block_reward(1) + 1)]).unwrap());
    let err = super::state::validate_block_contents(&batch, 1, false, block_reward(1))
        .unwrap_err()
        .to_string();
    assert!(err.contains("coinbase does not pay exactly"), "{err}");
    chain.mine(&[], &miner.address()).unwrap();
}

#[test]
fn forged_owner_offset_is_rejected() {
    // Same as a valid transaction but with the owner offset changed, so the
    // owner sum no longer balances.
    let mut alice = TestWallet::new();
    let chain = funded_chain(&mut alice);
    let h = chain.state.height;
    let mut tx = build_transaction(
        &alice.spendable_at(h),
        &[Payment {
            to: alice.address(),
            value: 1,
        }],
        &alice.address(),
        50_000,
        h,
    )
    .unwrap()
    .tx;
    tx.owner_offset = random_scalar().to_bytes();
    assert!(tx.validate(Context::Relay).is_err());
}

#[test]
fn input_signature_cannot_move_to_another_output() {
    let mut alice = TestWallet::new();
    let chain = funded_chain(&mut alice);
    let coin = alice.spendable_at(chain.state.height)[0].clone();
    let genuine = Input::sign(coin.commitment, &coin.owner_secret);
    let mut moved = genuine.clone();
    moved.commitment = [9u8; 32];
    assert!(genuine.verify_signature());
    assert!(!moved.verify_signature());
    let _ = (Kernel::new, KernelFeatures::Plain, TxBody::default()); // silence unused imports in some cfgs
}

/// Once the cap is reached there is nothing to mint, so a block with no fees
/// carries no coinbase at all. Without this rule the chain would stall the
/// first time the mempool ran dry after the last coin was issued: a coinbase
/// is mandatory today, and a coinbase paying zero cannot be built.
#[test]
fn blocks_after_the_last_coin_need_no_coinbase() {
    let mut alice = TestWallet::new();
    let chain = funded_chain(&mut alice);
    let end = EMISSION
        .final_reward_height()
        .expect("the schedule reaches the cap");
    assert_eq!(block_reward(end + 1), 0);

    // A state whose next block is past the end of issuance.
    let mut after = chain.state.clone();
    after.height = end + 1;
    let supply = issued_before(after.height);
    after.supply = supply;

    // An empty block there pays nobody and carries no coinbase.
    let template = build_template(&after, &chain.timestamps, &[], &alice.address(), None).unwrap();
    assert!(template.batch.coinbase.is_none());
    validate_block_contents(&template.batch, after.height, false, block_reward(after.height)).unwrap();
    let next = apply_body(&after, &template.batch.body, None, 0).unwrap();
    assert_eq!(next.supply, supply, "no coins after the cap");

    // Claiming anything there is invalid.
    let mut forged = template.batch.clone();
    forged.coinbase = Some(super::mw::build_coinbase(&[(alice.address(), 1)]).unwrap());
    assert!(validate_block_contents(&forged, after.height, true, block_reward(after.height)).is_err());
}

/// Fees still have to be claimed after issuance ends: an unclaimed fee would
/// leave the chain's Pedersen supply audit permanently unbalanced.
#[test]
fn fees_after_the_last_coin_still_need_a_coinbase() {
    let mut alice = TestWallet::new();
    let mut chain = funded_chain(&mut alice);
    let bob = TestWallet::new();
    let fee = 5_000u64;
    let coins = alice.spendable_at(chain.state.height);
    let tx = build_transaction(
        &coins,
        &[Payment {
            to: bob.address(),
            value: 1_000_000,
        }],
        &alice.address(),
        fee,
        0,
    )
    .unwrap()
    .tx;

    let end = EMISSION.final_reward_height().unwrap();
    let mut after = chain.state.clone();
    after.height = end + 1;
    after.supply = issued_before(after.height);

    let template = build_template(
        &after,
        &chain.timestamps,
        &[tx.clone()],
        &alice.address(),
        None,
    )
    .unwrap();
    let cb = template
        .batch
        .coinbase
        .as_ref()
        .expect("a fee-paying block still pays the miner");
    cb.verify_sum(fee).expect("the coinbase claims the fees");
    validate_block_contents(&template.batch, after.height, false, block_reward(after.height)).unwrap();

    // Dropping the coinbase would burn the fee, and is rejected.
    let mut stripped = template.batch.clone();
    stripped.coinbase = None;
    assert!(validate_block_contents(&stripped, after.height, true, block_reward(after.height)).is_err());

    // The chain itself is unaffected at ordinary heights.
    chain.mine(&[tx], &alice.address()).unwrap();
}

/// Tiny rewards cannot promise one base unit to every address: that would
/// subsidise Sybil splitting. Verify conservation and proportional rounding.
#[test]
fn tiny_rewards_round_proportionally() {
    let payees: Vec<(StealthAddress, u64)> = (0..32)
        .map(|i| (TestWallet::new().address(), 1 + i as u64 * 97))
        .collect();
    let total_weight: u128 = payees.iter().map(|(_, w)| *w as u128).sum();
    for total in [0u64, 1, 2, 32, 100, 553, 1_108, 23_932_616] {
        let split = super::template::split_by_weight(total, &payees).unwrap();
        assert_eq!(split.iter().map(|(_, v)| *v).sum::<u64>(), total);
        assert!(split.len() <= payees.len());
        assert!(split.iter().all(|(_, v)| *v > 0));
        if total == 32 {
            assert!(
                split.len() < payees.len(),
                "minimum per address is a Sybil subsidy"
            );
        }
        for (address, weight) in &payees {
            let actual = split
                .iter()
                .find(|(recipient, _)| recipient == address)
                .map_or(0, |(_, value)| *value);
            let numerator = total as u128 * *weight as u128;
            let floor = (numerator / total_weight) as u64;
            let ceil = floor + u64::from(numerator % total_weight != 0);
            assert!(
                actual >= floor && actual <= ceil,
                "{actual} base units for weight {weight} at reward {total}: expected {floor}..={ceil}"
            );
        }
    }
}

#[test]
fn coinbase_rounding_ties_use_input_order_without_overflow() {
    let a = TestWallet::new().address();
    let b = TestWallet::new().address();
    let c = TestWallet::new().address();
    let payees = [(a, u64::MAX), (b, u64::MAX), (c, u64::MAX)];
    let split = super::template::split_by_weight(2, &payees).unwrap();
    assert_eq!(split, vec![(a, 1), (b, 1)]);

    let split = super::template::split_by_weight(u64::MAX, &payees).unwrap();
    assert_eq!(
        split.iter().map(|(_, v)| *v as u128).sum::<u128>(),
        u64::MAX as u128
    );
    let amounts: Vec<u64> = split.iter().map(|(_, value)| *value).collect();
    assert!(*amounts.iter().max().unwrap() - *amounts.iter().min().unwrap() <= 1);
}

#[test]
fn heavier_fork_wins() {
    let miner = TestWallet::new();
    let mut a = TestChain::new();
    let mut b = TestChain::new();
    a.mine(&[], &miner.address()).unwrap();
    b.mine(&[], &miner.address()).unwrap();
    b.mine(&[], &miner.address()).unwrap();
    assert_eq!(choose_best_state(&a.state, &b.state).height, b.state.height);
}

// ── Bonded mining ────────────────────────────────────────────────────────────
//
// Test builds leave the authorisation optional (see `bond::BONDED_MINING_FROM`)
// but check it in full whenever a block carries one, so these tests exercise
// the production rules through `apply_batch`.

use super::bond::{
    authorization_message, check_miner_authorization, devnet_registrations, est_midstate_height,
    min_remaining_bond_lock, MinerBond,
};
use super::relay::{RelayFeed, RelayHeaders};
use super::state::apply_registrations;
use super::template::{build_template_bonded, BlockTemplate};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

/// A lock comfortably inside `MAX_BOND_HORIZON` and well past the minimum
/// remaining lock, wherever the clock is.
fn locked_long() -> u64 {
    super::bond::est_midstate_height(super::state::current_timestamp())
        + super::bond::MAX_BOND_HORIZON / 2
}

/// A block producer with a fresh bond locked until `bonded_until`, proven on
/// a stand-in midstate whose headers its blocks relay.
fn bonded_miner(chain: &TestChain, seed: &[u8], bonded_until: u64) -> MinerBond {
    bonded_miners(chain, &[(seed, bonded_until)]).remove(0)
}

/// Producers whose bonds are proven on one stand-in midstate, so their
/// headers agree (separate stand-ins would be competing branches).
fn bonded_miners(chain: &TestChain, specs: &[(&[u8], u64)]) -> Vec<MinerBond> {
    let secrets: Vec<Scalar> = specs
        .iter()
        .map(|(seed, _)| Scalar::from_bytes_mod_order(hash(seed)))
        .collect();
    let bonds: Vec<([u8; 32], u64, [u8; 32])> = specs
        .iter()
        .zip(&secrets)
        .map(|((seed, until), secret)| {
            (
                RistrettoPoint::mul_base(secret).compress().to_bytes(),
                *until,
                hash(seed),
            )
        })
        .collect();
    let (registrations, headers) = devnet_registrations(&bonds, &chain.state.target);
    registrations
        .into_iter()
        .zip(secrets)
        .map(|(registration, secret)| MinerBond {
            co_bonds: Vec::new(),
            secret,
            bond_id: registration.bond_id(),
            registration: Some(registration),
            midstate: Some(headers.clone()),
        })
        .collect()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl TestChain {
    fn bonded_template(&self, bond: &MinerBond, payout: &StealthAddress) -> Result<BlockTemplate> {
        let payouts = [(*payout, 1u64)];
        Ok(build_template_bonded(
            &self.state,
            &self.timestamps,
            &[],
            &payouts,
            [0u8; 32],
            None,
            Some(bond),
        )?
        .0)
    }

    fn make_bonded_block(&self, bond: &MinerBond, payout: &StealthAddress) -> Result<Batch> {
        Ok(self.bonded_template(bond, payout)?.mine_blocking())
    }

    fn bonded_block_at(
        &self,
        bond: &MinerBond,
        payout: &StealthAddress,
        timestamp: u64,
    ) -> Result<Batch> {
        Ok(build_template_bonded(
            &self.state,
            &self.timestamps,
            &[],
            &[(*payout, 1u64)],
            [0u8; 32],
            Some(timestamp),
            Some(bond),
        )?
        .0
        .mine_blocking())
    }
}

/// A bond whose lock has run down leaves the set, and with it the state
/// root, at the first block whose earliest possible timestamp it cannot sign
/// at. Templates and validation agree on it, the diff says so, and the bond
/// cannot be registered again.
#[test]
fn expired_bonds_leave_the_bond_set() {
    let mut chain = TestChain::new();
    let payout = TestWallet::new().address();
    let t0 = now();
    // `brief` is eligible for blocks stamped up to about t0 + 300.
    let mut bonds = bonded_miners(
        &chain,
        &[
            (b"lasting", locked_long()),
            (
                b"brief",
                est_midstate_height(t0 + 300) + min_remaining_bond_lock(t0 + 300),
            ),
        ],
    );
    let (lasting, brief) = (bonds.remove(0), bonds.remove(0));
    chain
        .apply(chain.bonded_block_at(&lasting, &payout, t0 + 60).unwrap())
        .unwrap();
    chain
        .apply(chain.bonded_block_at(&brief, &payout, t0 + 120).unwrap())
        .unwrap();
    let added: Vec<[u8; 32]> = chain
        .state
        .effects
        .bonds_added
        .iter()
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(added, vec![brief.bond_id]);
    chain
        .apply(chain.bonded_block_at(&lasting, &payout, t0 + 240).unwrap())
        .unwrap();
    chain
        .apply(chain.bonded_block_at(&lasting, &payout, t0 + 400).unwrap())
        .unwrap();
    assert!(
        chain.state.bonds.contains_key(&brief.bond_id),
        "still eligible at t0 + 241, the earliest that block could carry"
    );
    assert!(chain.state.effects.bonds_removed.is_empty());

    // The next block cannot be stamped before t0 + 401: the bond is gone.
    let root_before = chain.state.bonds.root();
    chain
        .apply(chain.bonded_block_at(&lasting, &payout, t0 + 500).unwrap())
        .unwrap();
    assert!(!chain.state.bonds.contains_key(&brief.bond_id));
    assert!(chain.state.bonds.contains_key(&lasting.bond_id));
    let removed: Vec<[u8; 32]> = chain
        .state
        .effects
        .bonds_removed
        .iter()
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(removed, vec![brief.bond_id]);
    assert_ne!(chain.state.bonds.root(), root_before);
    assert_eq!(
        chain.state.root_parts().bonds_root,
        chain.state.bonds.root()
    );

    // It cannot sign, and it cannot come back.
    let err = chain
        .bonded_block_at(&brief, &payout, t0 + 600)
        .unwrap_err();
    assert!(err.to_string().contains("not eligible"), "{err}");
}

#[test]
fn a_bonded_miner_registers_in_its_first_block_and_mines_on() {
    let mut chain = TestChain::new();
    let payout = TestWallet::new().address();
    let bond = bonded_miner(&chain, b"bonded miner", locked_long());

    // The first block carries its own registration and is signed by the bond
    // it registers: this is how block 1 of the real chain gets mined.
    let first = chain.make_bonded_block(&bond, &payout).unwrap();
    assert_eq!(first.registrations.len(), 1);
    assert_eq!(first.miner.as_ref().unwrap().bond_id, bond.bond_id);
    chain.apply(first).unwrap();
    assert_eq!(
        chain.state.bonds.get(&bond.bond_id).unwrap().mining_key,
        bond.mining_key()
    );

    // After that the chain has it, and blocks carry only the signature.
    let second = chain.make_bonded_block(&bond, &payout).unwrap();
    assert!(second.registrations.is_empty());
    chain.apply(second).unwrap();
    assert_eq!(
        chain.state.root_parts().bonds_root,
        chain.state.bonds.root()
    );
}

#[test]
fn a_rebound_template_is_a_valid_block_with_its_own_extra() {
    let mut chain = TestChain::new();
    let payout = TestWallet::new().address();
    let bond = bonded_miner(&chain, b"pool operator", locked_long());
    chain
        .apply(chain.make_bonded_block(&bond, &payout).unwrap())
        .unwrap();
    let template = chain.bonded_template(&bond, &payout).unwrap();
    let copy = super::template::rebind(&template, [7; 32], Some(&bond)).unwrap();
    let (cb, original) = (
        copy.batch.coinbase.as_ref().unwrap(),
        template.batch.coinbase.as_ref().unwrap(),
    );
    assert_eq!(cb.extra, [7; 32]);
    assert_eq!(cb.outputs, original.outputs);
    assert_ne!(copy.mining_hash, template.mining_hash);
    // The old signature does not cover a changed extra: re-signing is needed.
    let mut stale = template.batch.clone();
    stale.coinbase.as_mut().unwrap().extra = [7; 32];
    assert!(
        check_miner_authorization(&chain.state.bonds, &chain.state.mw_midstate, &stale).is_err()
    );
    check_miner_authorization(&chain.state.bonds, &chain.state.mw_midstate, &copy.batch).unwrap();
    // A nonce found for the copy seals a block the chain accepts.
    chain.apply(copy.mine_blocking()).unwrap();
}

#[test]
fn a_forged_signature_is_rejected_even_with_valid_work() {
    let mut chain = TestChain::new();
    let payout = TestWallet::new().address();
    let bond = bonded_miner(&chain, b"honest", locked_long());
    chain
        .apply(chain.make_bonded_block(&bond, &payout).unwrap())
        .unwrap();

    // Someone who knows the bond id but not its mining key signs a block as
    // that bond and does the proof of work for it.
    let thief = Scalar::from_bytes_mod_order(hash(b"thief"));
    let mut template = chain.bonded_template(&bond, &payout).unwrap();
    let message = authorization_message(&chain.state.mw_midstate, &template.batch);
    template.batch.miner.as_mut().unwrap().signature =
        super::mw::crypto::schnorr_sign(&thief, &message);
    let mut header = template.batch.header();
    header.height = template.height;
    template.mining_hash = compute_header_hash(&header);
    let forged = template.mine_blocking();
    let err = chain.apply(forged).unwrap_err();
    assert!(err.to_string().contains("signature"), "{err}");
}

/// A bond the chain has never seen, or one whose lock is too short to sign,
/// cannot sign a block. While no registered bond can sign either, its
/// producer's blocks are unsigned; once one can, it cannot mine at all.
#[test]
fn unregistered_and_short_locked_bonds_cannot_mine() {
    let mut chain = TestChain::new();
    let payout = TestWallet::new().address();
    let mut bonds = bonded_miners(
        &chain,
        &[
            (b"unregistered", locked_long()),
            (
                b"short lock",
                est_midstate_height(now()) + min_remaining_bond_lock(now()) - 1_000,
            ),
            (b"lasting", locked_long()),
        ],
    );
    // A bond with no registration to carry, and one whose lock runs out
    // within the month: it would register, but cannot authorise a block.
    let unregistered = MinerBond {
        registration: None,
        ..bonds.remove(0)
    };
    let (short, lasting) = (bonds.remove(0), bonds.remove(0));
    for bond in [&unregistered, &short] {
        let block = chain.make_bonded_block(bond, &payout).unwrap();
        assert!(block.miner.is_none() && block.registrations.is_empty());
    }
    chain
        .apply(chain.make_bonded_block(&lasting, &payout).unwrap())
        .unwrap();
    assert!(chain.make_bonded_block(&unregistered, &payout).is_err());
    let err = chain.make_bonded_block(&short, &payout).unwrap_err();
    assert!(err.to_string().contains("not eligible"), "{err}");
}

#[test]
fn the_signature_binds_the_whole_block() {
    let mut chain = TestChain::new();
    let payout = TestWallet::new().address();
    let bond = bonded_miner(&chain, b"binder", locked_long());
    chain
        .apply(chain.make_bonded_block(&bond, &payout).unwrap())
        .unwrap();
    let signed = chain.bonded_template(&bond, &payout).unwrap().batch;
    let prev = chain.state.mw_midstate;
    check_miner_authorization(&chain.state.bonds, &prev, &signed).unwrap();
    let tampers: [fn(&mut Batch); 4] = [
        |b| b.timestamp += 1,
        |b| b.state_root[0] ^= 1,
        |b| b.prev_header_hash[0] ^= 1,
        |b| b.coinbase = None,
    ];
    for tamper in tampers {
        let mut t = signed.clone();
        tamper(&mut t);
        assert!(check_miner_authorization(&chain.state.bonds, &prev, &t).is_err());
    }
    // And the proof of work covers the signature.
    assert_ne!(fold_block(&prev, &signed), fold_unsigned(&prev, &signed));
}

#[test]
fn registrations_are_verified_and_limited() {
    let chain = TestChain::new();
    let payout = TestWallet::new().address();
    let bond = bonded_miner(&chain, b"verified", locked_long());
    let block = chain.make_bonded_block(&bond, &payout).unwrap();
    let height = chain.state.height;
    // The first block relays the bond's midstate headers with it.
    let relayed = block
        .relay
        .as_ref()
        .expect("the block relays the bond's headers");
    assert_eq!(
        relayed.headers.len(),
        bond.midstate.as_ref().unwrap().headers.len()
    );
    validate_block_contents(&block, height, false, block_reward(height)).unwrap();
    // A relayed header with a forged proof of work is caught with the
    // block's other proofs.
    let mut forged = block.clone();
    forged.relay.as_mut().unwrap().headers[5].nonce ^= 1;
    assert!(validate_block_contents(&forged, height, false, block_reward(height)).is_err());
    // Two registrations in one block are refused outright.
    let mut two = block.clone();
    two.registrations.push(block.registrations[0].clone());
    assert!(validate_block_contents(&two, height, true, block_reward(height)).is_err());
}

/// Without the relay holding its header, a registration has nothing to be
/// checked against: a producer whose bond file carries no headers cannot
/// register (its blocks are unsigned while no bond can sign) until something
/// relays them, and then it can.
#[test]
fn registrations_wait_for_the_relay() {
    let mut chain = TestChain::new();
    let payout = TestWallet::new().address();
    let mut bond = bonded_miner(&chain, b"patient", locked_long());
    let headers = bond.midstate.take().unwrap();
    let waiting = chain.make_bonded_block(&bond, &payout).unwrap();
    assert!(waiting.miner.is_none() && waiting.registrations.is_empty());
    assert!(waiting.relay.is_none(), "it has nothing to relay");
    // A block from someone else relays the headers (a producer whose node
    // follows midstate)...
    let mut feed = RelayFeed::default();
    feed.add(&headers, true);
    let relaying = crate::core::template::build_template_relayed(
        &chain.state,
        &chain.timestamps,
        &[],
        &[(payout, 1)],
        [0; 32],
        None,
        None,
        Some(&feed),
    )
    .unwrap()
    .0
    .mine_blocking();
    assert!(relaying.relay.is_some());
    chain.apply(relaying).unwrap();
    assert_eq!(
        chain.state.relay.tip().hash,
        headers.headers.last().unwrap().final_hash
    );
    // ...and now the registration verifies and the bond mines.
    let first = chain.make_bonded_block(&bond, &payout).unwrap();
    assert!(first.relay.is_none(), "nothing left to relay");
    chain.apply(first).unwrap();
    assert!(chain.state.bonds.contains_key(&bond.bond_id));
}

/// The freeze unsigned blocks end: a bond proven further past the relay's
/// tip than one block can relay. While a block had to be signed, nothing
/// could be mined before the first bond registered, and no single block
/// could relay what its registration needed. Now blocks are unsigned while
/// no bond can sign, and relay midstate a day at a time until the proof is
/// buried; the block that registers the bond is signed by it.
#[test]
fn a_bond_proven_beyond_one_blocks_relay_still_registers() {
    use super::bond::{
        registration_cap, registration_work, BondCoin, BondRegistration, BondScript,
        MIN_MINING_BOND,
    };
    use super::relay::{devnet::DevnetMidstate, MAX_RELAY_HEADERS_PER_BLOCK};
    let mut chain = TestChain::new();
    let payout = TestWallet::new().address();
    let secret = Scalar::from_bytes_mod_order(hash(b"late"));
    let coin = BondCoin {
        script: BondScript {
            mining_key: RistrettoPoint::mul_base(&secret).compress().to_bytes(),
            bonded_until: locked_long(),
            owner_pk: hash(b"late owner"),
        },
        value: MIN_MINING_BOND,
        salt: hash(b"late salt"),
    };
    // Midstate runs on past the root for more than a block can relay before
    // the coin is locked, then buries it.
    let mut midstate = DevnetMidstate::new();
    midstate.mine(MAX_RELAY_HEADERS_PER_BLOCK as u64 + 100);
    midstate.lock(&coin);
    midstate.mine(1);
    let proof = midstate.prove(&coin);
    let required = registration_work(&chain.state.target);
    let per =
        super::state::calculate_work(&midstate.target).min(registration_cap(&chain.state.target));
    midstate.mine(required.div_ceil(per) as u64 + 1);
    let registration = BondRegistration { proof };
    let bond = MinerBond {
        co_bonds: Vec::new(),
        secret,
        bond_id: registration.bond_id(),
        registration: Some(registration),
        midstate: Some(midstate.mined.clone()),
    };

    let first = chain.make_bonded_block(&bond, &payout).unwrap();
    assert!(first.miner.is_none() && first.registrations.is_empty());
    assert_eq!(
        first.relay.as_ref().unwrap().headers.len(),
        MAX_RELAY_HEADERS_PER_BLOCK
    );
    chain.apply(first).unwrap();
    assert!(chain.state.bonds.is_empty());

    let second = chain.make_bonded_block(&bond, &payout).unwrap();
    assert_eq!(second.registrations.len(), 1);
    assert_eq!(second.miner.as_ref().unwrap().bond_id, bond.bond_id);
    chain.apply(second).unwrap();
    assert!(chain.state.bonds.contains_key(&bond.bond_id));
    assert_eq!(chain.state.relay.tip().height, midstate.height());
}

/// The review's attack: one private midstate branch, mined once, holding
/// coins nobody locked, backs bond after bond. Here it does so only while it
/// is the relay's chain. Once a heavier branch (midstate's real chain, as an
/// honest producer relays it) replaces it, every bond proven on it is
/// revoked together: its coins are no longer known to exist.
#[test]
fn a_heavier_midstate_branch_revokes_bonds_proven_on_the_old_one() {
    let mut chain = TestChain::new();
    let payout = TestWallet::new().address();
    let mut forged = bonded_miners(
        &chain,
        &[
            (b"forged 1", locked_long()),
            (b"forged 2", locked_long()),
            (b"forged 3", locked_long()),
        ],
    );
    for bond in &forged {
        chain
            .apply(chain.make_bonded_block(bond, &payout).unwrap())
            .unwrap();
        assert!(chain.state.bonds.contains_key(&bond.bond_id));
    }
    assert_eq!(chain.state.bonds.len(), 3, "one branch backed three bonds");
    let bond = forged.remove(0);
    let replaced = chain.state.relay.tip().height;

    // Another stand-in midstate from the same root, longer: heavier.
    let mut honest = super::relay::devnet::DevnetMidstate::new();
    honest.mine(bond.midstate.as_ref().unwrap().headers.len() as u64 + 3);
    let mut feed = RelayFeed::default();
    feed.add(&honest.mined, true);
    let block = crate::core::template::build_template_relayed(
        &chain.state,
        &chain.timestamps,
        &[],
        &[(payout, 1)],
        [0; 32],
        None,
        None,
        Some(&feed),
    )
    .unwrap()
    .0
    .mine_blocking();
    assert_eq!(
        block.relay.as_ref().unwrap().prev,
        super::relay::RelayEntry::root().hash
    );
    chain.apply(block).unwrap();
    assert!(
        chain.state.bonds.is_empty(),
        "every bond on the branch is revoked"
    );
    let mut revoked: Vec<[u8; 32]> = chain
        .state
        .effects
        .bonds_removed
        .iter()
        .map(|(id, _)| *id)
        .collect();
    let mut expected: Vec<[u8; 32]> = std::iter::once(bond.bond_id)
        .chain(forged.iter().map(|b| b.bond_id))
        .collect();
    revoked.sort();
    expected.sort();
    assert_eq!(revoked, expected);
    assert!(
        chain.state.effects.relay_removed.len() as u64
            >= replaced - super::relay::RelayEntry::root().height
    );
    assert!(chain.state.relay.tip().height > replaced);

    // It can no longer sign, and its old registration has nothing to stand
    // on: with no registered bond left, its producer's block is unsigned.
    let block = chain.make_bonded_block(&bond, &payout).unwrap();
    assert!(block.miner.is_none() && block.registrations.is_empty());
    // The lighter branch cannot come back.
    let old = bond.midstate.as_ref().unwrap();
    let lighter = RelayHeaders {
        prev: old.prev,
        headers: old.headers.clone(),
    };
    assert!(chain.state.relay.clone().extend(&lighter, now()).is_err());
}

#[test]
fn a_bond_registers_once() {
    let mut chain = TestChain::new();
    let payout = TestWallet::new().address();
    let bond = bonded_miner(&chain, b"twice", locked_long());
    let first = chain.make_bonded_block(&bond, &payout).unwrap();
    let registration = first.registrations[0].clone();
    chain.apply(first).unwrap();
    let entry = registration
        .verify(&chain.state.relay, &chain.state.target)
        .unwrap();
    let mut state = chain.state.clone();
    assert!(apply_registrations(&mut state, &[(registration.bond_id(), entry)]).is_err());
}

/// Past the mainnet switch a producer over its per-bond cap may mint less,
/// and its own template pays the lower figure: `validate_block_contents`
/// accepts the block at the tapered subsidy and refuses it at the full
/// scheduled reward. That is the producer and the chain agreeing on what the
/// coinbase may claim — if they disagreed, `Coinbase::verify_sum` would fail
/// and the producer's blocks would be rejected the moment the switch landed.
///
/// The window is filled with blocks stamped now (a node refuses a block more
/// than 900s ahead of its clock, so the switch itself cannot be mined through
/// in a test); only the block under test is stamped past it.
#[test]
fn past_the_switch_a_template_pays_an_over_cap_block_less() {
    let mut chain = TestChain::new();
    let payout = TestWallet::new().address();
    let mut bonds = bonded_miners(
        &chain,
        &[(b"greedy", locked_long()), (b"other", locked_long())],
    );
    let (greedy, other) = (bonds.remove(0), bonds.remove(0));

    // Both bonds on chain: one registration a block.
    chain
        .apply(chain.make_bonded_block(&greedy, &payout).unwrap())
        .unwrap();
    chain
        .apply(chain.make_bonded_block(&other, &payout).unwrap())
        .unwrap();
    // The greedy bond then takes the whole window for itself.
    for _ in 0..crate::core::bond::CAP_WINDOW {
        chain
            .apply(chain.make_bonded_block(&greedy, &payout).unwrap())
            .unwrap();
    }

    // One block stamped after the switch, built by this producer's template.
    let t = crate::core::bond::EARLY_BONDS_UNTIL + 60;
    let height = chain.state.height;
    let batch = chain.bonded_block_at(&greedy, &payout, t).unwrap();

    // What the chain will let it mint, worked out the way `apply_batch` does.
    let cap = crate::core::bond::signer_cap(&chain.state.bonds, t);
    let mut recent = chain.state.recent_signers.clone();
    let mut counts = chain.state.signer_counts.clone();
    crate::core::bond::credit_in_window(
        &mut recent,
        &mut counts,
        &chain.state.bonds,
        height,
        Some(greedy.bond_id),
        0,
        t,
    );
    let n = counts.get(&greedy.bond_id).copied().unwrap_or(0) as usize;
    assert!(n > cap, "the greedy bond should be past its cap ({n} of {cap})");
    let scheduled = block_reward(height);
    let tapered = crate::core::bond::capped_subsidy(scheduled, n, cap);
    assert!(tapered < scheduled, "an over-cap block should mint less");

    // The template paid exactly the tapered figure, and nothing else passes.
    validate_block_contents(&batch, height, true, tapered).unwrap();
    assert!(validate_block_contents(&batch, height, true, scheduled).is_err());
}
