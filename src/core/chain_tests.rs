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
    let err = apply_body(&replay_state, &tx, None)
        .unwrap_err()
        .to_string();
    assert!(err.contains("already on chain"), "{err}");

    // Without the prior kernel the same body applies.
    apply_body(&chain.state, &tx, None).unwrap();
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
    let err = super::state::validate_block_contents(&batch, 1, false)
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
    validate_block_contents(&template.batch, after.height, false).unwrap();
    let next = apply_body(&after, &template.batch.body, None).unwrap();
    assert_eq!(next.supply, supply, "no coins after the cap");

    // Claiming anything there is invalid.
    let mut forged = template.batch.clone();
    forged.coinbase = Some(super::mw::build_coinbase(&[(alice.address(), 1)]).unwrap());
    assert!(validate_block_contents(&forged, after.height, true).is_err());
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

    let template =
        build_template(&after, &chain.timestamps, &[tx.clone()], &alice.address(), None).unwrap();
    let cb = template
        .batch
        .coinbase
        .as_ref()
        .expect("a fee-paying block still pays the miner");
    cb.verify_sum(fee).expect("the coinbase claims the fees");
    validate_block_contents(&template.batch, after.height, false).unwrap();

    // Dropping the coinbase would burn the fee, and is rejected.
    let mut stripped = template.batch.clone();
    stripped.coinbase = None;
    assert!(validate_block_contents(&stripped, after.height, true).is_err());

    // The chain itself is unaffected at ordinary heights.
    chain.mine(&[tx], &alice.address()).unwrap();
}

/// Slow-start blocks are worth only a few hundred base units, and a pool
/// splits them across up to 32 payees. Nobody weighted may round to nothing.
#[test]
fn tiny_rewards_still_pay_every_payee() {
    let payees: Vec<(StealthAddress, u64)> = (0..32)
        .map(|i| (TestWallet::new().address(), 1 + i as u64 * 97))
        .collect();
    for total in [32u64, 100, 553, 1_108, 23_932_616] {
        let split = super::template::split_by_weight(total, &payees).unwrap();
        assert_eq!(split.len(), payees.len(), "someone was dropped at {total}");
        assert!(split.iter().all(|(_, v)| *v > 0));
        assert_eq!(split.iter().map(|(_, v)| *v).sum::<u64>(), total);
    }
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
    authorization_message, check_miner_authorization, est_midstate_height, test_registration,
    MinerBond, MIN_REMAINING_BOND_LOCK,
};
use super::state::apply_registrations;
use super::template::{build_template_bonded, BlockTemplate};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

const LOCKED_LONG: u64 = 10_000_000;

/// A block producer with a fresh bond locked until `bonded_until`.
fn bonded_miner(chain: &TestChain, seed: &[u8], bonded_until: u64) -> MinerBond {
    let secret = Scalar::from_bytes_mod_order(hash(seed));
    let mining_key = RistrettoPoint::mul_base(&secret).compress().to_bytes();
    let registration =
        test_registration(mining_key, bonded_until, hash(seed), &chain.state.target);
    MinerBond {
        secret,
        bond_id: registration.bond_id(),
        registration: Some(registration),
    }
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
}

#[test]
fn a_bonded_miner_registers_in_its_first_block_and_mines_on() {
    let mut chain = TestChain::new();
    let payout = TestWallet::new().address();
    let bond = bonded_miner(&chain, b"bonded miner", LOCKED_LONG);

    // The first block carries its own registration and is signed by the bond
    // it registers: this is how block 1 of the real chain gets mined.
    let first = chain.make_bonded_block(&bond, &payout).unwrap();
    assert_eq!(first.registrations.len(), 1);
    assert_eq!(first.miner.as_ref().unwrap().bond_id, bond.bond_id);
    chain.apply(first).unwrap();
    assert_eq!(chain.state.bonds[&bond.bond_id].mining_key, bond.mining_key());

    // After that the chain has it, and blocks carry only the signature.
    let second = chain.make_bonded_block(&bond, &payout).unwrap();
    assert!(second.registrations.is_empty());
    chain.apply(second).unwrap();
    assert_eq!(chain.state.root_parts().bonds_root, bonds_root(&chain.state.bonds));
}

#[test]
fn a_forged_signature_is_rejected_even_with_valid_work() {
    let mut chain = TestChain::new();
    let payout = TestWallet::new().address();
    let bond = bonded_miner(&chain, b"honest", LOCKED_LONG);
    chain.apply(chain.make_bonded_block(&bond, &payout).unwrap()).unwrap();

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

#[test]
fn unregistered_and_short_locked_bonds_cannot_mine() {
    let chain = TestChain::new();
    let payout = TestWallet::new().address();
    // A bond the chain has never seen, with no registration to carry.
    let unregistered = MinerBond {
        registration: None,
        ..bonded_miner(&chain, b"unregistered", LOCKED_LONG)
    };
    assert!(chain.make_bonded_block(&unregistered, &payout).is_err());
    // A bond whose lock runs out within the month: it would register, but
    // cannot authorise a block.
    let short = bonded_miner(
        &chain,
        b"short lock",
        est_midstate_height(now()) + MIN_REMAINING_BOND_LOCK - 1_000,
    );
    let err = chain.make_bonded_block(&short, &payout).unwrap_err();
    assert!(err.to_string().contains("not eligible"), "{err}");
}

#[test]
fn the_signature_binds_the_whole_block() {
    let mut chain = TestChain::new();
    let payout = TestWallet::new().address();
    let bond = bonded_miner(&chain, b"binder", LOCKED_LONG);
    chain.apply(chain.make_bonded_block(&bond, &payout).unwrap()).unwrap();
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
    let bond = bonded_miner(&chain, b"verified", LOCKED_LONG);
    let block = chain.make_bonded_block(&bond, &payout).unwrap();
    let height = chain.state.height;
    validate_block_contents(&block, height, false).unwrap();
    // Cut short, the registration no longer carries a day of work.
    let mut short = block.clone();
    short.registrations[0].headers.truncate(10);
    assert!(validate_block_contents(&short, height, false).is_err());
    // Two registrations in one block are refused outright.
    let mut two = block.clone();
    two.registrations.push(block.registrations[0].clone());
    assert!(validate_block_contents(&two, height, true).is_err());
}

#[test]
fn a_bond_registers_once() {
    let mut chain = TestChain::new();
    let payout = TestWallet::new().address();
    let bond = bonded_miner(&chain, b"twice", LOCKED_LONG);
    let first = chain.make_bonded_block(&bond, &payout).unwrap();
    let registration = first.registrations[0].clone();
    chain.apply(first).unwrap();
    let mut state = chain.state.clone();
    assert!(apply_registrations(&mut state, &[registration]).is_err());
}
