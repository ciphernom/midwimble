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
