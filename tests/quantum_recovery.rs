//! Post-quantum recovery and Midstate anchoring (`docs/ANCHORING.md`).
//!
//! `cargo test --features fast-mining --test quantum_recovery`
//!
//! The success criterion: after a checkpoint is anchored, an attacker who
//! holds *every* elliptic-curve secret still cannot claim checkpointed coins,
//! while their rightful owners can.

mod support;
use support::*;

use curve25519_dalek::scalar::Scalar;
use midwimble::anchor::{anchor_once, find_commit, post_commit, verify_records};
use midwimble::core::anchor::Checkpoint;
use midwimble::core::mmr::UtxoAccumulator;
use midwimble::core::mw::crypto::{random_scalar, IDENTITY};
use midwimble::core::mw::{build_transaction, scan_output, Output, Payment, Spendable, WalletKeys};
use midwimble::core::recovery::{
    derive_recovery_keypair, recovery_commitment, ClaimedOutput, Generators, RecoveryClaim,
    RecoveryState,
};
use midwimble::core::state::apply_batch;
use midwimble::core::template::build_template;
use midwimble::core::types::{
    network_anchor, utxo_leaf, Batch, State, StateRootParts, UtxoEntry, COINBASE_MATURITY,
};
use midwimble::node::{Node, NodeConfig};
use midwimble::rpc::RpcClient;
use std::time::{Duration, Instant};

struct Chain {
    state: State,
    ts: Vec<u64>,
    blocks: Vec<Batch>,
}

impl Chain {
    fn new() -> Self {
        let mut state = State::genesis();
        apply_batch(&mut state, Batch::genesis(), &[]).unwrap();
        Self {
            state,
            ts: vec![Batch::genesis().timestamp],
            blocks: vec![Batch::genesis().clone()],
        }
    }

    fn mine(&mut self, txs: &[midwimble::core::mw::Transaction], to: &WalletKeys) -> &Batch {
        let b = build_template(&self.state, &self.ts, txs, &to.address(), None)
            .unwrap()
            .mine_blocking();
        apply_batch(&mut self.state, &b, &self.ts).unwrap();
        self.ts.push(b.timestamp);
        self.blocks.push(b);
        self.blocks.last().unwrap()
    }

    fn tip_header(&self) -> midwimble::core::BatchHeader {
        let mut h = self.blocks.last().unwrap().header();
        h.height = self.state.height - 1;
        h
    }
}

fn outputs_of(b: &Batch) -> Vec<Output> {
    b.body
        .outputs()
        .cloned()
        .chain(b.coinbase.iter().flat_map(|c| c.outputs.outputs.clone()))
        .collect()
}

fn owned(keys: &WalletKeys, state: &State, blocks: &[Batch]) -> Vec<ClaimedOutput> {
    blocks
        .iter()
        .flat_map(outputs_of)
        .filter(|o| state.utxos.contains_key(&o.commitment))
        .filter_map(|o| {
            let seen = scan_output(keys, &o)?;
            Some(
                ClaimedOutput::from_state(
                    state,
                    o.commitment,
                    seen.value,
                    seen.blinding.to_bytes(),
                    seen.recovery_salt,
                )
                .unwrap(),
            )
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quantum_break_after_an_anchor_cannot_steal_checkpointed_coins() {
    // Wallets with real post-quantum recovery keys (MSS height 1: two claims).
    let alice_mss = derive_recovery_keypair(b"alice seed", 1).unwrap();
    let bob_mss = derive_recovery_keypair(b"bob seed", 1).unwrap();
    let alice = WalletKeys::from_seed(b"alice seed", alice_mss.public_key());
    let bob = WalletKeys::from_seed(b"bob seed", bob_mss.public_key());
    let miner = WalletKeys::random();

    // A Midwimble chain: Alice's reward matures and she pays Bob.
    let mut chain = Chain::new();
    let reward_block = chain.mine(&[], &alice).clone();
    for _ in 0..COINBASE_MATURITY {
        chain.mine(&[], &miner);
    }
    let reward = &reward_block.coinbase.as_ref().unwrap().outputs.outputs[0];
    let mine_it = scan_output(&alice, reward).unwrap();
    assert!(mine_it.recovery_ok);
    let coin = Spendable {
        commitment: reward.commitment,
        value: mine_it.value,
        blinding: mine_it.blinding,
        owner_secret: mine_it.owner_secret,
    };
    let pay = build_transaction(
        &[coin],
        &[Payment {
            to: bob.address(),
            value: 5_000_000,
        }],
        &alice.address(),
        100_000,
        chain.state.height,
    )
    .unwrap()
    .tx;
    chain.mine(&[pay], &miner);

    // Checkpoint the tip and anchor it in Midstate with a Commit transaction.
    let checkpoint = Checkpoint::new(&chain.tip_header(), chain.state.depth, [0; 32]);
    let parts = chain.state.checkpoint_parts();
    assert_eq!(
        parts.root(),
        checkpoint.mw_state_root,
        "checkpoint commits to exactly these parts"
    );
    let id = checkpoint.id();
    let (ms_addr, _mock) = start_mock_midstate().await;
    let evidence = tokio::task::spawn_blocking(move || {
        let ms = RpcClient::new(ms_addr.clone());
        mine_midstate_block(&ms_addr);
        mine_midstate_block(&ms_addr);
        let posted = post_commit(&ms, &id).unwrap();
        assert!(
            find_commit(&ms, &id, posted, 3).unwrap().is_none(),
            "not mined yet"
        );
        for _ in 0..3 {
            mine_midstate_block(&ms_addr);
        }
        find_commit(&ms, &id, posted, 3).unwrap().expect("anchored")
    })
    .await
    .unwrap();
    evidence.verify(&id, 3, 0).unwrap();
    assert!(
        evidence.verify(&[0xEE; 32], 3, 0).is_err(),
        "evidence binds the checkpoint id"
    );
    assert!(evidence.verify(&id, 5, 0).is_err(), "depth is enforced");

    // The chain continues past the checkpoint; the attacker mints an output
    // there with their own recovery key.
    let mut attacker_mss = derive_recovery_keypair(b"attacker", 1).unwrap();
    let attacker = WalletKeys::random_with_recovery(attacker_mss.public_key());
    let checkpoint_state = chain.state.clone();
    let checkpoint_blocks = chain.blocks.clone();
    chain.mine(&[], &attacker);

    // THE BREAK. The attacker now holds every elliptic-curve secret: both
    // wallets' scan and spend keys (so every blinding, shared secret and
    // owner key), and can produce any Schnorr signature. What they cannot do
    // is sign with anyone else's MSS key.
    let stolen_view_of_bob = owned(&bob, &checkpoint_state, &checkpoint_blocks);
    assert_eq!(stolen_view_of_bob.len(), 1);
    let bobs_output = stolen_view_of_bob[0].clone();
    assert_eq!(bobs_output.value, 5_000_000);
    let attacker_dest = [0xAA; 32];
    let mut recovery =
        RecoveryState::activate(checkpoint.clone(), parts.clone(), Generators::standard()).unwrap();

    // a) Claim Bob's coin with the attacker's own recovery key.
    let a = RecoveryClaim::build(
        &mut attacker_mss.clone(),
        id,
        vec![bobs_output.clone()],
        attacker_dest,
    )
    .unwrap();
    let e = recovery.apply(&a).unwrap_err().to_string();
    assert!(e.contains("recovery commitment mismatch"), "{e}");

    // b) Name Bob's recovery key but sign with the attacker's.
    let mut b = a.clone();
    b.recovery_key = bob_mss.public_key();
    let e = recovery.apply(&b).unwrap_err().to_string();
    assert!(e.contains("invalid recovery signature"), "{e}");

    // c) Redirect a claim Bob genuinely signed.
    let bob_dest = [0xB0; 32];
    let bob_claim = RecoveryClaim::build(
        &mut bob_mss.clone(),
        id,
        vec![bobs_output.clone()],
        bob_dest,
    )
    .unwrap();
    let mut redirected = bob_claim.clone();
    redirected.destination = attacker_dest;
    let e = recovery.apply(&redirected).unwrap_err().to_string();
    assert!(e.contains("invalid recovery signature"), "{e}");

    // d) Claim an output minted after the checkpoint (with a valid-looking
    //    proof against the later state).
    let later = owned(&attacker, &chain.state, &chain.blocks);
    assert_eq!(later.len(), 1);
    let d = RecoveryClaim::build(&mut attacker_mss, id, later, attacker_dest).unwrap();
    let e = recovery.apply(&d).unwrap_err().to_string();
    assert!(e.contains("not in the checkpoint's UTXO set"), "{e}");

    // e) Even Bob cannot claim more than his output is worth.
    let mut inflated = bobs_output.clone();
    inflated.value += 1;
    let e_claim = RecoveryClaim::build(&mut bob_mss.clone(), id, vec![inflated], bob_dest).unwrap();
    let e = recovery.apply(&e_claim).unwrap_err().to_string();
    assert!(e.contains("recovery commitment mismatch"), "{e}");

    assert_eq!(recovery.total_claimed, 0, "the attacker got nothing");

    // The rightful owners claim with their post-quantum keys.
    assert_eq!(recovery.apply(&bob_claim).unwrap(), 5_000_000);
    let again = RecoveryClaim::build(
        &mut {
            let mut k = bob_mss.clone();
            k.set_next_leaf(1);
            k
        },
        id,
        vec![bobs_output.clone()],
        bob_dest,
    )
    .unwrap();
    let e = recovery.apply(&again).unwrap_err().to_string();
    assert!(e.contains("already claimed"), "{e}");

    let alice_coins = owned(&alice, &checkpoint_state, &checkpoint_blocks);
    assert_eq!(alice_coins.len(), 1, "Alice's change");
    let change = alice_coins[0].value;
    let alice_claim =
        RecoveryClaim::build(&mut alice_mss.clone(), id, alice_coins, [0xA1; 32]).unwrap();
    assert_eq!(recovery.apply(&alice_claim).unwrap(), change);

    // A second claim signed with the same MSS leaf is refused outright.
    let reuse =
        RecoveryClaim::build(&mut alice_mss.clone(), id, vec![bobs_output], [0xA1; 32]).unwrap();
    let e = recovery.apply(&reuse).unwrap_err().to_string();
    assert!(e.contains("already used"), "{e}");

    assert_eq!(
        recovery.credited,
        vec![(bob_dest, 5_000_000), ([0xA1; 32], change)]
    );
    assert!(recovery.total_claimed <= parts.supply);
}

/// With generators whose discrete-log relation is known, commitments stop
/// binding: exactly what a quantum attacker gets. The frozen opening in the
/// recovery commitment still pins the value.
#[test]
fn broken_binding_cannot_inflate_a_claim() {
    let k = Scalar::from(1_234_567u64);
    let g = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    let broken = Generators { g, h: k * g };

    let owner = derive_recovery_keypair(b"owner", 1).unwrap();
    let r = owner.public_key();
    let (value, blinding, salt) = (1_000u64, random_scalar(), [9u8; 32]);
    let commitment = broken.commit(value, &blinding);
    let entry = UtxoEntry {
        output_hash: [2; 32],
        owner_key: [1; 32],
        recovery_commitment: recovery_commitment(&r, value, &blinding.to_bytes(), &salt),
        height: 5,
        coinbase: false,
    };
    let leaf = utxo_leaf(&commitment, &entry);
    let mut acc = UtxoAccumulator::new();
    acc.insert(leaf, true);
    let proof = acc.prove(&leaf, true).unwrap();
    let parts = StateRootParts {
        utxo_root: acc.root(true),
        kernel_root: [0; 32],
        chain_mmr_root: [0; 32],
        kernel_excess_sum: IDENTITY,
        total_kernel_offset: [0; 32],
        supply: 1_000_000_000,
    };
    let checkpoint = Checkpoint {
        version: 1,
        network: network_anchor(),
        mw_height: 6,
        mw_header_hash: [7; 32],
        mw_state_root: parts.root(),
        mw_cumulative_work: 1,
        previous_checkpoint: [0; 32],
    };

    // The owner, who now also knows k, opens the same commitment to far more.
    let forged_value = value + 1_000_000;
    let forged_blinding = blinding - Scalar::from(forged_value - value) * k.invert();
    assert_eq!(
        broken.commit(forged_value, &forged_blinding),
        commitment,
        "binding really is broken"
    );

    let mut state = RecoveryState::activate(checkpoint.clone(), parts.clone(), broken).unwrap();
    let forged = ClaimedOutput {
        commitment,
        entry,
        value: forged_value,
        blinding: forged_blinding.to_bytes(),
        salt,
        proof: proof.clone(),
    };
    let claim =
        RecoveryClaim::build(&mut owner.clone(), checkpoint.id(), vec![forged], [3; 32]).unwrap();
    let e = state.apply(&claim).unwrap_err().to_string();
    assert!(e.contains("recovery commitment mismatch"), "{e}");

    let honest = ClaimedOutput {
        commitment,
        entry,
        value,
        blinding: blinding.to_bytes(),
        salt,
        proof,
    };

    // The supply recorded in the checkpoint caps what can come back.
    let mut capped_parts = parts.clone();
    capped_parts.supply = value - 1;
    let mut capped_cp = checkpoint.clone();
    capped_cp.mw_state_root = capped_parts.root();
    let mut capped = RecoveryState::activate(capped_cp.clone(), capped_parts, broken).unwrap();
    let over = RecoveryClaim::build(
        &mut owner.clone(),
        capped_cp.id(),
        vec![honest.clone()],
        [3; 32],
    )
    .unwrap();
    let e = capped.apply(&over).unwrap_err().to_string();
    assert!(e.contains("exceed"), "{e}");

    let good =
        RecoveryClaim::build(&mut owner.clone(), checkpoint.id(), vec![honest], [3; 32]).unwrap();
    assert_eq!(state.apply(&good).unwrap(), value);

    // Mismatched parts cannot activate a checkpoint.
    let mut wrong = parts;
    wrong.supply += 1;
    assert!(RecoveryState::activate(checkpoint, wrong, broken).is_err());
}

/// The anchoring tool against a live node and a Midstate node: checkpoint,
/// Commit, confirmations, stored evidence, verification, tamper detection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anchoring_round_trip_with_a_live_node() {
    let (ms_addr, _mock) = start_mock_midstate().await;
    let dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::new(
        dir.path().join("node"),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
    );
    config.mine_to = Some(WalletKeys::random().address());
    config.mining_threads = 1;
    config.min_block_interval = Duration::from_millis(50);
    let (node, handle) = Node::new(config).await.unwrap();
    tokio::spawn(node.run());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mw_addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(midwimble::rpc::serve_on(handle.clone(), listener));
    let deadline = Instant::now() + Duration::from_secs(60);
    while handle.state().height < 12 {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let store = dir.path().join("anchors.jsonl");
    let store2 = store.clone();
    tokio::task::spawn_blocking(move || {
        let (mw, ms) = (
            RpcClient::new(mw_addr.clone()),
            RpcClient::new(ms_addr.clone()),
        );
        mine_midstate_block(&ms_addr);
        mine_midstate_block(&ms_addr);
        // Midstate keeps producing blocks while the tool waits.
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let producer = {
            let (stop, addr) = (stop.clone(), ms_addr.clone());
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(200));
                    mine_midstate_block(&addr);
                }
            })
        };
        let first = anchor_once(&mw, &ms, &store2, 5, 3, 0, Duration::from_secs(60)).unwrap();
        let second = anchor_once(&mw, &ms, &store2, 2, 3, 0, Duration::from_secs(60)).unwrap();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        producer.join().unwrap();
        assert_eq!(
            second.checkpoint.previous_checkpoint,
            first.checkpoint.id(),
            "checkpoints are chained"
        );
        assert!(second.checkpoint.mw_height > first.checkpoint.mw_height);

        let results = verify_records(&mw, &store2, 3, 0).unwrap();
        assert_eq!(results.len(), 2);
        assert!(
            results.iter().all(|(_, r)| r.is_ok()),
            "{:?}",
            results
                .iter()
                .map(|(i, r)| (i, r.as_ref().err().map(|e| e.to_string())))
                .collect::<Vec<_>>()
        );

        // Tampering with a stored checkpoint is caught.
        let text = std::fs::read_to_string(&store2).unwrap();
        let mut records: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        records[0]["checkpoint"]["mw_cumulative_work"] = serde_json::json!(1);
        std::fs::write(
            &store2,
            records
                .iter()
                .map(|r| r.to_string() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let results = verify_records(&mw, &store2, 3, 0).unwrap();
        assert!(results[0].1.is_err());
        assert!(results[1].1.is_ok());
    })
    .await
    .unwrap();
    let _ = store;
}
