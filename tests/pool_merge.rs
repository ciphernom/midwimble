//! A pool mining midwimble with the same search it runs for midstate, through
//! `/merge/job` and `/merge/found` (`docs/POOL_MERGED_MINING.md`).
//!
//! `cargo test --features fast-mining --test pool_merge`
//!
//! This is the path most hashrate will take, and the pool never touches
//! midwimble's block format: it asks what to commit to, plants that in a
//! coinbase output's salt beside its own score root, and hands back the
//! winning nonce.
#![cfg(feature = "fast-mining")]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use midwimble::core::auxpow::bytes32;
use midwimble::core::bond::{devnet_registration, MinerBond};
use midwimble::core::extension::create_extension;
use midwimble::core::mw::WalletKeys;
use midwimble::core::types::{hash, GENESIS_TARGET};
use midwimble::node::{Node, NodeConfig};
use midwimble::rpc::RpcClient;
use serde_json::{json, Value};
use std::time::Duration;

mod support;
use support::*;

fn hex32(v: &Value) -> [u8; 32] {
    let bytes = hex::decode(v.as_str().expect("hex string")).expect("hex");
    bytes.try_into().expect("32 bytes")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pool_mines_midwimble_with_its_midstate_search() {
    // A midwimble node holding the pool operator's bond. It mines nothing
    // itself: every block here comes from the pool's midstate search.
    let dir = tempfile::tempdir().unwrap();
    let secret = Scalar::from_bytes_mod_order(hash(b"pool operator bond"));
    let mining_key = RistrettoPoint::mul_base(&secret).compress().to_bytes();
    let registration =
        devnet_registration(mining_key, 10_000_000, hash(b"pool bond salt"), &GENESIS_TARGET);
    let bond = MinerBond {
        secret,
        bond_id: registration.bond_id(),
        registration: Some(registration),
    };
    let bond_id = hex::encode(bond.bond_id);
    let mut config = NodeConfig::new(dir.path(), "/ip4/127.0.0.1/tcp/0".parse().unwrap());
    config.mining_bond = Some(bond);
    config.poll_interval = Duration::from_millis(500);
    let (node, handle) = Node::new(config).await.unwrap();
    let _node = tokio::spawn(node.run());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let midwimble_rpc = listener.local_addr().unwrap().to_string();
    tokio::spawn(midwimble::rpc::serve_on(handle.clone(), listener));

    let (midstate_rpc, _mock) = start_mock_midstate().await;
    let payout = WalletKeys::random().address().encode();

    // Everything the pool does is blocking: HTTP, then a proof-of-work search.
    let job_and_result = tokio::task::spawn_blocking(move || {
        let mw = RpcClient::new(midwimble_rpc);
        let ms = RpcClient::new(midstate_rpc);

        // 1. Ask what to commit to, paying the pool's miners by weight.
        let job = mw
            .post(
                "/merge/job",
                &json!({ "payouts": [{ "address": payout, "weight": 1 }] }),
            )
            .expect("/merge/job");
        let commitment = hex32(&job["commitment"]);
        let target = hex32(&job["target"]);

        // 2. Build the midstate coinbase the pool would build, with the
        //    commitment in one output's salt.
        let values = midwimble::merge_mine::decompose_value(REWARD);
        let commit_index = values.len() - 1;
        let coinbase: Vec<Value> = values
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let salt = if i == commit_index {
                    commitment
                } else {
                    hash(&(i as u64).to_le_bytes())
                };
                json!({
                    "address": hex::encode([0x22u8; 32]),
                    "value": v,
                    "salt": hex::encode(salt),
                })
            })
            .collect();
        let tpl = ms
            .post("/block_template", &json!({ "coinbase": coinbase }))
            .expect("/block_template");
        let parent_mining_hash = bytes32(&tpl["mining_midstate"]).unwrap();

        // 3. One search. A share that clears midwimble's target is a block.
        let (nonce, final_hash) = (0u64..)
            .find_map(|nonce| {
                let ext = create_extension(parent_mining_hash, nonce);
                (ext.final_hash < target).then_some((nonce, ext.final_hash))
            })
            .expect("a nonce below the target");

        // A job the node never handed out, and the commitment claimed in the
        // wrong output, are both refused: the node rebuilds the proof itself
        // rather than taking the pool's word for it.
        let stale = mw.post(
            "/merge/found",
            &json!({
                "mining_hash": hex::encode([9u8; 32]),
                "batch_template": tpl["batch_template"],
                "commit_index": commit_index,
                "nonce": nonce,
                "final_hash": hex::encode(final_hash),
            }),
        );
        let wrong_output = mw.post(
            "/merge/found",
            &json!({
                "mining_hash": job["mining_hash"],
                "batch_template": tpl["batch_template"],
                "commit_index": if commit_index == 0 { 1 } else { commit_index - 1 },
                "nonce": nonce,
                "final_hash": hex::encode(final_hash),
            }),
        );

        // 4. Hand it back.
        let found = mw
            .post(
                "/merge/found",
                &json!({
                    "mining_hash": job["mining_hash"],
                    "batch_template": tpl["batch_template"],
                    "commit_index": commit_index,
                    "nonce": nonce,
                    "final_hash": hex::encode(final_hash),
                }),
            )
            .expect("/merge/found");
        (job, found, stale.is_err(), wrong_output.is_err())
    })
    .await
    .unwrap();
    let (job, found, stale_refused, wrong_output_refused) = job_and_result;
    assert!(stale_refused, "a mining hash the node never issued was accepted");
    assert!(
        wrong_output_refused,
        "a commitment claimed in the wrong coinbase output was accepted"
    );

    assert_eq!(found["accepted"], true, "{found}");
    assert_eq!(found["merged_mined"], true, "the block carries its aux proof");
    assert_eq!(found["height"], job["height"]);

    // The node accepted it as its own tip, and it is a merge-mined block
    // signed by the pool's bond, carrying that bond's registration.
    let state = handle.state();
    assert_eq!(state.height, job["height"].as_u64().unwrap() + 1);
    let block = handle.storage().load_batches(1, 1, usize::MAX).unwrap();
    let block = &block[0];
    assert!(block.aux_pow.is_some(), "the block's work lives in midstate");
    assert_eq!(hex::encode(block.miner.as_ref().unwrap().bond_id), bond_id);
    assert_eq!(block.registrations.len(), 1, "block 1 registers the bond");
    assert_eq!(state.bonds.len(), 1);
}
