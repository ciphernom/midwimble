//! Anchored pruning: finality, body pruning, checkpoint sync, reorg floor.
//!
//! `cargo test --features fast-mining --test pruning`

mod support;
use support::*;

use midwimble::anchor::anchor_once;
use midwimble::core::mw::WalletKeys;
use midwimble::finality::FinalityConfig;
use midwimble::node::{Node, NodeConfig, NodeHandle};
use midwimble::rpc::RpcClient;
use std::time::{Duration, Instant};

struct TestNode {
    handle: NodeHandle,
    rpc: String,
    p2p: String,
    _dir: tempfile::TempDir,
}

fn finality() -> FinalityConfig {
    FinalityConfig {
        anchor_depth: 2,
        finality_depth: 5,
        min_work: 0,
        retained_checkpoints: 2,
        prune: true,
    }
}

async fn start(mine: bool, peers: Vec<String>, checkpoint: Option<[u8; 32]>) -> TestNode {
    start_paying(
        mine.then(|| WalletKeys::random().address()),
        peers,
        checkpoint,
    )
    .await
}

async fn start_paying(
    mine_to: Option<midwimble::core::mw::StealthAddress>,
    peers: Vec<String>,
    checkpoint: Option<[u8; 32]>,
) -> TestNode {
    let dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::new(
        dir.path().join("node"),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
    );
    config.bootstrap = peers.iter().map(|p| p.parse().unwrap()).collect();
    if let Some(address) = mine_to {
        config.mine_to = Some(address);
        config.mining_threads = 1;
        config.min_block_interval = Duration::from_millis(40);
    }
    config.poll_interval = Duration::from_millis(300);
    config.finality = finality();
    config.checkpoint = checkpoint;
    config.bootstrap_timeout = Duration::from_secs(60);
    let (node, handle) = Node::new(config).await.unwrap();
    tokio::spawn(node.run());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc = listener.local_addr().unwrap().to_string();
    tokio::spawn(midwimble::rpc::serve_on(handle.clone(), listener));
    let deadline = Instant::now() + Duration::from_secs(10);
    let p2p = loop {
        let info = handle.info();
        if let Some(tcp) = info.listen_addrs.iter().find(|a| a.contains("/tcp/")) {
            break format!("{}/p2p/{}", tcp, info.peer_id);
        }
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    TestNode {
        handle,
        rpc,
        p2p,
        _dir: dir,
    }
}

async fn wait_until(what: &str, secs: u64, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Anchors a checkpoint of `node` in the mock Midstate and hands the record
/// to the node. Returns the checkpoint id and height.
async fn anchor(node: &TestNode, ms_addr: &str, lag: u64) -> ([u8; 32], u64) {
    let (rpc, ms_addr) = (node.rpc.clone(), ms_addr.to_string());
    let store = node._dir.path().join("tool-anchors.jsonl");
    let record = tokio::task::spawn_blocking(move || {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let producer = {
            let (stop, addr) = (stop.clone(), ms_addr.clone());
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(150));
                    mine_midstate_block(&addr);
                }
            })
        };
        let r = anchor_once(
            &RpcClient::new(rpc),
            &RpcClient::new(ms_addr),
            &store,
            lag,
            2,
            0,
            Duration::from_secs(60),
        );
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        producer.join().unwrap();
        r.unwrap()
    })
    .await
    .unwrap();
    let id = record.checkpoint.id();
    let height = record.checkpoint.mw_height;
    node.handle.submit_anchor(record).await.unwrap();
    (id, height)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anchored_checkpoints_finalize_prune_and_bootstrap_new_nodes() {
    let (ms_addr, _mock) = start_mock_midstate().await;
    mine_midstate_block(&ms_addr);
    mine_midstate_block(&ms_addr);

    let a = start(true, vec![], None).await;
    wait_until("A to mine", 60, || a.handle.state().height >= 25).await;
    let (cp_id, cp_height) = anchor(&a, &ms_addr, 3).await;

    // Finalized once the chain is 5 blocks past it; bodies below it pruned.
    wait_until("the checkpoint to finalize", 60, || {
        a.handle.info().finality.floor == cp_height
    })
    .await;
    wait_until("bodies to be pruned", 30, || {
        a.handle.info().finality.pruned_below == cp_height
    })
    .await;
    assert!(
        a.handle.storage().load_batch(1).unwrap().is_none(),
        "old body pruned"
    );
    assert!(
        a.handle.storage().load_batch(cp_height).unwrap().is_some(),
        "live history kept"
    );
    assert!(
        a.handle.storage().load_header(1).unwrap().is_some(),
        "headers kept"
    );
    let fin = RpcClient::new(a.rpc.clone());
    let fin = tokio::task::spawn_blocking(move || fin.get("/finality").unwrap())
        .await
        .unwrap();
    assert_eq!(fin["floor"].as_u64(), Some(cp_height), "{fin}");

    // A pruned node keeps producing and validating blocks.
    let h = a.handle.state().height;
    wait_until("A to keep mining", 60, || a.handle.state().height > h + 3).await;
    a.handle.state().verify_supply().unwrap();

    // Checkpoint verification: D starts from A's snapshot at the checkpoint
    // and follows the chain from there, holding no earlier history.
    let d = start(false, vec![a.p2p.clone()], Some(cp_id)).await;
    let base = d.handle.storage().base().unwrap().expect("snapshot base");
    assert_eq!(base.height, cp_height);
    // No history below the base: no block bodies at all, and only the
    // snapshot's header window (all of it on a chain this short).
    assert!(d.handle.storage().load_batch(0).unwrap().is_none());
    assert!(d
        .handle
        .storage()
        .load_batch(cp_height - 1)
        .unwrap()
        .is_none());
    assert!(d
        .handle
        .storage()
        .load_header(cp_height - 1)
        .unwrap()
        .is_some());
    wait_until("D to catch up", 60, || {
        d.handle.state().height >= a.handle.state().height
            && d.handle.state().height > cp_height + 3
    })
    .await;
    wait_until("D and A to agree", 60, || {
        d.handle.state().header_hash == a.handle.state().header_hash
    })
    .await;
    assert_eq!(d.handle.state().state_root(), a.handle.state().state_root());
    d.handle.state().verify_supply().unwrap();
    assert_eq!(d.handle.info().finality.floor, cp_height);

    // A trusted id nobody anchored fails instead of silently syncing.
    let dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::new(
        dir.path().join("node"),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
    );
    config.bootstrap = vec![a.p2p.parse().unwrap()];
    config.finality = finality();
    config.checkpoint = Some([0x55; 32]);
    config.bootstrap_timeout = Duration::from_secs(3);
    assert!(Node::new(config).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn heavier_chains_cannot_reorganise_below_the_floor() {
    let (ms_addr, _mock) = start_mock_midstate().await;
    mine_midstate_block(&ms_addr);
    mine_midstate_block(&ms_addr);

    // A: anchored and finalized, then stops mining.
    let a = start(true, vec![], None).await;
    wait_until("A to mine", 60, || a.handle.state().height >= 15).await;
    let (_, cp_height) = anchor(&a, &ms_addr, 2).await;
    wait_until("finality", 60, || {
        a.handle.info().finality.floor == cp_height
    })
    .await;
    a.handle.set_mining(None);
    tokio::time::sleep(Duration::from_millis(400)).await;
    let a_tip = a.handle.state().header_hash;
    let a_height = a.handle.state().height;

    // C: an independent, much longer chain from genesis (more work).
    let c = start(true, vec![], None).await;
    wait_until("C to outgrow A", 120, || {
        c.handle.state().height > a_height + 15
    })
    .await;
    c.handle.set_mining(None);

    a.handle.dial(c.p2p.parse().unwrap());
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        a.handle.state().header_hash,
        a_tip,
        "A must not abandon its finalized history"
    );
    assert!(
        a.handle.info().sync_stats.sessions >= 1,
        "A did consider C's chain"
    );
}

/// A wallet whose history the node has pruned still finds its coins, by
/// scanning the unspent-output set instead of block bodies.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallets_restore_from_a_pruned_node() {
    let (ms_addr, _mock) = start_mock_midstate().await;
    mine_midstate_block(&ms_addr);
    mine_midstate_block(&ms_addr);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("w.mww");
    let (wallet, _) = midwimble::wallet::Wallet::create(&path, "pw", 1).unwrap();
    let address = wallet.address();
    drop(wallet);

    let a = start_paying(Some(address), vec![], None).await;
    wait_until("A to mine", 60, || a.handle.state().height >= 25).await;
    let (_, cp_height) = anchor(&a, &ms_addr, 3).await;
    wait_until("pruning", 60, || {
        a.handle.info().finality.pruned_below == cp_height
    })
    .await;
    let expected: u64 = (1..cp_height)
        .map(midwimble::core::types::block_reward)
        .sum();

    let (rpc, path2) = (a.rpc.clone(), path.clone());
    let (found, balance, spendable) = tokio::task::spawn_blocking(move || {
        let client = RpcClient::new(rpc);
        let mut w = midwimble::wallet::Wallet::open(&path2, "pw").unwrap();
        let found = w.sync_from_node(&client).unwrap();
        let tip = client.height().unwrap();
        let b = w.balance(tip);
        (found, b.spendable + b.immature, b.spendable)
    })
    .await
    .unwrap();

    assert!(found > 20, "found {found} coinbase outputs");
    assert!(
        balance >= expected,
        "wallet balance {balance} covers the mined rewards {expected}"
    );
    assert!(spendable > 0, "matured rewards are spendable");
}
