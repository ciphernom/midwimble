//! Merged mining against a stand-in midstate node.
//!
//! `cargo test --features fast-mining --test merge_mining`
//!
//! The mock's block types and header fold are copied from midstate's source
//! (`core/types.rs`: `Batch`, `Transaction`, `InputReveal`, `OutputData`,
//! `CoinbaseOutput`, `Batch::header`, `compute_header_hash`) with the same
//! serde derives, so the JSON it serves and the mining hashes it computes are
//! midstate's, not a second copy of midwimble's reconstruction.

use midwimble::core::mw::WalletKeys;
use midwimble::merge_mine::{run, MergeMineConfig, MergeStats};
use midwimble::node::{Node, NodeConfig, NodeHandle};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

mod support;
use support::*;

struct Midwimble {
    handle: NodeHandle,
    rpc: String,
    p2p: String,
    _dir: tempfile::TempDir,
}

async fn start_midwimble(peers: Vec<String>) -> Midwimble {
    let dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::new(dir.path(), "/ip4/127.0.0.1/tcp/0".parse().unwrap());
    config.bootstrap = peers.iter().map(|p| p.parse().unwrap()).collect();
    config.poll_interval = Duration::from_millis(500);
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
    Midwimble {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_search_mines_both_chains() {
    if let Ok(level) = std::env::var("MIDWIMBLE_TEST_LOG") {
        let _ = tracing_subscriber::fmt()
            .with_max_level(level.parse().unwrap_or(tracing::Level::INFO))
            .with_test_writer()
            .try_init();
    }
    let (midstate_rpc, mock) = start_mock_midstate().await;
    let a = start_midwimble(vec![]).await;
    let keys = WalletKeys::random();
    let log_dir = tempfile::tempdir().unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(MergeStats::default());
    let cfg = MergeMineConfig {
        midstate_rpc,
        midwimble_rpc: a.rpc.clone(),
        midstate_address: [7; 32],
        midwimble_address: keys.address(),
        threads: 1,
        coinbase_log: log_dir.path().join("coinbase.jsonl"),
        refresh: Duration::from_secs(5),
        anchor_store: Some(log_dir.path().join("anchors.jsonl")),
        anchor_depth: 2,
    };
    let miner = {
        let (stop, stats) = (stop.clone(), stats.clone());
        std::thread::spawn(move || run(cfg, stop, stats))
    };

    wait_until("three merged-mined midwimble blocks", 120, || {
        a.handle.state().height >= 4
    })
    .await;
    wait_until("midstate blocks too", 60, || {
        mock.lock().unwrap().accepted >= 3
    })
    .await;
    wait_until("merged-mining anchors to be recorded", 60, || {
        stats.anchors_recorded.load(Ordering::Relaxed) >= 2
    })
    .await;
    stop.store(true, Ordering::Relaxed);
    miner.join().unwrap().unwrap();
    eprintln!(
        "rounds={} midstate={} midwimble={} rejected={} mock_accepted={}",
        stats.rounds.load(Ordering::Relaxed),
        stats.midstate_blocks.load(Ordering::Relaxed),
        stats.midwimble_blocks.load(Ordering::Relaxed),
        stats.rejected.load(Ordering::Relaxed),
        mock.lock().unwrap().accepted
    );

    // Every midwimble block after genesis carries a midstate parent.
    let state = a.handle.state();
    for h in 1..state.height {
        let b = a.handle.storage().load_batch(h).unwrap().unwrap();
        assert!(b.aux_pow.is_some(), "block {h} was merge-mined");
    }
    state.verify_supply().unwrap();
    assert!(stats.rejected.load(Ordering::Relaxed) == 0);

    // The midstate coinbase salts were logged for the midstate wallet.
    let log = std::fs::read_to_string(log_dir.path().join("coinbase.jsonl")).unwrap();
    assert!(log.lines().count() >= 3);
    assert!(log.contains("\"accepted\":true"));

    // Blocks anchored by merged mining verify against Midstate evidence and
    // this node's chain.
    let (rpc, store) = (a.rpc.clone(), log_dir.path().join("anchors.jsonl"));
    let results = tokio::task::spawn_blocking(move || {
        midwimble::anchor::verify_records(&midwimble::rpc::RpcClient::new(rpc), &store, 2, 0)
            .unwrap()
    })
    .await
    .unwrap();
    assert!(results.len() >= 2);
    for (id, r) in &results {
        assert!(
            r.is_ok(),
            "{id}: {:?}",
            r.as_ref().err().map(|e| e.to_string())
        );
    }

    // A second node syncs the merged-mined chain headers-first.
    let b = start_midwimble(vec![a.p2p.clone()]).await;
    wait_until("B to sync", 60, || {
        b.handle.state().header_hash == a.handle.state().header_hash
    })
    .await;
    assert!(b.handle.info().sync_stats.header_chunks_verified >= 1);
}
