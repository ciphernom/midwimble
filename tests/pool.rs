//! A pool and two auditing miners against a real node.
//!
//! `cargo test --features fast-mining --test pool`

use midwimble::core::mw::{scan_output, StealthAddress, WalletKeys};
use midwimble::node::{Node, NodeConfig, NodeHandle};
use midwimble::pool::{
    run_pool, run_pool_miner, PoolConfig, PoolMinerConfig, PoolMinerStats, PoolStats,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

async fn wait_until(what: &str, secs: u64, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Value paid to `keys` by coinbases on the node's chain.
fn coinbase_income(node: &NodeHandle, keys: &WalletKeys) -> u64 {
    let state = node.state();
    let mut total = 0;
    for h in 1..state.height {
        let b = node.storage().load_batch(h).unwrap().unwrap();
        for o in &b.coinbase.as_ref().unwrap().outputs.outputs {
            if let Some(owned) = scan_output(keys, o) {
                total += owned.value;
            }
        }
    }
    total
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_pays_auditing_miners() {
    if let Ok(level) = std::env::var("MIDWIMBLE_TEST_LOG") {
        let _ = tracing_subscriber::fmt()
            .with_max_level(level.parse().unwrap_or(tracing::Level::INFO))
            .with_test_writer()
            .try_init();
    }
    let dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::new(
        dir.path().join("node"),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
    );
    config.poll_interval = Duration::from_millis(500);
    let (node, handle) = Node::new(config).await.unwrap();
    tokio::spawn(node.run());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc = listener.local_addr().unwrap().to_string();
    tokio::spawn(midwimble::rpc::serve_on(handle.clone(), listener));

    let operator = WalletKeys::random();
    let stratum_port = free_port();
    let api_port = free_port();
    let pool_stats = Arc::new(PoolStats::default());
    let cfg = PoolConfig {
        pool_address: operator.address(),
        node_rpc: rpc,
        stratum_bind: format!("127.0.0.1:{stratum_port}").parse().unwrap(),
        api_bind: format!("127.0.0.1:{api_port}").parse().unwrap(),
        api_public: None,
        fee_percent: 2.0,
        share_bits: 2,
        data_dir: dir.path().join("pool"),
        poll_interval: Duration::from_millis(200),
    };
    tokio::spawn(run_pool(cfg, pool_stats.clone()));
    tokio::time::sleep(Duration::from_millis(500)).await;

    let alice = WalletKeys::random();
    let bob = WalletKeys::random();
    let stop = Arc::new(AtomicBool::new(false));
    let mut miners = Vec::new();
    for (name, keys) in [("alice", &alice), ("bob", &bob)] {
        let stats = Arc::new(PoolMinerStats::default());
        let cfg = PoolMinerConfig {
            pool: format!("stratum+tcp://127.0.0.1:{stratum_port}"),
            address: keys.address(),
            worker: name.to_string(),
            threads: 1,
        };
        tokio::spawn(run_pool_miner(cfg, stop.clone(), stats.clone()));
        miners.push(stats);
    }

    wait_until("the pool to find blocks", 120, || {
        handle.state().height >= 10
    })
    .await;
    wait_until("both miners to be paid", 120, || {
        coinbase_income(&handle, &alice) > 0 && coinbase_income(&handle, &bob) > 0
    })
    .await;
    stop.store(true, Ordering::Relaxed);

    for m in &miners {
        assert!(m.audits_passed.load(Ordering::Relaxed) >= 2, "{m:?}");
        assert_eq!(m.audits_failed.load(Ordering::Relaxed), 0, "{m:?}");
        assert!(m.shares_accepted.load(Ordering::Relaxed) > 0, "{m:?}");
    }
    assert!(pool_stats.blocks_found.load(Ordering::Relaxed) >= 5);

    // Blocks commit to the pool's score table and pay the operator's fee.
    let state = handle.state();
    let committed = (1..state.height)
        .filter(|h| {
            handle
                .storage()
                .load_batch(*h)
                .unwrap()
                .unwrap()
                .coinbase
                .unwrap()
                .extra
                != [0u8; 32]
        })
        .count();
    assert!(committed > 0);
    assert!(coinbase_income(&handle, &operator) > 0);
    state.verify_supply().unwrap();

    // The pool's public stats agree.
    let stats = midwimble::rpc::RpcClient::new(format!("127.0.0.1:{api_port}"))
        .get("/pool/stats")
        .unwrap();
    assert!(stats["blocks_found"].as_u64().unwrap() >= 5, "{stats}");
    let _ = StealthAddress::decode(&alice.address().encode()).unwrap();
}
