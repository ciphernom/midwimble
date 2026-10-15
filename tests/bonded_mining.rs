//! A bonded producer end to end: its first block registers its own bond,
//! every block is signed, and a second node syncs and validates all of it.
//!
//! `cargo test --features fast-mining --test bonded_mining`
#![cfg(feature = "fast-mining")]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use midwimble::core::bond::{
    devnet_registration, est_midstate_height, MinerBond, MIN_REMAINING_BOND_LOCK,
};
use midwimble::core::state::current_timestamp;
use midwimble::core::mw::WalletKeys;
use midwimble::core::types::{hash, GENESIS_TARGET};
use midwimble::node::{Node, NodeConfig, NodeHandle};
use std::time::{Duration, Instant};

mod support;
use support::{mine_midstate_block, start_mock_midstate_at};

struct TestNode {
    handle: NodeHandle,
    _dir: tempfile::TempDir,
    _task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

async fn start(bond: Option<MinerBond>, peers: Vec<String>) -> TestNode {
    let mine = bond.is_some();
    start_full(bond, mine, peers, None).await
}

async fn start_full(
    bond: Option<MinerBond>,
    mine: bool,
    peers: Vec<String>,
    midstate_rpc: Option<String>,
) -> TestNode {
    let dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::new(dir.path(), "/ip4/127.0.0.1/tcp/0".parse().unwrap());
    config.bootstrap = peers.iter().map(|p| p.parse().unwrap()).collect();
    if mine {
        config.mine_to = Some(WalletKeys::random().address());
    }
    config.mining_bond = bond;
    config.midstate_rpc = midstate_rpc;
    config.relay_poll = Duration::from_millis(200);
    config.mining_threads = 1;
    config.poll_interval = Duration::from_millis(500);
    config.min_block_interval = Duration::from_millis(250);
    let (node, handle) = Node::new(config).await.unwrap();
    let task = tokio::spawn(node.run());
    TestNode { handle, _dir: dir, _task: task }
}

impl TestNode {
    async fn dial_addr(&self) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let info = self.handle.info();
            if let Some(tcp) = info.listen_addrs.iter().find(|a| a.contains("/tcp/")) {
                return format!("{}/p2p/{}", tcp, info.peer_id);
            }
            assert!(Instant::now() < deadline, "node never started listening");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn height(&self) -> u64 {
        self.handle.info().state.height
    }
}

async fn wait_until(what: &str, secs: u64, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bonded_producer_mines_and_a_peer_validates_every_block() {
    let secret = Scalar::from_bytes_mod_order(hash(b"integration bond"));
    let mining_key = RistrettoPoint::mul_base(&secret).compress().to_bytes();
    // Test bonds must be within the registration horizon (one Midstate year),
    // while remaining eligible throughout the test. A fixed height of
    // 10_000_000 exceeds that horizon and prevents block template creation.
    let bonded_until = est_midstate_height(current_timestamp())
        + MIN_REMAINING_BOND_LOCK
        + 10_000;
    let (registration, headers) = devnet_registration(
        mining_key, bonded_until, hash(b"integration salt"), &GENESIS_TARGET,
    );
    let bond = MinerBond {
        secret,
        bond_id: registration.bond_id(),
        registration: Some(registration),
        midstate: Some(headers),
        co_bonds: vec![],
    };

    let producer = start(Some(bond.clone()), vec![]).await;
    wait_until("the bonded producer to mine", 90, || producer.height() > 6).await;
    let peer = start(None, vec![producer.dial_addr().await]).await;
    wait_until("the peer to sync", 90, || peer.height() > 6).await;

    // The peer validated every block, registration and signatures included,
    // and arrived at the same bond set.
    assert_eq!(
        peer.handle
            .state()
            .bonds
            .get(&bond.bond_id)
            .unwrap()
            .mining_key,
        mining_key
    );
    let blocks = peer
        .handle
        .storage()
        .load_batches(1, 5, usize::MAX)
        .unwrap();
    assert_eq!(
        blocks[0].registrations.len(),
        1,
        "block 1 registers its producer's bond"
    );
    assert!(blocks[1..].iter().all(|b| b.registrations.is_empty()));
    for block in &blocks {
        assert_eq!(block.miner.as_ref().expect("signed").bond_id, bond.bond_id);
    }

    // The operator's view over RPC agrees, and it is what the rehearsal
    // script checks against a real network: /bonds lists the bond as
    // eligible, /miners shows who signed and who registered each block.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(midwimble::rpc::serve_on(peer.handle.clone(), listener));
    let id = hex::encode(bond.bond_id);
    let (bonds, miners) = tokio::task::spawn_blocking(move || {
        let client = midwimble::rpc::RpcClient::new(addr);
        (client.get("/bonds").unwrap(), client.get("/miners/1/3").unwrap())
    })
    .await
    .unwrap();
    assert!(bonds["bonds"]
        .as_array()
        .unwrap()
        .iter()
        .any(|b| b["bond_id"] == id.as_str() && b["eligible_now"] == true));
    let listed = miners["blocks"].as_array().unwrap();
    assert_eq!(listed[0]["registrations"][0], id.as_str());
    assert!(listed.iter().all(|b| b["bond_id"] == id.as_str()));
}

/// A producer whose node follows a midstate node relays midstate's headers
/// in the blocks it mines, catching up and then keeping up, and a peer that
/// validates those blocks ends with the same relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_producer_relays_the_headers_its_midstate_node_serves() {
    use midwimble::core::relay::RelayEntry;
    let root = RelayEntry::root();
    let (ms, _mock) = start_mock_midstate_at(root.height + 1, root.hash).await;
    let mine = |n: usize| {
        let ms = ms.clone();
        tokio::task::spawn_blocking(move || {
            for _ in 0..n {
                mine_midstate_block(&ms);
            }
        })
    };
    mine(5).await.unwrap();

    let producer = start_full(None, true, vec![], Some(ms.clone())).await;
    let relay_tip = |n: &TestNode| n.handle.state().relay.tip().height;
    wait_until("the producer to relay midstate's headers", 60, || {
        relay_tip(&producer) == root.height + 5
    })
    .await;
    mine(3).await.unwrap();
    wait_until("the producer to keep up", 60, || {
        relay_tip(&producer) == root.height + 8
    })
    .await;
    let relayed = producer
        .handle
        .storage()
        .load_batches(1, producer.height(), usize::MAX)
        .unwrap()
        .iter()
        .filter_map(|b| b.relay.as_ref())
        .map(|r| r.headers.len())
        .sum::<usize>();
    assert_eq!(relayed, 8, "each header relayed once");

    let peer = start_full(None, false, vec![producer.dial_addr().await], None).await;
    wait_until("the peer to sync", 60, || {
        peer.height() >= producer.height() && relay_tip(&peer) == root.height + 8
    })
    .await;
    assert_eq!(
        peer.handle.state().relay.commitment(),
        producer.handle.state().relay.commitment()
    );
}
