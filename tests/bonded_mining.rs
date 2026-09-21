//! A bonded producer end to end: its first block registers its own bond,
//! every block is signed, and a second node syncs and validates all of it.
//!
//! `cargo test --features fast-mining --test bonded_mining`
#![cfg(feature = "fast-mining")]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use midwimble::core::bond::{devnet_registration, MinerBond};
use midwimble::core::mw::WalletKeys;
use midwimble::core::types::{hash, GENESIS_TARGET};
use midwimble::node::{Node, NodeConfig, NodeHandle};
use std::time::{Duration, Instant};

struct TestNode {
    handle: NodeHandle,
    _dir: tempfile::TempDir,
    _task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

async fn start(bond: Option<MinerBond>, peers: Vec<String>) -> TestNode {
    let dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::new(dir.path(), "/ip4/127.0.0.1/tcp/0".parse().unwrap());
    config.bootstrap = peers.iter().map(|p| p.parse().unwrap()).collect();
    if let Some(bond) = bond {
        config.mine_to = Some(WalletKeys::random().address());
        config.mining_bond = Some(bond);
    }
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
    let registration =
        devnet_registration(mining_key, 10_000_000, hash(b"integration salt"), &GENESIS_TARGET);
    let bond = MinerBond {
        secret,
        bond_id: registration.bond_id(),
        registration: Some(registration),
    };

    let producer = start(Some(bond.clone()), vec![]).await;
    wait_until("the bonded producer to mine", 90, || producer.height() > 6).await;
    let peer = start(None, vec![producer.dial_addr().await]).await;
    wait_until("the peer to sync", 90, || peer.height() > 6).await;

    // The peer validated every block, registration and signatures included,
    // and arrived at the same bond set.
    assert_eq!(peer.handle.state().bonds[&bond.bond_id].mining_key, mining_key);
    let blocks = peer.handle.storage().load_batches(1, 5, usize::MAX).unwrap();
    assert_eq!(blocks[0].registrations.len(), 1, "block 1 registers its producer's bond");
    assert!(blocks[1..].iter().all(|b| b.registrations.is_empty()));
    for block in &blocks {
        assert_eq!(block.miner.as_ref().expect("signed").bond_id, bond.bond_id);
    }
}
