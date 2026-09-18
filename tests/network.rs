//! Multi-node tests over real libp2p connections on localhost.
//!
//! `cargo test --features fast-mining --test network`

use midwimble::core::mw::{scan_output, StealthAddress, WalletKeys};
use midwimble::core::types::{block_reward, COINBASE_MATURITY};
use midwimble::node::{Node, NodeConfig, NodeHandle};
use midwimble::wallet::Wallet;
use std::time::{Duration, Instant};

struct TestNode {
    handle: NodeHandle,
    dir: std::sync::Arc<tempfile::TempDir>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

fn init_logging() {
    if let Ok(level) = std::env::var("MIDWIMBLE_TEST_LOG") {
        let level = level.parse().unwrap_or(tracing::Level::INFO);
        let _ = tracing_subscriber::fmt()
            .with_max_level(level)
            .with_test_writer()
            .try_init();
    }
}

impl TestNode {
    async fn start(mine_to: Option<StealthAddress>, peers: Vec<String>) -> Self {
        Self::start_with(mine_to, peers, Duration::from_millis(250), None).await
    }

    async fn start_with(
        mine_to: Option<StealthAddress>,
        peers: Vec<String>,
        pace: Duration,
        reuse: Option<std::sync::Arc<tempfile::TempDir>>,
    ) -> Self {
        Self::start_full(mine_to, peers, pace, reuse, None).await
    }

    async fn start_full(
        mine_to: Option<StealthAddress>,
        peers: Vec<String>,
        pace: Duration,
        reuse: Option<std::sync::Arc<tempfile::TempDir>>,
        batch_bytes: Option<usize>,
    ) -> Self {
        init_logging();
        let dir = reuse.unwrap_or_else(|| std::sync::Arc::new(tempfile::tempdir().unwrap()));
        let mut config = NodeConfig::new(dir.path(), "/ip4/127.0.0.1/tcp/0".parse().unwrap());
        config.bootstrap = peers.iter().map(|p| p.parse().unwrap()).collect();
        config.mine_to = mine_to;
        config.mining_threads = 1;
        config.poll_interval = Duration::from_millis(500);
        config.stem_timeout = Duration::from_secs(1);
        config.min_block_interval = pace;
        if let Some(bytes) = batch_bytes {
            config.batch_response_bytes = bytes;
        }
        let (node, handle) = Node::new(config).await.unwrap();
        let task = tokio::spawn(node.run());
        Self { handle, dir, task }
    }

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

    fn tip(&self) -> [u8; 32] {
        self.handle.info().state.header_hash
    }

    fn stats(&self) -> midwimble::sync::SyncStats {
        self.handle.info().sync_stats
    }

    async fn stop(self) {
        self.handle.shutdown();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
    }
}

async fn wait_until(what: &str, secs: u64, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Value owned by `keys` on the node's chain, scanning every stored block.
fn owned_value(node: &TestNode, keys: &WalletKeys) -> u64 {
    let storage = node.handle.storage();
    let state = node.handle.state();
    let mut total = 0;
    let mut start = 0;
    while start < state.height {
        let batches = storage.load_batches(start, 64, usize::MAX).unwrap();
        if batches.is_empty() {
            break;
        }
        start += batches.len() as u64;
        for b in &batches {
            let cb = b.coinbase.iter().flat_map(|c| c.outputs.outputs.iter());
            for o in b.body.outputs().chain(cb) {
                if state.utxos.contains_key(&o.commitment) {
                    if let Some(owned) = scan_output(keys, o) {
                        total += owned.value;
                    }
                }
            }
        }
    }
    total
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_sync_and_settle_a_payment() {
    let wallet_dir = tempfile::tempdir().unwrap();
    let (mut alice, _) = Wallet::create(&wallet_dir.path().join("alice.mww"), "pw", 1).unwrap();
    let bob = WalletKeys::random();

    let a = TestNode::start(Some(alice.address()), vec![]).await;
    let b = TestNode::start(None, vec![a.dial_addr().await]).await;

    // A mines past coinbase maturity; B follows over the network.
    let wanted = COINBASE_MATURITY + 3;
    wait_until("A to mine", 60, || a.height() > wanted).await;
    wait_until("B to sync", 60, || {
        b.height() >= wanted && b.handle.info().peers.len() == 1
    })
    .await;

    // Alice scans A's chain and pays Bob through B (Dandelion++ stem to A).
    let tip = a.height();
    let storage = a.handle.storage().clone();
    alice
        .sync_with(tip, |s, n| storage.load_batches(s, n, usize::MAX))
        .unwrap();
    assert!(alice.balance(tip).spendable >= block_reward(1));
    let amount = 5_000_000;
    let tx = alice
        .build_send(&bob.address(), amount, None, b.height())
        .unwrap();
    b.handle.submit_transaction(tx).await.unwrap();

    // It gets mined and both nodes see Bob's money.
    wait_until("payment to confirm on A", 60, || {
        owned_value(&a, &bob) == amount
    })
    .await;
    wait_until("payment to reach B", 60, || owned_value(&b, &bob) == amount).await;

    // Both nodes converge and pass the MimbleWimble supply audit.
    wait_until("tips to converge", 60, || {
        a.tip() == b.tip() || b.height() > a.height()
    })
    .await;
    a.handle.state().verify_supply().unwrap();
    b.handle.state().verify_supply().unwrap();

    b.stop().await;
    a.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_reorgs_onto_a_heavier_chain() {
    let miner = WalletKeys::random();
    let a = TestNode::start(Some(miner.address()), vec![]).await;
    let c = TestNode::start(Some(miner.address()), vec![]).await;

    // Two isolated chains from the same genesis.
    wait_until("A to mine", 60, || a.height() >= 4).await;
    a.handle.set_mining(None);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let a_height = a.height();
    let a_tip = a.tip();

    wait_until("C to outgrow A", 60, || c.height() >= a_height + 3).await;
    c.handle.set_mining(None);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_ne!(c.tip(), a_tip);

    // Connect them: A must abandon its chain for C's.
    a.handle.dial(c.dial_addr().await.parse().unwrap());
    wait_until("A to reorg onto C", 60, || a.tip() == c.tip()).await;
    assert_eq!(a.height(), c.height());
    let state = a.handle.state();
    state.verify_supply().unwrap();
    // Only C's blocks remain on A's disk.
    let stored = a.handle.storage().load_batch(1).unwrap().unwrap();
    assert_eq!(Some(stored), c.handle.storage().load_batch(1).unwrap());

    a.stop().await;
    c.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_joiner_syncs_headers_first_and_survives_restart() {
    let miner = WalletKeys::random();
    let a = TestNode::start_with(Some(miner.address()), vec![], Duration::ZERO, None).await;
    // More than one 64-block GetBatches chunk.
    wait_until("A to mine 80 blocks", 120, || a.height() > 80).await;
    a.handle.set_mining(None);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (height, tip) = (a.height(), a.tip());

    let d = TestNode::start(None, vec![a.dial_addr().await]).await;
    wait_until("D to sync", 120, || d.tip() == tip).await;
    assert!(d.stats().header_chunks_verified >= 1);
    assert!(d.stats().batch_chunks_applied >= 2, "{:?}", d.stats());
    let (sa, sd) = (a.handle.state(), d.handle.state());
    assert_eq!(sd.height, height);
    assert_eq!(sd.state_root(), sa.state_root());
    assert_eq!(sd.supply, sa.supply);
    sd.verify_supply().unwrap();

    // Restart D from its data directory: same chain, no network needed.
    let dir = d.dir.clone();
    d.stop().await;
    let d2 = TestNode::start_with(None, vec![], Duration::ZERO, Some(dir)).await;
    assert_eq!(d2.height(), height);
    assert_eq!(d2.tip(), tip);
    assert_eq!(d2.handle.state().state_root(), sa.state_root());

    d2.stop().await;
    a.stop().await;
}

/// A sync interrupted by a restart continues from the headers it already
/// verified instead of fetching and verifying them again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_sync_resumes_from_verified_headers() {
    let miner = WalletKeys::random();
    // A answers every block request with a single block, so the download is slow.
    let a =
        TestNode::start_full(Some(miner.address()), vec![], Duration::ZERO, None, Some(1)).await;
    wait_until("A to mine 300 blocks", 120, || a.height() > 300).await;
    a.handle.set_mining(None);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let tip = a.tip();

    let d = TestNode::start(None, vec![a.dial_addr().await]).await;
    wait_until("D to be part-way through", 120, || d.height() > 40).await;
    let first_stats = d.stats();
    assert_eq!(first_stats.resumed, 0);
    assert!(first_stats.header_chunks_verified >= 1);
    let dir = d.dir.clone();
    d.stop().await;

    let d2 = TestNode::start_with(None, vec![a.dial_addr().await], Duration::ZERO, Some(dir)).await;
    assert!(
        d2.height() > 40,
        "blocks committed before the restart are kept"
    );
    wait_until("D to finish after restart", 120, || d2.tip() == tip).await;
    let stats = d2.stats();
    assert_eq!(stats.resumed, 1, "{stats:?}");
    assert_eq!(
        stats.header_chunks_verified, 0,
        "headers were not verified again: {stats:?}"
    );
    d2.handle.state().verify_supply().unwrap();

    d2.stop().await;
    a.stop().await;
}

/// Blocks are fetched from every peer that has them, out of order, with
/// size-truncated responses re-requested.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocks_download_from_several_peers() {
    let miner = WalletKeys::random();
    let limit = Some(8_000); // a few blocks per response
    let a = TestNode::start_full(Some(miner.address()), vec![], Duration::ZERO, None, limit).await;
    wait_until("A to mine 200 blocks", 120, || a.height() > 200).await;
    a.handle.set_mining(None);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let tip = a.tip();
    let b =
        TestNode::start_full(None, vec![a.dial_addr().await], Duration::ZERO, None, limit).await;
    wait_until("B to sync", 120, || b.tip() == tip).await;

    let c = TestNode::start(None, vec![a.dial_addr().await, b.dial_addr().await]).await;
    wait_until("C to sync", 120, || c.tip() == tip).await;
    let stats = c.stats();
    assert_eq!(
        stats.batch_sources, 2,
        "both peers served blocks: {stats:?}"
    );
    assert!(
        stats.batch_chunks_applied > 200 / 64,
        "responses were truncated and refetched: {stats:?}"
    );
    assert_eq!(c.handle.state().state_root(), a.handle.state().state_root());

    c.stop().await;
    b.stop().await;
    a.stop().await;
}

/// A reorg whose fork point is older than the in-memory state cache derives
/// the fork state from on-disk undo records.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deep_reorg_uses_undo_records() {
    let miner = WalletKeys::random();
    let a = TestNode::start_with(Some(miner.address()), vec![], Duration::ZERO, None).await;
    let c = TestNode::start_with(Some(miner.address()), vec![], Duration::ZERO, None).await;
    wait_until("A to mine 80 blocks", 120, || a.height() > 80).await;
    a.handle.set_mining(None);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let a_height = a.height();
    wait_until("C to outgrow A", 120, || c.height() > a_height + 5).await;
    c.handle.set_mining(None);
    tokio::time::sleep(Duration::from_millis(500)).await;

    a.handle.dial(c.dial_addr().await.parse().unwrap());
    wait_until("A to reorg onto C", 120, || a.tip() == c.tip()).await;
    let state = a.handle.state();
    assert_eq!(state.state_root(), c.handle.state().state_root());
    state.verify_supply().unwrap();
    // The on-disk state agrees too (reload it from the tables).
    let reloaded = a.handle.storage().load_state().unwrap().unwrap();
    assert_eq!(reloaded.state_root(), state.state_root());

    a.stop().await;
    c.stop().await;
}

/// A hostile peer: serves the honest node's (valid) headers but corrupts every
/// block it sends. Returns its dial address, peer id and a counter of block
/// requests it received.
async fn start_forger(
    source: NodeHandle,
) -> (
    String,
    libp2p::PeerId,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    use midwimble::network::{Message, Network, NetworkEvent};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();
    let mut net = Network::new(
        keypair,
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
        Default::default(),
    )
    .await
    .unwrap();
    let requests = std::sync::Arc::new(AtomicUsize::new(0));
    let counter = requests.clone();
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut addr_tx = Some(addr_tx);
        loop {
            tokio::select! {
                event = net.next_event() => {
                    if let NetworkEvent::MessageReceived { message, channel: Some(channel), .. } = event {
                        let reply = match message {
                            Message::GetState => {
                                let s = source.state();
                                Message::StateInfo { height: s.height, depth: s.depth, mw_midstate: s.mw_midstate }
                            }
                            Message::GetHeaders { start_height, count } => Message::Headers {
                                start_height,
                                headers: source.storage().load_headers(start_height, count.min(5000)).unwrap(),
                            },
                            Message::GetBatches { start_height, count } => {
                                counter.fetch_add(1, Ordering::SeqCst);
                                let mut batches = source.storage().load_batches(start_height, count.min(64), usize::MAX).unwrap();
                                for b in &mut batches {
                                    // Same header and proof of work, different contents:
                                    // the range-proof binding no longer verifies.
                                    if let Some(cb) = b.coinbase.as_mut() {
                                        cb.outputs.outputs[0].payload[0] ^= 1;
                                    }
                                }
                                Message::Batches { start_height, batches }
                            }
                            _ => Message::Pong { nonce: 0 },
                        };
                        net.respond(channel, reply);
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
            if addr_tx.is_some() {
                if let Some(tcp) = net
                    .listen_addrs()
                    .iter()
                    .find(|a| a.to_string().contains("/tcp/"))
                {
                    let full = format!("{}/p2p/{}", tcp, net.local_peer_id());
                    let _ = addr_tx.take().unwrap().send(full);
                }
            }
        }
    });
    (addr_rx.await.unwrap(), peer_id, requests)
}

/// The only peer offers a heavier chain with valid headers but forged
/// blocks: nothing is adopted, the peer is banned, and an honest peer later
/// brings the node up to date.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_blocks_from_the_sync_peer_are_rejected() {
    use std::sync::atomic::Ordering;
    let miner = WalletKeys::random();
    let a = TestNode::start_with(Some(miner.address()), vec![], Duration::ZERO, None).await;
    wait_until("A to mine", 60, || a.height() > 30).await;
    a.handle.set_mining(None);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (forger_addr, forger_id, requests) = start_forger(a.handle.clone()).await;
    let d = TestNode::start(None, vec![forger_addr]).await;
    wait_until("D to reject the forger", 60, || {
        let info = d.handle.info();
        requests.load(Ordering::SeqCst) > 0
            && !info.syncing
            && !info.peers.contains(&forger_id.to_string())
    })
    .await;
    assert_eq!(d.height(), 1, "no forged block was adopted");
    assert!(
        d.stats().header_chunks_verified >= 1,
        "the forger's headers were genuinely valid"
    );

    d.handle.dial(a.dial_addr().await.parse().unwrap());
    wait_until("D to sync from the honest peer", 60, || d.tip() == a.tip()).await;
    d.handle.state().verify_supply().unwrap();

    d.stop().await;
    a.stop().await;
}

/// A second peer joins mid-sync and serves forged blocks: the node discards
/// them, drops that peer, refetches from the honest one and finishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_blocks_from_a_helper_peer_are_routed_around() {
    use std::sync::atomic::Ordering;
    let miner = WalletKeys::random();
    // Honest but slow: one block per response.
    let a =
        TestNode::start_full(Some(miner.address()), vec![], Duration::ZERO, None, Some(1)).await;
    wait_until("A to mine", 120, || a.height() > 600).await;
    a.handle.set_mining(None);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (forger_addr, forger_id, requests) = start_forger(a.handle.clone()).await;

    let d = TestNode::start(None, vec![a.dial_addr().await]).await;
    wait_until("D to start syncing from A", 30, || d.handle.info().syncing).await;
    d.handle.dial(forger_addr.parse().unwrap());

    wait_until("D to finish", 120, || d.tip() == a.tip()).await;
    assert!(
        requests.load(Ordering::SeqCst) > 0,
        "the forger was asked for blocks"
    );
    assert!(
        !d.handle.info().peers.contains(&forger_id.to_string()),
        "the forger was dropped"
    );
    assert_eq!(d.handle.state().state_root(), a.handle.state().state_root());
    d.handle.state().verify_supply().unwrap();

    d.stop().await;
    a.stop().await;
}
