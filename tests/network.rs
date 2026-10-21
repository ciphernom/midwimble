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
        Self::start_tuned(mine_to, peers, pace, reuse, |config| {
            if let Some(bytes) = batch_bytes {
                config.batch_response_bytes = bytes;
            }
        })
        .await
    }

    async fn start_tuned(
        mine_to: Option<StealthAddress>,
        peers: Vec<String>,
        pace: Duration,
        reuse: Option<std::sync::Arc<tempfile::TempDir>>,
        tune: impl FnOnce(&mut NodeConfig),
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
        tune(&mut config);
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

/// A node that takes longer to verify a header chunk than its peers get to go
/// quiet still syncs: verifying is its own work, not a silent peer. It used
/// to time out partway through every chunk and start the same chunk again,
/// forever, which is what a one-core seed did on the testnet.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_verifier_still_syncs() {
    let miner = WalletKeys::random();
    let a = TestNode::start_with(Some(miner.address()), vec![], Duration::ZERO, None).await;
    wait_until("A to mine 40 blocks", 120, || a.height() > 40).await;
    a.handle.set_mining(None);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let tip = a.tip();

    // D needs about 4 s to verify A's headers, and drops a quiet peer after 2.
    let peers = vec![a.dial_addr().await];
    let d = TestNode::start_tuned(None, peers, Duration::from_millis(250), None, |config| {
        config.sync_timeout = Duration::from_secs(2);
        config.header_verify_delay = Duration::from_millis(100);
    })
    .await;
    wait_until("D to sync", 60, || d.tip() == tip).await;
    let stats = d.stats();
    assert_eq!(stats.sessions, 1, "the session never timed out: {stats:?}");
    assert!(stats.header_chunks_verified >= 1, "{stats:?}");
    d.handle.state().verify_supply().unwrap();

    d.stop().await;
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
                                Message::StateInfo { height: s.height, depth: s.depth, weight: s.weight(), mw_midstate: s.mw_midstate }
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

/// Anchor gossip is checked cheaply on the event loop and verified off it.
/// Records weaker than this node requires are ignored without hashing any
/// proof of work and without blaming the sender (another node may accept
/// them); a record whose evidence is forged gets its sender banned.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_anchor_gossip_gets_the_sender_banned() {
    use midwimble::anchor::AnchorRecord;
    use midwimble::core::anchor::{
        AnchoredItem, Checkpoint, HeaderLink, MidstateInclusion, CHECKPOINT_VERSION,
    };
    use midwimble::core::types::{hash, hash_concat, network_anchor};
    use midwimble::network::{Message, Network, NetworkEvent};

    /// Free to make: the fold is right, every claimed target carries work,
    /// and only hashing the made-up proofs of work refutes them.
    fn forged(i: u64, confirmations: usize) -> AnchorRecord {
        let checkpoint = Checkpoint {
            version: CHECKPOINT_VERSION,
            network: network_anchor(),
            mw_height: 1_000 + i,
            mw_header_hash: hash(&i.to_le_bytes()),
            mw_state_root: [0; 32],
            mw_cumulative_work: 0,
            previous_checkpoint: [0; 32],
        };
        let id = checkpoint.id();
        let pre = hash(b"pre");
        let mut target = [0xffu8; 32];
        target[0] = 0;
        let link = |post: [u8; 32]| HeaderLink {
            post_tx_midstate: post,
            state_root: [0; 32],
            timestamp: 0,
            target,
            nonce: 0,
            final_hash: [0; 32],
        };
        AnchorRecord {
            checkpoint,
            checkpoint_id: hex::encode(id),
            posted_at_midstate_height: 0,
            evidence: Some(MidstateInclusion {
                midstate_height: 0,
                kind: AnchoredItem::Commit,
                pre_item_midstate: pre,
                items_after: vec![],
                prev_header_hash: [0; 32],
                block: link(hash_concat(&pre, &id)),
                confirmations: vec![link([1; 32]); confirmations],
            }),
            mw_header: None,
        }
    }

    let a = TestNode::start_tuned(None, vec![], Duration::ZERO, None, |config| {
        config.finality.anchor_depth = 8;
        config.finality.min_work = 1;
    })
    .await;
    let addr = a.dial_addr().await;

    let mut net = Network::new(
        libp2p::identity::Keypair::generate_ed25519(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![addr.parse().unwrap()],
        Default::default(),
    )
    .await
    .unwrap();
    let me = net.local_peer_id().to_string();
    let (to_send, mut outbox) = tokio::sync::mpsc::unbounded_channel::<Message>();
    let attacker = tokio::spawn(async move {
        let mut victim = None;
        loop {
            tokio::select! {
                event = net.next_event() => match event {
                    NetworkEvent::PeerConnected(peer, _) => victim = Some(peer),
                    NetworkEvent::MessageReceived { channel: Some(ch), .. } => {
                        net.respond(ch, Message::Pong { nonce: 0 })
                    }
                    _ => {}
                },
                Some(message) = outbox.recv(), if victim.is_some() => {
                    net.send(victim.unwrap(), message)
                }
            }
        }
    });
    wait_until("the attacker to connect", 20, || {
        a.handle.info().peers.contains(&me)
    })
    .await;

    // Too few confirmations for this node: ignored, sender not blamed.
    to_send
        .send(Message::Anchors((0..64).map(|i| forged(i, 3)).collect()))
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        a.handle.info().peers.contains(&me),
        "weak evidence is not a ban"
    );
    assert!(a.handle.anchors().await.unwrap().is_empty());

    // Deep enough, but forged: banned, and nothing kept.
    to_send
        .send(Message::Anchors(
            (0..64).map(|i| forged(100 + i, 7)).collect(),
        ))
        .unwrap();
    wait_until("the forger to be banned", 30, || {
        !a.handle.info().peers.contains(&me)
    })
    .await;
    let t = Instant::now();
    assert!(a.handle.anchors().await.unwrap().is_empty());
    assert!(
        t.elapsed() < Duration::from_secs(1),
        "the node stayed responsive"
    );
    assert_eq!(a.handle.info().anchors_known, 0);

    attacker.abort();
    a.stop().await;
}

/// How a lying peer answers the sync requests its claim draws.
#[derive(Clone)]
enum Lie {
    /// An acknowledgement, whatever was asked: the review's stall.
    Acks,
    /// No headers at all.
    NoHeaders,
    /// The honest chain's headers, which weigh far less than it claims.
    HonestHeaders(NodeHandle),
    /// Nothing: header requests are held unanswered.
    Silence,
}

/// A peer that dials `target` and claims the heaviest chain there can be,
/// every 50 ms, answering as `lie` says. Returns its peer id.
async fn start_liar(target: String, lie: Lie) -> String {
    use midwimble::network::{Message, Network, NetworkEvent};
    let mut net = Network::new(
        libp2p::identity::Keypair::generate_ed25519(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![target.parse().unwrap()],
        Default::default(),
    )
    .await
    .unwrap();
    let id = net.local_peer_id().to_string();
    let claim = Message::StateInfo {
        height: 1_000_000,
        depth: u128::MAX,
        weight: u128::MAX,
        mw_midstate: [0; 32],
    };
    tokio::spawn(async move {
        let mut victim = None;
        let mut held = Vec::new();
        let mut tick = tokio::time::interval(Duration::from_millis(50));
        loop {
            tokio::select! {
                event = net.next_event() => match event {
                    NetworkEvent::PeerConnected(peer, _) => victim = Some(peer),
                    NetworkEvent::MessageReceived { message, channel: Some(channel), .. } => {
                        let reply = match (&lie, message) {
                            (_, Message::GetState) => Some(claim.clone()),
                            (Lie::NoHeaders, Message::GetHeaders { start_height, .. }) => {
                                Some(Message::Headers { start_height, headers: vec![] })
                            }
                            (Lie::HonestHeaders(source), Message::GetHeaders { start_height, count }) => {
                                Some(Message::Headers {
                                    start_height,
                                    headers: source.storage().load_headers(start_height, count.min(5000)).unwrap(),
                                })
                            }
                            (Lie::Silence, Message::GetHeaders { .. }) => None,
                            _ => Some(Message::Pong { nonce: 0 }),
                        };
                        match reply {
                            Some(reply) => net.respond(channel, reply),
                            None => held.push(channel),
                        }
                    }
                    _ => {}
                },
                _ = tick.tick() => {
                    if let Some(victim) = victim {
                        net.send(victim, claim.clone());
                    }
                }
            }
        }
    });
    id
}

/// The review's stall, and the other ways a peer can claim a heavier chain
/// and not back it. While a session with a liar only fetches headers, the
/// node keeps taking the honest producer's blocks; and every liar is banned:
/// at once for a wrong reply, and after three strikes for no headers,
/// headers lighter than its claim, or silence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peers_that_lie_about_their_chain_neither_stall_the_node_nor_stay() {
    let producer = TestNode::start(Some(WalletKeys::random().address()), vec![]).await;
    let peers = vec![producer.dial_addr().await];
    let follower = TestNode::start_tuned(None, peers, Duration::from_millis(250), None, |config| {
        config.sync_timeout = Duration::from_secs(2);
        config.sync_cooldown = Duration::from_millis(300);
    })
    .await;
    wait_until("the follower to catch up", 60, || {
        producer.height() > 5 && follower.height() + 1 >= producer.height()
    })
    .await;

    let target = follower.dial_addr().await;
    let liars = [
        start_liar(target.clone(), Lie::Acks).await,
        start_liar(target.clone(), Lie::NoHeaders).await,
        start_liar(target.clone(), Lie::HonestHeaders(producer.handle.clone())).await,
        start_liar(target.clone(), Lie::Silence).await,
    ];
    wait_until("the liars to connect", 20, || {
        let peers = follower.handle.info().peers;
        liars.iter().filter(|l| peers.contains(*l)).count() >= 2
    })
    .await;

    // The follower keeps up while they lie.
    let (start, mut worst) = (producer.height(), 0);
    let until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < until {
        worst = worst.max(producer.height().saturating_sub(follower.height()));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(producer.height() >= start + 10, "the producer kept mining");
    assert!(
        worst <= 8,
        "the follower fell {worst} blocks behind the producer"
    );
    assert!(follower.stats().sessions > 0, "the liars were heard");

    // And every one of them is banned.
    producer.handle.set_mining(None);
    wait_until("the liars to be banned", 60, || {
        let peers = follower.handle.info().peers;
        liars.iter().all(|l| !peers.contains(l))
    })
    .await;
    wait_until("the follower to reach the producer's tip", 30, || {
        follower.tip() == producer.tip()
    })
    .await;

    follower.stop().await;
    producer.stop().await;
}

/// What a browser wallet does (`web-wallet/`): dial the node over
/// WebRTC-direct, then talk the light protocol. Browsers speak nothing else,
/// and the node used to ban them on sight for it.
#[cfg(feature = "webrtc")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn browser_wallets_reach_a_node_over_webrtc() {
    use futures::StreamExt;
    use libp2p::core::muxing::StreamMuxerBox;
    use libp2p::{PeerId, StreamProtocol, Transport};
    use midwimble::network::light_protocol::{
        read_response_raw, write_request_raw, LightRequest, LIGHT_PROTOCOL,
    };

    let keys = WalletKeys::random();
    let node = TestNode::start(Some(keys.address()), vec![]).await;
    wait_until("a few blocks", 60, || node.height() > 3).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    let (addr, peer) = loop {
        let info = node.handle.info();
        if let Some(a) = info.listen_addrs.iter().find(|a| a.contains("/certhash/")) {
            break (
                format!("{a}/p2p/{}", info.peer_id),
                info.peer_id.parse::<PeerId>().unwrap(),
            );
        }
        assert!(Instant::now() < deadline, "no WebRTC listener");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    // The data dir keeps the certificate, so the address survives a restart.
    assert!(node.dir.path().join("webrtc_cert.pem").exists());

    let cert = libp2p_webrtc::tokio::Certificate::generate(&mut rand::rngs::OsRng).unwrap();
    let mut browser = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_other_transport(|key| {
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                libp2p_webrtc::tokio::Transport::new(key.clone(), cert)
                    .map(|(p, c), _| (p, StreamMuxerBox::new(c))),
            )
        })
        .unwrap()
        .with_behaviour(|_| libp2p_stream::Behaviour::new())
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    let mut control = browser.behaviour().new_control();
    // rust-libp2p's WebRTC transport dials from its listening socket.
    browser
        .listen_on("/ip4/127.0.0.1/udp/0/webrtc-direct".parse().unwrap())
        .unwrap();
    browser
        .dial(addr.parse::<libp2p::Multiaddr>().unwrap())
        .unwrap();
    tokio::spawn(async move {
        loop {
            browser.select_next_some().await;
        }
    });

    async fn ask(
        control: &mut libp2p_stream::Control,
        peer: PeerId,
        protocol: StreamProtocol,
        req: &LightRequest,
    ) -> midwimble::network::light_protocol::LightResponse {
        let mut s = control.open_stream(peer, protocol).await.unwrap();
        write_request_raw(&mut s, req).await.unwrap();
        read_response_raw(&mut s).await.unwrap()
    }

    // Asked twice, a second apart: a banned client would be gone by then.
    for _ in 0..2 {
        let r = tokio::time::timeout(
            Duration::from_secs(20),
            ask(&mut control, peer, LIGHT_PROTOCOL, &LightRequest::GetState),
        )
        .await
        .expect("the node answers a light client");
        assert!(r.ok, "{:?}", r.error);
        assert!(r.data.unwrap()["height"].as_u64().unwrap() > 3);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    // Blocks come in bulk, as a wallet scanning the chain asks for them.
    let r = ask(
        &mut control,
        peer,
        LIGHT_PROTOCOL,
        &LightRequest::GetBlocks {
            start_height: 0,
            count: 3,
        },
    )
    .await;
    let data = r.data.expect("blocks");
    let blocks: Vec<midwimble::core::Batch> =
        bincode::deserialize(&hex::decode(data["blocks_hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(blocks.len(), 3);
    assert_eq!(
        blocks[0].extension.final_hash,
        midwimble::core::Batch::genesis().extension.final_hash
    );
    node.stop().await;
}

/// A node keeps its `--peer`s: one that is down when the node starts, or that
/// restarts later, is redialled until it is back. Each failed dial used to
/// erase the address, and the startup dial was the only one, so a node
/// started while its seed was restarting never dialled the seed again (on the
/// testnet, the seed ended up with no peers and mined a branch of its own).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_redials_its_peer_until_it_is_back() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let miner = WalletKeys::random();
    let start_seed = |reuse: Option<std::sync::Arc<tempfile::TempDir>>| {
        TestNode::start_tuned(
            Some(miner.address()),
            vec![],
            Duration::from_millis(250),
            reuse,
            move |config| config.listen = format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap(),
        )
    };
    let seed = start_seed(None).await;
    let (seed_addr, seed_id) = (seed.dial_addr().await, seed.handle.info().peer_id);
    wait_until("the seed to mine", 60, || seed.height() >= 3).await;
    let dir = seed.dir.clone();
    seed.stop().await;

    // The follower starts while its seed is down.
    let follower = TestNode::start(None, vec![seed_addr]).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(follower.handle.info().peers.is_empty());

    let seed = start_seed(Some(dir)).await;
    wait_until("the follower to reach its seed", 30, || {
        follower.handle.info().peers.contains(&seed_id)
    })
    .await;
    wait_until("the follower to sync", 60, || follower.height() >= 3).await;

    // The seed restarts: the follower sees it go, and dials it again.
    let dir = seed.dir.clone();
    seed.stop().await;
    wait_until("the follower to see its seed go", 30, || {
        !follower.handle.info().peers.contains(&seed_id)
    })
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let seed = start_seed(Some(dir)).await;
    wait_until("the follower to reach its seed again", 30, || {
        follower.handle.info().peers.contains(&seed_id)
    })
    .await;
    let height = seed.height() + 2;
    wait_until("the follower to follow its seed", 60, || {
        follower.height() >= height
    })
    .await;

    follower.stop().await;
    seed.stop().await;
}

/// A node of another network that shares our transports (a midstate node,
/// say: same machines, same code) is dropped as soon as it identifies, and
/// banned for a day, once; its redials are refused, and it never counts as a
/// peer. Midwimble peers are not affected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn foreign_peers_are_dropped_once_and_kept_out() {
    use futures::StreamExt;
    use libp2p::swarm::SwarmEvent;
    use libp2p::{identify, noise, tcp, yamux};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let node = TestNode::start(Some(WalletKeys::random().address()), vec![]).await;
    let target: libp2p::Multiaddr = node.dial_addr().await.parse().unwrap();
    let friend = TestNode::start(None, vec![node.dial_addr().await]).await;
    let friend_id = friend.handle.info().peer_id;

    // Midstate's identify, and none of midwimble's protocols.
    let mut foreign = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|key| {
            identify::Behaviour::new(identify::Config::new(
                "/midstate/id/1.0.0".to_string(),
                key.public(),
            ))
        })
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    let foreign_id = foreign.local_peer_id().to_string();
    let node_id: libp2p::PeerId = node.handle.info().peer_id.parse().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = connections.clone();
    let dialler = tokio::spawn(async move {
        // It keeps dialling, as a midstate node holding our address does.
        let mut tick = tokio::time::interval(Duration::from_millis(300));
        loop {
            tokio::select! {
                event = foreign.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { .. } = event {
                        counted.fetch_add(1, Ordering::SeqCst);
                    }
                }
                _ = tick.tick() => {
                    if !foreign.is_connected(&node_id) {
                        let _ = foreign.dial(target.clone());
                    }
                }
            }
        }
    });

    let banned_for = |node: &TestNode| {
        let banned = node.handle.info().banned;
        let mine: Vec<_> = banned.iter().filter(|b| b.peer == foreign_id).collect();
        assert!(
            mine.len() <= 1,
            "one ban, not one per failed request: {banned:?}"
        );
        mine.first().map(|b| (b.reason.clone(), b.seconds_left))
    };
    wait_until("the foreign peer to be banned", 20, || {
        banned_for(&node).is_some()
    })
    .await;
    let (reason, left) = banned_for(&node).unwrap();
    assert_eq!(reason, "speaks none of our protocols");
    assert!(left.unwrap() > 23 * 3600, "banned for a day: {left:?}");

    // It keeps knocking, and is refused: never a peer.
    let after_ban = connections.load(Ordering::SeqCst);
    let until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < until {
        assert!(!node.handle.info().peers.contains(&foreign_id));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        connections.load(Ordering::SeqCst) > after_ban,
        "it kept dialling (and the node kept refusing it)"
    );
    assert!(banned_for(&node).is_some());
    // The midwimble peer stays.
    assert!(node.handle.info().peers.contains(&friend_id));
    assert!(node
        .handle
        .info()
        .banned
        .iter()
        .all(|b| b.peer != friend_id));

    dialler.abort();
    friend.stop().await;
    node.stop().await;
}

/// Bans end. A peer banned for misbehaving is let back in when its ban is
/// over, and banned for twice as long if it misbehaves again. Bans used to
/// last as long as the node ran, so one mistaken ban of an honest peer, the
/// seed everyone syncs from say, split the network for good.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bans_end_and_grow_for_repeat_offenders() {
    use midwimble::network::{Message, Network, NetworkEvent};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let producer = TestNode::start(Some(WalletKeys::random().address()), vec![]).await;
    let follower = TestNode::start_tuned(
        None,
        vec![producer.dial_addr().await],
        Duration::from_millis(250),
        None,
        |config| {
            config.ban_duration = Duration::from_secs(3);
            config.sync_cooldown = Duration::from_millis(300);
        },
    )
    .await;
    wait_until("the follower to catch up", 60, || {
        producer.height() > 3 && follower.height() + 1 >= producer.height()
    })
    .await;

    // A peer that claims the heaviest chain and answers the follower's
    // header request with an acknowledgement, which is banned at once. It
    // dials the follower again whenever it is not connected.
    let target: libp2p::Multiaddr = follower.dial_addr().await.parse().unwrap();
    let mut net = Network::new(
        libp2p::identity::Keypair::generate_ed25519(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
        Default::default(),
    )
    .await
    .unwrap();
    let liar = net.local_peer_id().to_string();
    let asked = Arc::new(AtomicUsize::new(0));
    let heard = asked.clone();
    let task = tokio::spawn(async move {
        let claim = Message::StateInfo {
            height: 1_000_000,
            depth: u128::MAX,
            weight: u128::MAX,
            mw_midstate: [0; 32],
        };
        let mut victim = None;
        let mut tick = tokio::time::interval(Duration::from_millis(200));
        loop {
            tokio::select! {
                event = net.next_event() => match event {
                    NetworkEvent::PeerConnected(peer, _) => victim = Some(peer),
                    NetworkEvent::PeerDisconnected(_) => victim = None,
                    NetworkEvent::MessageReceived { message, channel: Some(channel), .. } => {
                        let reply = match message {
                            Message::GetState => {
                                heard.fetch_add(1, Ordering::SeqCst);
                                claim.clone()
                            }
                            _ => Message::Pong { nonce: 0 },
                        };
                        net.respond(channel, reply);
                    }
                    _ => {}
                },
                _ = tick.tick() => match victim {
                    Some(v) => net.send(v, claim.clone()),
                    None => net.dial_trusted(target.clone()),
                },
            }
        }
    });

    let ban_of = |node: &TestNode| {
        node.handle
            .info()
            .banned
            .into_iter()
            .find(|b| b.peer == liar)
    };
    wait_until("the liar to be banned", 30, || ban_of(&follower).is_some()).await;
    let ban = ban_of(&follower).unwrap();
    assert_eq!(ban.reason, "answered a sync request with something else");
    assert!(ban.seconds_left.unwrap() <= 3, "{ban:?}");

    // While banned it is refused, however often it dials.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let during = asked.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(ban_of(&follower).is_some());
    assert_eq!(
        asked.load(Ordering::SeqCst),
        during,
        "a banned peer was let in"
    );

    // Then the ban ends and it is heard again...
    wait_until("the liar to be heard again", 30, || {
        asked.load(Ordering::SeqCst) > during
    })
    .await;
    // ...and, lying again, banned for twice as long.
    wait_until("the liar to be banned again", 30, || {
        ban_of(&follower).is_some_and(|b| b.seconds_left.unwrap() > 3)
    })
    .await;
    assert!(ban_of(&follower).unwrap().seconds_left.unwrap() <= 6);
    // The honest producer was never banned.
    let producer_id = producer.handle.info().peer_id;
    assert!(follower
        .handle
        .info()
        .banned
        .iter()
        .all(|b| b.peer != producer_id));

    task.abort();
    follower.stop().await;
    producer.stop().await;
}

/// A seed that is slow to serve blocks is waited for, not banned. Once a
/// peer's verified headers weigh what it claimed it has backed its claim,
/// and a session that goes quiet after that is paused, not struck. Three
/// such timeouts used to ban the peer for as long as the node ran: on the
/// testnet, that is how nodes could lose the one-core seed they all synced
/// from.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_seed_is_waited_for_not_banned() {
    use midwimble::network::{Message, Network, NetworkEvent, MAX_GETBATCHES_COUNT};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let producer = TestNode::start_with(
        Some(WalletKeys::random().address()),
        vec![],
        Duration::ZERO,
        None,
    )
    .await;
    wait_until("the producer to mine", 60, || producer.height() > 30).await;
    producer.handle.set_mining(None);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let tip = producer.tip();

    let follower =
        TestNode::start_tuned(None, vec![], Duration::from_millis(250), None, |config| {
            config.sync_timeout = Duration::from_secs(2);
            config.sync_cooldown = Duration::from_millis(300);
        })
        .await;

    // The seed serves the producer's chain over a link that answers state
    // and header requests at once, and holds block requests until `serve`.
    let target: libp2p::Multiaddr = follower.dial_addr().await.parse().unwrap();
    let mut net = Network::new(
        libp2p::identity::Keypair::generate_ed25519(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
        Default::default(),
    )
    .await
    .unwrap();
    let seed = net.local_peer_id().to_string();
    let serve = Arc::new(AtomicBool::new(false));
    let serving = serve.clone();
    let source = producer.handle.clone();
    let task = tokio::spawn(async move {
        let info = |source: &NodeHandle| {
            let s = source.state();
            Message::StateInfo {
                height: s.height,
                depth: s.depth,
                weight: s.weight(),
                mw_midstate: s.mw_midstate,
            }
        };
        let (mut victim, mut held) = (None, Vec::new());
        let mut tick = tokio::time::interval(Duration::from_millis(200));
        loop {
            tokio::select! {
                event = net.next_event() => match event {
                    NetworkEvent::PeerConnected(peer, _) => victim = Some(peer),
                    NetworkEvent::PeerDisconnected(_) => victim = None,
                    NetworkEvent::MessageReceived { message, channel: Some(channel), .. } => {
                        let reply = match message {
                            Message::GetState => Some(info(&source)),
                            Message::GetHeaders { start_height, count } => Some(Message::Headers {
                                start_height,
                                headers: source.storage().load_headers(start_height, count.min(5000)).unwrap(),
                            }),
                            Message::GetBatches { start_height, count } if serving.load(Ordering::SeqCst) => {
                                Some(Message::Batches {
                                    start_height,
                                    batches: source
                                        .storage()
                                        .load_batches(start_height, count.min(MAX_GETBATCHES_COUNT), usize::MAX)
                                        .unwrap(),
                                })
                            }
                            Message::GetBatches { .. } => None,
                            _ => Some(Message::Pong { nonce: 0 }),
                        };
                        match reply {
                            Some(reply) => net.respond(channel, reply),
                            None => held.push(channel),
                        }
                    }
                    _ => {}
                },
                _ = tick.tick() => match victim {
                    Some(v) => net.send(v, info(&source)),
                    None => net.dial_trusted(target.clone()),
                },
            }
        }
    });

    wait_until("the seed to connect", 20, || {
        follower.handle.info().peers.contains(&seed)
    })
    .await;
    // Session after session takes its headers and then waits on its blocks
    // until it times out.
    wait_until("several sessions to time out", 60, || {
        follower.stats().sessions >= 4
    })
    .await;
    assert!(
        follower.handle.info().peers.contains(&seed),
        "the slow seed was dropped"
    );
    assert!(follower.handle.info().banned.is_empty());
    assert!(follower.height() < producer.height());

    // When it gets round to the blocks, the follower takes them.
    serve.store(true, Ordering::SeqCst);
    wait_until("the follower to sync from the seed", 60, || {
        follower.tip() == tip
    })
    .await;

    task.abort();
    follower.stop().await;
    producer.stop().await;
}

/// A peer this node dials that hangs up before identifying itself (a midstate
/// node that has banned this node's subnet, a peer that is full) counts as a
/// failed dial, so an unchecked address is not dialled again and again. Its
/// connection opened, so the transport had reported nothing. A peer that
/// identified, and then went, counts as nothing of the kind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_hangs_up_before_identifying_counts_as_a_failed_dial() {
    use futures::StreamExt;
    use libp2p::swarm::{dummy, SwarmEvent};
    use libp2p::{noise, tcp, yamux, Multiaddr};
    use midwimble::network::{Network, NetworkEvent};

    init_logging();
    let mut net = Network::new(
        libp2p::identity::Keypair::generate_ed25519(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
        Default::default(),
    )
    .await
    .unwrap();

    // Accepts a connection and closes it at once, saying nothing.
    let mut refuser = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|_| dummy::Behaviour)
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    refuser
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let refuser_id = *refuser.local_peer_id();
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel::<Multiaddr>();
    let refusing = tokio::spawn(async move {
        let mut addr_tx = Some(addr_tx);
        loop {
            match refuser.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    if let Some(tx) = addr_tx.take() {
                        let _ = tx.send(address);
                    }
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    let _ = refuser.disconnect_peer_id(peer_id);
                }
                _ => {}
            }
        }
    });
    let refuser_addr = addr_rx
        .await
        .unwrap()
        .with(libp2p::multiaddr::Protocol::P2p(refuser_id));

    // A midwimble peer, which identifies, and later goes away.
    let mut friend = Network::new(
        libp2p::identity::Keypair::generate_ed25519(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        vec![],
        Default::default(),
    )
    .await
    .unwrap();
    let friend_id = friend.local_peer_id();
    let friend_addr = loop {
        tokio::select! {
            _ = friend.next_event() => {}
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                if let Some(a) = friend.listen_addrs().into_iter().find(|a| a.to_string().contains("/tcp/")) {
                    break a.with(libp2p::multiaddr::Protocol::P2p(friend_id));
                }
            }
        }
    };
    let befriending = tokio::spawn(async move {
        loop {
            friend.next_event().await;
        }
    });

    net.dial_trusted(refuser_addr.clone());
    net.dial_trusted(friend_addr.clone());
    let mut failed = Vec::new();
    let mut identified = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while failed.is_empty() || !identified {
        let event = tokio::time::timeout_at(deadline, net.next_event())
            .await
            .expect("the refusal to count as a failed dial, and the friend to identify");
        match event {
            NetworkEvent::OutgoingConnectionFailed(a) => failed.push(a),
            NetworkEvent::PeerIdentified { peer, dialled, .. } if peer == friend_id => {
                // Loopback addresses are not routable, so none is kept.
                assert_eq!(dialled, None);
                identified = true;
            }
            _ => {}
        }
    }
    assert_eq!(failed, vec![refuser_addr.to_string()]);

    // The friend goes away: an identified peer's disconnection is not a
    // failed dial.
    befriending.abort();
    let until = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut gone = false;
    while let Ok(event) = tokio::time::timeout_at(until, net.next_event()).await {
        match event {
            NetworkEvent::PeerDisconnected(peer) if peer == friend_id => gone = true,
            NetworkEvent::OutgoingConnectionFailed(a) => {
                assert!(
                    !a.contains(&friend_id.to_string()),
                    "counted against the friend: {a}"
                )
            }
            _ => {}
        }
    }
    assert!(gone, "the friend's going was noticed");
    refusing.abort();
}
