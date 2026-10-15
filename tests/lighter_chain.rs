//! A peer offering a chain deeper than ours but lighter. Its announcements
//! say what its chain weighs, so we never fetch it, however often it is
//! announced; ours says what ours weighs, so the peer moves onto it.
//!
//! `cargo test --features fast-mining --test lighter_chain`
#![cfg(feature = "fast-mining")]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use midwimble::core::bond::{
    devnet_registrations, est_midstate_height, MinerBond, MIN_REMAINING_BOND_LOCK,
};
use midwimble::core::mw::WalletKeys;
use midwimble::core::state::{apply_batch, current_timestamp};
use midwimble::core::template::build_template_bonded;
use midwimble::core::types::{hash, GENESIS_TARGET, GENESIS_TIMESTAMP};
use midwimble::core::{Batch, State};
use midwimble::node::{Node, NodeConfig, NodeHandle};
use midwimble::storage::Storage;
use std::time::{Duration, Instant};

/// Bonds eligible both at the chain's old timestamps and now, registered
/// together: they share one stand-in midstate, whose headers the first block
/// relays.
fn bonds(seeds: &[&[u8]]) -> Vec<MinerBond> {
    let until = est_midstate_height(current_timestamp()) + MIN_REMAINING_BOND_LOCK + 10_000;
    let secrets: Vec<Scalar> = seeds
        .iter()
        .map(|seed| Scalar::from_bytes_mod_order(hash(seed)))
        .collect();
    let specs: Vec<([u8; 32], u64, [u8; 32])> = seeds
        .iter()
        .zip(&secrets)
        .map(|(seed, secret)| {
            let mining_key = RistrettoPoint::mul_base(secret).compress().to_bytes();
            (mining_key, until, hash(seed))
        })
        .collect();
    let (registrations, headers) = devnet_registrations(&specs, &GENESIS_TARGET);
    registrations
        .into_iter()
        .zip(secrets)
        .map(|(registration, secret)| MinerBond {
            secret,
            bond_id: registration.bond_id(),
            registration: Some(registration),
            midstate: Some(headers.clone()),
            co_bonds: vec![],
        })
        .collect()
}

/// Mines a block on `state` signed by `bond` (registering it if need be),
/// stamped on schedule so that every block carries the same work.
fn mine(state: &mut State, ts: &mut Vec<u64>, bond: &MinerBond) -> Batch {
    let to = WalletKeys::random().address();
    let on_schedule = GENESIS_TIMESTAMP + 60 * state.height;
    let (template, _) =
        build_template_bonded(state, ts, &[], &[(to, 1)], [0; 32], Some(on_schedule), Some(bond))
            .unwrap();
    let block = template.mine_blocking();
    apply_batch(state, &block, ts).unwrap();
    ts.push(block.timestamp);
    block
}

/// A data directory holding genesis and then `blocks`, which end at `state`.
/// The blocks are applied again on the way in, for what each one changed.
fn stored(blocks: &[Batch], state: &State) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::open(dir.path()).unwrap();
    let mut replay = State::genesis();
    apply_batch(&mut replay, Batch::genesis(), &[]).unwrap();
    let genesis_effects = std::slice::from_ref(&replay.effects);
    storage
        .commit_chain(0, std::slice::from_ref(Batch::genesis()), genesis_effects, &replay)
        .unwrap();
    let (mut ts, mut effects) = (vec![Batch::genesis().timestamp], Vec::new());
    for block in blocks {
        apply_batch(&mut replay, block, &ts).unwrap();
        ts.push(block.timestamp);
        effects.push(replay.effects.clone());
    }
    assert_eq!(replay.state_root(), state.state_root());
    storage.commit_chain(1, blocks, &effects, &replay).unwrap();
    dir
}

struct TestNode {
    handle: NodeHandle,
    _task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl TestNode {
    async fn start(dir: &tempfile::TempDir, bond: Option<MinerBond>, peers: Vec<String>) -> Self {
        let mut config = NodeConfig::new(dir.path(), "/ip4/127.0.0.1/tcp/0".parse().unwrap());
        config.bootstrap = peers.iter().map(|p| p.parse().unwrap()).collect();
        config.mining_bond = bond;
        config.mining_threads = 1;
        config.poll_interval = Duration::from_millis(500);
        config.min_block_interval = Duration::from_millis(250);
        let (node, handle) = Node::new(config).await.unwrap();
        let task = tokio::spawn(node.run());
        Self { handle, _task: task }
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

    fn tip(&self) -> [u8; 32] {
        self.handle.info().state.header_hash
    }

    fn stats(&self) -> midwimble::sync::SyncStats {
        self.handle.info().sync_stats
    }
}

async fn wait_until(what: &str, secs: u64, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deeper_but_lighter_chain_is_never_fetched_and_its_holder_moves() {
    let mut both = bonds(&[b"bond a", b"bond b"]);
    let (a, b) = (both.remove(0), both.remove(0));

    // A start both chains share, registering both bonds: each may then sign
    // 8 of any 16 blocks in full (fast-mining builds: a 16-block window).
    let mut shared = State::genesis();
    apply_batch(&mut shared, Batch::genesis(), &[]).unwrap();
    let mut shared_ts = vec![Batch::genesis().timestamp];
    let prefix = vec![
        mine(&mut shared, &mut shared_ts, &a),
        mine(&mut shared, &mut shared_ts, &b),
    ];

    // Ours: 8 blocks, the bonds in turn, every one within its share.
    let (mut ours, mut ts, mut ours_blocks) = (shared.clone(), shared_ts.clone(), prefix.clone());
    for i in 0..8 {
        let signer = if i % 2 == 0 { &a } else { &b };
        ours_blocks.push(mine(&mut ours, &mut ts, signer));
    }
    // Theirs: 12 blocks, all by bond a, so its last 5 are past its share.
    let (mut theirs, mut ts, mut theirs_blocks) = (shared.clone(), shared_ts, prefix);
    for _ in 0..12 {
        theirs_blocks.push(mine(&mut theirs, &mut ts, &a));
    }
    assert!(theirs.depth > ours.depth, "theirs has more work");
    assert!(theirs.weight() < ours.weight(), "but weighs less");

    let (our_dir, their_dir) = (stored(&ours_blocks, &ours), stored(&theirs_blocks, &theirs));
    // Their node can later mine with bond b, which has room in its share.
    let peer = TestNode::start(&their_dir, Some(b), vec![]).await;
    let node = TestNode::start(&our_dir, None, vec![peer.dial_addr().await]).await;

    // The peer hears that ours weighs more and moves onto it. Their chain,
    // announced again and again until then and for six polls after, starts
    // no session on our node: the announcement says it weighs less.
    wait_until("the peer to move onto our chain", 60, || {
        peer.tip() == ours.header_hash
    })
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(node.stats().sessions, 0, "{:?}", node.stats());
    assert_eq!(node.tip(), ours.header_hash);

    // The peer mines on with bond b, and the node follows on the one chain.
    peer.handle.set_mining(Some(WalletKeys::random().address()));
    wait_until("the node to follow the peer", 60, || {
        node.handle.state().height > ours.height && node.tip() == peer.tip()
    })
    .await;
    assert!(node.handle.state().weight() > ours.weight());
    let third = node.handle.storage().load_batch(3).unwrap();
    assert_eq!(
        third.as_ref(),
        Some(&ours_blocks[2]),
        "theirs was never adopted"
    );

    node.handle.shutdown();
    peer.handle.shutdown();
}
