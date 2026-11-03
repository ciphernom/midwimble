//! Orphaning over-cap blocks end to end (`core::orphan`): while the tip is a
//! run of another producer's over-cap blocks, a node builds on the block
//! before the run. The block it builds there replaces the run on every node,
//! without a sync session, and carries the run's transactions again.
//!
//! The chains here are stamped on schedule from genesis, so every block
//! carries the genesis target's work and an over-cap block's sliver is
//! smaller than a full-weight block. Their bonds have lapsed by the time the
//! nodes build on them, so the nodes' own blocks are unsigned, which a
//! fast-mining build counts in full: a stand-in for a bond under its cap
//! (`core::bonded_tests` has the signed case, on the production cap).
//!
//! `cargo test --features fast-mining --test orphan_over_cap`
#![cfg(feature = "fast-mining")]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use midwimble::core::bond::{
    devnet_registrations, est_midstate_height, MinerBond, MAX_BOND_HORIZON,
};
use midwimble::core::mw::{
    build_transaction, scan_output, Payment, Spendable, StealthAddress, Transaction, WalletKeys,
};
use midwimble::core::orphan::{COMPATIBLE_ORPHAN_DEPTH, MAX_ORPHAN_DEPTH};
use midwimble::core::state::apply_batch;
use midwimble::core::template::build_template_bonded;
use midwimble::core::types::{hash, Batch, BlockEffects, State, GENESIS_TARGET, GENESIS_TIMESTAMP};
use midwimble::node::{Node, NodeConfig, NodeHandle};
use midwimble::rpc::RpcClient;
use midwimble::storage::Storage;
use midwimble::sync::INITIAL_STEP_BACK;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Bonds registered together, locked well past the timestamps of a chain
/// mined on schedule from genesis.
fn bonds(seeds: &[&[u8]]) -> Vec<MinerBond> {
    let until = est_midstate_height(GENESIS_TIMESTAMP) + MAX_BOND_HORIZON / 2;
    let secrets: Vec<Scalar> = seeds
        .iter()
        .map(|s| Scalar::from_bytes_mod_order(hash(s)))
        .collect();
    let specs: Vec<([u8; 32], u64, [u8; 32])> = seeds
        .iter()
        .zip(&secrets)
        .map(|(s, k)| {
            (
                RistrettoPoint::mul_base(k).compress().to_bytes(),
                until,
                hash(s),
            )
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

/// A chain built in memory, block by block, as a node would apply it.
#[derive(Clone)]
struct Chain {
    blocks: Vec<Batch>,
    effects: Vec<Arc<BlockEffects>>,
    state: State,
    timestamps: Vec<u64>,
}

impl Chain {
    fn genesis() -> Self {
        let mut state = State::genesis();
        apply_batch(&mut state, Batch::genesis(), &[]).unwrap();
        Chain {
            blocks: vec![Batch::genesis().clone()],
            effects: vec![state.effects.clone()],
            state,
            timestamps: vec![Batch::genesis().timestamp],
        }
    }

    /// The next block, signed by `bond` and paying `to`, on schedule.
    fn next(&self, bond: &MinerBond, txs: &[Transaction], to: StealthAddress) -> Batch {
        build_template_bonded(
            &self.state,
            &self.timestamps,
            txs,
            &[(to, 1)],
            [0; 32],
            Some(GENESIS_TIMESTAMP + 60 * self.state.height),
            Some(bond),
        )
        .unwrap()
        .0
        .mine_blocking()
    }

    fn push(&mut self, block: Batch) {
        apply_batch(&mut self.state, &block, &self.timestamps).unwrap();
        self.timestamps.push(block.timestamp);
        self.effects.push(self.state.effects.clone());
        self.blocks.push(block);
    }

    fn extend(&mut self, bond: &MinerBond) -> Batch {
        let block = self.next(bond, &[], WalletKeys::random().address());
        self.push(block.clone());
        block
    }

    /// A node data directory holding the chain.
    fn store(&self) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        Storage::open(dir.path())
            .unwrap()
            .commit_chain(0, &self.blocks, &self.effects, &self.state)
            .unwrap();
        dir
    }
}

/// The chain both tests start from. `big` registers in block 1 (paying
/// `wallet`), `small` in block 2, and `big` signs blocks 3 to 9: with two
/// bonds registered each may sign 8 of the 16-block window at full weight,
/// so block 9 is `big`'s last before its cap.
fn prefix(big: &MinerBond, small: &MinerBond, wallet: &WalletKeys) -> Chain {
    let mut chain = Chain::genesis();
    let first = chain.next(big, &[], wallet.address());
    chain.push(first);
    chain.extend(small);
    for _ in 3..=9 {
        chain.extend(big);
    }
    chain
}

struct TestNode {
    handle: NodeHandle,
    rpc: String,
    _dir: tempfile::TempDir,
    _task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

/// A node on `dir` signing with `bond`, not mining until told to. It polls
/// its peers only once a minute, so a peer hears of a new block from the
/// block itself.
async fn start(
    dir: tempfile::TempDir,
    bond: Option<MinerBond>,
    peers: Vec<String>,
    orphan_over_cap: bool,
) -> TestNode {
    start_with(dir, bond, peers, |config| {
        config.orphan_over_cap = orphan_over_cap
    })
    .await
}

/// [`start`], with `configure` given the last word on the node's config.
async fn start_with(
    dir: tempfile::TempDir,
    bond: Option<MinerBond>,
    peers: Vec<String>,
    configure: impl FnOnce(&mut NodeConfig),
) -> TestNode {
    let mut config = NodeConfig::new(dir.path(), "/ip4/127.0.0.1/tcp/0".parse().unwrap());
    config.bootstrap = peers.iter().map(|p| p.parse().unwrap()).collect();
    config.mining_bond = bond;
    config.mining_threads = 1;
    config.poll_interval = Duration::from_secs(60);
    config.min_block_interval = Duration::from_millis(250);
    configure(&mut config);
    let (node, handle) = Node::new(config).await.unwrap();
    let task = tokio::spawn(node.run());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc = listener.local_addr().unwrap().to_string();
    tokio::spawn(midwimble::rpc::serve_on(handle.clone(), listener));
    TestNode {
        handle,
        rpc,
        _dir: dir,
        _task: task,
    }
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

    fn tip(&self) -> [u8; 32] {
        self.handle.info().state.header_hash
    }

    async fn get(&self, path: &str) -> Value {
        let (rpc, path) = (self.rpc.clone(), path.to_string());
        tokio::task::spawn_blocking(move || RpcClient::new(rpc).get(&path).unwrap())
            .await
            .unwrap()
    }

    async fn post(&self, path: &str, body: Value) -> anyhow::Result<Value> {
        let (rpc, path) = (self.rpc.clone(), path.to_string());
        tokio::task::spawn_blocking(move || RpcClient::new(rpc).post(&path, &body))
            .await
            .unwrap()
    }
}

async fn wait_until(what: &str, secs: u64, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn hex32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

/// A template from the RPC, as the block it would be.
fn decode(template: &Value) -> Batch {
    bincode::deserialize(&hex::decode(template["template_hex"].as_str().unwrap()).unwrap()).unwrap()
}

/// The RPC's template, mined, and handed back through the RPC.
async fn mine_and_submit(node: &TestNode, template: &Value) -> Batch {
    let mut sealed = midwimble::rpc::template_from_hex(
        template["template_hex"].as_str().unwrap(),
        hex32(&template["mining_hash"]),
    )
    .unwrap();
    sealed.height = template["height"].as_u64().unwrap();
    let block = sealed.mine_blocking();
    let hex = hex::encode(bincode::serialize(&block).unwrap());
    node.post("/mining/submit", json!({ "block_hex": hex }))
        .await
        .expect("the node takes the block");
    block
}

/// A node's RPC hands out a template that orphans the run, carrying the
/// transaction one of the run's blocks mined. Mined and submitted, it
/// replaces the run on that node, and a peer that held the run takes it
/// straight from the block, without a sync session. The explorer tells the
/// run's blocks from full-weight ones, and counts the confirmations that
/// would take bonds to undo.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_weight_block_replaces_a_run_of_over_cap_blocks_everywhere() {
    let mut bonds = bonds(&[b"orphan big", b"orphan small"]);
    let (big, small) = (bonds.remove(0), bonds.remove(0));
    let wallet = WalletKeys::random();
    let mut chain = prefix(&big, &small, &wallet);
    let base_hash = chain.state.header_hash;

    // The node that will orphan the run holds the chain to block 9, alone,
    // so the transaction goes straight into its pool.
    let ours = start(chain.store(), Some(small.clone()), vec![], true).await;
    let out = &chain.blocks[1].coinbase.as_ref().unwrap().outputs.outputs[0];
    let owned = scan_output(&wallet, out).unwrap();
    let coin = Spendable {
        commitment: out.commitment,
        value: owned.value,
        blinding: owned.blinding,
        owner_secret: owned.owner_secret,
    };
    let tx = build_transaction(
        &[coin],
        &[Payment {
            to: WalletKeys::random().address(),
            value: 10,
        }],
        &wallet.address(),
        100_000,
        chain.state.height,
    )
    .unwrap()
    .tx;
    let kernel = tx.kernel_ids()[0];
    ours.handle.submit_transaction(tx.clone()).await.unwrap();
    wait_until("the pool to take the transaction", 10, || {
        ours.handle.info().mempool_count == 1
    })
    .await;

    // `big` runs past its cap: blocks 10 to 12, the first mining the
    // transaction.
    let run_start = chain.state.height;
    let first = chain.next(&big, &[tx], WalletKeys::random().address());
    chain.push(first.clone());
    ours.handle.submit_block(first).await.unwrap();
    for _ in 0..2 {
        let block = chain.extend(&big);
        ours.handle.submit_block(block).await.unwrap();
    }
    wait_until("the node to take the run", 10, || {
        ours.tip() == chain.state.header_hash && ours.handle.info().orphan_base.is_some()
    })
    .await;
    assert_eq!(ours.handle.info().mempool_count, 0, "mined in the run");

    // A peer holding the same chain.
    let peer = start(chain.store(), None, vec![ours.dial_addr().await], true).await;
    wait_until("the peer to connect", 30, || {
        !ours.handle.info().peers.is_empty()
    })
    .await;

    // The node sees the run, and the explorer shows it.
    let state = ours.get("/state").await;
    assert_eq!(state["orphaning"]["height"], run_start);
    assert_eq!(state["orphaning"]["replaces"], 3);
    assert_eq!(state["orphaning"]["prev_hash"], hex::encode(base_hash));
    let listed = ours.get("/explorer/blocks?count=4").await;
    let weights: Vec<&Value> = listed["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| &b["full_weight"])
        .collect();
    assert_eq!(weights, [false, false, false, true], "blocks 12 to 9");
    let below = ours
        .get(&format!("/explorer/block/{}", run_start - 1))
        .await;
    assert_eq!(below["confirmations"], 4);
    assert_eq!(below["full_weight_confirmations"], 1, "only itself counts");

    // Asked to keep to the tip, the RPC does.
    let payouts = json!([{ "address": WalletKeys::random().address().encode(), "weight": 1 }]);
    let on_tip = ours
        .post(
            "/mining/template",
            json!({ "payouts": payouts, "orphan_over_cap": false }),
        )
        .await
        .unwrap();
    assert_eq!(on_tip["orphans"], 0);
    assert_eq!(decode(&on_tip).prev_header_hash, chain.state.header_hash);

    // Otherwise it builds on block 9, carrying the run's transaction.
    let template = ours
        .post("/mining/template", json!({ "payouts": payouts }))
        .await
        .unwrap();
    assert_eq!(template["orphans"], 3);
    assert_eq!(template["height"], run_start);
    assert_eq!(template["prev_hash"], hex::encode(base_hash));
    let block = decode(&template);
    assert_eq!(block.prev_header_hash, base_hash);
    assert!(
        block.body.kernel_ids().contains(&kernel),
        "carries the run's transaction"
    );
    assert!(
        block.chain_weight > chain.state.weight(),
        "outweighs the run"
    );

    let replacement = mine_and_submit(&ours, &template).await;
    let hash = replacement.extension.final_hash;
    assert_eq!(ours.tip(), hash);
    assert_eq!(ours.handle.info().state.height, run_start + 1);
    assert_eq!(
        ours.handle.info().mempool_count,
        0,
        "the transaction is mined again"
    );
    let stored = ours
        .handle
        .storage()
        .load_batch(run_start)
        .unwrap()
        .unwrap();
    assert_eq!(stored.extension.final_hash, hash);
    let below = ours
        .get(&format!("/explorer/block/{}", run_start - 1))
        .await;
    assert_eq!(below["full_weight_confirmations"], 2);
    assert!(ours.get("/state").await["orphaning"].is_null());

    // The peer takes the block as it arrives.
    wait_until("the peer to follow", 30, || peer.tip() == hash).await;
    assert_eq!(
        peer.handle.info().state.weight(),
        ours.handle.info().state.weight()
    );
    assert_eq!(peer.handle.info().sync_stats.sessions, 0, "no sync session");
}

/// A node mining on its own does the same: its miner builds on the block
/// before the run, from a base state it has to derive from undo records
/// (nothing cached: it starts on the run's tip). With orphaning turned off,
/// a node keeps to the tip.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mining_node_builds_past_the_run_unless_told_not_to() {
    let mut bonds = bonds(&[b"miner big", b"miner small"]);
    let (big, small) = (bonds.remove(0), bonds.remove(0));
    let mut chain = prefix(&big, &small, &WalletKeys::random());
    let (base_height, base_hash) = (chain.state.height - 1, chain.state.header_hash);
    for _ in 0..3 {
        chain.extend(&big);
    }
    let run_tip = chain.state.header_hash;

    let off = start(chain.store(), Some(small.clone()), vec![], false).await;
    assert!(off.get("/state").await["orphaning"].is_null());
    let payouts = json!([{ "address": WalletKeys::random().address().encode(), "weight": 1 }]);
    let template = off
        .post("/mining/template", json!({ "payouts": payouts }))
        .await
        .unwrap();
    assert_eq!(template["orphans"], 0);
    assert_eq!(decode(&template).prev_header_hash, run_tip);

    let ours = start(chain.store(), Some(small), vec![], true).await;
    wait_until("the base to be derived", 30, || {
        ours.handle.info().orphan_base.is_some()
    })
    .await;
    ours.handle.set_mining(Some(WalletKeys::random().address()));
    wait_until("the node to replace the run", 60, || {
        let s = ours.handle.storage();
        s.load_header(base_height + 1)
            .ok()
            .flatten()
            .is_some_and(|h| {
                h.prev_header_hash == base_hash
                    && h.extension.final_hash
                        != chain.blocks[base_height as usize + 1].extension.final_hash
            })
    })
    .await;
    // The run is gone, and the chain carries on from the replacement.
    let replaced = ours
        .handle
        .storage()
        .load_header(base_height + 1)
        .unwrap()
        .unwrap();
    assert!(chain.blocks[base_height as usize + 1..]
        .iter()
        .all(|b| b.extension.final_hash != replaced.extension.final_hash));
    assert!(ours.handle.info().state.weight() > chain.state.weight());
}

/// A block that replaces a run leaves a chain that is heavier but shorter.
/// A node still holding a run longer than a sync steps back takes it all
/// the same: it asks for headers from below the shorter of the two tips, so
/// its peer has them, and it strikes nobody. (Older nodes asked from below
/// their own tip, past the peer's, got no headers, and struck the peer,
/// then banned it.) By default a node replaces only the latest
/// `COMPATIBLE_ORPHAN_DEPTH` blocks of a run, which such nodes can follow.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_follows_a_heavier_but_shorter_chain() {
    let mut bonds = bonds(&[b"short big", b"short small"]);
    let (big, small) = (bonds.remove(0), bonds.remove(0));
    let mut chain = prefix(&big, &small, &WalletKeys::random());
    let base_height = chain.state.height - 1;
    let mut replaced = chain.clone();
    // `big` runs further past its cap than a syncing node steps back.
    let run = INITIAL_STEP_BACK + 4;
    for _ in 0..run {
        chain.extend(&big);
    }

    // By default, a node replaces the latest blocks of the run only.
    let capped = start(chain.store(), Some(small.clone()), vec![], true).await;
    wait_until("the base to be derived", 30, || {
        capped.handle.info().orphan_base.is_some()
    })
    .await;
    let state = capped.get("/state").await;
    assert_eq!(state["orphaning"]["replaces"], COMPATIBLE_ORPHAN_DEPTH);
    assert_eq!(
        state["orphaning"]["height"],
        chain.state.height - COMPATIBLE_ORPHAN_DEPTH
    );

    // Allowed to, a node builds past the whole run.
    let deep = start_with(chain.store(), Some(small.clone()), vec![], |config| {
        config.max_orphan_depth = MAX_ORPHAN_DEPTH
    })
    .await;
    wait_until("the base to be derived", 30, || {
        deep.handle.info().orphan_base.is_some()
    })
    .await;
    assert_eq!(deep.get("/state").await["orphaning"]["replaces"], run);

    // A node whose chain replaced the run: heavier, and shorter by all but
    // two of the run's blocks. (Two full-weight blocks, because this build's
    // targets carry so little work that a sliver's floor of one lets twenty
    // over-cap blocks outweigh a single one.)
    replaced.extend(&small);
    let hash = replaced.extend(&small).extension.final_hash;
    assert!(
        replaced.state.weight() > chain.state.weight(),
        "outweighs the run"
    );
    let seed = start(replaced.store(), None, vec![], true).await;
    wait_until("the seed to load its chain", 10, || seed.tip() == hash).await;

    // A node still on the run, building on the tip as older nodes do, meets
    // it afterwards: it hears of the heavier chain from the seed's state,
    // not from the block, and syncs to it.
    let old = start_with(
        chain.store(),
        None,
        vec![seed.dial_addr().await],
        |config| config.orphan_over_cap = false,
    )
    .await;
    wait_until("the node to take the heavier, shorter chain", 60, || {
        old.tip() == hash
    })
    .await;
    let info = old.handle.info();
    assert_eq!(info.state.height, base_height + 3);
    assert!(info.sync_stats.sessions >= 1, "through a sync session");
    assert!(info.banned.is_empty(), "nobody banned: {:?}", info.banned);
}
