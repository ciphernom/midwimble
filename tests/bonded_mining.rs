//! A bonded producer end to end: its first block registers its own bond,
//! every block is signed, and a second node syncs and validates all of it.
//!
//! `cargo test --features fast-mining --test bonded_mining`
#![cfg(feature = "fast-mining")]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use midwimble::core::bond::{
    devnet_registration, devnet_registrations, est_midstate_height, MinerBond, MAX_BOND_HORIZON,
    MIN_REMAINING_BOND_LOCK,
};
use midwimble::core::mw::WalletKeys;
use midwimble::core::state::{apply_batch, current_timestamp};
use midwimble::core::template::build_template_bonded;
use midwimble::core::types::{hash, Batch, BlockEffects, State, GENESIS_TARGET, GENESIS_TIMESTAMP};
use midwimble::node::{Node, NodeConfig, NodeHandle};
use midwimble::storage::Storage;
use std::sync::Arc;
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
    start_in(
        tempfile::tempdir().unwrap(),
        bond,
        mine,
        peers,
        midstate_rpc,
    )
    .await
}

/// [`start_full`] on an existing data directory.
async fn start_in(
    dir: tempfile::TempDir,
    bond: Option<MinerBond>,
    mine: bool,
    peers: Vec<String>,
    midstate_rpc: Option<String>,
) -> TestNode {
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
    TestNode {
        handle,
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

    fn height(&self) -> u64 {
        self.handle.info().state.height
    }

    fn tip(&self) -> [u8; 32] {
        self.handle.info().state.header_hash
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
    let bonded_until = est_midstate_height(current_timestamp()) + MIN_REMAINING_BOND_LOCK + 10_000;
    let (registration, headers) = devnet_registration(
        mining_key,
        bonded_until,
        hash(b"integration salt"),
        &GENESIS_TARGET,
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
        (
            client.get("/bonds").unwrap(),
            client.get("/miners/1/3").unwrap(),
        )
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

    // The explorer's own listener serves the explorer and nothing else: it
    // can be published without handing out control of the node.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(midwimble::rpc::serve_explorer_on(
        peer.handle.clone(),
        listener,
        Default::default(),
    ));
    let (page, state, bonds, mining, peers) = tokio::task::spawn_blocking(move || {
        let client = midwimble::rpc::RpcClient::new(addr);
        (
            client.get("/").unwrap(),
            client.get("/state").unwrap(),
            client.get("/explorer/bonds").unwrap(),
            client
                .post_raw("/mining", &serde_json::json!({ "address": null }))
                .unwrap(),
            client
                .post_raw(
                    "/peers",
                    &serde_json::json!({ "addr": "/ip4/127.0.0.1/tcp/1" }),
                )
                .unwrap(),
        )
    })
    .await
    .unwrap();
    assert!(page.as_str().is_some_and(|html| html.contains("<html")));
    assert!(state["height"].as_u64().unwrap() > 6);
    assert!(bonds.to_string().contains(&id));
    assert_eq!(mining.0, 404, "no mining control on the explorer listener");
    assert_eq!(peers.0, 404);
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

/// A launch, end to end: the producer starts with a bond proven at
/// midstate's tip, not yet buried. No bond can sign, so it mines unsigned
/// blocks, relaying the headers its midstate node serves. Once they bury
/// the proof, its next block registers the bond and is signed by it, as is
/// every block after; a peer validates all of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_producer_mines_unsigned_until_its_bond_is_buried_then_signs() {
    use midwimble::core::bond::{
        BondCoin, BondProof, BondRegistration, BondScript, MidstateRoots, MIN_MINING_BOND,
    };
    use midwimble::core::mmr::UtxoAccumulator;
    use midwimble::core::relay::RelayEntry;
    let root = RelayEntry::root();
    let (ms, mock) = start_mock_midstate_at(root.height + 1, root.hash).await;
    let mine = |n: usize| {
        let ms = ms.clone();
        tokio::task::spawn_blocking(move || {
            for _ in 0..n {
                mine_midstate_block(&ms);
            }
        })
    };
    mine(3).await.unwrap();

    // The bond's coin, in the state midstate's next header commits to.
    let secret = Scalar::from_bytes_mod_order(hash(b"launch bond"));
    let coin = BondCoin {
        script: BondScript {
            mining_key: RistrettoPoint::mul_base(&secret).compress().to_bytes(),
            bonded_until: est_midstate_height(current_timestamp()) + MAX_BOND_HORIZON / 2,
            owner_pk: hash(b"launch owner"),
        },
        value: MIN_MINING_BOND,
        salt: hash(b"launch salt"),
    };
    let mut coins = UtxoAccumulator::new();
    coins.insert(coin.coin_id(), true);
    let roots = MidstateRoots {
        coins: coins.root(true),
        commitments: hash(b"launch commitments"),
        chain_mmr: hash(b"launch chain"),
        burned_wots: Some(hash(b"launch burned")),
    };
    let proven = root.height + 4;
    mock.lock()
        .unwrap()
        .state_roots
        .insert(proven, roots.state_root(proven).unwrap());
    mine(1).await.unwrap();
    let registration = BondRegistration {
        proof: BondProof {
            coin,
            midstate_height: proven,
            roots,
            smt: coins.prove(&coin.coin_id(), true).unwrap(),
        },
    };
    let bond = MinerBond {
        co_bonds: Vec::new(),
        secret,
        bond_id: registration.bond_id(),
        registration: Some(registration),
        midstate: None,
    };

    let producer = start_full(Some(bond.clone()), true, vec![], Some(ms.clone())).await;
    wait_until("unsigned blocks relaying the proof's header", 60, || {
        producer.handle.state().relay.tip().height == proven && producer.height() > 4
    })
    .await;
    assert!(producer.handle.state().bonds.is_empty());

    // Midstate buries the proof.
    mine(80).await.unwrap();
    wait_until("the bond to register", 90, || {
        producer.handle.state().bonds.contains_key(&bond.bond_id)
    })
    .await;
    let registered_at = producer.height();
    wait_until("signed blocks after it", 60, || {
        producer.height() > registered_at + 2
    })
    .await;
    let blocks = producer
        .handle
        .storage()
        .load_batches(1, producer.height() - 1, usize::MAX)
        .unwrap();
    let first_signed = blocks
        .iter()
        .position(|b| b.miner.is_some())
        .expect("a signed block");
    assert!(first_signed >= 3, "unsigned blocks came first");
    assert!(blocks[..first_signed]
        .iter()
        .all(|b| b.miner.is_none() && b.registrations.is_empty()));
    assert_eq!(blocks[first_signed].registrations.len(), 1);
    assert!(blocks[first_signed..]
        .iter()
        .all(|b| b.miner.as_ref().is_some_and(|m| m.bond_id == bond.bond_id)));

    // A peer that validates every block, unsigned and signed, ends with the
    // same blocks and the bond.
    let peer = start_full(None, false, vec![producer.dial_addr().await], None).await;
    let height = producer.height();
    wait_until("the peer to sync", 60, || peer.height() >= height).await;
    assert!(peer.handle.state().bonds.contains_key(&bond.bond_id));
    let synced = peer
        .handle
        .storage()
        .load_batches(1, blocks.len() as u64, usize::MAX)
        .unwrap();
    assert!(synced == blocks, "the peer holds the producer's blocks");
}

/// Bonds registered together (one stand-in midstate holds them all), locked
/// well past the timestamps of a chain mined on schedule from genesis.
fn bonds_from_genesis(seeds: &[&[u8]]) -> Vec<MinerBond> {
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

    /// Mines one block signed by `bond`, on schedule, so every block has the
    /// genesis target's work.
    fn extend(&mut self, bond: &MinerBond) {
        let to = WalletKeys::random().address();
        let (template, _) = build_template_bonded(
            &self.state,
            &self.timestamps,
            &[],
            &[(to, 1)],
            [0; 32],
            Some(GENESIS_TIMESTAMP + 60 * self.state.height),
            Some(bond),
        )
        .unwrap();
        let block = template.mine_blocking();
        apply_batch(&mut self.state, &block, &self.timestamps).unwrap();
        self.timestamps.push(block.timestamp);
        self.effects.push(self.state.effects.clone());
        self.blocks.push(block);
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

/// Sync goes by the weight fork choice goes by. Chain A is longer and has
/// more work, but one bond signed nearly all of it, far over its cap; chain
/// B, signed in turn by two bonds, is shorter and weighs more. A node on A
/// syncs to B, and a node on B never starts a session to fetch A (which it
/// would only throw away), however much more work A has.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_follows_the_heavier_chain_not_the_one_with_more_work() {
    let mut bonds = bonds_from_genesis(&[b"weight a", b"weight b"]);
    let (a, b) = (bonds.remove(0), bonds.remove(0));
    let mut prefix = Chain::genesis();
    prefix.extend(&a);
    prefix.extend(&b);
    let (mut heavy, mut long) = (prefix.clone(), prefix);
    for i in 0..10 {
        heavy.extend(if i % 2 == 0 { &a } else { &b });
    }
    for _ in 0..14 {
        long.extend(&a);
    }
    assert!(long.state.height > heavy.state.height, "A is longer");
    assert!(long.state.depth > heavy.state.depth, "A has more work");
    assert!(long.state.weight() < heavy.state.weight(), "B weighs more");
    let heavy_tip = heavy.state.header_hash;

    let on_b = start_in(heavy.store(), None, false, vec![], None).await;
    let on_a = start_in(
        long.store(),
        None,
        false,
        vec![on_b.dial_addr().await],
        None,
    )
    .await;
    wait_until("the node on A to reorganise onto B", 60, || {
        on_a.tip() == heavy_tip
    })
    .await;
    assert_eq!(on_a.handle.state().weight(), heavy.state.weight());

    // The node on B has heard A's tip all along and never chased it.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(on_b.tip(), heavy_tip);
    assert_eq!(on_b.handle.info().sync_stats.sessions, 0);
}

/// The burn tracker adds up, end to end. Once a second bond is registered,
/// one bond signs every block, so it runs past its cap (half the window) and
/// its blocks mint `cap / n` of their subsidy. Every figure the explorer's
/// own listener publishes -- the banner's total, the leaderboard in each
/// period, the per-day and per-1,000-block series, the bond page -- equals a
/// manual sum of the withheld values `/explorer/blocks` lists block by block,
/// and that sum equals the schedule less the supply `/state` reports.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_burn_tracker_adds_up_to_the_coinbases() {
    use midwimble::core::bond::EARLY_BONDS_UNTIL;
    use midwimble::core::types::{block_reward, issued_before, MAX_SUPPLY};
    use serde_json::Value;
    use std::collections::HashMap;
    assert!(
        current_timestamp() >= EARLY_BONDS_UNTIL,
        "the taper applies from the mainnet switch"
    );

    let secrets =
        [b"burner".as_slice(), b"bystander"].map(|s| Scalar::from_bytes_mod_order(hash(s)));
    let until = est_midstate_height(current_timestamp()) + MIN_REMAINING_BOND_LOCK + 10_000;
    let specs: Vec<([u8; 32], u64, [u8; 32])> = secrets
        .iter()
        .enumerate()
        .map(|(i, s)| {
            (
                RistrettoPoint::mul_base(s).compress().to_bytes(),
                until,
                hash(&[i as u8, 0xb5]),
            )
        })
        .collect();
    let (registrations, headers) = devnet_registrations(&specs, &GENESIS_TARGET);
    let bonds: Vec<MinerBond> = registrations
        .into_iter()
        .zip(secrets)
        .map(|(registration, secret)| MinerBond {
            secret,
            bond_id: registration.bond_id(),
            registration: Some(registration),
            midstate: Some(headers.clone()),
            co_bonds: vec![],
        })
        .collect();
    let (burner, bystander) = (bonds[0].clone(), bonds[1].clone());

    // The bystander's producer registers its bond, then stops mining.
    let quiet = start(Some(bystander.clone()), vec![]).await;
    wait_until("the bystander's bond to register", 60, || {
        quiet.handle.state().bonds.contains_key(&bystander.bond_id)
    })
    .await;
    quiet.handle.set_mining(None);
    // The burner's producer then signs every block. Two eligible bonds share
    // the 16-block test window at 8 each, and it goes past that.
    let busy = start(Some(burner.clone()), vec![quiet.dial_addr().await]).await;
    let tapered = |n: &TestNode| {
        let storage = n.handle.storage();
        (1..n.height())
            .filter(|&h| {
                storage
                    .subsidy_at(h)
                    .ok()
                    .flatten()
                    .is_some_and(|m| m < block_reward(h))
            })
            .count()
    };
    wait_until("a run of over-cap blocks", 120, || tapered(&busy) >= 12).await;
    busy.handle.set_mining(None);
    let mut last = busy.height();
    loop {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        if busy.height() == last {
            break;
        }
        last = busy.height();
    }

    // Everything as a reader of the published explorer would see it.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(midwimble::rpc::serve_explorer_on(
        busy.handle.clone(),
        listener,
        Default::default(),
    ));
    let id = hex::encode(burner.bond_id);
    let path = format!("/explorer/bond/{id}");
    let (state, blocks, burn, bond) = tokio::task::spawn_blocking(move || {
        let client = midwimble::rpc::RpcClient::new(addr);
        let state = client.get("/state").unwrap();
        let tip = state["height"].as_u64().unwrap();
        let mut blocks: Vec<Value> = Vec::new();
        let mut before = tip;
        while before > 0 {
            let page = client
                .get(&format!("/explorer/blocks?count=200&before={before}"))
                .unwrap();
            let listed = page["blocks"].as_array().unwrap().clone();
            before = listed.last().unwrap()["height"].as_u64().unwrap();
            blocks.extend(listed);
        }
        (
            state,
            blocks,
            client.get("/explorer/burn").unwrap(),
            client.get(&path).unwrap(),
        )
    })
    .await
    .unwrap();

    // The manual sum: every block stamped from the switch, as each
    // coinbase's withheld figure lists it.
    let n = |v: &Value| v.as_u64().unwrap();
    let mut counted: Vec<&Value> = blocks
        .iter()
        .filter(|b| n(&b["timestamp"]) >= EARLY_BONDS_UNTIL)
        .collect();
    counted.sort_by_key(|b| n(&b["height"]));
    #[derive(Default, Debug, PartialEq)]
    struct Sum {
        blocks: u64,
        tapered: u64,
        scheduled: u64,
        minted: u64,
        withheld: u64,
    }
    let add = |s: &mut Sum, b: &Value| {
        let withheld = n(&b["withheld"]);
        s.blocks += 1;
        s.tapered += u64::from(withheld > 0);
        s.scheduled += n(&b["reward"]);
        s.minted += n(&b["minted"]);
        s.withheld += withheld;
    };
    let mut total = Sum::default();
    let mut by_bond: HashMap<String, Sum> = HashMap::new();
    let (mut streak, mut longest) = (0u64, 0u64);
    for b in &counted {
        assert_eq!(n(&b["minted"]) + n(&b["withheld"]), n(&b["reward"]));
        add(&mut total, b);
        if let Some(miner) = b["miner"].as_str() {
            add(by_bond.entry(miner.to_string()).or_default(), b);
            if miner == id {
                streak = if n(&b["withheld"]) > 0 { streak + 1 } else { 0 };
                longest = longest.max(streak);
            }
        } else {
            assert_eq!(n(&b["withheld"]), 0, "an unsigned block is never tapered");
        }
    }
    let height = n(&state["height"]);
    let supply = n(&state["supply"]);
    assert!(total.tapered >= 12, "{total:?}");
    assert_eq!(
        total.withheld,
        issued_before(height) - supply,
        "the coinbases' withheld figures are what the supply is short of the schedule"
    );

    // The banner, the network totals and the check.
    assert_eq!(burn["complete"], true);
    assert_eq!(burn["burned_source"], "blocks");
    assert_eq!(n(&burn["burned"]), total.withheld);
    assert_eq!(n(&burn["consensus"]["withheld"]), total.withheld);
    assert_eq!(burn["consensus"]["matches"], true);
    assert_eq!(
        n(&burn["effective_max_supply"]),
        MAX_SUPPLY - total.withheld
    );
    assert_eq!(n(&burn["supply"]), supply);
    let tally = |t: &Value| Sum {
        blocks: n(&t["blocks"]),
        tapered: n(&t["tapered"]),
        scheduled: n(&t["scheduled"]),
        minted: n(&t["minted"]),
        withheld: n(&t["withheld"]),
    };
    // The test chain is minutes old, so the day and the week are all of it.
    for period in ["all", "week", "day"] {
        let p = &burn["periods"][period];
        assert_eq!(tally(p), total, "{period}");
        assert_eq!(n(&p["bonds_withheld"]), total.withheld, "{period}");
        assert_eq!(n(&p["unknown"]), 0);
    }

    // The leaderboard: each bond's row is its manual sum, the rows add up to
    // the network total, and the burner is ranked first with its streak.
    let rows = burn["bonds"].as_array().unwrap();
    for period in ["all", "week", "day"] {
        let sum: u64 = rows.iter().map(|b| n(&b[period]["withheld"])).sum();
        assert_eq!(sum, total.withheld, "{period}");
    }
    for b in rows {
        let key = b["bond_id"].as_str().unwrap();
        let expected = by_bond.remove(key).unwrap_or_default();
        assert_eq!(tally(&b["all"]), expected, "bond {key}");
    }
    assert!(by_bond.is_empty(), "every signer is on the leaderboard");
    let top = &rows[0];
    assert_eq!(top["bond_id"], id.as_str());
    assert_eq!(top["all"]["rank"], 1);
    assert_eq!(top["day"]["rank"], 1);
    assert_eq!(n(&top["streak"]), streak);
    assert_eq!(n(&top["longest_streak"]), longest);

    // The series add up to the same total.
    for series in ["days", "kblocks"] {
        let buckets = burn["series"][series].as_array().unwrap();
        let sum: u64 = buckets.iter().map(|b| n(&b["withheld"])).sum();
        let blocks: u64 = buckets.iter().map(|b| n(&b["blocks"])).sum();
        assert_eq!((sum, blocks), (total.withheld, total.blocks), "{series}");
    }

    // The bond page carries the same row.
    let page = &bond["burn"];
    assert_eq!(page["bond"], *top);
    assert_eq!(page["periods"], burn["periods"]);

    eprintln!(
        "burn check: {} blocks from height {} to {}, {} over cap; withheld {} = schedule {} - supply {}; burner {} withheld {} (rank 1, streak {})",
        total.blocks,
        n(&counted[0]["height"]),
        n(&counted[counted.len() - 1]["height"]),
        total.tapered,
        total.withheld,
        issued_before(height),
        supply,
        &id[..12],
        n(&top["all"]["withheld"]),
        streak
    );
}
