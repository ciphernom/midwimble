//! The full node.
//!
//! Follows midstate's `node.rs` structure and algorithms, minus the
//! subsystems that do not apply to this chain (CoinJoin, chat, pruning
//! licences, WOTS bounty hunting).
//!
//! * **Nothing expensive runs on the event loop.** Block validation, orphan
//!   proof-of-work checks, transaction proof verification, header
//!   verification, fork-state derivation and block application all run on
//!   blocking workers and report back through an internal channel. Blocks are
//!   validated one at a time against the tip they were started on; a result
//!   that arrives after the tip moved is simply re-evaluated.
//! * **New blocks** (midstate `handle_new_batch`): extend the tip after full
//!   validation, or screen the proof of work of an orphan, hold it in a
//!   bounded pool, and ask the sender for its state.
//! * **Pipelined, resumable sync** (midstate `sync.rs`, `PipelinedRebuild`,
//!   `SyncStateBackup`):
//!   - Headers come from the session peer in chunks. The next chunk is
//!     requested while the current one is verified off-thread (SIMD proof of
//!     work).
//!   - Each verified chunk is persisted, so a restart resumes where
//!     verification stopped.
//!   - Block download starts as soon as the verified headers outweigh our
//!     chain from the fork point, while more headers are still arriving.
//!     Requests fan out to every peer that has the blocks; out-of-order
//!     responses are buffered under a memory cap. Size-truncated,
//!     timed-out or mismatching responses are re-requested, and a peer
//!     whose data fails is excluded (banned if it served invalid blocks).
//!   - The fork-point state is derived from undo records while the first
//!     blocks download.
//!   - A fast-forward commits as it goes. A reorg is staged until strictly
//!     heavier, then committed in one atomic write.
//! * **Dandelion++** (midstate's dynamic fluff probability). Stem
//!   transactions that time out together are aggregated before fluffing.
//! * **Mining** on a dedicated thread, restarted on every tip or pool change.

use crate::anchor::{load_records, AnchorRecord};
use crate::core::auxpow::verify_pow;
use crate::core::filter::CompactFilter;
use crate::core::mw::{Context, StealthAddress, Transaction};
use crate::core::snapshot::Snapshot;
use crate::core::state::{apply_batch, apply_batch_skip_pow, choose_best_state};
use crate::core::template::{build_template, select_transactions};
use crate::core::types::{
    compute_header_hash, utxo_leaf, Batch, BatchHeader, State, DIFFICULTY_LOOKBACK, KERNEL_WEIGHT,
    MAX_BLOCK_WEIGHT, MEDIAN_TIME_PAST_WINDOW, OUTPUT_WEIGHT,
};
use crate::finality::{FinalityConfig, FinalityTracker};
use crate::mempool::{Mempool, ReorgCache};
use crate::miner::{MinedBlock, Miner};
use crate::network::amino::{self, AminoHandle};
use crate::network::light_protocol::{LightNotification, LightRequest, LightResponse};
use crate::network::protocol::BATCH_RESPONSE_SOFT_LIMIT;
use crate::network::protocol::{MAX_ANCHORS_PER_MESSAGE, SNAPSHOT_PART_BYTES};
use crate::network::{Message, Network, NetworkEvent, MAX_GETBATCHES_COUNT, MAX_GETHEADERS_COUNT};
use crate::storage::FinalityInfo;
use crate::storage::Storage;
use crate::sync::{
    headers_work, verify_header_chain, BlockSync, Chunk, HeaderSync, InFlight, SyncSession,
    SyncStats, BATCH_LOOKAHEAD_BLOCKS, BATCH_REQUEST_TIMEOUT_SECS, INITIAL_STEP_BACK,
    MAX_BATCH_REQUESTS_IN_FLIGHT, MAX_BUFFER_BYTES, MAX_QUEUED_HEADER_CHUNKS, MAX_REORG_DEPTH,
};
use anyhow::{anyhow, Context as _, Result};
use libp2p::identity::Keypair;
use libp2p::request_response::ResponseChannel;
use libp2p::{Multiaddr, PeerId};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

const STATE_CACHE_SIZE: usize = 64;
const ORPHAN_LIMIT: usize = 8;
const ORPHANS_PER_PARENT: usize = 4;
const MAX_STEM_POOL: usize = 1000;
const TARGET_OUTBOUND_PEERS: usize = 8;
const TX_RATE_WINDOW_SECS: u64 = 60;
const MAX_TX_PER_PEER_PER_WINDOW: u32 = 200;
const SEEN_TX_LIMIT: usize = 20_000;
const MAX_PENDING_BLOCKS: usize = 16;
const MAX_ORPHAN_CHECKS: usize = 4;
const MAX_TX_VALIDATIONS: usize = 64;

// ── Configuration and handle ────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub data_dir: PathBuf,
    pub listen: Multiaddr,
    pub bootstrap: Vec<Multiaddr>,
    pub mine_to: Option<StealthAddress>,
    /// Mining threads; 0 means all cores.
    pub mining_threads: usize,
    /// Publish/discover through the public IPFS DHT (see `network/amino.rs`).
    pub amino: bool,
    pub public_address: Option<Multiaddr>,
    /// How often peers are asked for their tip.
    pub poll_interval: Duration,
    /// Dandelion++ embargo before a stem transaction is fluffed by us.
    pub stem_timeout: Duration,
    /// Minimum time between our tip changing and mining the next block.
    /// Zero in production; tests and demos use it to pace fast-mining chains.
    pub min_block_interval: Duration,
    /// Size cap for our `Batches` responses.
    pub batch_response_bytes: usize,
    /// Finalized checkpoints and pruning (`docs/PRUNING.md`).
    pub finality: FinalityConfig,
    /// Anchor records to read (defaults to `<data_dir>/anchors.jsonl`).
    pub anchors_file: Option<PathBuf>,
    /// Checkpoint verification: start an empty node from a snapshot at this
    /// trusted checkpoint id instead of verifying history from genesis.
    pub checkpoint: Option<[u8; 32]>,
    /// How long checkpoint bootstrap may take.
    pub bootstrap_timeout: Duration,
}

impl NodeConfig {
    pub fn new(data_dir: impl Into<PathBuf>, listen: Multiaddr) -> Self {
        Self {
            data_dir: data_dir.into(),
            listen,
            bootstrap: Vec::new(),
            mine_to: None,
            mining_threads: 0,
            amino: false,
            public_address: None,
            poll_interval: Duration::from_secs(10),
            stem_timeout: Duration::from_secs(30),
            min_block_interval: Duration::ZERO,
            batch_response_bytes: BATCH_RESPONSE_SOFT_LIMIT,
            finality: FinalityConfig::default(),
            anchors_file: None,
            checkpoint: None,
            bootstrap_timeout: Duration::from_secs(600),
        }
    }
}

/// Read-mostly view published by the node for the RPC and tests.
#[derive(Clone)]
pub struct NodeInfo {
    pub state: State,
    pub peer_id: String,
    pub peers: Vec<String>,
    pub listen_addrs: Vec<String>,
    pub syncing: bool,
    pub mempool_count: usize,
    pub mempool_weight: u64,
    pub mining: bool,
    pub hashes: u64,
    pub sync_stats: SyncStats,
    pub finality: FinalityInfo,
    pub anchors_known: usize,
}

pub enum Command {
    SubmitTransaction(Transaction, oneshot::Sender<Result<()>>),
    /// A solved block from a miner (template RPC, pool or merged miner).
    SubmitBlock(Batch, oneshot::Sender<Result<()>>),
    Mempool(oneshot::Sender<Vec<Transaction>>),
    SetMining(Option<StealthAddress>),
    Dial(Multiaddr),
    SubmitAnchor(AnchorRecord, oneshot::Sender<Result<()>>),
    Anchors(oneshot::Sender<Vec<AnchorRecord>>),
    Shutdown,
}

#[derive(Clone)]
pub struct NodeHandle {
    info: Arc<RwLock<NodeInfo>>,
    storage: Storage,
    commands: mpsc::UnboundedSender<Command>,
}

impl NodeHandle {
    pub fn info(&self) -> NodeInfo {
        self.info.read().expect("node info lock poisoned").clone()
    }

    pub fn state(&self) -> State {
        self.info().state
    }

    pub fn storage(&self) -> &Storage {
        &self.storage
    }

    /// Validates the transaction and sends it into Dandelion++.
    pub async fn submit_transaction(&self, tx: Transaction) -> Result<()> {
        let (tx_back, rx) = oneshot::channel();
        self.commands
            .send(Command::SubmitTransaction(tx, tx_back))
            .map_err(|_| anyhow!("node stopped"))?;
        rx.await.map_err(|_| anyhow!("node stopped"))?
    }

    /// Submits a mined block and waits for it to be accepted or rejected.
    pub async fn submit_block(&self, batch: Batch) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::SubmitBlock(batch, tx))
            .map_err(|_| anyhow!("node stopped"))?;
        tokio::time::timeout(Duration::from_secs(120), rx)
            .await
            .map_err(|_| anyhow!("block validation timed out"))?
            .map_err(|_| anyhow!("node stopped"))?
    }

    pub async fn mempool(&self) -> Result<Vec<Transaction>> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Mempool(tx))
            .map_err(|_| anyhow!("node stopped"))?;
        rx.await.map_err(|_| anyhow!("node stopped"))
    }

    pub fn set_mining(&self, to: Option<StealthAddress>) {
        let _ = self.commands.send(Command::SetMining(to));
    }

    pub fn dial(&self, addr: Multiaddr) {
        let _ = self.commands.send(Command::Dial(addr));
    }

    /// Hands the node a verified-anchor record (it re-verifies it).
    pub async fn submit_anchor(&self, record: AnchorRecord) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::SubmitAnchor(record, tx))
            .map_err(|_| anyhow!("node stopped"))?;
        rx.await.map_err(|_| anyhow!("node stopped"))?
    }

    pub async fn anchors(&self) -> Result<Vec<AnchorRecord>> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Anchors(tx))
            .map_err(|_| anyhow!("node stopped"))?;
        rx.await.map_err(|_| anyhow!("node stopped"))
    }

    pub fn shutdown(&self) {
        let _ = self.commands.send(Command::Shutdown);
    }
}

// ── Internal plumbing ───────────────────────────────────────────────────────

enum TxReply {
    Rpc(oneshot::Sender<Result<()>>),
    Light(oneshot::Sender<LightResponse>),
}

impl TxReply {
    fn send(self, result: Result<()>) {
        match self {
            TxReply::Rpc(s) => {
                let _ = s.send(result);
            }
            TxReply::Light(s) => {
                let _ = s.send(match result {
                    Ok(()) => LightResponse::success(serde_json::json!({ "accepted": true })),
                    Err(e) => LightResponse::error(format!("{e:#}")),
                });
            }
        }
    }
}

enum TxOrigin {
    /// Fluff-phase gossip.
    Gossip(Option<PeerId>),
    /// Dandelion++ stem hop.
    Stem(PeerId),
    /// Submitted locally (RPC or light client).
    Local(TxReply),
}

enum Internal {
    BlockValidated {
        parent: [u8; 32],
        batch: Batch,
        from: Option<PeerId>,
        result: Result<State>,
    },
    OrphanChecked {
        batch: Batch,
        from: Option<PeerId>,
        pow_ok: bool,
    },
    TxValidated {
        tx: Transaction,
        origin: TxOrigin,
        result: Result<()>,
    },
    HeadersVerified {
        session: u64,
        chunk: Vec<BatchHeader>,
        result: Result<()>,
    },
    ForkState {
        session: u64,
        result: Result<State>,
    },
    SnapshotReady {
        checkpoint_id: [u8; 32],
        result: Result<Arc<Vec<u8>>>,
    },
    BatchesApplied {
        session: u64,
        source: PeerId,
        candidate: State,
        timestamps: VecDeque<u64>,
        applied: Vec<Batch>,
        error: Option<String>,
    },
}

struct OrphanPool {
    by_parent: HashMap<[u8; 32], Vec<Batch>>,
    order: VecDeque<[u8; 32]>,
}

impl OrphanPool {
    fn new() -> Self {
        Self {
            by_parent: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn insert(&mut self, batch: Batch) {
        let parent = batch.prev_header_hash;
        let list = self.by_parent.entry(parent).or_default();
        if list
            .iter()
            .any(|b| b.extension.final_hash == batch.extension.final_hash)
            || list.len() >= ORPHANS_PER_PARENT
        {
            return;
        }
        list.push(batch);
        if list.len() == 1 {
            self.order.push_back(parent);
        }
        if self.order.len() > ORPHAN_LIMIT {
            for _ in 0..ORPHAN_LIMIT / 2 {
                if let Some(k) = self.order.pop_front() {
                    self.by_parent.remove(&k);
                }
            }
        }
    }

    fn take_children(&mut self, parent: &[u8; 32]) -> Vec<Batch> {
        self.order.retain(|p| p != parent);
        self.by_parent.remove(parent).unwrap_or_default()
    }
}

/// What `on_headers` decided, acted on once the session is back in place.
enum HeaderStep {
    Continue,
    Ban(&'static str),
    Abort(&'static str),
    Restart { step_back: u64, allow_resume: bool },
}

pub struct Node {
    config: NodeConfig,
    state: State,
    timestamps: VecDeque<u64>,
    state_cache: BTreeMap<u64, (State, VecDeque<u64>)>,
    storage: Storage,
    network: Network,
    mempool: Mempool,
    reorg_cache: ReorgCache,
    stem_pool: HashMap<[u8; 32], (Transaction, Instant)>,
    seen_txs: HashSet<[u8; 32]>,
    seen_order: VecDeque<[u8; 32]>,
    validating_txs: HashSet<[u8; 32]>,
    peer_tx_counts: HashMap<PeerId, (u32, Instant)>,
    peer_tips: HashMap<PeerId, (u64, u128)>,
    orphans: OrphanPool,
    orphan_checking: HashSet<[u8; 32]>,
    recent_blocks: VecDeque<[u8; 32]>,
    block_validation: Option<[u8; 32]>,
    block_queue: VecDeque<(Batch, Option<PeerId>)>,
    sync: Option<SyncSession>,
    next_session_id: u64,
    sync_stats: SyncStats,
    batch_sources: HashSet<PeerId>,
    miner: Miner,
    mined_rx: mpsc::UnboundedReceiver<MinedBlock>,
    known_addrs: HashSet<String>,
    amino: Option<(AminoHandle, mpsc::Receiver<Vec<String>>)>,
    internal_tx: mpsc::UnboundedSender<Internal>,
    internal_rx: mpsc::UnboundedReceiver<Internal>,
    commands: mpsc::UnboundedReceiver<Command>,
    info: Arc<RwLock<NodeInfo>>,
    last_tip_change: Instant,
    /// Miners waiting to hear what became of a submitted block.
    block_replies: HashMap<[u8; 32], Vec<oneshot::Sender<Result<()>>>>,
    finality: FinalityTracker,
    anchors_seen_len: u64,
    snapshot_cache: Option<([u8; 32], Arc<Vec<u8>>)>,
    snapshot_building: Option<[u8; 32]>,
}

fn load_or_create_identity(dir: &std::path::Path) -> Result<Keypair> {
    let path = dir.join("identity.key");
    if let Ok(bytes) = std::fs::read(&path) {
        return Keypair::from_protobuf_encoding(&bytes).context("corrupt identity.key");
    }
    let kp = Keypair::generate_ed25519();
    std::fs::write(&path, kp.to_protobuf_encoding()?)?;
    Ok(kp)
}

impl Node {
    pub async fn new(config: NodeConfig) -> Result<(Node, NodeHandle)> {
        let storage = Storage::open(&config.data_dir)?;
        let keypair = load_or_create_identity(&config.data_dir)?;
        let mut network = Network::new(
            keypair.clone(),
            config.listen.clone(),
            config.bootstrap.clone(),
            HashSet::new(),
        )
        .await?;
        if let Some(addr) = &config.public_address {
            network.declare_public(addr.clone());
        }
        if let (Some(trusted), None) = (config.checkpoint, storage.load_meta()?) {
            bootstrap_from_checkpoint(&mut network, &storage, trusted, &config).await?;
        }
        let state = match storage.load_state()? {
            Some(s) => s,
            None => {
                let mut s = State::genesis();
                apply_batch(&mut s, Batch::genesis(), &[])?;
                storage.commit_chain(0, std::slice::from_ref(Batch::genesis()), &s)?;
                s
            }
        };
        match (storage.base()?, storage.load_header(0)?) {
            (Some(base), _) if base.checkpoint.network == crate::core::types::network_anchor() => {}
            (None, Some(g)) if g.extension.final_hash == Batch::genesis().extension.final_hash => {}
            _ => {
                return Err(anyhow!(
                    "database belongs to a different network (genesis mismatch)"
                ))
            }
        }
        let timestamps: VecDeque<u64> = storage
            .load_timestamps(state.height, DIFFICULTY_LOOKBACK)?
            .into();
        let finality = FinalityTracker::new(config.finality.clone(), &storage.finality()?);

        let amino = if config.amino {
            match amino::spawn(keypair, crate::core::types::network_anchor()) {
                Ok(pair) => Some(pair),
                Err(e) => {
                    tracing::warn!("Amino DHT discovery unavailable: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let (miner, mined_rx) = Miner::new(config.mining_threads);
        let (internal_tx, internal_rx) = mpsc::unbounded_channel();
        let (cmd_tx, commands) = mpsc::unbounded_channel();
        let known_addrs = storage.load_peers()?.into_iter().collect();

        let info = Arc::new(RwLock::new(NodeInfo {
            state: state.clone(),
            peer_id: network.local_peer_id().to_string(),
            peers: Vec::new(),
            listen_addrs: Vec::new(),
            syncing: false,
            mempool_count: 0,
            mempool_weight: 0,
            mining: config.mine_to.is_some(),
            hashes: 0,
            sync_stats: SyncStats::default(),
            finality: storage.finality()?,
            anchors_known: 0,
        }));
        let handle = NodeHandle {
            info: info.clone(),
            storage: storage.clone(),
            commands: cmd_tx,
        };

        let mut node = Node {
            config,
            state,
            timestamps,
            state_cache: BTreeMap::new(),
            storage,
            network,
            mempool: Mempool::new(),
            reorg_cache: ReorgCache::default(),
            stem_pool: HashMap::new(),
            seen_txs: HashSet::new(),
            seen_order: VecDeque::new(),
            validating_txs: HashSet::new(),
            peer_tx_counts: HashMap::new(),
            peer_tips: HashMap::new(),
            orphans: OrphanPool::new(),
            orphan_checking: HashSet::new(),
            recent_blocks: VecDeque::new(),
            block_validation: None,
            block_queue: VecDeque::new(),
            sync: None,
            next_session_id: 1,
            sync_stats: SyncStats::default(),
            batch_sources: HashSet::new(),
            miner,
            mined_rx,
            known_addrs,
            amino,
            internal_tx,
            internal_rx,
            commands,
            info,
            last_tip_change: Instant::now(),
            block_replies: HashMap::new(),
            finality,
            anchors_seen_len: 0,
            snapshot_cache: None,
            snapshot_building: None,
        };
        node.cache_state();
        node.refresh_finality();
        Ok((node, handle))
    }

    pub async fn run(mut self) -> Result<()> {
        tracing::info!(
            "Node started at height {} (tip {})",
            self.state.height,
            hex::encode(&self.state.header_hash[..8])
        );
        let mut fast = tokio::time::interval(Duration::from_millis(100));
        let mut poll = tokio::time::interval(self.config.poll_interval);
        let mut slow = tokio::time::interval(Duration::from_secs(60));
        for t in [&mut fast, &mut poll, &mut slow] {
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        }
        self.refresh_mining();
        self.publish_info();

        loop {
            let amino = &mut self.amino;
            let amino_rx = async move {
                match amino.as_mut() {
                    Some((_, rx)) => rx.recv().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                event = self.network.next_event() => self.handle_network_event(event).await,
                Some(cmd) = self.commands.recv() => {
                    if matches!(cmd, Command::Shutdown) {
                        self.miner.stop();
                        tracing::info!("Node shutting down");
                        return Ok(());
                    }
                    self.handle_command(cmd);
                }
                Some(mined) = self.mined_rx.recv() => {
                    if mined.job == self.miner.current_job() {
                        self.miner.stop();
                        tracing::info!("Mined block at height {}", self.state.height);
                        self.handle_new_batch(mined.batch, None);
                    }
                }
                Some(msg) = self.internal_rx.recv() => self.handle_internal(msg),
                Some(addrs) = amino_rx => {
                    for a in addrs {
                        self.network.dial_addr(&a);
                    }
                }
                _ = fast.tick() => {
                    self.flush_stem_pool();
                    self.check_sync_timeouts();
                    if self.config.mine_to.is_some() && !self.miner.is_running() && self.sync.is_none() {
                        self.refresh_mining();
                    }
                    self.publish_info();
                }
                _ = poll.tick() => {
                    self.poll_peers();
                    self.refresh_finality();
                }
                _ = slow.tick() => self.maintenance().await,
            }
        }
    }

    // ── Bookkeeping ─────────────────────────────────────────────────────

    fn publish_info(&mut self) {
        self.sync_stats.batch_sources = self.batch_sources.len();
        let mut info = self.info.write().expect("node info lock poisoned");
        info.state = self.state.clone();
        info.peers = self
            .network
            .connected_peers()
            .iter()
            .map(|p| p.to_string())
            .collect();
        info.listen_addrs = self
            .network
            .listen_addrs()
            .iter()
            .map(|a| a.to_string())
            .collect();
        info.syncing = self.sync.is_some();
        info.mempool_count = self.mempool.len();
        info.mempool_weight = self.mempool.total_weight();
        info.mining = self.config.mine_to.is_some();
        info.hashes = self.miner.hashes.load(std::sync::atomic::Ordering::Relaxed);
        info.sync_stats = self.sync_stats.clone();
        info.finality = self.storage.finality().unwrap_or_default();
        info.anchors_known = self.finality.records(usize::MAX).len();
    }

    fn cache_state(&mut self) {
        self.state_cache.insert(
            self.state.height,
            (self.state.clone(), self.timestamps.clone()),
        );
        while self.state_cache.len() > STATE_CACHE_SIZE {
            let first = *self.state_cache.keys().next().expect("non-empty");
            self.state_cache.remove(&first);
        }
    }

    fn remember_block(&mut self, hash: [u8; 32]) {
        self.recent_blocks.push_back(hash);
        while self.recent_blocks.len() > 256 {
            self.recent_blocks.pop_front();
        }
    }

    fn mark_tx_seen(&mut self, hash: [u8; 32]) -> bool {
        if !self.seen_txs.insert(hash) {
            return false;
        }
        self.seen_order.push_back(hash);
        while self.seen_order.len() > SEEN_TX_LIMIT {
            if let Some(old) = self.seen_order.pop_front() {
                self.seen_txs.remove(&old);
            }
        }
        true
    }

    fn ban_peer(&mut self, peer: PeerId, reason: &str) {
        tracing::warn!("Banning peer {}: {}", peer, reason);
        if self.sync.as_ref().map_or(false, |s| s.peer == peer) {
            // Whatever it made us verify is suspect; do not resume from it.
            let _ = self.storage.clear_sync_headers();
            self.abort_sync("sync peer banned");
        }
        self.peer_tips.remove(&peer);
        self.network.ban_peer(peer);
    }

    fn respond(&mut self, channel: Option<ResponseChannel<Message>>, msg: Message) {
        if let Some(ch) = channel {
            self.network.respond(ch, msg);
        }
    }

    fn ack(&mut self, channel: Option<ResponseChannel<Message>>) {
        self.respond(channel, Message::Pong { nonce: 0 });
    }

    fn state_info(&self) -> Message {
        Message::StateInfo {
            height: self.state.height,
            depth: self.state.depth,
            mw_midstate: self.state.mw_midstate,
        }
    }

    fn poll_peers(&mut self) {
        let info = self.state_info();
        for peer in self.network.connected_peers() {
            self.network.send(peer, info.clone());
            self.network.send(peer, Message::GetState);
        }
        if self.network.outbound_peer_count() < TARGET_OUTBOUND_PEERS {
            use rand::seq::IteratorRandom;
            let picks: Vec<String> = self
                .known_addrs
                .iter()
                .cloned()
                .choose_multiple(&mut rand::thread_rng(), 3);
            for a in picks {
                self.network.dial_addr(&a);
            }
            if let Some(peer) = self.network.random_peer() {
                self.network.send(peer, Message::GetAddr);
            }
        }
    }

    async fn maintenance(&mut self) {
        self.network.gc_stale_light_peers().await;
        self.network.maintain_relays();
        let addrs: Vec<String> = self.known_addrs.iter().cloned().collect();
        if let Err(e) = self.storage.save_peers(&addrs) {
            tracing::debug!("Saving address book failed: {}", e);
        }
        if let Some((handle, _)) = &self.amino {
            if self.network.nat_status() != crate::network::NatStatus::Private {
                let dialable: Vec<Multiaddr> = self
                    .network
                    .dialable_addrs()
                    .iter()
                    .filter_map(|a| a.parse().ok())
                    .collect();
                handle.announce(dialable);
            }
            if self.network.outbound_peer_count() < TARGET_OUTBOUND_PEERS {
                handle.discover();
            }
        }
    }

    // ── Commands ────────────────────────────────────────────────────────

    fn handle_command(&mut self, cmd: Command) {
        match cmd {
            Command::SubmitTransaction(tx, reply) => {
                self.validate_tx(tx, TxOrigin::Local(TxReply::Rpc(reply)))
            }
            Command::SubmitBlock(batch, reply) => self.submit_block(batch, reply),
            Command::Mempool(reply) => {
                let _ = reply.send(self.mempool.transactions());
            }
            Command::SetMining(to) => {
                self.config.mine_to = to;
                if self.config.mine_to.is_none() {
                    self.miner.stop();
                } else {
                    self.refresh_mining();
                }
            }
            Command::Dial(addr) => self.network.dial_trusted(addr),
            Command::SubmitAnchor(record, reply) => {
                let result = self.finality.add(record).map(|_| ());
                if result.is_ok() {
                    self.refresh_finality();
                }
                let _ = reply.send(result);
            }
            Command::Anchors(reply) => {
                let _ = reply.send(self.finality.records(usize::MAX));
            }
            Command::Shutdown => {}
        }
    }

    // ── Network events ──────────────────────────────────────────────────

    async fn handle_network_event(&mut self, event: NetworkEvent) {
        match event {
            NetworkEvent::MessageReceived {
                peer,
                message,
                channel,
            } => self.handle_message(peer, message, channel),
            NetworkEvent::LightRequest {
                peer,
                request,
                respond,
            } => {
                if let LightRequest::SubmitTransaction { tx_hex } = &request {
                    let decoded = hex::decode(tx_hex)
                        .map_err(anyhow::Error::from)
                        .and_then(|b| {
                            bincode::deserialize::<Transaction>(&b).map_err(anyhow::Error::from)
                        });
                    match decoded {
                        Ok(tx) => self.validate_tx(tx, TxOrigin::Local(TxReply::Light(respond))),
                        Err(e) => {
                            let _ =
                                respond.send(LightResponse::error(format!("bad transaction: {e}")));
                        }
                    }
                    return;
                }
                let response = self.handle_light_request(request);
                if response.ok {
                    self.network.observe_honest_light_peer(peer).await;
                }
                let _ = respond.send(response);
            }
            NetworkEvent::PeerConnected(peer, addr) => {
                let routable = addr
                    .parse::<Multiaddr>()
                    .map_or(false, |a| crate::network::is_routable(&a));
                if routable {
                    self.known_addrs.insert(addr);
                }
                self.network.send(peer, Message::GetState);
                self.network.send(peer, Message::GetAddr);
                self.network.send(peer, Message::GetAnchors);
            }
            NetworkEvent::PeerDisconnected(peer) => {
                self.peer_tips.remove(&peer);
                self.peer_unavailable(peer);
            }
            NetworkEvent::RequestFailed(peer) => self.peer_unavailable(peer),
            NetworkEvent::ProtocolMismatch(peer) => {
                self.ban_peer(peer, "speaks none of our protocols")
            }
            NetworkEvent::OutgoingConnectionFailed(addr) => {
                self.known_addrs.remove(&addr);
            }
        }
    }

    fn handle_message(
        &mut self,
        peer: PeerId,
        message: Message,
        channel: Option<ResponseChannel<Message>>,
    ) {
        match message {
            Message::GetState => {
                let info = self.state_info();
                self.respond(channel, info);
            }
            Message::StateInfo { height, depth, .. } => {
                self.ack(channel);
                self.on_state_info(peer, height, depth);
            }
            Message::GetHeaders {
                start_height,
                count,
            } => {
                let headers = self
                    .storage
                    .load_headers(start_height, count.min(MAX_GETHEADERS_COUNT))
                    .unwrap_or_default();
                self.respond(
                    channel,
                    Message::Headers {
                        start_height,
                        headers,
                    },
                );
            }
            Message::Headers {
                start_height,
                headers,
            } => {
                self.ack(channel);
                self.on_headers(peer, start_height, headers);
            }
            Message::GetBatches {
                start_height,
                count,
            } => {
                let batches = self
                    .storage
                    .load_batches(
                        start_height,
                        count.min(MAX_GETBATCHES_COUNT),
                        self.config.batch_response_bytes,
                    )
                    .unwrap_or_default();
                self.respond(
                    channel,
                    Message::Batches {
                        start_height,
                        batches,
                    },
                );
            }
            Message::Batches {
                start_height,
                batches,
            } => {
                self.ack(channel);
                self.on_batches(peer, start_height, batches);
            }
            Message::Batch(batch) => {
                self.ack(channel);
                self.handle_new_batch(batch, Some(peer));
            }
            Message::Transaction(tx) => {
                self.ack(channel);
                if !self.rate_limited(peer) {
                    self.handle_new_transaction(tx, Some(peer));
                }
            }
            Message::StemTransaction(tx) => {
                self.ack(channel);
                if !self.rate_limited(peer) {
                    self.handle_stem_transaction(tx, peer);
                }
            }
            Message::GetAddr => {
                let addrs = self.network.pex_addrs();
                self.respond(channel, Message::Addr(addrs));
            }
            Message::Addr(addrs) => {
                self.ack(channel);
                let need = self.network.outbound_peer_count() < TARGET_OUTBOUND_PEERS;
                for a in addrs.into_iter().take(crate::network::MAX_PEX_ADDRS) {
                    if let Ok(ma) = a.parse::<Multiaddr>() {
                        if crate::network::is_routable(&ma)
                            && crate::network::extract_peer_id(&ma).is_some()
                        {
                            if need {
                                self.network.dial_addr(&a);
                            }
                            self.known_addrs.insert(a);
                        }
                    }
                }
            }
            Message::GetAnchors => {
                let list = self.finality.records(MAX_ANCHORS_PER_MESSAGE);
                self.respond(channel, Message::Anchors(list));
            }
            Message::Anchors(list) => {
                self.ack(channel);
                let mut added = false;
                for record in list.into_iter().take(MAX_ANCHORS_PER_MESSAGE) {
                    match self.finality.add(record) {
                        Ok(new) => added |= new,
                        Err(e) => tracing::debug!("ignoring anchor from {}: {:#}", peer, e),
                    }
                }
                if added {
                    self.refresh_finality();
                }
            }
            Message::GetSnapshot {
                checkpoint_id,
                part,
            } => {
                let reply = self.snapshot_part(checkpoint_id, part);
                self.respond(channel, reply);
            }
            Message::SnapshotPart { .. } => self.ack(channel),
            Message::Ping { nonce } => self.respond(channel, Message::Pong { nonce }),
            Message::Pong { .. } => {}
        }
    }

    fn rate_limited(&mut self, peer: PeerId) -> bool {
        let now = Instant::now();
        let entry = self.peer_tx_counts.entry(peer).or_insert((0, now));
        if now.duration_since(entry.1).as_secs() >= TX_RATE_WINDOW_SECS {
            *entry = (0, now);
        }
        entry.0 += 1;
        entry.0 > MAX_TX_PER_PEER_PER_WINDOW
    }

    fn handle_internal(&mut self, msg: Internal) {
        match msg {
            Internal::BlockValidated {
                parent,
                batch,
                from,
                result,
            } => self.on_block_validated(parent, batch, from, result),
            Internal::OrphanChecked {
                batch,
                from,
                pow_ok,
            } => self.on_orphan_checked(batch, from, pow_ok),
            Internal::TxValidated { tx, origin, result } => {
                self.on_tx_validated(tx, origin, result)
            }
            Internal::HeadersVerified {
                session,
                chunk,
                result,
            } => self.on_headers_verified(session, chunk, result),
            Internal::ForkState { session, result } => self.on_fork_state(session, result),
            Internal::SnapshotReady {
                checkpoint_id,
                result,
            } => {
                self.snapshot_building = None;
                match result {
                    Ok(bytes) => self.snapshot_cache = Some((checkpoint_id, bytes)),
                    Err(e) => tracing::warn!(
                        "could not build snapshot {}: {:#}",
                        hex::encode(&checkpoint_id[..8]),
                        e
                    ),
                }
            }
            Internal::BatchesApplied {
                session,
                source,
                candidate,
                timestamps,
                applied,
                error,
            } => self.on_batches_applied(session, source, candidate, timestamps, applied, error),
        }
    }

    // ── Blocks ──────────────────────────────────────────────────────────

    fn resolve_block(&mut self, hash: &[u8; 32], result: Result<(), String>) {
        for reply in self.block_replies.remove(hash).unwrap_or_default() {
            let _ = reply.send(result.clone().map_err(|e| anyhow!(e)));
        }
    }

    fn submit_block(&mut self, batch: Batch, reply: oneshot::Sender<Result<()>>) {
        let hash = batch.extension.final_hash;
        if hash == self.state.header_hash || self.recent_blocks.contains(&hash) {
            let _ = reply.send(Ok(()));
            return;
        }
        if self.sync.is_some() {
            let _ = reply.send(Err(anyhow!("node is syncing; template is stale")));
            return;
        }
        if batch.prev_header_hash != self.state.header_hash {
            let _ = reply.send(Err(anyhow!("stale template: the chain tip has moved")));
            return;
        }
        self.block_replies.entry(hash).or_default().push(reply);
        self.handle_new_batch(batch, None);
    }

    fn handle_new_batch(&mut self, batch: Batch, from: Option<PeerId>) {
        // An active sync owns chain changes; it re-polls its peer at the end.
        if self.sync.is_some() {
            return;
        }
        let hash = batch.extension.final_hash;
        if hash == self.state.header_hash
            || self.recent_blocks.contains(&hash)
            || self.block_validation == Some(hash)
            || self.orphan_checking.contains(&hash)
            || self
                .block_queue
                .iter()
                .any(|(b, _)| b.extension.final_hash == hash)
        {
            return;
        }

        if batch.prev_header_hash != self.state.header_hash {
            // Orphan: screen its proof of work off-thread before holding it.
            if self.orphan_checking.len() >= MAX_ORPHAN_CHECKS {
                return;
            }
            self.orphan_checking.insert(hash);
            let tx = self.internal_tx.clone();
            tokio::task::spawn_blocking(move || {
                let mining_hash = compute_header_hash(&batch.header());
                let pow_ok = verify_pow(
                    mining_hash,
                    &batch.extension,
                    &batch.target,
                    batch.aux_pow.as_ref(),
                )
                .is_ok();
                let _ = tx.send(Internal::OrphanChecked {
                    batch,
                    from,
                    pow_ok,
                });
            });
            return;
        }
        if batch.target != self.state.target {
            self.resolve_block(&hash, Err("block does not use the current target".into()));
            return;
        }
        if self.block_validation.is_some() {
            if self.block_queue.len() < MAX_PENDING_BLOCKS {
                self.block_queue.push_back((batch, from));
            } else {
                self.resolve_block(&hash, Err("node busy".into()));
            }
            return;
        }

        self.block_validation = Some(hash);
        let parent = self.state.header_hash;
        let mut candidate = self.state.clone();
        let mut timestamps = self.timestamps.clone();
        let tx = self.internal_tx.clone();
        tokio::task::spawn_blocking(move || {
            let result = apply_batch(&mut candidate, &batch, timestamps.make_contiguous())
                .map(|()| candidate);
            let _ = tx.send(Internal::BlockValidated {
                parent,
                batch,
                from,
                result,
            });
        });
    }

    fn on_block_validated(
        &mut self,
        parent: [u8; 32],
        batch: Batch,
        from: Option<PeerId>,
        result: Result<State>,
    ) {
        self.block_validation = None;
        let hash = batch.extension.final_hash;
        if self.sync.is_some() {
            self.resolve_block(&hash, Err("node started syncing".into()));
        } else {
            if parent != self.state.header_hash {
                // The tip moved while this block was being checked.
                self.resolve_block(&hash, Err("the chain tip moved during validation".into()));
                self.handle_new_batch(batch, from);
            } else {
                match result {
                    Ok(candidate) => self.accept_block(candidate, batch, from),
                    Err(e) => {
                        tracing::debug!("Block rejected: {:#}", e);
                        self.resolve_block(&hash, Err(format!("block rejected: {e:#}")));
                        if let Some(peer) = from {
                            // Invalid contents behind valid proof of work are
                            // costly to make: the relayer is broken or hostile.
                            if !e.to_string().contains("timestamp") {
                                self.ban_peer(peer, "relayed an invalid block");
                            }
                        }
                    }
                }
            }
        }
        while self.block_validation.is_none() {
            let Some((next, next_from)) = self.block_queue.pop_front() else {
                break;
            };
            self.handle_new_batch(next, next_from);
        }
    }

    fn accept_block(&mut self, candidate: State, batch: Batch, from: Option<PeerId>) {
        let height = self.state.height;
        let hash = batch.extension.final_hash;
        if let Err(e) = self
            .storage
            .commit_chain(height, std::slice::from_ref(&batch), &candidate)
        {
            tracing::error!("Failed to persist block {}: {:#}", height, e);
            self.resolve_block(&hash, Err(format!("storage error: {e:#}")));
            return;
        }
        self.resolve_block(&hash, Ok(()));
        self.adopt_block(candidate, &batch, height);
        tracing::info!(
            "Chain extended to height {} ({})",
            self.state.height,
            hex::encode(&hash[..8])
        );
        self.network.broadcast_except(from, Message::Batch(batch));
        for child in self.orphans.take_children(&hash) {
            self.handle_new_batch(child, None);
        }
        self.refresh_mining();
    }

    fn on_orphan_checked(&mut self, batch: Batch, from: Option<PeerId>, pow_ok: bool) {
        self.orphan_checking.remove(&batch.extension.final_hash);
        if !pow_ok {
            if let Some(peer) = from {
                self.ban_peer(peer, "block with invalid proof of work");
            }
            return;
        }
        if self.sync.is_some() {
            return;
        }
        if batch.prev_header_hash == self.state.header_hash {
            // Its parent arrived in the meantime.
            self.handle_new_batch(batch, from);
            return;
        }
        let ours = primitive_types::U256::from_big_endian(&self.state.target);
        let theirs = primitive_types::U256::from_big_endian(&batch.target);
        let (limit, overflow) = ours.overflowing_mul(primitive_types::U256::from(16u64));
        if !overflow && theirs > limit {
            return;
        }
        self.orphans.insert(batch);
        if let Some(peer) = from {
            self.network.send(peer, Message::GetState);
        }
    }

    /// Adopts `state`, the result of applying `batch` at `height`.
    fn adopt_block(&mut self, state: State, batch: &Batch, height: u64) {
        self.state = state;
        self.last_tip_change = Instant::now();
        self.timestamps.push_back(batch.timestamp);
        while self.timestamps.len() > DIFFICULTY_LOOKBACK as usize {
            self.timestamps.pop_front();
        }
        self.remember_block(batch.extension.final_hash);
        let mined = self.mempool.on_block(batch, &self.state);
        self.reorg_cache.record(height, mined);
        self.stem_pool
            .retain(|_, (tx, _)| crate::core::state::apply_body(&self.state, tx, None).is_ok());
        self.cache_state();
        self.push_light_tip(batch);
        self.publish_info();
    }

    /// Adopts a state reached by applying `blocks` from `first`.
    fn adopt_chain(
        &mut self,
        state: State,
        timestamps: VecDeque<u64>,
        first: u64,
        blocks: &[Batch],
        reorg: bool,
    ) {
        let restored = if reorg {
            self.state_cache.retain(|h, _| *h <= first);
            self.reorg_cache.take_from(first)
        } else {
            Vec::new()
        };
        self.state = state;
        self.last_tip_change = Instant::now();
        self.timestamps = timestamps;
        for (i, b) in blocks.iter().enumerate() {
            self.remember_block(b.extension.final_hash);
            let mined = self.mempool.on_block(b, &self.state);
            self.reorg_cache.record(first + i as u64, mined);
        }
        self.mempool.revalidate(&self.state);
        for tx in restored {
            let _ = self.mempool.add(tx, &self.state, true);
        }
        self.cache_state();
        if let Some(last) = blocks.last() {
            self.push_light_tip(last);
        }
    }

    fn push_light_tip(&mut self, batch: &Batch) {
        if !self.network.has_light_peers() {
            return;
        }
        let filter = CompactFilter::build(batch);
        let n = CompactFilter::items_in(batch).len() as u64;
        self.network
            .broadcast_light_push(&LightNotification::NewBlockTip {
                height: self.state.height - 1,
                target: hex::encode(self.state.target),
                filter_hex: hex::encode(filter.data),
                block_hash: hex::encode(batch.extension.final_hash),
                element_count: n,
            });
    }

    // ── Transactions and Dandelion++ ────────────────────────────────────

    /// Verifies range proofs and signatures on a worker thread.
    fn validate_tx(&mut self, tx: Transaction, origin: TxOrigin) {
        let hash = tx.hash();
        if self.validating_txs.contains(&hash) {
            if let TxOrigin::Local(reply) = origin {
                reply.send(Err(anyhow!("transaction is already being validated")));
            }
            return;
        }
        if self.validating_txs.len() >= MAX_TX_VALIDATIONS {
            if let TxOrigin::Local(reply) = origin {
                reply.send(Err(anyhow!("node busy, try again")));
            }
            return;
        }
        self.validating_txs.insert(hash);
        let internal = self.internal_tx.clone();
        tokio::task::spawn_blocking(move || {
            let result = tx.validate(Context::Relay);
            let _ = internal.send(Internal::TxValidated { tx, origin, result });
        });
    }

    fn on_tx_validated(&mut self, tx: Transaction, origin: TxOrigin, result: Result<()>) {
        self.validating_txs.remove(&tx.hash());
        match origin {
            TxOrigin::Gossip(from) => {
                match result.and_then(|()| self.mempool.add(tx.clone(), &self.state, true)) {
                    Ok(()) => {
                        self.network
                            .broadcast_except(from, Message::Transaction(tx));
                        self.refresh_mining();
                    }
                    Err(e) => tracing::debug!("Transaction rejected: {:#}", e),
                }
            }
            TxOrigin::Stem(from) => match result {
                Ok(()) => self.route_stem(tx, from),
                Err(e) => tracing::debug!("Stem transaction rejected: {:#}", e),
            },
            TxOrigin::Local(reply) => {
                let outcome = result.and_then(|()| self.submit_validated_local(tx));
                reply.send(outcome);
            }
        }
    }

    fn submit_validated_local(&mut self, tx: Transaction) -> Result<()> {
        self.mempool.check(&tx, &self.state, true)?;
        let hash = tx.hash();
        self.mark_tx_seen(hash);
        match self.network.random_peer() {
            Some(peer) => {
                // Dandelion++: we are the first stem hop. Keep it in our stem
                // pool so the embargo timer fluffs it if the stem dies.
                self.stem_pool.insert(hash, (tx.clone(), Instant::now()));
                self.network.send(peer, Message::StemTransaction(tx));
            }
            None => {
                // No peers (solo devnet): straight into our own pool.
                self.mempool.add(tx, &self.state, true)?;
                self.refresh_mining();
            }
        }
        Ok(())
    }

    fn handle_new_transaction(&mut self, tx: Transaction, from: Option<PeerId>) {
        let hash = tx.hash();
        if !self.mark_tx_seen(hash) || self.mempool.contains(&hash) {
            return;
        }
        self.stem_pool.remove(&hash);
        self.validate_tx(tx, TxOrigin::Gossip(from));
    }

    fn handle_stem_transaction(&mut self, tx: Transaction, from: PeerId) {
        let hash = tx.hash();
        if self.stem_pool.contains_key(&hash)
            || self.mempool.contains(&hash)
            || self.stem_pool.len() >= MAX_STEM_POOL
        {
            return;
        }
        self.validate_tx(tx, TxOrigin::Stem(from));
    }

    fn route_stem(&mut self, tx: Transaction, from: PeerId) {
        let hash = tx.hash();
        if self.stem_pool.contains_key(&hash) || self.mempool.contains(&hash) {
            return;
        }
        if let Err(e) = self.mempool.check(&tx, &self.state, true) {
            tracing::debug!("Stem transaction rejected: {:#}", e);
            return;
        }
        let outbound = self.network.outbound_peer_count().max(1) as u32;
        let fluff_percent = (100 / outbound).clamp(2, 50);
        let next = self.network.random_peer_except(from);
        if rand::random::<u32>() % 100 < fluff_percent || next.is_none() {
            self.fluff(tx);
        } else if let Some(next) = next {
            self.stem_pool.insert(hash, (tx.clone(), Instant::now()));
            self.network.send(next, Message::StemTransaction(tx));
        }
    }

    fn fluff(&mut self, tx: Transaction) {
        let hash = tx.hash();
        self.mark_tx_seen(hash);
        match self.mempool.add(tx.clone(), &self.state, true) {
            Ok(()) => {
                self.network.broadcast(Message::Transaction(tx));
                self.refresh_mining();
            }
            Err(e) => tracing::debug!("Fluff failed: {:#}", e),
        }
    }

    /// Fluffs stem transactions whose embargo expired; those expiring
    /// together are merged into one transaction first when possible.
    fn flush_stem_pool(&mut self) {
        let timeout = self.config.stem_timeout;
        let expired: Vec<[u8; 32]> = self
            .stem_pool
            .iter()
            .filter(|(_, (_, t))| t.elapsed() >= timeout)
            .map(|(h, _)| *h)
            .collect();
        if expired.is_empty() {
            return;
        }
        let mut ready = Vec::new();
        for h in expired {
            if let Some((tx, _)) = self.stem_pool.remove(&h) {
                if !self.mempool.contains(&h) && self.mempool.check(&tx, &self.state, true).is_ok()
                {
                    ready.push(tx);
                }
            }
        }
        if ready.len() > 1 {
            if let Ok(agg) = Transaction::aggregate(&ready) {
                if agg.validate_structure(Context::Relay).is_ok()
                    && self.mempool.check(&agg, &self.state, true).is_ok()
                {
                    tracing::debug!(
                        "Dandelion++: fluffing {} stem transactions as one aggregate",
                        ready.len()
                    );
                    self.fluff(agg);
                    return;
                }
            }
        }
        for tx in ready {
            self.fluff(tx);
        }
    }

    // ── Sync: sessions ──────────────────────────────────────────────────

    fn on_state_info(&mut self, peer: PeerId, height: u64, depth: u128) {
        self.peer_tips.insert(peer, (height, depth));
        if let Some(s) = self.sync.as_mut() {
            if s.peer == peer {
                s.peer_height = s.peer_height.max(height);
                s.peer_depth = s.peer_depth.max(depth);
            }
            // A newly known peer may be able to serve blocks.
            self.schedule_batch_requests();
            return;
        }
        if depth > self.state.depth {
            self.start_sync(peer, height, depth, INITIAL_STEP_BACK, true);
        }
    }

    /// Verified headers on disk that extend our tip:
    /// (last header, MTP window after it, their work, count).
    fn resume_point(&self) -> Option<(BatchHeader, VecDeque<u64>, u128, u64)> {
        let mut window: VecDeque<u64> = self
            .storage
            .load_timestamps(self.state.height, MEDIAN_TIME_PAST_WINDOW as u64)
            .ok()?
            .into();
        let mut from = self.state.height;
        let mut last: Option<BatchHeader> = None;
        let (mut work, mut count) = (0u128, 0u64);
        loop {
            let chunk = self
                .storage
                .load_sync_headers(from, MAX_GETHEADERS_COUNT)
                .ok()?;
            let Some(first) = chunk.first() else { break };
            let links = match &last {
                Some(l) => first.prev_header_hash == l.extension.final_hash,
                None => {
                    first.prev_header_hash == self.state.header_hash
                        && first.prev_midstate == self.state.mw_midstate
                }
            };
            if !links {
                break;
            }
            work = work.saturating_add(headers_work(&chunk));
            count += chunk.len() as u64;
            for h in &chunk {
                window.push_back(h.timestamp);
                while window.len() > MEDIAN_TIME_PAST_WINDOW {
                    window.pop_front();
                }
            }
            let full = chunk.len() as u64 == MAX_GETHEADERS_COUNT;
            last = chunk.into_iter().last();
            from = last.as_ref().map_or(from, |l| l.height + 1);
            if !full {
                break;
            }
        }
        last.map(|l| (l, window, work, count))
    }

    fn start_sync(
        &mut self,
        peer: PeerId,
        height: u64,
        depth: u128,
        step_back: u64,
        allow_resume: bool,
    ) {
        let id = self.next_session_id;
        self.next_session_id += 1;
        let our_height = self.state.height;
        let resume = if allow_resume {
            self.resume_point()
        } else {
            None
        };
        let headers = match resume {
            Some((last, window, work, count)) => {
                tracing::info!(
                    "Resuming sync from {}: {} verified headers on disk (to height {})",
                    peer,
                    count,
                    last.height
                );
                self.sync_stats.resumed += 1;
                HeaderSync {
                    start: our_height,
                    fork: Some(our_height),
                    window,
                    verified_to: last.height + 1,
                    their_work: work,
                    our_work: 0,
                    queue: VecDeque::new(),
                    verifying: false,
                    next_fetch: last.height,
                    fetch_in_flight: false,
                    fetch_deferred: false,
                    done: false,
                    expect_overlap: Some(last.extension.final_hash),
                    resumed: true,
                    tip: Some(last),
                }
            }
            None => {
                let _ = self.storage.clear_sync_headers();
                let start = our_height.saturating_sub(step_back);
                let window = self
                    .storage
                    .load_timestamps(start, MEDIAN_TIME_PAST_WINDOW as u64)
                    .unwrap_or_default()
                    .into();
                HeaderSync {
                    start,
                    fork: None,
                    tip: None,
                    window,
                    verified_to: start,
                    their_work: 0,
                    our_work: 0,
                    queue: VecDeque::new(),
                    verifying: false,
                    next_fetch: start,
                    fetch_in_flight: false,
                    fetch_deferred: false,
                    done: false,
                    expect_overlap: None,
                    resumed: false,
                }
            }
        };
        tracing::info!(
            "Syncing from {} (height {}, ours {})",
            peer,
            height,
            our_height
        );
        self.sync_stats.sessions += 1;
        self.sync = Some(SyncSession {
            id,
            peer,
            peer_height: height,
            peer_depth: depth,
            step_back,
            last_progress: Instant::now(),
            headers,
            blocks: None,
        });
        self.miner.stop();
        self.request_headers();
        self.maybe_start_blocks();
        self.schedule_batch_requests();
        self.publish_info();
    }

    fn abort_sync(&mut self, reason: &str) {
        if let Some(s) = self.sync.take() {
            tracing::info!("Sync with {} ended: {}", s.peer, reason);
        }
        self.refresh_mining();
        self.publish_info();
    }

    fn peer_unavailable(&mut self, peer: PeerId) {
        let Some(s) = self.sync.as_mut() else { return };
        if s.peer == peer {
            // Keep verified headers: another session can resume from them.
            self.abort_sync("sync peer unavailable");
            return;
        }
        if let Some(b) = s.blocks.as_mut() {
            let lost: Vec<u64> = b
                .in_flight
                .iter()
                .filter(|(_, f)| f.peer == peer)
                .map(|(k, _)| *k)
                .collect();
            for k in lost {
                if let Some(f) = b.in_flight.remove(&k) {
                    b.retry.push_back((k, f.count));
                }
            }
            b.excluded.insert(peer);
        }
        self.schedule_batch_requests();
    }

    fn check_sync_timeouts(&mut self) {
        let Some(s) = self.sync.as_mut() else { return };
        if s.timed_out() {
            self.abort_sync("timed out");
            return;
        }
        let session_peer = s.peer;
        if let Some(b) = s.blocks.as_mut() {
            let expired: Vec<u64> = b
                .in_flight
                .iter()
                .filter(|(_, f)| f.sent.elapsed().as_secs() >= BATCH_REQUEST_TIMEOUT_SECS)
                .map(|(k, _)| *k)
                .collect();
            for k in expired {
                if let Some(f) = b.in_flight.remove(&k) {
                    b.retry.push_back((k, f.count));
                    if f.peer != session_peer {
                        b.excluded.insert(f.peer);
                    }
                }
            }
        }
        self.schedule_batch_requests();
    }

    fn maybe_finish_sync(&mut self) {
        enum Verdict {
            Wait,
            Abort(&'static str),
            Done(PeerId),
        }
        let verdict = match self.sync.as_ref() {
            None => return,
            Some(s) => {
                let h = &s.headers;
                if !(h.done && h.queue.is_empty() && !h.verifying && !h.fetch_in_flight) {
                    Verdict::Wait
                } else {
                    match &s.blocks {
                        None if h.fork.is_none() => Verdict::Abort("peer has nothing new"),
                        None => Verdict::Abort("peer chain is not heavier"),
                        Some(b) if b.applying || b.rebuilding || b.cursor < h.verified_to => {
                            Verdict::Wait
                        }
                        Some(b) if !b.committed => {
                            Verdict::Abort("downloaded chain did not end up heavier")
                        }
                        Some(_) => Verdict::Done(s.peer),
                    }
                }
            }
        };
        match verdict {
            Verdict::Wait => {}
            Verdict::Abort(reason) => {
                let _ = self.storage.clear_sync_headers();
                self.abort_sync(reason);
            }
            Verdict::Done(peer) => {
                tracing::info!(
                    "Sync with {} complete at height {}",
                    peer,
                    self.state.height
                );
                self.sync = None;
                self.network.send(peer, Message::GetState);
                self.refresh_mining();
                self.publish_info();
            }
        }
    }

    // ── Sync: headers ───────────────────────────────────────────────────

    fn request_headers(&mut self) {
        let Some(s) = self.sync.as_mut() else { return };
        let h = &mut s.headers;
        if h.fetch_in_flight || h.done {
            return;
        }
        if h.queue.len() >= MAX_QUEUED_HEADER_CHUNKS {
            h.fetch_deferred = true;
            return;
        }
        h.fetch_deferred = false;
        h.fetch_in_flight = true;
        let (peer, start) = (s.peer, h.next_fetch);
        self.network.send(
            peer,
            Message::GetHeaders {
                start_height: start,
                count: MAX_GETHEADERS_COUNT,
            },
        );
    }

    fn on_headers(&mut self, peer: PeerId, start_height: u64, chunk: Vec<BatchHeader>) {
        let Some(mut s) = self.sync.take() else {
            return;
        };
        if s.peer != peer || !s.headers.fetch_in_flight || start_height != s.headers.next_fetch {
            self.sync = Some(s);
            return;
        }
        s.headers.fetch_in_flight = false;
        s.last_progress = Instant::now();
        let step = self.examine_headers(&mut s, chunk);
        let (height, depth) = (s.peer_height, s.peer_depth);
        self.sync = Some(s);
        match step {
            HeaderStep::Continue => {
                self.request_headers();
                self.verify_next_header_chunk();
                self.maybe_finish_sync();
            }
            HeaderStep::Ban(reason) => self.ban_peer(peer, reason),
            HeaderStep::Abort(reason) => self.abort_sync(reason),
            HeaderStep::Restart {
                step_back: new_step,
                allow_resume,
            } => {
                self.sync = None;
                self.start_sync(peer, height, depth, new_step, allow_resume);
            }
        }
    }

    /// Checks a header chunk's labels and linkage and queues it for
    /// verification.
    fn examine_headers(&mut self, s: &mut SyncSession, mut chunk: Vec<BatchHeader>) -> HeaderStep {
        let full = chunk.len() as u64 == MAX_GETHEADERS_COUNT;
        let h = &mut s.headers;
        if let Some(expected) = h.expect_overlap.take() {
            // Resuming: the peer must still have the last header we verified.
            if chunk.first().map(|x| x.extension.final_hash) != Some(expected) {
                tracing::info!(
                    "Stored sync progress does not match {}; starting over",
                    s.peer
                );
                let _ = self.storage.clear_sync_headers();
                return HeaderStep::Restart {
                    step_back: INITIAL_STEP_BACK,
                    allow_resume: false,
                };
            }
            chunk.remove(0);
            h.next_fetch += 1;
        }
        if chunk.is_empty() {
            if h.tip.is_none() {
                return HeaderStep::Abort("peer returned no headers");
            }
            if !full {
                h.done = true;
            }
            return HeaderStep::Continue;
        }
        if chunk
            .iter()
            .enumerate()
            .any(|(i, x)| x.height != h.next_fetch + i as u64)
        {
            return HeaderStep::Ban("mislabelled headers");
        }
        match &h.tip {
            Some(tip) => {
                if chunk[0].prev_header_hash != tip.extension.final_hash
                    || chunk[0].prev_midstate != tip.post_tx_midstate
                {
                    return HeaderStep::Ban("header chunks do not link");
                }
            }
            None => {
                let links = if h.start == 0 {
                    chunk[0].extension.final_hash == Batch::genesis().extension.final_hash
                } else {
                    match self.storage.load_header(h.start - 1).ok().flatten() {
                        Some(ours) => {
                            ours.extension.final_hash == chunk[0].prev_header_hash
                                && ours.post_tx_midstate == chunk[0].prev_midstate
                        }
                        None => false,
                    }
                };
                if !links {
                    if h.start == 0 {
                        return HeaderStep::Ban("different genesis");
                    }
                    // The fork is deeper than we looked: step further back.
                    let step_back = s.step_back.saturating_mul(8);
                    if step_back > MAX_REORG_DEPTH.saturating_mul(8) {
                        return HeaderStep::Abort("fork deeper than the reorg limit");
                    }
                    return HeaderStep::Restart {
                        step_back,
                        allow_resume: false,
                    };
                }
            }
        }
        h.next_fetch += chunk.len() as u64;
        h.tip = chunk.last().cloned();
        h.queue.push_back(chunk);
        if !(full && h.next_fetch < s.peer_height) {
            h.done = true;
        }
        HeaderStep::Continue
    }

    fn verify_next_header_chunk(&mut self) {
        let Some(s) = self.sync.as_mut() else { return };
        if s.headers.verifying {
            return;
        }
        let Some(chunk) = s.headers.queue.pop_front() else {
            return;
        };
        s.headers.verifying = true;
        let prior: Vec<u64> = s.headers.window.iter().copied().collect();
        let deferred = s.headers.fetch_deferred;
        let (id, tx) = (s.id, self.internal_tx.clone());
        tokio::task::spawn_blocking(move || {
            let result = verify_header_chain(&chunk, &prior, true);
            let _ = tx.send(Internal::HeadersVerified {
                session: id,
                chunk,
                result,
            });
        });
        if deferred {
            self.request_headers();
        }
    }

    fn on_headers_verified(&mut self, id: u64, chunk: Vec<BatchHeader>, result: Result<()>) {
        let Some(mut s) = self.sync.take() else {
            return;
        };
        if s.id != id {
            self.sync = Some(s);
            return;
        }
        s.headers.verifying = false;
        let peer = s.peer;
        if let Err(e) = result {
            self.sync = Some(s);
            self.ban_peer(peer, &format!("invalid header chain: {e:#}"));
            return;
        }
        self.sync_stats.header_chunks_verified += 1;
        s.last_progress = Instant::now();
        for x in &chunk {
            s.headers.window.push_back(x.timestamp);
            while s.headers.window.len() > MEDIAN_TIME_PAST_WINDOW {
                s.headers.window.pop_front();
            }
        }
        let last_height = chunk.last().map_or(s.headers.verified_to, |x| x.height + 1);
        let our_len = self.state.height;

        let new_headers: Vec<BatchHeader> = if s.headers.fork.is_some() {
            chunk
        } else {
            // Fork point: the first height where the peer's chain leaves ours.
            let mut fork = None;
            for x in &chunk {
                let ours = if x.height < our_len {
                    self.storage
                        .load_header(x.height)
                        .ok()
                        .flatten()
                        .map(|o| o.extension.final_hash)
                } else {
                    None
                };
                if ours != Some(x.extension.final_hash) {
                    fork = Some(x.height);
                    break;
                }
            }
            match fork {
                None => {
                    // This whole chunk is already ours; keep reading.
                    s.headers.verified_to = last_height;
                    if last_height >= our_len {
                        s.headers.fork = Some(our_len);
                    }
                    Vec::new()
                }
                Some(fork) => {
                    if our_len - fork > MAX_REORG_DEPTH || fork < self.finality.floor() {
                        self.sync = Some(s);
                        let _ = self.storage.clear_sync_headers();
                        self.abort_sync(
                            "reorg below the finalized checkpoint or deeper than the limit",
                        );
                        return;
                    }
                    if fork < our_len {
                        tracing::warn!(
                            "Fork found at height {} ({} of our blocks at stake)",
                            fork,
                            our_len - fork
                        );
                    }
                    s.headers.fork = Some(fork);
                    s.headers.our_work = headers_work(
                        &self
                            .storage
                            .load_headers(fork, our_len - fork)
                            .unwrap_or_default(),
                    );
                    chunk.into_iter().filter(|x| x.height >= fork).collect()
                }
            }
        };
        if !new_headers.is_empty() {
            if let Err(e) = self.storage.save_sync_headers(&new_headers) {
                tracing::warn!("Could not persist verified headers: {:#}", e);
            }
            s.headers.their_work = s
                .headers
                .their_work
                .saturating_add(headers_work(&new_headers));
        }
        s.headers.verified_to = last_height;
        self.sync = Some(s);

        self.maybe_start_blocks();
        self.schedule_batch_requests();
        self.request_headers();
        self.verify_next_header_chunk();
        self.maybe_finish_sync();
    }

    // ── Sync: blocks ────────────────────────────────────────────────────

    /// Starts block download once the verified headers outweigh our chain.
    fn maybe_start_blocks(&mut self) {
        let Some(s) = self.sync.as_mut() else { return };
        if s.blocks.is_some() {
            return;
        }
        let Some(fork) = s.headers.fork else { return };
        if s.headers.their_work <= s.headers.our_work || s.headers.verified_to <= fork {
            return;
        }
        let our_len = self.state.height;
        let timestamps: VecDeque<u64> = self
            .storage
            .load_timestamps(fork, DIFFICULTY_LOOKBACK)
            .unwrap_or_default()
            .into();
        let mut blocks = BlockSync::new(fork, timestamps, fork == our_len);
        if fork == our_len {
            blocks.candidate = Some(self.state.clone());
        } else if let Some((cached, _)) = self.state_cache.get(&fork) {
            blocks.candidate = Some(cached.clone());
        } else {
            // Pipelined: derive the fork state while blocks download.
            tracing::info!(
                "Deriving the state at fork height {} from undo records",
                fork
            );
            blocks.rebuilding = true;
            let (storage, current, id, tx) = (
                self.storage.clone(),
                self.state.clone(),
                s.id,
                self.internal_tx.clone(),
            );
            tokio::task::spawn_blocking(move || {
                let result = storage.state_at(&current, fork);
                let _ = tx.send(Internal::ForkState {
                    session: id,
                    result,
                });
            });
        }
        s.blocks = Some(blocks);
    }

    fn on_fork_state(&mut self, id: u64, result: Result<State>) {
        let Some(s) = self.sync.as_mut() else { return };
        if s.id != id {
            return;
        }
        match result {
            Ok(state) => {
                if let Some(b) = s.blocks.as_mut() {
                    b.rebuilding = false;
                    b.candidate = Some(state);
                }
                self.try_apply_next();
            }
            Err(e) => {
                tracing::error!("Could not derive the fork state: {:#}", e);
                self.abort_sync("fork state unavailable");
            }
        }
    }

    fn schedule_batch_requests(&mut self) {
        let connected: HashSet<PeerId> = self.network.connected_peers().into_iter().collect();
        let Some(s) = self.sync.as_mut() else { return };
        let end = s.headers.verified_to;
        let session_peer = s.peer;
        let Some(b) = s.blocks.as_mut() else { return };
        let mut sends = Vec::new();
        while b.in_flight.len() < MAX_BATCH_REQUESTS_IN_FLIGHT
            && b.buffered_bytes < MAX_BUFFER_BYTES
        {
            let (start, count) = match b.retry.pop_front() {
                Some(r) => r,
                None => {
                    if b.next_request >= end
                        || b.next_request >= b.cursor.saturating_add(BATCH_LOOKAHEAD_BLOCKS)
                    {
                        break;
                    }
                    let count = (end - b.next_request).min(MAX_GETBATCHES_COUNT);
                    let r = (b.next_request, count);
                    b.next_request += count;
                    r
                }
            };
            // Any connected peer that reported having these blocks; the
            // session peer is always a fallback.
            let mut candidates: Vec<PeerId> = self
                .peer_tips
                .iter()
                .filter(|(p, (h, _))| {
                    *h >= start + count && connected.contains(*p) && !b.excluded.contains(*p)
                })
                .map(|(p, _)| *p)
                .collect();
            if !candidates.contains(&session_peer) {
                candidates.push(session_peer);
            }
            let load = |p: &PeerId| b.in_flight.values().filter(|f| f.peer == *p).count();
            let peer = candidates
                .into_iter()
                .min_by_key(|p| (load(p), *p != session_peer))
                .expect("session peer is always a candidate");
            b.in_flight.insert(
                start,
                InFlight {
                    peer,
                    count,
                    sent: Instant::now(),
                },
            );
            sends.push((peer, start, count));
        }
        for (peer, start, count) in sends {
            self.network.send(
                peer,
                Message::GetBatches {
                    start_height: start,
                    count,
                },
            );
        }
    }

    fn on_batches(&mut self, peer: PeerId, start_height: u64, mut batches: Vec<Batch>) {
        enum Verdict {
            Ok,
            Ban(&'static str),
            Abort(&'static str),
        }
        let Some(s) = self.sync.as_mut() else { return };
        let session_peer = s.peer;
        let Some(b) = s.blocks.as_mut() else { return };
        match b.in_flight.get(&start_height) {
            Some(f) if f.peer == peer => {}
            _ => return,
        }
        let req = b.in_flight.remove(&start_height).expect("checked above");
        s.last_progress = Instant::now();
        batches.truncate(req.count as usize);

        let verdict = if batches.is_empty() {
            b.retry.push_back((start_height, req.count));
            if peer == session_peer {
                Verdict::Abort("sync peer returned no blocks")
            } else {
                b.excluded.insert(peer);
                Verdict::Ok
            }
        } else {
            let expected = self
                .storage
                .load_sync_headers(start_height, batches.len() as u64)
                .unwrap_or_default();
            let matches = expected.len() == batches.len()
                && batches
                    .iter()
                    .zip(&expected)
                    .all(|(x, h)| x.extension == h.extension && x.aux_pow == h.aux_pow);
            if !matches {
                b.retry.push_back((start_height, req.count));
                if peer == session_peer {
                    Verdict::Ban("blocks do not match the verified headers")
                } else {
                    // Probably on another chain; just stop asking it.
                    b.excluded.insert(peer);
                    Verdict::Ok
                }
            } else {
                let got = batches.len() as u64;
                if got < req.count {
                    // Size-limited response: fetch the rest next.
                    b.retry.push_front((start_height + got, req.count - got));
                }
                let bytes: usize = batches
                    .iter()
                    .map(|x| bincode::serialized_size(x).unwrap_or(0) as usize)
                    .sum();
                b.buffered_bytes += bytes;
                b.buffer.insert(
                    start_height,
                    Chunk {
                        source: peer,
                        batches,
                        headers: expected,
                        bytes,
                    },
                );
                Verdict::Ok
            }
        };
        match verdict {
            Verdict::Ok => {
                self.try_apply_next();
                self.schedule_batch_requests();
            }
            Verdict::Ban(reason) => self.ban_peer(peer, reason),
            Verdict::Abort(reason) => self.abort_sync(reason),
        }
    }

    fn try_apply_next(&mut self) {
        let Some(s) = self.sync.as_mut() else { return };
        let id = s.id;
        let Some(b) = s.blocks.as_mut() else { return };
        if b.applying || b.candidate.is_none() {
            return;
        }
        // Drop chunks entirely behind the cursor (overlapping retries).
        while let Some((&k, c)) = b.buffer.first_key_value() {
            if k + c.batches.len() as u64 > b.cursor {
                break;
            }
            if let Some(c) = b.buffer.remove(&k) {
                b.buffered_bytes -= c.bytes;
            }
        }
        let Some((&k, _)) = b.buffer.first_key_value() else {
            return;
        };
        if k > b.cursor {
            return; // waiting for the chunk at the cursor
        }
        let mut chunk = b.buffer.remove(&k).expect("key exists");
        b.buffered_bytes -= chunk.bytes;
        let skip = (b.cursor - k) as usize;
        chunk.batches.drain(..skip);
        chunk.headers.drain(..skip);

        let mut state = b.candidate.take().expect("checked above");
        let mut ts = b.timestamps.clone();
        b.applying = true;
        let tx = self.internal_tx.clone();
        let source = chunk.source;
        tokio::task::spawn_blocking(move || {
            let mut applied = Vec::new();
            let mut error = None;
            for (batch, header) in chunk.batches.into_iter().zip(chunk.headers) {
                if let Err(e) = apply_batch_skip_pow(
                    &mut state,
                    &batch,
                    ts.make_contiguous(),
                    compute_header_hash(&header),
                ) {
                    error = Some(format!("block {} invalid: {e:#}", header.height));
                    break;
                }
                ts.push_back(batch.timestamp);
                while ts.len() > DIFFICULTY_LOOKBACK as usize {
                    ts.pop_front();
                }
                applied.push(batch);
            }
            let _ = tx.send(Internal::BatchesApplied {
                session: id,
                source,
                candidate: state,
                timestamps: ts,
                applied,
                error,
            });
        });
    }

    fn on_batches_applied(
        &mut self,
        id: u64,
        source: PeerId,
        new_state: State,
        new_ts: VecDeque<u64>,
        applied: Vec<Batch>,
        error: Option<String>,
    ) {
        let Some(mut s) = self.sync.take() else {
            return;
        };
        if s.id != id || s.blocks.is_none() {
            self.sync = Some(s);
            return;
        }
        let session_peer = s.peer;
        let verified_to = s.headers.verified_to;
        let our_height = self.state.height;
        let mut fatal: Option<(bool, String)> = None;
        let mut ban_other = None;
        {
            let b = s.blocks.as_mut().expect("checked above");
            b.applying = false;
            let first = b.cursor;
            b.cursor += applied.len() as u64;
            b.timestamps = new_ts.clone();
            if !applied.is_empty() {
                s.last_progress = Instant::now();
                self.sync_stats.batch_chunks_applied += 1;
                self.batch_sources.insert(source);
            }
            if b.committed {
                if !applied.is_empty() {
                    if our_height != first {
                        fatal = Some((false, "chain tip moved during sync".into()));
                    } else if let Err(e) = self.storage.commit_chain(first, &applied, &new_state) {
                        fatal = Some((false, format!("persisting synced blocks failed: {e:#}")));
                    } else {
                        self.adopt_chain(new_state.clone(), new_ts, first, &applied, false);
                    }
                }
            } else {
                b.staged.extend(applied);
                let heavier = new_state.depth > self.state.depth
                    && choose_best_state(&self.state, &new_state).mw_midstate
                        == new_state.mw_midstate;
                if heavier {
                    let blocks = std::mem::take(&mut b.staged);
                    match self.storage.commit_chain(b.fork, &blocks, &new_state) {
                        Ok(()) => {
                            tracing::warn!(
                                "REORG: replaced {} block(s) from height {}; new height {}",
                                self.state.height - b.fork,
                                b.fork,
                                new_state.height
                            );
                            self.adopt_chain(new_state.clone(), new_ts, b.fork, &blocks, true);
                            b.committed = true;
                        }
                        Err(e) => fatal = Some((false, format!("persisting reorg failed: {e:#}"))),
                    }
                }
            }
            b.candidate = Some(new_state);

            if let Some(e) = error {
                if source == session_peer {
                    fatal = Some((true, e));
                } else {
                    // Only that peer's data was bad: drop it, refetch elsewhere.
                    b.excluded.insert(source);
                    let theirs: Vec<u64> = b
                        .buffer
                        .iter()
                        .filter(|(_, c)| c.source == source)
                        .map(|(k, _)| *k)
                        .collect();
                    for k in theirs {
                        if let Some(c) = b.buffer.remove(&k) {
                            b.buffered_bytes -= c.bytes;
                            b.retry.push_back((k, c.batches.len() as u64));
                        }
                    }
                    let next_key = b.buffer.keys().next().copied().unwrap_or(u64::MAX);
                    let count = next_key
                        .min(verified_to)
                        .saturating_sub(b.cursor)
                        .min(MAX_GETBATCHES_COUNT);
                    if count > 0 {
                        b.retry.push_front((b.cursor, count));
                    }
                    ban_other = Some((source, e));
                }
            }
        }
        self.sync = Some(s);
        if let Some((peer, e)) = ban_other {
            tracing::warn!("Banning peer {}: served an invalid block ({})", peer, e);
            self.peer_tips.remove(&peer);
            self.network.ban_peer(peer);
        }
        match fatal {
            Some((true, e)) => {
                self.ban_peer(session_peer, &e);
                return;
            }
            Some((false, e)) => {
                self.abort_sync(&e);
                return;
            }
            None => {}
        }
        self.try_apply_next();
        self.schedule_batch_requests();
        self.maybe_finish_sync();
        self.publish_info();
    }

    // ── Finality and snapshots ──────────────────────────────────────────

    fn anchors_path(&self) -> PathBuf {
        self.config
            .anchors_file
            .clone()
            .unwrap_or_else(|| self.config.data_dir.join("anchors.jsonl"))
    }

    fn refresh_finality(&mut self) {
        let path = self.anchors_path();
        let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if len != self.anchors_seen_len {
            self.anchors_seen_len = len;
            match load_records(&path) {
                Ok(records) => {
                    for r in records {
                        if let Err(e) = self.finality.add(r) {
                            tracing::debug!("ignoring stored anchor: {:#}", e);
                        }
                    }
                }
                Err(e) => tracing::warn!("reading {}: {:#}", path.display(), e),
            }
        }
        match self.finality.refresh(&self.storage, &self.state) {
            Ok(Some(info)) => {
                if let Err(e) = self.storage.set_finality(&info) {
                    tracing::error!("recording finality failed: {:#}", e);
                    return;
                }
                tracing::info!("checkpoint at height {} finalized", info.floor);
                self.state_cache.retain(|h, _| *h >= info.floor);
                if self.config.finality.prune {
                    match self.storage.prune_bodies_below(info.floor) {
                        Ok(n) if n > 0 => {
                            tracing::info!("pruned {} block bodies below height {}", n, info.floor)
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!("pruning failed: {:#}", e),
                    }
                }
                self.publish_info();
            }
            Ok(None) => {}
            Err(e) => tracing::warn!("finality refresh failed: {:#}", e),
        }
    }

    /// One part of a snapshot, building it in the background on first use.
    /// `total == 0` means "not ready yet, ask again".
    fn snapshot_part(&mut self, checkpoint_id: [u8; 32], part: u32) -> Message {
        let not_ready = Message::SnapshotPart {
            checkpoint_id,
            part,
            total: 0,
            data: Vec::new(),
        };
        if let Some((id, bytes)) = &self.snapshot_cache {
            if *id == checkpoint_id {
                let total = bytes.len().div_ceil(SNAPSHOT_PART_BYTES).max(1) as u32;
                let start = part as usize * SNAPSHOT_PART_BYTES;
                if part >= total {
                    return not_ready;
                }
                let data = bytes[start..(start + SNAPSHOT_PART_BYTES).min(bytes.len())].to_vec();
                return Message::SnapshotPart {
                    checkpoint_id,
                    part,
                    total,
                    data,
                };
            }
        }
        let Some(record) = self.finality.get(&checkpoint_id).cloned() else {
            return not_ready;
        };
        if self.snapshot_building.is_none() {
            self.snapshot_building = Some(checkpoint_id);
            let (storage, state, tx) = (
                self.storage.clone(),
                self.state.clone(),
                self.internal_tx.clone(),
            );
            tokio::task::spawn_blocking(move || {
                let result = storage
                    .export_snapshot(&state, &record.checkpoint)
                    .and_then(|s| Ok(Arc::new(bincode::serialize(&s)?)));
                let _ = tx.send(Internal::SnapshotReady {
                    checkpoint_id,
                    result,
                });
            });
        }
        not_ready
    }

    // ── Mining ──────────────────────────────────────────────────────────

    fn refresh_mining(&mut self) {
        let Some(payout) = self.config.mine_to else {
            self.miner.stop();
            return;
        };
        if self.sync.is_some()
            || self.state.height == 0
            || self.last_tip_change.elapsed() < self.config.min_block_interval
        {
            // The fast tick retries once the pacing interval has passed.
            self.miner.stop();
            return;
        }
        let budget = MAX_BLOCK_WEIGHT - OUTPUT_WEIGHT - KERNEL_WEIGHT;
        let txs = select_transactions(&self.mempool.candidates(), self.state.height, budget);
        let template = build_template(
            &self.state,
            self.timestamps.make_contiguous(),
            &txs,
            &payout,
            None,
        )
        .or_else(|e| {
            tracing::warn!(
                "Template with {} transactions failed ({:#}); mining an empty block",
                txs.len(),
                e
            );
            build_template(
                &self.state,
                self.timestamps.make_contiguous(),
                &[],
                &payout,
                None,
            )
        });
        match template {
            Ok(t) => self.miner.start(t),
            Err(e) => tracing::error!("Cannot build a block template: {:#}", e),
        }
    }

    // ── Light clients ───────────────────────────────────────────────────

    fn handle_light_request(&mut self, request: LightRequest) -> LightResponse {
        match self.light_request_inner(request) {
            Ok(v) => LightResponse::success(v),
            Err(e) => LightResponse::error(format!("{e:#}")),
        }
    }

    fn light_request_inner(&mut self, request: LightRequest) -> Result<serde_json::Value> {
        use serde_json::json;
        Ok(match request {
            LightRequest::GetState => json!({
                "height": self.state.height,
                "depth": self.state.depth.to_string(),
                "tip": hex::encode(self.state.header_hash),
                "target": hex::encode(self.state.target),
                "state_root": hex::encode(self.state.state_root()),
                "supply": self.state.supply,
                "utxos": self.state.utxos.len(),
            }),
            LightRequest::GetHeaders {
                start_height,
                count,
            } => {
                let headers = self
                    .storage
                    .load_headers(start_height, count.min(MAX_GETHEADERS_COUNT))?;
                json!({ "headers_hex": hex::encode(bincode::serialize(&headers)?) })
            }
            LightRequest::GetBlock { height } => {
                let batch = self
                    .storage
                    .load_batch(height)?
                    .ok_or_else(|| anyhow!("no block at {height}"))?;
                json!({ "height": height, "block_hex": hex::encode(bincode::serialize(&batch)?) })
            }
            LightRequest::GetFilters {
                start_height,
                end_height,
            } => {
                let end = end_height
                    .min(start_height.saturating_add(1000))
                    .min(self.state.height);
                let mut filters = Vec::new();
                for h in start_height..end {
                    if let Some(b) = self.storage.load_batch(h)? {
                        filters.push(json!({
                            "height": h,
                            "block_hash": hex::encode(b.extension.final_hash),
                            "filter_hex": hex::encode(CompactFilter::build(&b).data),
                            "element_count": CompactFilter::items_in(&b).len(),
                        }));
                    }
                }
                json!({ "filters": filters })
            }
            LightRequest::GetMempool => {
                json!({ "count": self.mempool.len(), "weight": self.mempool.total_weight() })
            }
            LightRequest::SubmitTransaction { .. } => {
                return Err(anyhow!("submissions are handled asynchronously"));
            }
            LightRequest::GetUtxoProof { commitment } => {
                let bytes: [u8; 32] = hex::decode(commitment)?
                    .try_into()
                    .map_err(|_| anyhow!("commitment must be 32 bytes"))?;
                let entry = self
                    .state
                    .utxos
                    .get(&bytes)
                    .ok_or_else(|| anyhow!("not in the UTXO set"))?;
                let proof = self.state.utxo_set.prove(&utxo_leaf(&bytes, entry), true)?;
                json!({
                    "height": entry.height,
                    "coinbase": entry.coinbase,
                    "owner_key": hex::encode(entry.owner_key),
                    "state_root": hex::encode(self.state.state_root()),
                    "proof": proof,
                })
            }
        })
    }
}

/// Checkpoint verification: fetches the trusted checkpoint's anchor record
/// and snapshot from peers, verifies both, and imports the snapshot into the
/// (empty) database (`docs/PRUNING.md` §5).
async fn bootstrap_from_checkpoint(
    network: &mut Network,
    storage: &Storage,
    trusted: [u8; 32],
    config: &NodeConfig,
) -> Result<()> {
    tracing::info!(
        "checkpoint sync: looking for checkpoint {}",
        hex::encode(trusted)
    );
    let deadline = Instant::now() + config.bootstrap_timeout;
    let fin = &config.finality;
    // A locally supplied record is used if present.
    let mut record: Option<AnchorRecord> = load_records(
        &config
            .anchors_file
            .clone()
            .unwrap_or_else(|| config.data_dir.join("anchors.jsonl")),
    )
    .unwrap_or_default()
    .into_iter()
    .find(|r| r.checkpoint.id() == trusted);
    if let Some(r) = &record {
        r.verify_standalone(fin.anchor_depth, fin.min_work)?;
    }
    let mut source: Option<PeerId> = None;
    let mut parts: Vec<Option<Vec<u8>>> = Vec::new();
    let mut asked: HashSet<PeerId> = HashSet::new();
    let mut retry = tokio::time::interval(Duration::from_millis(500));
    loop {
        if Instant::now() > deadline {
            anyhow::bail!("checkpoint sync timed out");
        }
        tokio::select! {
            _ = retry.tick() => {
                for peer in network.connected_peers() {
                    if record.is_none() && asked.insert(peer) {
                        network.send(peer, Message::GetAnchors);
                    }
                }
                if let (Some(_), None) = (&record, source) {
                    source = network.random_peer();
                }
                if let (Some(_), Some(peer)) = (&record, source) {
                    let next = parts.iter().position(Option::is_none).unwrap_or(parts.len()) as u32;
                    network.send(peer, Message::GetSnapshot { checkpoint_id: trusted, part: next });
                }
            }
            event = network.next_event() => {
                let NetworkEvent::MessageReceived { peer, message, channel } = event else { continue };
                if let Some(ch) = channel {
                    network.respond(ch, Message::Pong { nonce: 0 });
                }
                match message {
                    Message::Anchors(list) if record.is_none() => {
                        if let Some(r) = list.into_iter().find(|r| r.checkpoint.id() == trusted) {
                            match r.verify_standalone(fin.anchor_depth, fin.min_work) {
                                Ok(()) => {
                                    tracing::info!("checkpoint sync: anchor evidence verified (from {})", peer);
                                    record = Some(r);
                                    source = Some(peer);
                                }
                                Err(e) => tracing::warn!("checkpoint sync: bad anchor from {}: {:#}", peer, e),
                            }
                        }
                    }
                    Message::SnapshotPart { checkpoint_id, part, total, data } if checkpoint_id == trusted && Some(peer) == source => {
                        if total == 0 {
                            continue; // not ready: the retry tick asks again
                        }
                        if parts.len() != total as usize {
                            parts = vec![None; total as usize];
                        }
                        if let Some(slot) = parts.get_mut(part as usize) {
                            *slot = Some(data);
                        }
                        if let Some(next) = parts.iter().position(Option::is_none) {
                            network.send(peer, Message::GetSnapshot { checkpoint_id: trusted, part: next as u32 });
                            continue;
                        }
                        let bytes: Vec<u8> = parts.drain(..).flatten().flatten().collect();
                        let snapshot: Snapshot = bincode::deserialize(&bytes)?;
                        let state = tokio::task::spawn_blocking(move || snapshot.verify(&trusted).map(|s| (snapshot, s)))
                            .await
                            .map_err(|e| anyhow!("verification task failed: {e}"))?;
                        match state {
                            Ok((snapshot, state)) => {
                                storage.import_snapshot(&snapshot, &state)?;
                                if let Some(r) = &record {
                                    let path = config.anchors_file.clone().unwrap_or_else(|| config.data_dir.join("anchors.jsonl"));
                                    let _ = crate::anchor::append_record(&path, r);
                                }
                                tracing::info!("checkpoint sync: imported state at height {}", state.height);
                                return Ok(());
                            }
                            Err(e) => {
                                tracing::warn!("checkpoint sync: snapshot from {} rejected: {:#}", peer, e);
                                network.ban_peer(peer);
                                source = None;
                                parts.clear();
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
