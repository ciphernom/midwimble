//! Peer-to-peer networking.
//!
//! Ported from midstate `src/network/mod.rs`. Kept as-is: the behaviour stack
//! (request-response, raw light-client streams, Kademlia, identify, circuit
//! relay client and server, DCUtR hole punching, AutoNAT, connection limits),
//! the light-client rate limiter with Beta-distribution reputation, subnet
//! eclipse limits, inbound caps, PEX with routability filtering, relay
//! maintenance behind NAT, and the relay-address leak fixes.
//!
//! Changed:
//! * Protocol ids are `/midwimble/...`, including Kademlia. Midstate had to
//!   keep libp2p's default `/ipfs/kad/1.0.0` for compatibility with deployed
//!   nodes; a new network does not, and a private protocol id keeps foreign
//!   IPFS peers out of the routing table by construction (the identify
//!   filter is kept as a second line of defence).
//! * The HTTP seed registry (`seeds.midstate.cash`) is removed: it belongs to
//!   midstate. Bootstrap is config peers, the Amino DHT rendezvous
//!   (`amino.rs`), the on-disk address book and PEX.
//! * WebRTC-direct (browser light clients) is behind the `webrtc` feature.

pub mod amino;
pub mod light_protocol;
pub mod protocol;

pub use protocol::{
    Message, MidwimbleCodec, MAX_GETBATCHES_COUNT, MAX_GETHEADERS_COUNT, MIDWIMBLE_PROTOCOL,
};

use anyhow::Result;
use futures::StreamExt;
use libp2p::{
    autonat,
    core::ConnectedPoint,
    dcutr, identify,
    identity::Keypair,
    kad, noise, relay,
    request_response::{
        self, Config as RequestResponseConfig, OutboundRequestId, ProtocolSupport, ResponseChannel,
    },
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm,
};
use light_protocol::{
    LightNotification, LightRequest, LightResponse, LIGHT_PROTOCOL, LIGHT_PUSH_PROTOCOL,
};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const MAX_PEX_ADDRS: usize = 50;
pub const KAD_PROTOCOL: StreamProtocol = StreamProtocol::new("/midwimble/kad/1.0.0");
const IDENTIFY_PROTOCOL: &str = "/midwimble/id/1.0.0";
const MAX_INBOUND_PEERS: usize = 200;
const MAX_PEERS_PER_SUBNET: usize = 4;

// ── Light client protection (midstate) ──────────────────────────────────────

const MAX_LIGHT_PEERS: usize = 500;
const MAX_LIGHT_STREAMS_PER_PEER: usize = 50;
const LIGHT_RATE_WINDOW_SECS: u64 = 60;
const LIGHT_BAN_THRESHOLD: u32 = 20;
const LIGHT_BAN_DURATION_SECS: u64 = 500;
const LIGHT_READ_TIMEOUT_SECS: u64 = 10;
const LIGHT_RESPONSE_TIMEOUT_SECS: u64 = 30;

struct LightPeerState {
    request_count: u32,
    expensive_count: u32,
    window_start: Instant,
    active_streams: u32,
    violations: u32,
    banned_until: Option<Instant>,
    /// Beta-distribution reputation: honest observations.
    alpha: u32,
    /// Beta-distribution reputation: adversarial observations.
    beta: u32,
}

impl LightPeerState {
    fn new() -> Self {
        Self {
            request_count: 0,
            expensive_count: 0,
            window_start: Instant::now(),
            active_streams: 0,
            violations: 0,
            banned_until: None,
            alpha: 1,
            beta: 1,
        }
    }

    fn honesty(&self) -> f32 {
        self.alpha as f32 / (self.alpha + self.beta) as f32
    }

    fn current_rate_limit(&self) -> u32 {
        let p = self.honesty();
        if p < 0.1 {
            return 5;
        }
        (50.0 + 450.0 * p) as u32
    }

    fn current_expensive_limit(&self) -> u32 {
        let p = self.honesty();
        if p < 0.2 {
            return 5;
        }
        (20.0 + 200.0 * p) as u32
    }

    fn maybe_reset_window(&mut self) {
        if self.window_start.elapsed().as_secs() >= LIGHT_RATE_WINDOW_SECS {
            self.request_count = 0;
            self.expensive_count = 0;
            self.window_start = Instant::now();
        }
    }

    fn is_banned(&self) -> bool {
        self.banned_until.map_or(false, |t| Instant::now() < t)
    }

    fn strike(&mut self) -> bool {
        self.violations += 1;
        if self.violations >= LIGHT_BAN_THRESHOLD {
            self.banned_until = Some(Instant::now() + Duration::from_secs(LIGHT_BAN_DURATION_SECS));
            true
        } else {
            false
        }
    }
}

#[derive(Clone)]
struct LightGuard {
    inner: Arc<tokio::sync::Mutex<HashMap<PeerId, LightPeerState>>>,
}

impl LightGuard {
    fn new() -> Self {
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    async fn try_open_stream(&self, peer: PeerId) -> Result<(), &'static str> {
        let mut peers = self.inner.lock().await;
        let state = peers.entry(peer).or_insert_with(LightPeerState::new);
        if state.is_banned() {
            return Err("banned: peer is temporarily banned");
        }
        state.maybe_reset_window();
        if state.active_streams >= MAX_LIGHT_STREAMS_PER_PEER as u32 {
            return Err(if state.strike() {
                "banned: too many concurrent streams"
            } else {
                "too many concurrent streams"
            });
        }
        if state.request_count >= state.current_rate_limit() {
            return Err(if state.strike() {
                "banned: rate limit exceeded"
            } else {
                "rate limit exceeded"
            });
        }
        state.active_streams += 1;
        state.request_count += 1;
        Ok(())
    }

    async fn check_expensive(&self, peer: PeerId) -> bool {
        let mut peers = self.inner.lock().await;
        if let Some(state) = peers.get_mut(&peer) {
            state.maybe_reset_window();
            if state.expensive_count >= state.current_expensive_limit() {
                state.strike();
                return false;
            }
            state.expensive_count += 1;
        }
        true
    }

    async fn close_stream(&self, peer: PeerId) {
        if let Some(state) = self.inner.lock().await.get_mut(&peer) {
            state.active_streams = state.active_streams.saturating_sub(1);
        }
    }

    async fn remove_peer(&self, peer: &PeerId) {
        self.inner.lock().await.remove(peer);
    }

    async fn is_banned(&self, peer: &PeerId) -> bool {
        self.inner
            .lock()
            .await
            .get(peer)
            .map_or(false, |s| s.is_banned())
    }

    async fn observe_honest(&self, peer: PeerId) {
        if let Some(state) = self.inner.lock().await.get_mut(&peer) {
            state.alpha = state.alpha.saturating_add(1).min(10_000);
        }
    }

    async fn observe_adversarial(&self, peer: PeerId) {
        if let Some(state) = self.inner.lock().await.get_mut(&peer) {
            // One bad act outweighs ten good ones.
            state.beta = state.beta.saturating_add(10).min(10_000);
            if state.beta > state.alpha * 10 {
                state.banned_until =
                    Some(Instant::now() + Duration::from_secs(LIGHT_BAN_DURATION_SECS));
            }
        }
    }

    async fn gc_stale(&self) {
        let stale = Duration::from_secs(3600);
        self.inner.lock().await.retain(|_, s| {
            s.active_streams > 0 || s.is_banned() || s.window_start.elapsed() < stale
        });
    }
}

// ── Behaviour ───────────────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
pub struct MidwimbleBehaviour {
    pub rr: request_response::Behaviour<MidwimbleCodec>,
    pub light: libp2p_stream::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub relay_client: relay::client::Behaviour,
    pub relay_server: relay::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub autonat: autonat::Behaviour,
    pub connection_limits: libp2p::connection_limits::Behaviour,
}

fn make_behaviour(key: &Keypair, relay_client: relay::client::Behaviour) -> MidwimbleBehaviour {
    let local_peer = key.public().to_peer_id();

    let rr = request_response::Behaviour::new(
        [(MIDWIMBLE_PROTOCOL, ProtocolSupport::Full)],
        RequestResponseConfig::default().with_request_timeout(Duration::from_secs(60)),
    );

    let store = kad::store::MemoryStore::new(local_peer);
    let mut kademlia =
        kad::Behaviour::with_config(local_peer, store, kad::Config::new(KAD_PROTOCOL));
    kademlia.set_mode(Some(kad::Mode::Client));

    let identify = identify::Behaviour::new(
        identify::Config::new(IDENTIFY_PROTOCOL.to_string(), key.public())
            .with_push_listen_addr_updates(true)
            .with_interval(Duration::from_secs(60)),
    );

    // Midstate's relay choke: enough for light clients, not for bulk transfer.
    let mut relay_config = relay::Config::default();
    relay_config.max_circuits = 32;
    relay_config.max_circuits_per_peer = 4;
    relay_config.max_circuit_duration = Duration::from_secs(10 * 60);
    relay_config.max_circuit_bytes = 33_554_432;
    let relay_server = relay::Behaviour::new(local_peer, relay_config);

    let autonat = autonat::Behaviour::new(
        local_peer,
        autonat::Config {
            boot_delay: Duration::from_secs(10),
            refresh_interval: Duration::from_secs(120),
            retry_interval: Duration::from_secs(60),
            throttle_server_period: Duration::from_secs(15),
            only_global_ips: true,
            ..Default::default()
        },
    );

    let limits = libp2p::connection_limits::ConnectionLimits::default()
        .with_max_established_per_peer(Some(20))
        .with_max_pending_incoming(Some(500))
        .with_max_established_incoming(Some(800))
        .with_max_established_outgoing(Some(200));

    MidwimbleBehaviour {
        rr,
        light: libp2p_stream::Behaviour::new(),
        kademlia,
        identify,
        relay_client,
        relay_server,
        dcutr: dcutr::Behaviour::new(local_peer),
        autonat,
        connection_limits: libp2p::connection_limits::Behaviour::new(limits),
    }
}

#[cfg(not(feature = "webrtc"))]
fn build_swarm(keypair: Keypair) -> Result<Swarm<MidwimbleBehaviour>> {
    Ok(libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| make_behaviour(key, relay_client))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
        .build())
}

#[cfg(feature = "webrtc")]
fn build_swarm(keypair: Keypair) -> Result<Swarm<MidwimbleBehaviour>> {
    use libp2p::core::muxing::StreamMuxerBox;
    use libp2p::Transport;
    Ok(libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_other_transport(|keypair| {
            let certificate = libp2p_webrtc::tokio::Certificate::generate(&mut rand::rngs::OsRng)
                .expect("WebRTC certificate generation");
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                libp2p_webrtc::tokio::Transport::new(keypair.clone(), certificate)
                    .map(|(peer_id, conn), _| (peer_id, StreamMuxerBox::new(conn))),
            )
        })?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| make_behaviour(key, relay_client))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
        .build())
}

// ── Events ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatStatus {
    Unknown,
    Public,
    Private,
}

pub enum NetworkEvent {
    MessageReceived {
        peer: PeerId,
        message: Message,
        channel: Option<ResponseChannel<Message>>,
    },
    LightRequest {
        peer: PeerId,
        request: LightRequest,
        respond: tokio::sync::oneshot::Sender<LightResponse>,
    },
    PeerConnected(PeerId, String),
    PeerDisconnected(PeerId),
    OutgoingConnectionFailed(String),
    RequestFailed(PeerId),
    /// Handshake completed but the peer speaks none of our protocols.
    ProtocolMismatch(PeerId),
}

type LightJob = (
    PeerId,
    LightRequest,
    tokio::sync::oneshot::Sender<LightResponse>,
);

pub struct Network {
    swarm: Swarm<MidwimbleBehaviour>,
    light_incoming: libp2p_stream::IncomingStreams,
    light_rx: tokio::sync::mpsc::UnboundedReceiver<LightJob>,
    light_tx: tokio::sync::mpsc::UnboundedSender<LightJob>,
    light_guard: LightGuard,
    light_peers: HashSet<PeerId>,
    connected: HashMap<PeerId, ConnectedPoint>,
    pending_requests: HashMap<OutboundRequestId, PeerId>,
    nat_status: NatStatus,
    declared_public: bool,
    relay_reservations: HashSet<PeerId>,
    listen_addrs: Vec<Multiaddr>,
    external_addrs: Vec<Multiaddr>,
    subnet_peers: HashMap<IpAddr, HashSet<PeerId>>,
    pub static_banned_peers: HashSet<PeerId>,
    pending_dials: HashSet<PeerId>,
}

impl Network {
    pub async fn new(
        keypair: Keypair,
        listen_addr: Multiaddr,
        bootstrap_peers: Vec<Multiaddr>,
        static_banned_peers: HashSet<PeerId>,
    ) -> Result<Self> {
        tracing::info!("Local peer id: {}", keypair.public().to_peer_id());
        let mut swarm = build_swarm(keypair)?;
        let light_incoming = swarm
            .behaviour_mut()
            .light
            .new_control()
            .accept(LIGHT_PROTOCOL)
            .map_err(|_| anyhow::anyhow!("light protocol already registered"))?;
        let (light_tx, light_rx) = tokio::sync::mpsc::unbounded_channel();

        let mut net = Self {
            swarm,
            light_incoming,
            light_rx,
            light_tx,
            light_guard: LightGuard::new(),
            light_peers: HashSet::new(),
            connected: HashMap::new(),
            pending_requests: HashMap::new(),
            nat_status: NatStatus::Unknown,
            declared_public: false,
            relay_reservations: HashSet::new(),
            listen_addrs: Vec::new(),
            external_addrs: Vec::new(),
            subnet_peers: HashMap::new(),
            static_banned_peers,
            pending_dials: HashSet::new(),
        };

        net.swarm.listen_on(listen_addr.clone())?;
        if let Some(quic) = tcp_to_quic(&listen_addr) {
            match net.swarm.listen_on(quic.clone()) {
                Ok(_) => tracing::info!("Also listening on QUIC: {}", quic),
                Err(e) => tracing::debug!("QUIC listen failed (non-fatal): {}", e),
            }
        }
        #[cfg(feature = "webrtc")]
        if let Some(webrtc) = tcp_to_webrtc(&listen_addr) {
            match net.swarm.listen_on(webrtc.clone()) {
                Ok(_) => tracing::info!("WebRTC listening on {}", webrtc),
                Err(e) => tracing::debug!("WebRTC listen failed (non-fatal): {}", e),
            }
        }

        for addr in &bootstrap_peers {
            if let Some(peer) = extract_peer_id(addr) {
                // No relay reservation here: see maintain_relays() and midstate's
                // note on relay addresses polluting external_addrs.
                net.swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer, addr.clone());
            }
            if let Err(e) = net.swarm.dial(addr.clone()) {
                tracing::warn!("Failed to dial {}: {}", addr, e);
            }
        }
        if !bootstrap_peers.is_empty() {
            if let Err(e) = net.swarm.behaviour_mut().kademlia.bootstrap() {
                tracing::debug!("Kademlia bootstrap not ready: {}", e);
            }
        }
        Ok(net)
    }

    // ── Light clients ───────────────────────────────────────────────────

    pub fn has_light_peers(&self) -> bool {
        !self.light_peers.is_empty()
    }

    pub fn broadcast_light_push(&mut self, notification: &LightNotification) {
        if self.light_peers.is_empty() {
            return;
        }
        let bytes = serde_json::to_vec(notification).unwrap_or_default();
        let mut payload = (bytes.len() as u32).to_le_bytes().to_vec();
        payload.extend_from_slice(&bytes);
        let control = self.swarm.behaviour_mut().light.new_control();
        for &peer in &self.light_peers {
            let mut ctrl = control.clone();
            let data = payload.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(5), async move {
                    if let Ok(mut stream) = ctrl.open_stream(peer, LIGHT_PUSH_PROTOCOL).await {
                        use futures::AsyncWriteExt;
                        let _ = stream.write_all(&data).await;
                        let _ = stream.close().await;
                    }
                })
                .await;
            });
        }
    }

    // These return owned futures rather than being `async fn(&self)`: holding
    // `&Network` across an await would require the swarm to be `Sync`, which
    // it is not, and would make the node's event loop impossible to spawn.

    pub fn observe_honest_light_peer(
        &self,
        peer: PeerId,
    ) -> impl std::future::Future<Output = ()> + Send + 'static {
        let guard = self.light_guard.clone();
        async move { guard.observe_honest(peer).await }
    }

    pub fn observe_adversarial_light_peer(
        &self,
        peer: PeerId,
    ) -> impl std::future::Future<Output = ()> + Send + 'static {
        let guard = self.light_guard.clone();
        async move { guard.observe_adversarial(peer).await }
    }

    pub fn gc_stale_light_peers(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        let guard = self.light_guard.clone();
        async move { guard.gc_stale().await }
    }

    pub fn is_light_peer(&self, peer: &PeerId) -> bool {
        self.light_peers.contains(peer)
    }

    // ── NAT / relays ────────────────────────────────────────────────────

    /// Seeks public peers to relay for us once AutoNAT says we are private.
    pub fn maintain_relays(&mut self) {
        if self.nat_status != NatStatus::Private || self.relay_reservations.len() >= 2 {
            return;
        }
        let candidates: Vec<(PeerId, Multiaddr)> = self
            .connected
            .iter()
            .filter(|(p, e)| {
                e.is_dialer()
                    && !self.light_peers.contains(p)
                    && !self.relay_reservations.contains(p)
                    && !self.static_banned_peers.contains(p)
            })
            .map(|(p, e)| (*p, e.get_remote_address().clone()))
            .collect();
        use rand::seq::SliceRandom;
        if let Some((peer, addr)) = candidates.choose(&mut rand::thread_rng()) {
            let mut base = addr.clone();
            if extract_peer_id(&base).is_none() {
                base.push(libp2p::multiaddr::Protocol::P2p(*peer));
            }
            let relay_addr = base.with(libp2p::multiaddr::Protocol::P2pCircuit);
            tracing::info!("Requesting inbound relay from public peer {}", peer);
            if let Err(e) = self.swarm.listen_on(relay_addr) {
                tracing::debug!("Relay request to {} failed: {}", peer, e);
            }
        }
    }

    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    pub fn nat_status(&self) -> NatStatus {
        self.nat_status
    }

    /// Operator-declared public address; overrides AutoNAT permanently
    /// (midstate: AutoNAT was observed flapping on reachable hosts).
    pub fn declare_public(&mut self, addr: Multiaddr) {
        if !is_routable(&addr) {
            tracing::warn!("Ignoring public_address {}: not routable", addr);
            return;
        }
        tracing::info!(
            "Operator-declared public address: {} (AutoNAT overridden)",
            addr
        );
        self.declared_public = true;
        self.nat_status = NatStatus::Public;
        self.swarm.add_external_address(addr.clone());
        if !self.external_addrs.contains(&addr) {
            self.external_addrs.push(addr);
        }
        self.swarm
            .behaviour_mut()
            .kademlia
            .set_mode(Some(kad::Mode::Server));
    }

    // ── Messaging ───────────────────────────────────────────────────────

    pub fn send(&mut self, peer: PeerId, msg: Message) {
        let id = self.swarm.behaviour_mut().rr.send_request(&peer, msg);
        self.pending_requests.insert(id, peer);
    }

    pub fn broadcast(&mut self, msg: Message) {
        self.broadcast_except(None, msg);
    }

    pub fn broadcast_except(&mut self, exclude: Option<PeerId>, msg: Message) {
        let peers: Vec<PeerId> = self
            .connected
            .keys()
            .filter(|&&p| Some(p) != exclude && !self.light_peers.contains(&p))
            .copied()
            .collect();
        for peer in peers {
            self.send(peer, msg.clone());
        }
    }

    pub fn respond(&mut self, channel: ResponseChannel<Message>, msg: Message) {
        if self
            .swarm
            .behaviour_mut()
            .rr
            .send_response(channel, msg)
            .is_err()
        {
            tracing::debug!("Failed to send response (channel closed)");
        }
    }

    pub fn peer_count(&self) -> usize {
        self.connected.len()
    }

    pub fn outbound_peer_count(&self) -> usize {
        self.connected.values().filter(|e| e.is_dialer()).count()
    }

    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.connected
            .keys()
            .copied()
            .filter(|p| !self.light_peers.contains(p))
            .collect()
    }

    pub fn disconnect_peer(&mut self, peer: PeerId) {
        let _ = self.swarm.disconnect_peer_id(peer);
    }

    pub fn peer_subnet(&self, peer: &PeerId) -> Option<IpAddr> {
        self.connected
            .get(peer)
            .and_then(|e| extract_subnet(e.get_remote_address()))
    }

    pub fn random_peer(&self) -> Option<PeerId> {
        use rand::seq::IteratorRandom;
        self.connected
            .keys()
            .filter(|p| !self.light_peers.contains(p))
            .copied()
            .choose(&mut rand::thread_rng())
    }

    pub fn random_peer_except(&self, exclude: PeerId) -> Option<PeerId> {
        use rand::seq::IteratorRandom;
        self.connected
            .keys()
            .filter(|p| **p != exclude && !self.light_peers.contains(p))
            .copied()
            .choose(&mut rand::thread_rng())
    }

    /// Bans a peer for the rest of this session and drops any relay routed
    /// through it (midstate `drop_relay_reservation`).
    pub fn ban_peer(&mut self, peer: PeerId) {
        self.static_banned_peers.insert(peer);
        if self.relay_reservations.remove(&peer) {
            let circuit = format!("/p2p/{peer}/p2p-circuit");
            self.external_addrs
                .retain(|a| !a.to_string().contains(&circuit));
            self.listen_addrs
                .retain(|a| !a.to_string().contains(&circuit));
        }
        self.disconnect_peer(peer);
    }

    // ── PEX ─────────────────────────────────────────────────────────────

    pub fn listen_addrs(&self) -> Vec<Multiaddr> {
        self.listen_addrs.clone()
    }

    /// Our own externally reachable addresses (midstate, including its
    /// routability and relay-IP fixes).
    pub fn advertisable_addrs(&self) -> Vec<String> {
        let local_id = *self.swarm.local_peer_id();
        let external_ip = self
            .external_addrs
            .iter()
            .filter(|a| {
                !a.iter()
                    .any(|p| p == libp2p::multiaddr::Protocol::P2pCircuit)
            })
            .find_map(extract_ip);
        let mut addrs: Vec<String> = self
            .listen_addrs
            .iter()
            .filter_map(|a| {
                let candidate = match external_ip {
                    Some(ip) => replace_ip(a, ip),
                    None => a.clone(),
                };
                if !is_routable(&candidate) {
                    return None;
                }
                Some(if extract_peer_id(&candidate).is_some() {
                    candidate.to_string()
                } else {
                    candidate
                        .with(libp2p::multiaddr::Protocol::P2p(local_id))
                        .to_string()
                })
            })
            .collect();
        addrs.sort();
        addrs.dedup();
        addrs
    }

    /// Server-dialable subset (no browser transports).
    pub fn dialable_addrs(&self) -> Vec<String> {
        self.advertisable_addrs()
            .into_iter()
            .filter(|a| !a.contains("/webrtc-direct"))
            .collect()
    }

    pub fn connected_peer_addrs(&mut self) -> Vec<String> {
        let mut addrs = Vec::new();
        for bucket in self.swarm.behaviour_mut().kademlia.kbuckets() {
            for entry in bucket.iter() {
                let peer = *entry.node.key.preimage();
                if !self.connected.contains_key(&peer) {
                    continue;
                }
                for addr in entry.node.value.iter() {
                    if is_localhost(addr) {
                        continue;
                    }
                    if extract_peer_id(addr).is_some() {
                        addrs.push(addr.to_string());
                    } else {
                        addrs.push(
                            addr.clone()
                                .with(libp2p::multiaddr::Protocol::P2p(peer))
                                .to_string(),
                        );
                    }
                }
            }
        }
        addrs.truncate(MAX_PEX_ADDRS);
        addrs
    }

    pub fn pex_addrs(&mut self) -> Vec<String> {
        let mut all = self.advertisable_addrs();
        all.extend(self.connected_peer_addrs());
        all.sort();
        all.dedup();
        all.truncate(MAX_PEX_ADDRS);
        all
    }

    /// Dials a PEX/discovery address with midstate's filters: no browser
    /// transports, routable only (relay circuits allowed, for DCUtR), no
    /// banned or already-connected peers, no duplicate in-flight dials, and a
    /// per-subnet cap.
    pub fn dial_addr(&mut self, addr_str: &str) {
        if addr_str.contains("webrtc-direct") {
            return;
        }
        let addr: Multiaddr = match addr_str.parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!("PEX ignoring bad multiaddr '{}': {}", addr_str, e);
                return;
            }
        };
        let is_relayed = addr
            .iter()
            .any(|p| p == libp2p::multiaddr::Protocol::P2pCircuit);
        if !is_relayed && !is_routable(&addr) {
            return;
        }
        self.dial_checked(addr);
    }

    /// Dial that skips the routability filter (explicit operator/test peers).
    pub fn dial_trusted(&mut self, addr: Multiaddr) {
        self.dial_checked(addr);
    }

    fn dial_checked(&mut self, addr: Multiaddr) {
        let Some(peer) = extract_peer_id(&addr) else {
            tracing::debug!("Ignoring address without a peer id: {}", addr);
            return;
        };
        if self.static_banned_peers.contains(&peer)
            || self.connected.contains_key(&peer)
            || peer == *self.swarm.local_peer_id()
            || self.pending_dials.contains(&peer)
        {
            return;
        }
        if let Some(subnet) = extract_subnet(&addr) {
            if let Some(peers) = self.subnet_peers.get(&subnet) {
                if peers.len() >= MAX_PEERS_PER_SUBNET && !peers.contains(&peer) {
                    return;
                }
            }
        }
        self.pending_dials.insert(peer);
        if let Err(e) = self.swarm.dial(addr.clone()) {
            self.pending_dials.remove(&peer);
            tracing::debug!("Dial {} failed: {}", addr, e);
        }
    }

    // ── Event loop ──────────────────────────────────────────────────────

    pub async fn next_event(&mut self) -> NetworkEvent {
        loop {
            tokio::select! {
                Some((peer, stream)) = self.light_incoming.next() => {
                    self.accept_light_stream(peer, stream).await;
                }
                Some((peer, request, respond)) = self.light_rx.recv() => {
                    return NetworkEvent::LightRequest { peer, request, respond };
                }
                event = self.swarm.select_next_some() => {
                    if let Some(ev) = self.handle_swarm_event(event).await {
                        return ev;
                    }
                }
            }
        }
    }

    async fn accept_light_stream(&mut self, peer: PeerId, stream: libp2p::Stream) {
        if self.static_banned_peers.contains(&peer) {
            let _ = self.swarm.disconnect_peer_id(peer);
            return;
        }
        if let Err(reason) = self.light_guard.try_open_stream(peer).await {
            tracing::debug!("Light stream from {} denied: {}", peer, reason);
            if reason.starts_with("banned") {
                let _ = self.swarm.disconnect_peer_id(peer);
            }
            return;
        }
        let tx = self.light_tx.clone();
        let guard = self.light_guard.clone();
        let light_count = self.light_peers.len();
        tokio::spawn(async move {
            use light_protocol::{read_request_raw, write_response_raw};
            let mut stream = stream;
            let request = match tokio::time::timeout(
                Duration::from_secs(LIGHT_READ_TIMEOUT_SECS),
                read_request_raw(&mut stream),
            )
            .await
            {
                Ok(Ok(req)) => req,
                _ => {
                    guard.close_stream(peer).await;
                    return;
                }
            };
            if request.is_expensive() && !guard.check_expensive(peer).await {
                let _ = write_response_raw(
                    &mut stream,
                    LightResponse::error("rate limit: too many expensive requests"),
                )
                .await;
                guard.close_stream(peer).await;
                return;
            }
            let is_get_state = matches!(request, LightRequest::GetState);
            let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
            if tx.send((peer, request, resp_tx)).is_err() {
                guard.close_stream(peer).await;
                return;
            }
            let mut resp = match tokio::time::timeout(
                Duration::from_secs(LIGHT_RESPONSE_TIMEOUT_SECS),
                resp_rx,
            )
            .await
            {
                Ok(Ok(r)) => r,
                Ok(Err(_)) => LightResponse::error("internal error"),
                Err(_) => LightResponse::error("server timeout"),
            };
            if is_get_state {
                if let Some(serde_json::Value::Object(ref mut map)) = resp.data {
                    map.insert("light_connections".into(), serde_json::json!(light_count));
                    map.insert(
                        "max_light_connections".into(),
                        serde_json::json!(MAX_LIGHT_PEERS),
                    );
                }
            }
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                write_response_raw(&mut stream, resp),
            )
            .await;
            guard.close_stream(peer).await;
        });
    }

    async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<MidwimbleBehaviourEvent>,
    ) -> Option<NetworkEvent> {
        match event {
            SwarmEvent::Behaviour(MidwimbleBehaviourEvent::Rr(
                request_response::Event::Message { peer, message, .. },
            )) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    return Some(NetworkEvent::MessageReceived {
                        peer,
                        message: request,
                        channel: Some(channel),
                    });
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    self.pending_requests.remove(&request_id);
                    return Some(NetworkEvent::MessageReceived {
                        peer,
                        message: response,
                        channel: None,
                    });
                }
            },
            SwarmEvent::Behaviour(MidwimbleBehaviourEvent::Rr(
                request_response::Event::OutboundFailure {
                    peer,
                    request_id,
                    error,
                    ..
                },
            )) => {
                self.pending_requests.remove(&request_id);
                if matches!(
                    error,
                    request_response::OutboundFailure::UnsupportedProtocols
                ) {
                    return Some(NetworkEvent::ProtocolMismatch(peer));
                }
                tracing::debug!("Outbound request to {} failed: {}", peer, error);
                return Some(NetworkEvent::RequestFailed(peer));
            }
            SwarmEvent::Behaviour(MidwimbleBehaviourEvent::Rr(
                request_response::Event::InboundFailure { peer, error, .. },
            )) => {
                tracing::debug!("Inbound request from {} failed: {}", peer, error);
            }
            SwarmEvent::Behaviour(MidwimbleBehaviourEvent::Identify(
                identify::Event::Received { peer_id, info, .. },
            )) => {
                // Foreign-network isolation (midstate): only peers speaking our
                // protocol may populate the address graph.
                if !info.protocols.iter().any(|p| *p == MIDWIMBLE_PROTOCOL) {
                    return None;
                }
                for addr in &info.listen_addrs {
                    if addr.to_string().contains("webrtc-direct") {
                        continue;
                    }
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                }
                self.swarm
                    .behaviour_mut()
                    .autonat
                    .add_server(peer_id, Some(info.observed_addr.clone()));
            }
            SwarmEvent::Behaviour(MidwimbleBehaviourEvent::Autonat(
                autonat::Event::StatusChanged { old, new },
            )) => {
                tracing::info!("AutoNAT status: {:?} -> {:?}", old, new);
                if self.declared_public {
                    return None;
                }
                match new {
                    autonat::NatStatus::Public(_) => {
                        self.nat_status = NatStatus::Public;
                        self.swarm
                            .behaviour_mut()
                            .kademlia
                            .set_mode(Some(kad::Mode::Server));
                    }
                    autonat::NatStatus::Private => {
                        self.nat_status = NatStatus::Private;
                        self.swarm
                            .behaviour_mut()
                            .kademlia
                            .set_mode(Some(kad::Mode::Client));
                    }
                    autonat::NatStatus::Unknown => self.nat_status = NatStatus::Unknown,
                }
            }
            SwarmEvent::Behaviour(MidwimbleBehaviourEvent::RelayClient(
                relay::client::Event::ReservationReqAccepted { relay_peer_id, .. },
            )) => {
                self.relay_reservations.insert(relay_peer_id);
                tracing::info!("Relay reservation accepted by {}", relay_peer_id);
            }
            SwarmEvent::Behaviour(_) => {}

            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                num_established,
                ..
            } => {
                if peer_id == *self.swarm.local_peer_id() {
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return None;
                }
                self.pending_dials.remove(&peer_id);
                if self.static_banned_peers.contains(&peer_id) {
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return None;
                }
                if num_established.get() > 1 {
                    return None;
                }
                let remote_addr = endpoint.get_remote_address().clone();
                let is_webrtc = remote_addr.to_string().contains("webrtc-direct");
                if is_webrtc
                    && (self.light_peers.len() >= MAX_LIGHT_PEERS
                        || self.light_guard.is_banned(&peer_id).await)
                {
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return None;
                }
                // Eclipse defence: at most a few peers per /24 (/32 for IPv6).
                if let Some(subnet) = extract_subnet(&remote_addr) {
                    let peers = self.subnet_peers.entry(subnet).or_default();
                    if !peers.contains(&peer_id) {
                        let limit = if is_webrtc { 50 } else { MAX_PEERS_PER_SUBNET };
                        if peers.len() >= limit {
                            tracing::warn!(
                                "Eclipse defence: rejecting {}, subnet {} full",
                                peer_id,
                                subnet
                            );
                            let _ = self.swarm.disconnect_peer_id(peer_id);
                            return None;
                        }
                        peers.insert(peer_id);
                    }
                }
                if endpoint.is_listener()
                    && self.connected.values().filter(|e| e.is_listener()).count()
                        >= MAX_INBOUND_PEERS
                {
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return None;
                }
                if is_webrtc {
                    self.light_peers.insert(peer_id);
                } else {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, remote_addr.clone());
                }
                self.connected.insert(peer_id, endpoint.clone());
                tracing::info!(
                    "Peer connected: {} via {} (total {})",
                    peer_id,
                    remote_addr,
                    self.connected.len()
                );
                let full = if extract_peer_id(&remote_addr).is_some() {
                    remote_addr.to_string()
                } else {
                    remote_addr
                        .with(libp2p::multiaddr::Protocol::P2p(peer_id))
                        .to_string()
                };
                return Some(NetworkEvent::PeerConnected(peer_id, full));
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                endpoint,
                num_established,
                ..
            } => {
                if peer_id == *self.swarm.local_peer_id() {
                    return None;
                }
                self.pending_dials.remove(&peer_id);
                if num_established == 0 {
                    self.connected.remove(&peer_id);
                    self.relay_reservations.remove(&peer_id);
                    if self.light_peers.remove(&peer_id) {
                        self.light_guard.remove_peer(&peer_id).await;
                    }
                    if let Some(subnet) = extract_subnet(endpoint.get_remote_address()) {
                        if let std::collections::hash_map::Entry::Occupied(mut e) =
                            self.subnet_peers.entry(subnet)
                        {
                            e.get_mut().remove(&peer_id);
                            if e.get().is_empty() {
                                e.remove();
                            }
                        }
                    }
                    tracing::info!(
                        "Peer disconnected: {} (total {})",
                        peer_id,
                        self.connected.len()
                    );
                    return Some(NetworkEvent::PeerDisconnected(peer_id));
                }
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!("Listening on {}", address);
                self.listen_addrs.push(address);
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(pid) = peer_id {
                    self.pending_dials.remove(&pid);
                }
                match error {
                    libp2p::swarm::DialError::Transport(failed) => {
                        for (addr, _) in &failed {
                            if let Some(pid) = extract_peer_id(addr) {
                                self.pending_dials.remove(&pid);
                            }
                        }
                        if let Some((addr, _)) = failed.first() {
                            return Some(NetworkEvent::OutgoingConnectionFailed(addr.to_string()));
                        }
                    }
                    libp2p::swarm::DialError::WrongPeerId { address, .. } => {
                        if let Some(pid) = extract_peer_id(&address) {
                            self.pending_dials.remove(&pid);
                        }
                        return Some(NetworkEvent::OutgoingConnectionFailed(address.to_string()));
                    }
                    _ => {}
                }
            }
            SwarmEvent::ExternalAddrConfirmed { address } => {
                // A relayed address carries the relay's IP, not ours (midstate fix).
                let is_relayed = address
                    .iter()
                    .any(|p| p == libp2p::multiaddr::Protocol::P2pCircuit);
                if !is_relayed && !self.external_addrs.contains(&address) {
                    tracing::info!("External address confirmed: {}", address);
                    self.external_addrs.push(address);
                }
            }
            _ => {}
        }
        None
    }
}

// ── Helpers (midstate) ──────────────────────────────────────────────────────

pub fn is_routable(addr: &Multiaddr) -> bool {
    for proto in addr.iter() {
        match proto {
            libp2p::multiaddr::Protocol::Ip4(ip) => {
                if ip.is_loopback() || ip.is_private() || ip.is_link_local() {
                    return false;
                }
                if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
                    return false;
                }
                let o = ip.octets();
                if o[0] == 100 && (64..128).contains(&o[1]) {
                    return false;
                }
                if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
                    return false;
                }
            }
            libp2p::multiaddr::Protocol::Ip6(ip) => {
                if ip.is_loopback() || (ip.segments()[0] & 0xff00) == 0xfe00 {
                    return false;
                }
                if ip.is_unspecified() || (ip.segments()[0] & 0xfe00) == 0xfc00 {
                    return false;
                }
            }
            libp2p::multiaddr::Protocol::P2pCircuit => return false,
            _ => {}
        }
    }
    true
}

pub fn socket_to_multiaddr(addr: SocketAddr) -> Multiaddr {
    let mut ma = Multiaddr::empty();
    match addr.ip() {
        IpAddr::V4(ip) => ma.push(libp2p::multiaddr::Protocol::Ip4(ip)),
        IpAddr::V6(ip) => ma.push(libp2p::multiaddr::Protocol::Ip6(ip)),
    }
    ma.push(libp2p::multiaddr::Protocol::Tcp(addr.port()));
    ma
}

fn tcp_to_udp_variant(
    addr: &Multiaddr,
    port_offset: u16,
    suffix: libp2p::multiaddr::Protocol<'static>,
) -> Option<Multiaddr> {
    let mut components: Vec<_> = addr.iter().collect();
    let idx = components
        .iter()
        .position(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_)))?;
    let port = match components[idx] {
        libp2p::multiaddr::Protocol::Tcp(p) => p,
        _ => return None,
    };
    let port = if port == 0 {
        0
    } else {
        port.checked_add(port_offset).unwrap_or(port)
    };
    components[idx] = libp2p::multiaddr::Protocol::Udp(port);
    components.insert(idx + 1, suffix);
    Some(components.into_iter().collect())
}

/// `/ip4/x/tcp/p` → `/ip4/x/udp/p/quic-v1`
fn tcp_to_quic(addr: &Multiaddr) -> Option<Multiaddr> {
    tcp_to_udp_variant(addr, 0, libp2p::multiaddr::Protocol::QuicV1)
}

/// `/ip4/x/tcp/p` → `/ip4/x/udp/p+2/webrtc-direct`
#[cfg(feature = "webrtc")]
fn tcp_to_webrtc(addr: &Multiaddr) -> Option<Multiaddr> {
    tcp_to_udp_variant(addr, 2, libp2p::multiaddr::Protocol::WebRTCDirect)
}

pub fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::P2p(id) => Some(id),
        _ => None,
    })
}

/// /24 for IPv4, /32 for IPv6; `None` for loopback and relay circuits.
fn extract_subnet(addr: &Multiaddr) -> Option<IpAddr> {
    if is_localhost(addr)
        || addr
            .iter()
            .any(|p| p == libp2p::multiaddr::Protocol::P2pCircuit)
    {
        return None;
    }
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::Ip4(ip) => {
            let o = ip.octets();
            Some(IpAddr::V4(std::net::Ipv4Addr::new(o[0], o[1], o[2], 0)))
        }
        libp2p::multiaddr::Protocol::Ip6(ip) => {
            let s = ip.segments();
            Some(IpAddr::V6(std::net::Ipv6Addr::new(
                s[0], s[1], 0, 0, 0, 0, 0, 0,
            )))
        }
        _ => None,
    })
}

fn is_localhost(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        libp2p::multiaddr::Protocol::Ip4(ip) => ip.is_loopback(),
        libp2p::multiaddr::Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}

fn extract_ip(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        libp2p::multiaddr::Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

fn replace_ip(addr: &Multiaddr, new_ip: IpAddr) -> Multiaddr {
    addr.iter()
        .map(|proto| match proto {
            libp2p::multiaddr::Protocol::Ip4(_) | libp2p::multiaddr::Protocol::Ip6(_) => {
                match new_ip {
                    IpAddr::V4(ip) => libp2p::multiaddr::Protocol::Ip4(ip),
                    IpAddr::V6(ip) => libp2p::multiaddr::Protocol::Ip6(ip),
                }
            }
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_to_quic_basic() {
        let tcp: Multiaddr = "/ip4/0.0.0.0/tcp/9333".parse().unwrap();
        assert_eq!(
            tcp_to_quic(&tcp).unwrap().to_string(),
            "/ip4/0.0.0.0/udp/9333/quic-v1"
        );
        let udp: Multiaddr = "/ip4/0.0.0.0/udp/9333".parse().unwrap();
        assert!(tcp_to_quic(&udp).is_none());
    }

    #[test]
    fn routability_rules() {
        for bad in [
            "/ip4/0.0.0.0/tcp/1",
            "/ip4/127.0.0.1/tcp/1",
            "/ip4/10.1.2.3/tcp/1",
            "/ip4/100.64.12.9/tcp/1",
            "/ip6/fd00::1/tcp/1",
            "/ip6/fe80::1/tcp/1",
            "/ip4/1.2.3.4/tcp/9333/p2p/12D3KooWPbR63SQg1UBLpAMiNngqrRHGM4LaMP8ieAJUxhfw7dxv/p2p-circuit",
        ] {
            assert!(!is_routable(&bad.parse().unwrap()), "{bad}");
        }
        assert!(is_routable(&"/ip4/74.208.253.44/tcp/9333".parse().unwrap()));
    }

    #[test]
    fn subnet_grouping() {
        let a: Multiaddr = "/ip4/203.0.113.10/tcp/1".parse().unwrap();
        let b: Multiaddr = "/ip4/203.0.113.99/tcp/1".parse().unwrap();
        assert_eq!(extract_subnet(&a), extract_subnet(&b));
        assert!(extract_subnet(&"/ip4/127.0.0.1/tcp/1".parse().unwrap()).is_none());
    }

    #[test]
    fn peer_id_extraction() {
        let with: Multiaddr =
            "/ip4/1.2.3.4/tcp/9333/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
                .parse()
                .unwrap();
        assert!(extract_peer_id(&with).is_some());
        assert!(extract_peer_id(&"/ip4/1.2.3.4/tcp/9333".parse().unwrap()).is_none());
    }
}
