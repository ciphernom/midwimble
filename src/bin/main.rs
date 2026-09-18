//! `midwimble` command-line interface.

use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use midwimble::core::mw::StealthAddress;
use midwimble::core::types::block_reward;
use midwimble::node::{Node, NodeConfig};
use midwimble::rpc::{self, RpcClient};
use midwimble::wallet::Wallet;
use std::path::PathBuf;

/// `println!` that exits quietly when stdout is closed (e.g. piped into
/// `head`) instead of panicking.
macro_rules! out {
    ($($arg:tt)*) => {{
        use std::io::Write;
        if writeln!(std::io::stdout(), $($arg)*).is_err() {
            std::process::exit(0);
        }
    }};
}

#[derive(Parser)]
#[command(
    name = "midwimble",
    version,
    about = "Midstate consensus and networking with MimbleWimble transactions"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a full node.
    Node {
        #[arg(long, default_value = "./midwimble-data")]
        data_dir: PathBuf,
        #[arg(long, default_value = "/ip4/0.0.0.0/tcp/9433")]
        listen: String,
        /// Peer to connect to (multiaddr with /p2p/<id>); repeatable.
        #[arg(long = "peer")]
        peers: Vec<String>,
        #[arg(long, default_value = "127.0.0.1:9434")]
        rpc: String,
        /// Mine, paying rewards to this address.
        #[arg(long)]
        mine_to: Option<String>,
        /// Mining threads (0 = all cores).
        #[arg(long, default_value_t = 0)]
        threads: usize,
        /// Use the public IPFS DHT to find and announce peers.
        #[arg(long)]
        amino: bool,
        /// Publicly reachable address to advertise (overrides AutoNAT).
        #[arg(long)]
        public_address: Option<String>,
        /// Minimum milliseconds between blocks we mine (for local devnets).
        #[arg(long, default_value_t = 0)]
        min_block_interval: u64,
        /// Mining backend: auto, gpu or cpu (gpu needs a build with `--features gpu`).
        #[arg(long, default_value = "auto")]
        backend: String,
        /// Checkpoint verification: start an empty node from this trusted checkpoint id.
        #[arg(long)]
        checkpoint: Option<String>,
        /// Delete block bodies below the finalized checkpoint.
        #[arg(long)]
        prune: bool,
        /// Midstate blocks an anchor needs before it counts.
        #[arg(long, default_value_t = 6)]
        anchor_depth: usize,
        /// Midwimble blocks after a checkpoint before it is finalized.
        #[arg(long, default_value_t = 100)]
        finality_depth: u64,
        /// Minimum work per Midstate header in anchor evidence, as leading zero bits.
        #[arg(long, default_value_t = 0)]
        anchor_min_work_bits: u32,
        /// Anchor records to follow (default: <data-dir>/anchors.jsonl).
        #[arg(long)]
        anchors: Option<PathBuf>,
    },
    /// Merge-mine midstate and midwimble against two running nodes.
    MergeMine {
        /// midstate node RPC (host:port).
        #[arg(long)]
        midstate_rpc: String,
        /// midwimble node RPC (host:port).
        #[arg(long, default_value = "127.0.0.1:9434")]
        rpc: String,
        /// midstate address (64 hex chars, or 72 with midstate's checksum) for midstate rewards.
        #[arg(long)]
        midstate_address: String,
        /// midwimble address for midwimble rewards.
        #[arg(long)]
        midwimble_address: String,
        #[arg(long, default_value_t = 0)]
        threads: usize,
        /// Where midstate coinbase outputs (and their salts) are recorded.
        #[arg(long, default_value = "./midstate_coinbase.jsonl")]
        coinbase_log: PathBuf,
        #[arg(long, default_value = "auto")]
        backend: String,
        /// Record blocks anchored by merged mining here (same format as `anchor`).
        #[arg(long)]
        anchor_store: Option<PathBuf>,
        #[arg(long, default_value_t = 6)]
        anchor_depth: usize,
    },
    /// Run a provably fair Stratum pool on top of a local node.
    Pool {
        /// Address receiving the pool fee (and rewards while no miner has a score).
        #[arg(long)]
        address: String,
        #[arg(long, default_value = "127.0.0.1:9434")]
        rpc: String,
        #[arg(long, default_value = "0.0.0.0:3333")]
        stratum: String,
        #[arg(long, default_value = "0.0.0.0:8081")]
        api: String,
        /// Audit API address to tell miners (e.g. public-ip:8081).
        #[arg(long)]
        api_public: Option<String>,
        #[arg(long, default_value_t = 1.0)]
        fee: f64,
        /// Share difficulty in leading zero bits.
        #[arg(long, default_value_t = 12)]
        share_bits: u32,
        #[arg(long, default_value = "./pool-data")]
        data_dir: PathBuf,
    },
    /// Mine for a pool, auditing every job before hashing on it.
    PoolMine {
        /// Pool Stratum endpoint (host:port or stratum+tcp://host:port).
        #[arg(long)]
        pool: String,
        #[arg(long)]
        address: String,
        #[arg(long, default_value = "worker")]
        worker: String,
        #[arg(long, default_value_t = 0)]
        threads: usize,
        #[arg(long, default_value = "auto")]
        backend: String,
    },
    /// List GPUs and run the miner's shader self-test.
    GpuInfo,
    /// Anchor a checkpoint of the local chain in Midstate (Commit transaction).
    Anchor {
        #[arg(long, default_value = "127.0.0.1:9434")]
        rpc: String,
        #[arg(long)]
        midstate_rpc: String,
        /// Midstate blocks required, the anchor block included.
        #[arg(long, default_value_t = 6)]
        depth: usize,
        /// Checkpoint this many blocks below the tip.
        #[arg(long, default_value_t = 10)]
        lag: u64,
        #[arg(long, default_value = "./anchors.jsonl")]
        store: PathBuf,
        #[arg(long, default_value_t = 3600)]
        timeout_secs: u64,
    },
    /// Verify stored anchors against their Midstate evidence and the local chain.
    AnchorVerify {
        #[arg(long, default_value = "127.0.0.1:9434")]
        rpc: String,
        #[arg(long, default_value = "./anchors.jsonl")]
        store: PathBuf,
        #[arg(long, default_value_t = 6)]
        depth: usize,
    },
    /// Show the node's status.
    Status {
        #[arg(long, default_value = "127.0.0.1:9434")]
        rpc: String,
    },
    /// Start or stop mining on a running node.
    Mine {
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        stop: bool,
        #[arg(long, default_value = "127.0.0.1:9434")]
        rpc: String,
    },
    /// Wallet operations. The password is read from MIDWIMBLE_PASSWORD or prompted for.
    Wallet {
        #[arg(long, default_value = "./wallet.mww")]
        wallet: PathBuf,
        #[arg(long, default_value = "127.0.0.1:9434")]
        rpc: String,
        #[command(subcommand)]
        action: WalletCmd,
    },
}

#[derive(Subcommand)]
enum WalletCmd {
    /// Create a new wallet and print its recovery phrase.
    Create {
        /// MSS height of the post-quantum recovery key (2^height claims).
        #[arg(long, default_value_t = midwimble::core::recovery::DEFAULT_RECOVERY_HEIGHT)]
        recovery_height: u32,
    },
    /// Restore from a recovery phrase.
    Restore {
        #[arg(long)]
        mnemonic: String,
        #[arg(long, default_value_t = 0)]
        birth_height: u64,
        /// Must match the height used when the wallet was created.
        #[arg(long, default_value_t = midwimble::core::recovery::DEFAULT_RECOVERY_HEIGHT)]
        recovery_height: u32,
    },
    /// Print the receiving address.
    Address,
    /// Scan new blocks from the node.
    Sync,
    /// Scan, then print the balance.
    Balance,
    /// List known outputs.
    Coins,
    /// Scan, then pay an address.
    Send {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        /// Fee in base units (defaults to the relay minimum for the inputs used).
        #[arg(long)]
        fee: Option<u64>,
    },
}

fn password() -> Result<String> {
    if let Ok(p) = std::env::var("MIDWIMBLE_PASSWORD") {
        return Ok(p);
    }
    eprint!("Wallet password (input is visible; set MIDWIMBLE_PASSWORD to avoid this prompt): ");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let p = line.trim_end_matches(['\r', '\n']).to_string();
    if p.is_empty() {
        bail!("empty password");
    }
    Ok(p)
}

#[cfg(feature = "gpu")]
fn gpu_info() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    use midwimble::core::gpu_mining;
    let n = gpu_mining::gpu_device_count();
    out!("{} GPU(s) passed the shader self-test", n);
    for g in gpu_mining::shared_all() {
        out!("  {}", g.adapter_name());
    }
    if n > 0 {
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let target = [0xffu8; 32];
        let start = std::time::Instant::now();
        let found = gpu_mining::mine([7u8; 32], target, None, 1, cancel, counter.clone());
        out!(
            "mined a trivial target in {:?} ({} extension attempts); result valid: {}",
            start.elapsed(),
            counter.load(std::sync::atomic::Ordering::Relaxed),
            matches!(found, Some(midwimble::core::extension::MiningResult::Block(ref e))
                if midwimble::core::extension::create_extension([7u8; 32], e.nonce).final_hash == e.final_hash)
        );
    }
    Ok(())
}

#[cfg(not(feature = "gpu"))]
fn gpu_info() -> Result<()> {
    bail!("this binary was built without GPU support (rebuild with --features gpu)")
}

fn set_backend(name: &str) -> Result<()> {
    match name {
        "auto" | "gpu" | "cpu" => {}
        other => bail!("unknown backend '{other}' (auto, gpu, cpu)"),
    }
    #[cfg(feature = "gpu")]
    {
        use midwimble::core::gpu_mining::{set_backend, Backend};
        set_backend(match name {
            "gpu" => Backend::Gpu,
            "cpu" => Backend::Cpu,
            _ => Backend::Auto,
        });
    }
    #[cfg(not(feature = "gpu"))]
    if name == "gpu" {
        bail!("this binary was built without GPU support (rebuild with --features gpu)");
    }
    Ok(())
}

/// Runs `f` on Ctrl-C without pulling in another crate.
fn ctrlc_like(f: impl FnOnce() + Send + 'static) {
    std::thread::spawn(move || {
        if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            if rt.block_on(tokio::signal::ctrl_c()).is_ok() {
                f();
            }
        }
    });
}

fn sync_wallet(wallet: &mut Wallet, client: &RpcClient) -> Result<u64> {
    wallet.sync_from_node(client)
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Cmd::Node {
            data_dir,
            listen,
            peers,
            rpc,
            mine_to,
            threads,
            amino,
            public_address,
            min_block_interval,
            backend,
            checkpoint,
            prune,
            anchor_depth,
            finality_depth,
            anchor_min_work_bits,
            anchors,
        } => {
            set_backend(&backend)?;
            let level = std::env::var("MIDWIMBLE_LOG")
                .ok()
                .and_then(|l| l.parse::<tracing::Level>().ok())
                .unwrap_or(tracing::Level::INFO);
            tracing_subscriber::fmt().with_max_level(level).init();
            let mut config = NodeConfig::new(data_dir, listen.parse()?);
            config.bootstrap = peers.iter().map(|p| p.parse()).collect::<Result<_, _>>()?;
            config.mine_to = mine_to.as_deref().map(StealthAddress::decode).transpose()?;
            config.mining_threads = threads;
            config.amino = amino;
            config.public_address = public_address.map(|a| a.parse()).transpose()?;
            config.min_block_interval = std::time::Duration::from_millis(min_block_interval);
            config.finality = midwimble::finality::FinalityConfig {
                anchor_depth,
                finality_depth,
                min_work: if anchor_min_work_bits == 0 {
                    0
                } else {
                    1u128 << anchor_min_work_bits.min(127)
                },
                retained_checkpoints: 4,
                prune,
            };
            config.anchors_file = anchors;
            config.checkpoint = checkpoint
                .map(|c| -> Result<[u8; 32]> {
                    hex::decode(c.trim())?
                        .try_into()
                        .map_err(|_| anyhow!("checkpoint id must be 32 bytes"))
                })
                .transpose()?;
            let rpc_addr: std::net::SocketAddr = rpc.parse()?;
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(async move {
                let (node, handle) = Node::new(config).await?;
                let rpc_handle = handle.clone();
                tokio::spawn(async move {
                    if let Err(e) = rpc::serve(rpc_handle, rpc_addr).await {
                        tracing::error!("RPC server stopped: {:#}", e);
                    }
                });
                let shutdown = handle.clone();
                tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    shutdown.shutdown();
                });
                node.run().await
            })
        }
        Cmd::MergeMine {
            midstate_rpc,
            rpc,
            midstate_address,
            midwimble_address,
            threads,
            coinbase_log,
            backend,
            anchor_store,
            anchor_depth,
        } => {
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::INFO)
                .init();
            set_backend(&backend)?;
            let hex_addr = midstate_address.trim();
            let bytes = hex::decode(if hex_addr.len() == 72 {
                &hex_addr[..64]
            } else {
                hex_addr
            })?;
            let midstate_address: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow!("midstate address must be 32 bytes"))?;
            let cfg = midwimble::merge_mine::MergeMineConfig {
                midstate_rpc,
                midwimble_rpc: rpc,
                midstate_address,
                midwimble_address: StealthAddress::decode(&midwimble_address)?,
                threads,
                coinbase_log,
                refresh: std::time::Duration::from_secs(30),
                anchor_store,
                anchor_depth,
            };
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stats = std::sync::Arc::new(midwimble::merge_mine::MergeStats::default());
            {
                let stop = stop.clone();
                ctrlc_like(move || stop.store(true, std::sync::atomic::Ordering::Relaxed));
            }
            midwimble::merge_mine::run(cfg, stop, stats.clone())?;
            out!(
                "midstate blocks: {}, midwimble blocks: {}, rejected: {}",
                stats
                    .midstate_blocks
                    .load(std::sync::atomic::Ordering::Relaxed),
                stats
                    .midwimble_blocks
                    .load(std::sync::atomic::Ordering::Relaxed),
                stats.rejected.load(std::sync::atomic::Ordering::Relaxed)
            );
            Ok(())
        }
        Cmd::Pool {
            address,
            rpc,
            stratum,
            api,
            api_public,
            fee,
            share_bits,
            data_dir,
        } => {
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::INFO)
                .init();
            let cfg = midwimble::pool::PoolConfig {
                pool_address: StealthAddress::decode(&address)?,
                node_rpc: rpc,
                stratum_bind: stratum.parse()?,
                api_bind: api.parse()?,
                api_public,
                fee_percent: fee,
                share_bits,
                data_dir,
                poll_interval: std::time::Duration::from_secs(1),
            };
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(midwimble::pool::run_pool(cfg, Default::default()))
        }
        Cmd::PoolMine {
            pool,
            address,
            worker,
            threads,
            backend,
        } => {
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::INFO)
                .init();
            set_backend(&backend)?;
            let cfg = midwimble::pool::PoolMinerConfig {
                pool,
                address: StealthAddress::decode(&address)?,
                worker,
                threads,
            };
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            {
                let stop = stop.clone();
                ctrlc_like(move || stop.store(true, std::sync::atomic::Ordering::Relaxed));
            }
            let runtime = tokio::runtime::Runtime::new()?;
            loop {
                let stats = std::sync::Arc::new(midwimble::pool::PoolMinerStats::default());
                match runtime.block_on(midwimble::pool::run_pool_miner(
                    cfg.clone(),
                    stop.clone(),
                    stats,
                )) {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        tracing::warn!("pool connection ended: {e:#}; reconnecting in 5 s");
                        std::thread::sleep(std::time::Duration::from_secs(5));
                    }
                }
            }
        }
        Cmd::GpuInfo => gpu_info(),
        Cmd::Anchor {
            rpc,
            midstate_rpc,
            depth,
            lag,
            store,
            timeout_secs,
        } => {
            let node = RpcClient::new(rpc.clone());
            let record = midwimble::anchor::anchor_once(
                &RpcClient::new(rpc),
                &RpcClient::new(midstate_rpc),
                &store,
                lag,
                depth,
                0,
                std::time::Duration::from_secs(timeout_secs),
            )?;
            if let Err(e) = node.post("/anchors", &serde_json::to_value(&record)?) {
                eprintln!("warning: the node did not accept the anchor record: {e:#}");
            }
            let ev = record
                .evidence
                .as_ref()
                .expect("anchor_once returns evidence");
            out!(
                "checkpoint {} (height {}) anchored in Midstate block {} with {} confirmation(s)",
                record.checkpoint_id,
                record.checkpoint.mw_height,
                ev.midstate_height,
                ev.confirmations.len() + 1
            );
            Ok(())
        }
        Cmd::AnchorVerify { rpc, store, depth } => {
            let results =
                midwimble::anchor::verify_records(&RpcClient::new(rpc), &store, depth, 0)?;
            let mut failed = 0;
            for (id, r) in &results {
                match r {
                    Ok(()) => out!("{id}: ok"),
                    Err(e) => {
                        failed += 1;
                        out!("{id}: FAILED: {e:#}");
                    }
                }
            }
            if failed > 0 {
                bail!(
                    "{failed} of {} anchor(s) failed verification",
                    results.len()
                );
            }
            Ok(())
        }
        Cmd::Status { rpc } => {
            let v = RpcClient::new(rpc).get("/state")?;
            out!("{}", serde_json::to_string_pretty(&v)?);
            Ok(())
        }
        Cmd::Mine { address, stop, rpc } => {
            let client = RpcClient::new(rpc);
            let body = if stop {
                serde_json::json!({ "address": null })
            } else {
                let a = address.ok_or_else(|| anyhow!("--address or --stop is required"))?;
                StealthAddress::decode(&a)?;
                serde_json::json!({ "address": a })
            };
            out!("{}", client.post("/mining", &body)?);
            Ok(())
        }
        Cmd::Wallet {
            wallet: path,
            rpc,
            action,
        } => {
            let client = RpcClient::new(rpc);
            match action {
                WalletCmd::Create { recovery_height } => {
                    out!("Generating the post-quantum recovery key (height {recovery_height}); this can take a while...");
                    let (w, mnemonic) = Wallet::create(&path, &password()?, recovery_height)?;
                    out!("Wallet created at {}", path.display());
                    out!("Address: {}", w.address());
                    out!("\nRecovery phrase (write it down; anyone with it can spend your coins):\n{mnemonic}");
                }
                WalletCmd::Restore {
                    mnemonic,
                    birth_height,
                    recovery_height,
                } => {
                    let w = Wallet::restore(
                        &path,
                        &password()?,
                        &mnemonic,
                        birth_height,
                        recovery_height,
                    )?;
                    out!("Restored. Address: {}", w.address());
                }
                WalletCmd::Address => {
                    out!("{}", Wallet::open(&path, &password()?)?.address());
                }
                WalletCmd::Sync => {
                    let mut w = Wallet::open(&path, &password()?)?;
                    let n = sync_wallet(&mut w, &client)?;
                    out!(
                        "Scanned {} block(s); now at height {}",
                        n,
                        w.scanned_height()
                    );
                }
                WalletCmd::Balance => {
                    let mut w = Wallet::open(&path, &password()?)?;
                    sync_wallet(&mut w, &client)?;
                    let b = w.balance(client.height()?);
                    out!(
                        "spendable: {}\nimmature:  {}\npending:   {}",
                        b.spendable,
                        b.immature,
                        b.pending
                    );
                    out!(
                        "(one block reward is currently {} units)",
                        block_reward(client.height()?)
                    );
                }
                WalletCmd::Coins => {
                    let w = Wallet::open(&path, &password()?)?;
                    for c in w.coins() {
                        out!(
                            "{} value={} height={} coinbase={} spent={:?} pending={}",
                            hex::encode(c.output.commitment),
                            c.value,
                            c.height,
                            c.coinbase,
                            c.spent_height,
                            c.pending_tx.is_some()
                        );
                    }
                }
                WalletCmd::Send { to, amount, fee } => {
                    let mut w = Wallet::open(&path, &password()?)?;
                    sync_wallet(&mut w, &client)?;
                    let to = StealthAddress::decode(&to)?;
                    let tip = client.height()?;
                    let tx = w.build_send(&to, amount, fee, tip)?;
                    match client.submit(&tx) {
                        Ok(hash) => {
                            w.save()?;
                            out!("Submitted transaction {hash}");
                        }
                        Err(e) => {
                            w.cancel_pending(&hex::encode(tx.hash()));
                            return Err(e);
                        }
                    }
                }
            }
            Ok(())
        }
    }
}
