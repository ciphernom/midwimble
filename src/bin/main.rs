//! `midwimble` command-line interface.

use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use midwimble::core::mw::StealthAddress;
use midwimble::core::types::{block_reward, format_amount, parse_amount};
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
        /// Bond file to sign blocks with (see `midwimble bond`). Mining requires
        /// one from block 1.
        #[arg(long)]
        mining_bond: Option<PathBuf>,
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
        #[arg(long, default_value_t = 1_000)]
        anchor_depth: usize,
        /// Midwimble blocks after a checkpoint before it is finalized.
        #[arg(long, default_value_t = 100)]
        finality_depth: u64,
        /// Minimum work per Midstate header in anchor evidence, as leading
        /// zero bits. Zero accepts evidence built from trivial headers.
        #[arg(long, default_value_t = 19)]
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
        #[arg(long, default_value_t = 1_000)]
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
    /// Mining bonds: make a mining key, find the midstate address to lock MDS
    /// at, then register the bond once a day of work is buried above it.
    Bond {
        #[command(subcommand)]
        cmd: BondCmd,
    },
    /// Print this build's launch and consensus parameters, including the
    /// genesis block id to compare against the launch announcement.
    Params,
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
        /// Amount in coins, e.g. `--amount 0.25` (8 decimal places).
        #[arg(long)]
        amount: String,
        /// Fee in coins (defaults to the relay minimum for the inputs used).
        #[arg(long)]
        fee: Option<String>,
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

#[derive(Subcommand)]
enum BondCmd {
    /// Create a bond file holding a new mining key, and print the key.
    New {
        #[arg(long)]
        file: PathBuf,
    },
    /// Print the midstate script and address that lock a bond to this key.
    Address {
        #[arg(long)]
        file: PathBuf,
        /// Your midstate public key (hex): the only key that can spend the bond.
        #[arg(long)]
        owner_pk: String,
        /// Midstate height the bond stays locked until.
        #[arg(long)]
        until: u64,
    },
    /// Register a funded bond. The first run takes a proof against midstate's
    /// tip; run it again once a day of midstate work is buried above it.
    Register {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        owner_pk: String,
        #[arg(long)]
        until: u64,
        /// The bond coin's value, in midstate base units.
        #[arg(long)]
        value: u64,
        /// The bond coin's salt (hex), as your midstate wallet created it.
        #[arg(long)]
        salt: String,
        /// Your midstate node's RPC address, e.g. 127.0.0.1:8545.
        #[arg(long)]
        midstate_rpc: String,
        /// A midwimble node's RPC address, for its current target. Before
        /// launch, the genesis target is used.
        #[arg(long)]
        midwimble_rpc: Option<String>,
    },
}

fn bond_command(cmd: BondCmd) -> Result<()> {
    use midwimble::core::auxpow::bytes32;
    use midwimble::core::bond::*;
    use midwimble::core::state::calculate_work;
    use midwimble::core::types::GENESIS_TARGET;
    let read = |p: &PathBuf| -> Result<BondFile> { Ok(serde_json::from_slice(&std::fs::read(p)?)?) };
    let write = |p: &PathBuf, f: &BondFile| -> Result<()> {
        std::fs::write(p, serde_json::to_vec_pretty(f)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    };
    // Exactly 32 bytes of hex. Midstate's wallet prints *addresses* in a
    // 72-character checksummed form; refusing it stops the one mistake that
    // cannot be undone: a bond whose owner slot holds an address instead of a
    // public key can never be spent by anyone.
    let key32 = |s: &str, what: &str| -> Result<[u8; 32]> {
        let bytes = hex::decode(s.trim())?;
        match bytes.len() {
            32 => Ok(bytes.try_into().expect("32 bytes")),
            36 => anyhow::bail!(
                "{what} looks like a midstate address (72 hex characters with a checksum). \
                 A bond needs the owner's public key, not an address: a bond locked to an \
                 address can never be spent"
            ),
            _ => anyhow::bail!("{what} must be 32 bytes of hex"),
        }
    };
    match cmd {
        BondCmd::New { file } => {
            if file.exists() {
                anyhow::bail!("{} already exists", file.display());
            }
            let f = BondFile::generate();
            write(&file, &f)?;
            out!("mining key   {}", hex::encode(f.mining_key()?));
            out!("Keep {} safe: it can mine as the bond. Next: `midwimble bond address`.", file.display());
        }
        BondCmd::Address { file, owner_pk, until } => {
            let f = read(&file)?;
            let script = BondScript {
                mining_key: f.mining_key()?,
                bonded_until: until,
                owner_pk: key32(&owner_pk, "--owner-pk")?,
            };
            out!("script       {}", hex::encode(script.to_bytecode()));
            out!("address      {}", hex::encode(script.address()));
            out!(
                "Lock one coin of at least {} gMDS there on midstate. It can mine while more than 30 days of the lock remain.",
                MIN_MINING_BOND >> 30
            );
        }
        BondCmd::Register { file, owner_pk, until, value, salt, midstate_rpc, midwimble_rpc } => {
            let mut f = read(&file)?;
            let coin = BondCoin {
                script: BondScript {
                    mining_key: f.mining_key()?,
                    bonded_until: until,
                    owner_pk: key32(&owner_pk, "--owner-pk")?,
                },
                value,
                salt: key32(&salt, "--salt")?,
            };
            out!("bond coin    {}", hex::encode(coin.coin_id()));
            let midstate = RpcClient::new(midstate_rpc);

            // 1. The proof, taken once, against midstate's tip.
            let proof = match &f.proof {
                Some(p) if p.coin == coin => {
                    out!("✓ proof already taken at midstate height {}", p.midstate_height);
                    p.clone()
                }
                _ => {
                    let v = midstate.get(&format!("/utxo_proof/{}", hex::encode(coin.coin_id())))?;
                    let p = bond_proof_from_json(coin, &v)?;
                    let bond = p.verify(&bytes32(&v["state_root"])?)?;
                    out!("✓ four roots rebuild midstate's state root at height {}", p.midstate_height);
                    out!("✓ SMT proof: the bond coin is unspent there ({} units, locked until {})", bond.value, bond.bonded_until);
                    f.coin = Some(coin);
                    f.proof = Some(p.clone());
                    f.registration = None;
                    write(&file, &f)?;
                    p
                }
            };

            // 2. A day of midwimble-equivalent work buried above it, plus a margin.
            let target = match midwimble_rpc {
                Some(addr) => bytes32(&RpcClient::new(addr).get("/state")?["target"])?,
                None => GENESIS_TARGET,
            };
            let required = registration_work(&target);
            let goal = required + required / 4;
            let cap = (required / REGISTRATION_MIN_HEADERS).max(1);
            let (mut links, mut first_prev, mut next) = (Vec::new(), None, proof.midstate_height);
            let (mut credited, mut enough) = (0u128, false);
            'fetch: loop {
                let v = midstate.get(&format!("/headers/{next}/2000"))?;
                let headers = v["headers"].as_array().cloned().unwrap_or_default();
                for h in &headers {
                    let (link, prev) = header_link_from_json(h)?;
                    if first_prev.is_none() {
                        first_prev = Some(prev);
                    } else {
                        credited = credited.saturating_add(calculate_work(&link.target).min(cap));
                    }
                    links.push(link);
                    if credited >= goal {
                        enough = true;
                        break 'fetch;
                    }
                }
                if headers.len() < 2000 || links.len() >= REGISTRATION_MAX_HEADERS {
                    break;
                }
                next += headers.len() as u64;
            }
            out!("midstate work above the proof: {}% of what registration needs (with a 25% margin)", credited * 100 / goal.max(1));
            if !enough {
                out!("Not buried deep enough yet: run this again later, at most a day from the proof.");
                return Ok(());
            }
            let registration = BondRegistration {
                proof,
                prev_header_hash: first_prev.expect("headers were fetched"),
                headers: links,
            };
            let bond = registration.verify(&target)?;
            out!("✓ {} midstate headers link up and every proof of work checks", registration.headers.len());
            out!("✓ registration valid at midwimble's current target: bond {}", hex::encode(bond.id));
            f.registration = Some(registration);
            write(&file, &f)?;
            out!("Ready: midwimble node --mining-bond {} --mine-to <address>", file.display());
        }
    }
    Ok(())
}

/// `YYYY-MM-DD HH:MM UTC` for a Unix timestamp (Hinnant's civil-from-days,
/// to avoid a date crate for one command).
fn utc(ts: u64) -> String {
    let days = (ts / 86_400) as i64;
    let secs = ts % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        secs / 3600,
        secs % 3600 / 60
    )
}

fn print_params() {
    use midwimble::core::state::calculate_work;
    use midwimble::core::types::{
        count_leading_zeros, network_anchor, ASERT_HALF_LIFE, BITCOIN_BLOCK_HASH,
        BITCOIN_BLOCK_HEIGHT, BITCOIN_BLOCK_TIME, COINBASE_MATURITY, EMISSION,
        GENESIS_TARGET, GENESIS_TIMESTAMP, HALVING_INTERVAL, LAUNCH_PARAMETERS_SET,
        MAX_SUPPLY, MIDSTATE_BLOCK_HASH, MIDSTATE_BLOCK_HEIGHT, MIN_FEE_PER_WEIGHT, NETWORK_MAGIC,
        TARGET_BLOCK_TIME,
    };
    use midwimble::core::bond::{BONDED_MINING_FROM, MIN_MINING_BOND};
    let at = |height: u64| utc(GENESIS_TIMESTAMP + height * TARGET_BLOCK_TIME);
    let kind = match (LAUNCH_PARAMETERS_SET, cfg!(feature = "fast-mining")) {
        (_, true) => "FAST-MINING TEST BUILD (never run this on a real network)",
        (true, false) => "mainnet",
        (false, false) => "DEVNET: launch parameters are still placeholders",
    };
    out!("build                {kind}");
    out!("network magic        {}", String::from_utf8_lossy(NETWORK_MAGIC));
    out!("network anchor       {}", hex::encode(network_anchor()));
    out!(
        "bitcoin anchor       height {BITCOIN_BLOCK_HEIGHT}, mined {}",
        utc(BITCOIN_BLOCK_TIME)
    );
    out!("                     {BITCOIN_BLOCK_HASH}");
    out!("midstate anchor      height {MIDSTATE_BLOCK_HEIGHT}");
    out!("                     {MIDSTATE_BLOCK_HASH}");
    out!("genesis time         {} ({GENESIS_TIMESTAMP})", utc(GENESIS_TIMESTAMP));
    let work = calculate_work(&GENESIS_TARGET);
    out!(
        "genesis target       {} ({} leading zero bits; 60 s blocks at ~{} attempts/s)",
        hex::encode(GENESIS_TARGET),
        count_leading_zeros(&GENESIS_TARGET),
        work / TARGET_BLOCK_TIME as u128
    );
    out!(
        "genesis block        {}",
        hex::encode(midwimble::core::Batch::genesis().extension.final_hash)
    );
    out!("");
    out!(
        "block time           {TARGET_BLOCK_TIME} s, ASERT half-life {} h, coinbase maturity {COINBASE_MATURITY}",
        ASERT_HALF_LIFE / 3600
    );
    out!("relay fee floor      {MIN_FEE_PER_WEIGHT} units per weight");
    if BONDED_MINING_FROM == u64::MAX {
        out!("bonded mining        optional in this test build (verified when present)");
    } else {
        out!(
            "bonded mining        every block from height {BONDED_MINING_FROM}; bonds of at least {} gMDS",
            MIN_MINING_BOND >> 30
        );
    }
    out!("");
    out!("max supply           {} (8 decimal places, reached exactly)", format_amount(MAX_SUPPLY));
    if EMISSION.slow_start > 0 {
        out!(
            "slow start           blocks 1..={}, ending ~{}",
            EMISSION.slow_start,
            at(EMISSION.slow_start)
        );
    }
    out!("era-0 reward         {}", format_amount(EMISSION.initial_reward));
    out!(
        "halving interval     {HALVING_INTERVAL} blocks ({} s, Bitcoin's era length)",
        HALVING_INTERVAL * TARGET_BLOCK_TIME
    );
    for k in 1..=6u64 {
        let h = k * HALVING_INTERVAL;
        out!(
            "  halving {k}          height {h:>10}  reward {}  ~{}",
            format_amount(block_reward(h)),
            at(h)
        );
    }
    if let Some(end) = EMISSION.final_reward_height() {
        out!("last minting block   height {end}, ~{}", at(end));
    }
    out!("(dates assume the hashrate stays near its launch calibration; ASERT keeps them within a day or two)");
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
            mine_to, mining_bond,
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
            if !midwimble::core::types::LAUNCH_PARAMETERS_SET {
                tracing::warn!(
                    "this build carries placeholder launch parameters (network magic {}), so it is \
                     a devnet build: see docs/LAUNCH.md",
                    String::from_utf8_lossy(midwimble::core::types::NETWORK_MAGIC)
                );
            }
            let mut config = NodeConfig::new(data_dir, listen.parse()?);
            config.bootstrap = peers.iter().map(|p| p.parse()).collect::<Result<_, _>>()?;
            config.mine_to = mine_to.as_deref().map(StealthAddress::decode).transpose()?;
            if let Some(path) = &mining_bond {
                let file: midwimble::core::bond::BondFile = serde_json::from_slice(&std::fs::read(path)?)?;
                let bond = file.miner_bond()?;
                tracing::info!("Mining as bond {}", hex::encode(bond.bond_id));
                config.mining_bond = Some(bond);
            } else if config.mine_to.is_some()
                && midwimble::core::bond::BONDED_MINING_FROM != u64::MAX
            {
                anyhow::bail!("mining requires a registered bond: pass --mining-bond (see `midwimble bond`)");
            }
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
        Cmd::Bond { cmd } => bond_command(cmd),
        Cmd::Params => {
            print_params();
            Ok(())
        }
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
                        format_amount(b.spendable),
                        format_amount(b.immature),
                        format_amount(b.pending)
                    );
                    out!(
                        "(one block reward is currently {})",
                        format_amount(block_reward(client.height()?))
                    );
                }
                WalletCmd::Coins => {
                    let w = Wallet::open(&path, &password()?)?;
                    for c in w.coins() {
                        out!(
                            "{} value={} height={} coinbase={} spent={:?} pending={}",
                            hex::encode(c.output.commitment),
                            format_amount(c.value),
                            c.height,
                            c.coinbase,
                            c.spent_height,
                            c.pending_tx.is_some()
                        );
                    }
                }
                WalletCmd::Send { to, amount, fee } => {
                    let amount = parse_amount(&amount)?;
                    let fee = fee.as_deref().map(parse_amount).transpose()?;
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
