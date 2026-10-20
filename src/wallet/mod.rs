//! Wallet: keys, encrypted storage, chain scanning, spending.
//!
//! Keys come from a BIP39 mnemonic (pluribit's wallet does the same). The
//! wallet file is encrypted with Argon2id + XChaCha20-Poly1305 (midstate uses
//! Argon2id with AES-GCM; the AEAD is swapped for the one the payload
//! encryption already uses). Only public output data is stored; blinding
//! factors and owner secrets are re-derived from the seed when spending.
//!
//! The browser wallet (`web-wallet/`) reads and writes the same file, JSON
//! included: the payments this wallet made (`sent`) and its birth height go
//! with the file both ways.
//!
//! Following the chain: the wallet keeps the hashes of the last
//! [`REORG_WINDOW`] blocks it scanned. When the node's chain no longer holds
//! the last one, it steps back ten blocks at a time until the two agree and
//! scans the new chain from there; past the oldest hash it keeps, it rescans
//! from its birth height. A payment of its own that a lost block confirmed
//! waits for a block again, its coins still reserved for it, and is
//! broadcast again until a block takes it. Payments to it that wait in the
//! node's mempool show as incoming, and are not spendable until a block
//! confirms them.

use crate::core::mw::crypto::{self, Point32};
use crate::core::mw::stealth::scan_output;
use crate::core::mw::{
    build_transaction, Output, Payment, Spendable, StealthAddress, Transaction, WalletKeys,
};
use crate::core::recovery::{derive_recovery_keypair, ClaimedOutput, RecoveryClaim};
use crate::core::types::COINBASE_MATURITY;
use crate::core::Batch;
use crate::rpc::RpcClient;
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const FILE_MAGIC: &[u8] = b"MWWALLET1";
/// Recent block hashes kept for reorg detection.
pub const REORG_WINDOW: usize = 200;
/// What [`Wallet::scan_block`] fails with for a block that does not build on
/// the one scanned before it.
const REORG: &str = "reorg detected";
/// Times one sync steps back before giving up on a node whose chain will
/// not settle.
const MAX_ROLLBACKS: usize = 64;
/// A payment still waiting for a block is broadcast again once it is this
/// old (seconds) and the node's mempool does not have it. Younger, it may
/// still be on its Dandelion++ stem, out of every mempool's sight.
pub const REBROADCAST_SECS: u64 = 120;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletCoin {
    pub output: Output,
    pub value: u64,
    pub height: u64,
    pub coinbase: bool,
    /// Height of the block that spent it.
    pub spent_height: Option<u64>,
    /// Hash of an unconfirmed transaction spending it.
    pub pending_tx: Option<String>,
}

/// A payment made from this wallet (the browser wallet's, field for field).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sent {
    pub tx_hash: String,
    /// The transaction's kernel id: the block that carries it confirmed it.
    pub kernel: [u8; 32],
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub inputs: Vec<Point32>,
    /// The change output, which comes back to this wallet (not income).
    pub change: Option<Point32>,
    /// Unix seconds.
    pub created_at: u64,
    /// Kept for broadcasting again until its block is [`REORG_WINDOW`] deep.
    pub tx_hex: Option<String>,
    /// Height of the block that confirmed it.
    pub height: Option<u64>,
    /// Height of a block that spent its inputs without it: another
    /// transaction (from another copy of this wallet) got there first.
    pub failed_at: Option<u64>,
    /// Released (`wallet cancel`): its coins are spendable again.
    pub cancelled: bool,
}

impl Sent {
    /// Neither confirmed, failed nor released.
    pub fn is_pending(&self) -> bool {
        self.height.is_none() && self.failed_at.is_none() && !self.cancelled
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletData {
    version: u32,
    mnemonic: String,
    /// MSS master public key for post-quantum recovery (see `core/recovery.rs`).
    recovery_key: [u8; 32],
    recovery_height: u32,
    /// Next height to scan.
    scanned_height: u64,
    /// (height, block hash) of recently scanned blocks, for reorg detection.
    recent: Vec<(u64, [u8; 32])>,
    coins: Vec<WalletCoin>,
    /// Where a rescan starts: the height a restore began scanning at (0 for
    /// files from before it was kept).
    #[serde(default)]
    birth_height: u64,
    /// This wallet's own payments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    sent: Vec<Sent>,
    /// The id of block 0 of the chain this wallet scanned, recorded at its
    /// first sync: a node on another chain (another network, or the network
    /// relaunched) is refused. The browser wallet checks the network against
    /// its own configuration instead and leaves this out of files it saves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    genesis: Option<[u8; 32]>,
}

impl Drop for WalletData {
    fn drop(&mut self) {
        self.mnemonic.zeroize();
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Balance {
    pub spendable: u64,
    pub immature: u64,
    /// This wallet's coins in its own payments still waiting for a block
    /// (their change included).
    pub pending: u64,
    /// Payments to this wallet waiting in the node's mempool at the last
    /// sync: not spendable until a block confirms them.
    pub incoming: u64,
}

/// A payment to this wallet waiting in the node's mempool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incoming {
    pub tx_hash: String,
    pub value: u64,
}

/// What a [`Wallet::sync`] did and found.
#[derive(Debug, Default)]
pub struct SyncReport {
    /// The node's height (that of the next block).
    pub tip: u64,
    /// Whether the node said it is downloading a heavier chain, so that its
    /// chain may still change.
    pub node_syncing: bool,
    /// Blocks scanned.
    pub blocks: u64,
    /// Coins found reading the unspent outputs of a node that has pruned the
    /// blocks this wallet would have scanned.
    pub restored: u64,
    /// The node is behind this wallet: nothing was scanned or rolled back.
    pub behind: bool,
    /// The chain reorganised: the lowest height the wallet went back to.
    pub rolled_back_to: Option<u64>,
    /// The reorganisation went further back than the block hashes this
    /// wallet keeps: it rescanned from its birth height.
    pub rescanned: bool,
    /// New coins, the change of its own payments aside: (value, coinbase,
    /// height).
    pub received: Vec<(u64, bool, u64)>,
    /// Coins from blocks no longer on the chain, change aside: (value,
    /// coinbase).
    pub lost: Vec<(u64, bool)>,
    /// Its payments that a block confirmed: (tx hash, height).
    pub confirmed: Vec<(String, u64)>,
    /// Its payments whose coins a block spent some other way.
    pub failed: Vec<String>,
    /// Its payments that a reorganisation took out of their block: waiting
    /// for a block again.
    pub unconfirmed: Vec<String>,
    /// Its payments that can no longer confirm: the coins they spend are
    /// not on the node's chain (a reorganisation took the blocks that made
    /// them).
    pub orphaned: Vec<String>,
    /// Its payments broadcast again because the node had lost them.
    pub rebroadcast: Vec<String>,
    /// Its payments the node refused when they were broadcast again: (tx
    /// hash, why).
    pub refused: Vec<(String, String)>,
    /// Whether the node's mempool was looked at, so that
    /// [`Wallet::incoming`] is current (nodes from before `/mempool/txs`
    /// cannot show it, and a wallet that is not caught up does not look).
    pub mempool: bool,
}

/// What the wallet knew before a sync, to tell what the sync changed.
struct Snapshot {
    coins: HashMap<Point32, (u64, bool)>,
    /// tx hash → (height, failed_at).
    sent: HashMap<String, (Option<u64>, Option<u64>)>,
}

pub struct Wallet {
    path: PathBuf,
    password: String,
    data: WalletData,
    keys: WalletKeys,
    /// Payments to this wallet in the node's mempool at the last sync.
    incoming: Vec<Incoming>,
    /// What the wallet knew before a rescan: the next sync reports what
    /// changed since then, not everything the rescan found again.
    baseline: Option<Snapshot>,
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    // OWASP's Argon2id baseline: 19 MiB, 2 passes, 1 lane.
    let params = Params::new(19_456, 2, 1, Some(32)).map_err(|e| anyhow!("argon2 params: {e}"))?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("argon2: {e}"))?;
    Ok(key)
}

fn seed_of(mnemonic: &str) -> Result<[u8; 64]> {
    let m = bip39::Mnemonic::parse_normalized(mnemonic)
        .map_err(|e| anyhow!("invalid mnemonic: {e}"))?;
    Ok(m.to_seed(""))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Refusals that need nothing from the user when a payment is broadcast
/// again: it is in the pool already, or a block (one this wallet will scan
/// next) has settled it.
fn expected_refusal(e: &str) -> bool {
    [
        "already in pool",
        "already being validated",
        "not found or already spent",
        "node busy",
    ]
    .iter()
    .any(|m| e.contains(m))
}

impl Wallet {
    /// Creates a new wallet with a fresh 24-word mnemonic and a recovery key
    /// of `recovery_height` (2^height claims; generation takes a while).
    pub fn create(path: &Path, password: &str, recovery_height: u32) -> Result<(Self, String)> {
        let mut entropy: [u8; 32] = rand::random();
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
            .map_err(|e| anyhow!("{e}"))?
            .to_string();
        entropy.zeroize();
        let wallet = Self::restore(path, password, &mnemonic, 0, recovery_height)?;
        Ok((wallet, mnemonic))
    }

    /// Restores from a mnemonic; scanning starts at `birth_height`. The
    /// recovery height must match the one used at creation.
    pub fn restore(
        path: &Path,
        password: &str,
        mnemonic: &str,
        birth_height: u64,
        recovery_height: u32,
    ) -> Result<Self> {
        if path.exists() {
            bail!("{} already exists", path.display());
        }
        let mut seed = seed_of(mnemonic)?;
        let recovery_key = derive_recovery_keypair(&seed, recovery_height)?.public_key();
        let keys = WalletKeys::from_seed(&seed, recovery_key);
        seed.zeroize();
        let wallet = Self {
            path: path.to_path_buf(),
            password: password.to_string(),
            data: WalletData {
                version: 1,
                mnemonic: mnemonic.to_string(),
                recovery_key,
                recovery_height,
                scanned_height: birth_height,
                recent: Vec::new(),
                coins: Vec::new(),
                birth_height,
                sent: Vec::new(),
                genesis: None,
            },
            keys,
            incoming: Vec::new(),
            baseline: None,
        };
        wallet.save()?;
        Ok(wallet)
    }

    pub fn open(path: &Path, password: &str) -> Result<Self> {
        let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        if raw.len() < FILE_MAGIC.len() + 16 + 24 || !raw.starts_with(FILE_MAGIC) {
            bail!("not a midwimble wallet file");
        }
        let body = &raw[FILE_MAGIC.len()..];
        let (salt, rest) = body.split_at(16);
        let (nonce, ciphertext) = rest.split_at(24);
        let mut key = derive_key(password, salt)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        key.zeroize();
        let mut plain = cipher
            .decrypt(XNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow!("wrong password or corrupted wallet"))?;
        let data = serde_json::from_slice::<WalletData>(&plain);
        plain.zeroize();
        let data = data?;
        let mut seed = seed_of(&data.mnemonic)?;
        let keys = WalletKeys::from_seed(&seed, data.recovery_key);
        seed.zeroize();
        Ok(Self {
            path: path.to_path_buf(),
            password: password.to_string(),
            data,
            keys,
            incoming: Vec::new(),
            baseline: None,
        })
    }

    /// Writes atomically (temp file + rename).
    pub fn save(&self) -> Result<()> {
        let salt: [u8; 16] = rand::random();
        let nonce: [u8; 24] = rand::random();
        let mut key = derive_key(&self.password, &salt)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        key.zeroize();
        let mut plain = serde_json::to_vec(&self.data)?;
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), plain.as_slice())
            .map_err(|_| anyhow!("encryption failed"))?;
        plain.zeroize();
        let mut out = Vec::with_capacity(FILE_MAGIC.len() + 40 + ciphertext.len());
        out.extend_from_slice(FILE_MAGIC);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &out)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Encrypts the file under `password` from now on, and saves it.
    pub fn change_password(&mut self, password: &str) -> Result<()> {
        if password.is_empty() {
            bail!("empty password");
        }
        self.password.zeroize();
        self.password = password.to_string();
        self.save()
    }

    pub fn mnemonic(&self) -> &str {
        &self.data.mnemonic
    }

    pub fn address(&self) -> StealthAddress {
        self.keys.address()
    }

    /// A key that sees this wallet's incoming payments but cannot spend
    /// them, e.g. for a pool miner to audit its payouts with.
    pub fn view_key(&self) -> crate::core::mw::ViewKey {
        self.keys.view_only()
    }

    pub fn scanned_height(&self) -> u64 {
        self.data.scanned_height
    }

    /// Where a rescan starts.
    pub fn birth_height(&self) -> u64 {
        self.data.birth_height
    }

    pub fn coins(&self) -> &[WalletCoin] {
        &self.data.coins
    }

    /// This wallet's payments, oldest first.
    pub fn payments(&self) -> &[Sent] {
        &self.data.sent
    }

    /// Payments to this wallet waiting in the node's mempool at the last
    /// sync.
    pub fn incoming(&self) -> &[Incoming] {
        &self.incoming
    }

    /// The block hash we recorded at `height`, if still in the window.
    pub fn recorded_hash(&self, height: u64) -> Option<[u8; 32]> {
        self.data
            .recent
            .iter()
            .find(|(h, _)| *h == height)
            .map(|(_, x)| *x)
    }

    /// Forgets everything learned from blocks at or above `height`. A
    /// payment those blocks settled waits for a block again: its coins are
    /// reserved for it once more, and syncing broadcasts it again (the node
    /// usually puts it back in its mempool itself). Returns whether
    /// anything changed.
    pub fn rollback_to(&mut self, height: u64) -> bool {
        let before = self.data.coins.len();
        self.data.coins.retain(|c| c.height < height);
        let mut changed = self.data.coins.len() != before;
        for c in &mut self.data.coins {
            if c.spent_height.map_or(false, |h| h >= height) {
                c.spent_height = None;
                changed = true;
            }
        }
        for s in &mut self.data.sent {
            let mut unsettled = false;
            if s.height.map_or(false, |h| h >= height) {
                s.height = None;
                unsettled = true;
            }
            if s.failed_at.map_or(false, |h| h >= height) {
                s.failed_at = None;
                unsettled = true;
            }
            if unsettled {
                changed = true;
                if !s.cancelled {
                    for c in &mut self.data.coins {
                        if c.spent_height.is_none() && s.inputs.contains(&c.output.commitment) {
                            c.pending_tx = Some(s.tx_hash.clone());
                        }
                    }
                }
            }
        }
        self.data.recent.retain(|(h, _)| *h < height);
        self.data.scanned_height = self.data.scanned_height.min(height);
        changed
    }

    /// Scans again from `height` (at most the height scanned so far), as if
    /// the blocks from there on were new.
    pub fn rescan_from(&mut self, height: u64) -> Result<()> {
        if height > self.data.scanned_height {
            bail!(
                "this wallet has scanned up to block {}; it can rescan from there or below",
                self.data.scanned_height
            );
        }
        self.rollback_to(height);
        self.data.birth_height = self.data.birth_height.min(height);
        Ok(())
    }

    /// Forgets the chain this wallet scanned, coins and payments included,
    /// to scan another from its birth height: for a network that was
    /// relaunched.
    fn start_over(&mut self) {
        self.data.coins.clear();
        self.data.sent.clear();
        self.data.recent.clear();
        self.data.scanned_height = self.data.birth_height;
        self.data.genesis = None;
        self.incoming.clear();
    }

    /// Applies one block at `height` (must equal `scanned_height`). Fails
    /// with "reorg detected…" if the block does not build on the one
    /// scanned before it.
    pub fn scan_block(&mut self, height: u64, batch: &Batch) -> Result<()> {
        if height != self.data.scanned_height {
            bail!(
                "expected block {}, got {}",
                self.data.scanned_height,
                height
            );
        }
        if height > 0 {
            if let Some(prev) = self.recorded_hash(height - 1) {
                if prev != batch.prev_header_hash {
                    bail!("{REORG} below height {height}");
                }
            }
        }
        let spent: HashSet<Point32> = batch.body.input_commitments().copied().collect();
        for coin in &mut self.data.coins {
            if coin.spent_height.is_none() && spent.contains(&coin.output.commitment) {
                coin.spent_height = Some(height);
                coin.pending_tx = None;
            }
        }
        let kernels: HashSet<[u8; 32]> = batch.body.kernel_ids().into_iter().collect();
        for s in &mut self.data.sent {
            if s.height.is_some() || s.failed_at.is_some() {
                continue;
            }
            // The transaction is kept until the block is deep (below): a
            // reorganisation can undo it, and then it is broadcast again.
            if kernels.contains(&s.kernel) {
                s.height = Some(height);
            } else if s.inputs.iter().any(|c| spent.contains(c)) {
                s.failed_at = Some(height);
            }
        }
        let mut known: HashSet<Point32> = self
            .data
            .coins
            .iter()
            .map(|c| c.output.commitment)
            .collect();
        let body = batch.body.outputs().map(|o| (o, false));
        let reward = batch
            .coinbase
            .iter()
            .flat_map(|c| c.outputs.outputs.iter())
            .map(|o| (o, true));
        for (output, coinbase) in body.chain(reward) {
            if known.contains(&output.commitment) {
                continue;
            }
            if let Some(owned) = scan_output(&self.keys, output) {
                known.insert(output.commitment);
                // Found again after a rollback, a coin that a payment still
                // waiting for a block spends stays reserved for it.
                let pending_tx = self.reserved_for(&output.commitment);
                self.data.coins.push(WalletCoin {
                    output: output.clone(),
                    value: owned.value,
                    height,
                    coinbase,
                    spent_height: None,
                    pending_tx,
                });
            }
        }
        // Past the reorg window a payment's block is settled for this
        // wallet: its transaction is no longer needed.
        for s in &mut self.data.sent {
            if s.height
                .or(s.failed_at)
                .map_or(false, |h| height >= h + REORG_WINDOW as u64)
            {
                s.tx_hex = None;
            }
        }
        self.data.recent.push((height, batch.extension.final_hash));
        if self.data.recent.len() > REORG_WINDOW {
            self.data.recent.remove(0);
        }
        self.data.scanned_height = height + 1;
        Ok(())
    }

    /// The payment still waiting for a block that spends this coin, if any.
    fn reserved_for(&self, commitment: &Point32) -> Option<String> {
        self.data
            .sent
            .iter()
            .find(|s| s.is_pending() && s.inputs.contains(commitment))
            .map(|s| s.tx_hash.clone())
    }

    /// Brings the wallet up to date with a node, and saves it: checks that
    /// the node is on this wallet's chain, follows reorganisations, scans
    /// the new blocks (or reads the unspent outputs from a node that has
    /// pruned the blocks it would need), broadcasts its payments still
    /// waiting for a block again if the node lost them, and looks in the
    /// node's mempool for payments to it. A node behind this wallet (still
    /// syncing, say) is waited for: nothing is scanned or rolled back.
    pub fn sync(&mut self, client: &RpcClient) -> Result<SyncReport> {
        let state = client.get("/state")?;
        let tip = state["height"]
            .as_u64()
            .ok_or_else(|| anyhow!("bad /state response"))?;
        let mut report = SyncReport {
            tip,
            node_syncing: state["syncing"].as_bool().unwrap_or(false),
            ..SyncReport::default()
        };
        self.check_chain(client)?;
        let before = self.baseline.take().unwrap_or_else(|| self.snapshot());
        if tip < self.data.scanned_height {
            report.behind = true;
            self.save()?;
            return Ok(report);
        }
        let pruned_below = client
            .get("/finality")
            .map(|f| f["pruned_below"].as_u64().unwrap_or(0))
            .unwrap_or(0);
        let mut rollbacks = 0;
        for _ in 0..3 {
            self.check_last_block(
                tip,
                &mut |h| {
                    Ok(client
                        .block_ids(h, 1)?
                        .into_iter()
                        .find(|(x, _)| *x == h)
                        .map(|(_, id)| id))
                },
                &mut rollbacks,
                &mut report,
            )?;
            if self.data.scanned_height < pruned_below {
                report.restored += self.restore_from_unspent(client, tip)?;
            }
            self.scan_forward(
                tip,
                &mut |s, n| client.blocks(s, n),
                &mut rollbacks,
                &mut report,
            )?;
            if self.data.scanned_height >= tip {
                break;
            }
        }
        // Caught up only: coins in blocks not yet scanned would look like
        // payments waiting for a block.
        if self.data.scanned_height >= tip {
            report.orphaned = self.settle_orphans();
            self.look_at_mempool(client, &mut report);
        }
        self.compare(&before, &mut report);
        self.save()?;
        Ok(report)
    }

    /// Refuses a node on another chain than the one this wallet scanned:
    /// its block 0 must be the one recorded at the first sync.
    fn check_chain(&mut self, client: &RpcClient) -> Result<()> {
        // A node bootstrapped from a snapshot may lack the early headers:
        // then there is nothing to compare.
        let Some(genesis) = client
            .block_ids(0, 1)?
            .into_iter()
            .find(|(h, _)| *h == 0)
            .map(|(_, id)| id)
        else {
            return Ok(());
        };
        match self.data.genesis {
            Some(ours) if ours != genesis => bail!(
                "this wallet was synced on another chain (its block 0 is {}…, the node's is {}…). \
                 The node may be on another network. If the network was relaunched, \
                 `wallet rescan` starts this wallet over on the node's chain, forgetting the old \
                 chain's coins and payments",
                &hex::encode(ours)[..12],
                &hex::encode(genesis)[..12]
            ),
            Some(_) => {}
            None => self.data.genesis = Some(genesis),
        }
        Ok(())
    }

    /// Starts scanning over, from `from` or the birth height, for the next
    /// [`Self::sync`] to do; that sync reports only what the rescan changed.
    /// If the node is on another chain than the one this wallet scanned (a
    /// network relaunched), that chain's coins and payments are forgotten
    /// and scanning starts afresh at `from`; returns whether they were.
    pub fn rescan(&mut self, client: &RpcClient, from: Option<u64>) -> Result<bool> {
        let genesis = client
            .block_ids(0, 1)?
            .into_iter()
            .find(|(h, _)| *h == 0)
            .map(|(_, id)| id);
        let other_chain = matches!((self.data.genesis, genesis), (Some(a), Some(b)) if a != b);
        let from = from.unwrap_or(self.data.birth_height);
        if other_chain {
            self.start_over();
            self.data.birth_height = from;
            self.data.scanned_height = from;
            self.baseline = None;
        } else {
            let before = self.snapshot();
            self.rescan_from(from)?;
            self.baseline.get_or_insert(before);
        }
        Ok(other_chain)
    }

    /// Rolls back while the last block scanned is not the node's.
    /// `id_at(h)` is the id of the node's block `h`.
    fn check_last_block(
        &mut self,
        tip: u64,
        id_at: &mut dyn FnMut(u64) -> Result<Option<[u8; 32]>>,
        rollbacks: &mut usize,
        report: &mut SyncReport,
    ) -> Result<()> {
        loop {
            let h = self.data.scanned_height;
            if h == 0 || h > tip {
                return Ok(());
            }
            let Some(recorded) = self.recorded_hash(h - 1) else {
                return Ok(());
            };
            match id_at(h - 1)? {
                Some(id) if id == recorded => return Ok(()),
                Some(_) => self.step_back(rollbacks, report)?,
                // Below the snapshot a node started from: final anyway.
                None => return Ok(()),
            }
        }
    }

    /// Scans the node's blocks up to `tip` (exclusive), stepping back when
    /// one does not build on the block before it.
    fn scan_forward(
        &mut self,
        tip: u64,
        fetch: &mut dyn FnMut(u64, u64) -> Result<Vec<Batch>>,
        rollbacks: &mut usize,
        report: &mut SyncReport,
    ) -> Result<()> {
        while self.data.scanned_height < tip {
            let start = self.data.scanned_height;
            let batches = fetch(start, (tip - start).min(64))?;
            if batches.is_empty() {
                break;
            }
            for (i, b) in batches.iter().enumerate() {
                match self.scan_block(start + i as u64, b) {
                    Ok(()) => report.blocks += 1,
                    Err(e) if e.to_string().starts_with(REORG) => {
                        self.step_back(rollbacks, report)?;
                        break;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }

    /// A block this wallet scanned is no longer the node's: forgets the last
    /// eleven, and the caller looks again from there. Past the oldest block
    /// hash it keeps it cannot tell where the chains part, so it rescans
    /// from its birth height instead.
    fn step_back(&mut self, rollbacks: &mut usize, report: &mut SyncReport) -> Result<()> {
        *rollbacks += 1;
        if *rollbacks > MAX_ROLLBACKS {
            bail!("the node's chain keeps changing under this wallet; try again later");
        }
        let birth = self.data.birth_height;
        let mut to = birth.max(self.data.scanned_height.saturating_sub(11));
        if to > birth && self.recorded_hash(to - 1).is_none() {
            to = birth;
            report.rescanned = true;
        }
        self.rollback_to(to);
        report.rolled_back_to = Some(report.rolled_back_to.map_or(to, |r| r.min(to)));
        Ok(())
    }

    /// Reads the node's unspent outputs instead of the blocks it pruned.
    fn restore_from_unspent(&mut self, client: &RpcClient, tip: u64) -> Result<u64> {
        const PAGE: usize = 256;
        let mut outputs = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let (page, next) = client.unspent_outputs(cursor.as_deref(), PAGE)?;
            let got = page.len();
            outputs.extend(page);
            match next {
                Some(c) if got == PAGE => cursor = Some(c),
                _ => break,
            }
        }
        self.scan_unspent(&outputs, tip)
    }

    /// Once every block is scanned, a payment still waiting for a block
    /// whose coins this wallet does not hold unspent can never confirm on
    /// this chain: a reorganisation (or a rescan) took the blocks that made
    /// them. It is marked failed, at the last block scanned, so that a
    /// reorganisation back to a chain with those coins puts it back to
    /// waiting. Returns the hashes of the payments marked.
    fn settle_orphans(&mut self) -> Vec<String> {
        let unspent: HashSet<Point32> = self
            .data
            .coins
            .iter()
            .filter(|c| c.spent_height.is_none())
            .map(|c| c.output.commitment)
            .collect();
        let last = self.data.scanned_height.saturating_sub(1);
        let mut orphaned = Vec::new();
        for s in &mut self.data.sent {
            if s.is_pending() && s.inputs.iter().any(|c| !unspent.contains(c)) {
                s.failed_at = Some(last);
                orphaned.push(s.tx_hash.clone());
            }
        }
        for c in &mut self.data.coins {
            if c.pending_tx
                .as_ref()
                .map_or(false, |h| orphaned.contains(h))
            {
                c.pending_tx = None;
            }
        }
        orphaned
    }

    /// Broadcasts this wallet's payments again that the node's mempool
    /// lacks, then scans the mempool for payments to it.
    fn look_at_mempool(&mut self, client: &RpcClient, report: &mut SyncReport) {
        let Ok(hashes) = client.mempool_hashes() else {
            return;
        };
        let live: HashSet<&str> = hashes.iter().map(String::as_str).collect();
        let now = unix_now();
        let due: Vec<(String, String)> = self
            .data
            .sent
            .iter()
            .filter(|s| s.is_pending() && !live.contains(s.tx_hash.as_str()))
            .filter(|s| now >= s.created_at.saturating_add(REBROADCAST_SECS))
            .filter_map(|s| s.tx_hex.clone().map(|hex| (s.tx_hash.clone(), hex)))
            .collect();
        for (tx_hash, tx_hex) in due {
            let tx: Transaction = match hex::decode(&tx_hex)
                .map_err(anyhow::Error::from)
                .and_then(|b| Ok(bincode::deserialize(&b)?))
            {
                Ok(tx) => tx,
                Err(e) => {
                    report.refused.push((tx_hash, format!("unreadable: {e}")));
                    continue;
                }
            };
            match client.submit(&tx) {
                Ok(_) => report.rebroadcast.push(tx_hash),
                Err(e) => {
                    let e = format!("{e:#}");
                    if !expected_refusal(&e) {
                        report.refused.push((tx_hash, e));
                    }
                }
            }
        }
        if let Ok(txs) = client.mempool_txs(&hashes) {
            self.scan_mempool(&txs);
            report.mempool = true;
        }
    }

    /// Finds the payments to this wallet among transactions waiting in a
    /// mempool, scanning their outputs as blocks are scanned; they replace
    /// those found before. Its own payments, and anything spending its coins
    /// (another copy of it, whose change is not income), are left out.
    pub fn scan_mempool(&mut self, txs: &[Transaction]) {
        let known: HashSet<Point32> = self
            .data
            .coins
            .iter()
            .map(|c| c.output.commitment)
            .collect();
        let own: HashSet<[u8; 32]> = self.data.sent.iter().map(|s| s.kernel).collect();
        self.incoming.clear();
        for tx in txs {
            if tx.kernel_ids().iter().any(|k| own.contains(k))
                || tx.input_commitments().any(|c| known.contains(c))
            {
                continue;
            }
            let mut found = false;
            let mut value = 0u64;
            for output in tx.outputs() {
                if known.contains(&output.commitment) {
                    continue;
                }
                if let Some(owned) = scan_output(&self.keys, output) {
                    found = true;
                    value = value.saturating_add(owned.value);
                }
            }
            if found {
                self.incoming.push(Incoming {
                    tx_hash: hex::encode(tx.hash()),
                    value,
                });
            }
        }
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            coins: self
                .data
                .coins
                .iter()
                .map(|c| (c.output.commitment, (c.value, c.coinbase)))
                .collect(),
            sent: self
                .data
                .sent
                .iter()
                .map(|s| (s.tx_hash.clone(), (s.height, s.failed_at)))
                .collect(),
        }
    }

    /// What changed since `before`.
    fn compare(&self, before: &Snapshot, report: &mut SyncReport) {
        let change: HashSet<Point32> = self.data.sent.iter().filter_map(|s| s.change).collect();
        let now: HashSet<Point32> = self
            .data
            .coins
            .iter()
            .map(|c| c.output.commitment)
            .collect();
        for c in &self.data.coins {
            if !before.coins.contains_key(&c.output.commitment)
                && !change.contains(&c.output.commitment)
            {
                report.received.push((c.value, c.coinbase, c.height));
            }
        }
        for (commitment, (value, coinbase)) in &before.coins {
            if !now.contains(commitment) && !change.contains(commitment) {
                report.lost.push((*value, *coinbase));
            }
        }
        for s in &self.data.sent {
            let (height, failed_at) = before.sent.get(&s.tx_hash).copied().unwrap_or((None, None));
            if height.is_none() {
                if let Some(h) = s.height {
                    report.confirmed.push((s.tx_hash.clone(), h));
                }
            }
            if failed_at.is_none() && s.failed_at.is_some() && !report.orphaned.contains(&s.tx_hash)
            {
                report.failed.push(s.tx_hash.clone());
            }
            let was_settled = height.is_some() || failed_at.is_some();
            if was_settled && s.is_pending() {
                report.unconfirmed.push(s.tx_hash.clone());
            }
        }
    }

    /// Rebuilds the wallet from the chain's *unspent* outputs, for nodes that
    /// have pruned the block bodies this wallet would otherwise scan
    /// (`docs/PRUNING.md`). Coins it knew that are no longer unspent are
    /// marked spent, and its payments whose coins are all gone confirmed;
    /// payments it has no record of cannot be recovered this way. Returns
    /// the number of coins found.
    pub fn scan_unspent(
        &mut self,
        outputs: &[(Output, u64, bool)],
        tip_height: u64,
    ) -> Result<u64> {
        let mut found = 0;
        let mut known: HashSet<Point32> = self
            .data
            .coins
            .iter()
            .map(|c| c.output.commitment)
            .collect();
        let live: HashSet<Point32> = outputs.iter().map(|(o, _, _)| o.commitment).collect();
        for (output, height, coinbase) in outputs {
            if known.contains(&output.commitment) {
                continue;
            }
            if let Some(owned) = scan_output(&self.keys, output) {
                found += 1;
                known.insert(output.commitment);
                let pending_tx = self.reserved_for(&output.commitment);
                self.data.coins.push(WalletCoin {
                    output: output.clone(),
                    value: owned.value,
                    height: *height,
                    coinbase: *coinbase,
                    spent_height: None,
                    pending_tx,
                });
            }
        }
        for coin in &mut self.data.coins {
            if coin.spent_height.is_none() && !live.contains(&coin.output.commitment) {
                coin.spent_height = Some(tip_height);
                coin.pending_tx = None;
            }
        }
        for s in &mut self.data.sent {
            if s.height.is_none()
                && s.failed_at.is_none()
                && s.inputs.iter().all(|c| !live.contains(c))
            {
                // Its coins are gone; without the blocks, whether this very
                // transaction took them cannot be told. Most likely it did.
                s.height = Some(tip_height);
                s.tx_hex = None;
            }
        }
        self.data.scanned_height = tip_height;
        self.data.recent.clear();
        Ok(found)
    }

    /// Scans blocks produced by `fetch(start, count)` up to `tip_height`
    /// (exclusive), following reorganisations as [`Self::sync`] does.
    /// Returns the number of blocks scanned.
    pub fn sync_with<F>(&mut self, tip_height: u64, mut fetch: F) -> Result<u64>
    where
        F: FnMut(u64, u64) -> Result<Vec<Batch>>,
    {
        let mut report = SyncReport::default();
        if tip_height < self.data.scanned_height {
            return Ok(0);
        }
        let mut rollbacks = 0;
        self.check_last_block(
            tip_height,
            &mut |h| Ok(fetch(h, 1)?.first().map(|b| b.extension.final_hash)),
            &mut rollbacks,
            &mut report,
        )?;
        self.scan_forward(tip_height, &mut fetch, &mut rollbacks, &mut report)?;
        if self.data.scanned_height >= tip_height {
            self.settle_orphans();
        }
        Ok(report.blocks)
    }

    pub fn balance(&self, tip_height: u64) -> Balance {
        let mut b = Balance::default();
        for c in self.data.coins.iter().filter(|c| c.spent_height.is_none()) {
            if c.pending_tx.is_some() {
                b.pending += c.value;
            } else if c.coinbase && tip_height < c.height + COINBASE_MATURITY {
                b.immature += c.value;
            } else {
                b.spendable += c.value;
            }
        }
        b.incoming = self.incoming.iter().map(|i| i.value).sum();
        b
    }

    /// Builds a payment, reserves its coins and records it: syncing
    /// broadcasts it again until a block confirms it, unless
    /// [`Self::cancel_pending`] releases it. `tip_height` is the height of
    /// the next block. Without an explicit `fee`, pays the relay minimum
    /// for however many inputs end up selected.
    pub fn build_send(
        &mut self,
        to: &StealthAddress,
        amount: u64,
        fee: Option<u64>,
        tip_height: u64,
    ) -> Result<Transaction> {
        if amount == 0 {
            bail!("amount must be positive");
        }
        let mut candidates: Vec<&WalletCoin> = self
            .data
            .coins
            .iter()
            .filter(|c| {
                c.spent_height.is_none()
                    && c.pending_tx.is_none()
                    && (!c.coinbase || tip_height >= c.height + COINBASE_MATURITY)
            })
            .collect();
        candidates.sort_by(|a, b| b.value.cmp(&a.value));
        let mut chosen: Vec<Spendable> = Vec::new();
        let mut total = 0u64;
        let fee_for = |n: usize| fee.unwrap_or_else(|| suggested_fee(n.max(1) as u64));
        for c in candidates {
            let need = amount
                .checked_add(fee_for(chosen.len()))
                .ok_or_else(|| anyhow!("amount overflow"))?;
            if total >= need {
                break;
            }
            let owned = scan_output(&self.keys, &c.output)
                .ok_or_else(|| anyhow!("stored coin no longer opens"))?;
            chosen.push(Spendable {
                commitment: c.output.commitment,
                value: owned.value,
                blinding: owned.blinding,
                owner_secret: owned.owner_secret,
            });
            total += owned.value;
        }
        let fee = fee_for(chosen.len());
        let need = amount
            .checked_add(fee)
            .ok_or_else(|| anyhow!("amount overflow"))?;
        if total < need {
            bail!(
                "insufficient spendable funds: have {}, need {}",
                total,
                need
            );
        }
        let built = build_transaction(
            &chosen,
            &[Payment {
                to: *to,
                value: amount,
            }],
            &self.address(),
            fee,
            tip_height,
        )?;
        let tx = built.tx;
        let tx_hash = hex::encode(tx.hash());
        let inputs: Vec<Point32> = chosen.iter().map(|s| s.commitment).collect();
        for coin in &mut self.data.coins {
            if inputs.contains(&coin.output.commitment) {
                coin.pending_tx = Some(tx_hash.clone());
            }
        }
        self.data.sent.push(Sent {
            tx_hash,
            kernel: tx
                .body
                .kernels
                .first()
                .ok_or_else(|| anyhow!("a payment without a kernel"))?
                .id(),
            to: to.encode(),
            amount,
            fee,
            inputs,
            change: built.change.map(|(c, _)| c),
            created_at: unix_now(),
            tx_hex: Some(hex::encode(bincode::serialize(&tx)?)),
            height: None,
            failed_at: None,
            cancelled: false,
        });
        Ok(tx)
    }

    /// Coins whose recovery commitment was built wrongly by their sender.
    /// They spend normally but could not be claimed in a recovery epoch;
    /// sending them to yourself repairs that.
    pub fn unrecoverable_coins(&self) -> Vec<&WalletCoin> {
        self.data
            .coins
            .iter()
            .filter(|c| c.spent_height.is_none())
            .filter(|c| scan_output(&self.keys, &c.output).map_or(true, |o| !o.recovery_ok))
            .collect()
    }

    /// Builds a recovery-epoch claim for every coin unspent at `checkpoint`
    /// (whose state is `state`), paying `destination`. Regenerates the MSS
    /// key and signs with leaf `leaf` (a claimant must never reuse one).
    pub fn build_recovery_claim(
        &self,
        checkpoint: &crate::core::anchor::Checkpoint,
        state: &crate::core::State,
        destination: [u8; 32],
        leaf: u64,
    ) -> Result<RecoveryClaim> {
        let mut seed = seed_of(&self.data.mnemonic)?;
        let mut key = derive_recovery_keypair(&seed, self.data.recovery_height)?;
        seed.zeroize();
        key.set_next_leaf(leaf);
        let mut outputs = Vec::new();
        for coin in &self.data.coins {
            if !state.utxos.contains_key(&coin.output.commitment) {
                continue;
            }
            let owned = scan_output(&self.keys, &coin.output)
                .ok_or_else(|| anyhow!("coin no longer opens"))?;
            if !owned.recovery_ok {
                continue;
            }
            outputs.push(ClaimedOutput::from_state(
                state,
                coin.output.commitment,
                owned.value,
                owned.blinding.to_bytes(),
                owned.recovery_salt,
            )?);
        }
        if outputs.is_empty() {
            bail!("no recoverable coins at this checkpoint");
        }
        RecoveryClaim::build(&mut key, checkpoint.id(), outputs, destination)
    }

    /// Releases the coins of a payment that will never confirm (the node
    /// refuses it, or it fell out of every mempool), and stops broadcasting
    /// it. If it confirms after all, scanning still records it. Returns
    /// whether a payment waiting for a block had that hash.
    pub fn cancel_pending(&mut self, tx_hash: &str) -> bool {
        let mut found = false;
        for s in &mut self.data.sent {
            if s.tx_hash == tx_hash && s.is_pending() {
                s.cancelled = true;
                s.tx_hex = None;
                found = true;
            }
        }
        for coin in &mut self.data.coins {
            if coin.pending_tx.as_deref() == Some(tx_hash) {
                coin.pending_tx = None;
                found = true;
            }
        }
        found
    }

    /// Forgets a payment the node refused outright: it never left this
    /// wallet.
    pub fn discard_send(&mut self, tx_hash: &str) {
        self.cancel_pending(tx_hash);
        self.data
            .sent
            .retain(|s| !(s.tx_hash == tx_hash && s.height.is_none()));
    }
}

/// Minimal fee for a transaction of the usual shape (n inputs, 2 outputs).
pub fn suggested_fee(inputs: u64) -> u64 {
    use crate::core::types::{INPUT_WEIGHT, KERNEL_WEIGHT, MIN_FEE_PER_WEIGHT, OUTPUT_WEIGHT};
    (inputs * INPUT_WEIGHT + 2 * OUTPUT_WEIGHT + KERNEL_WEIGHT) * MIN_FEE_PER_WEIGHT
}

/// Parses a hex point, for CLI convenience.
pub fn parse_point(s: &str) -> Result<Point32> {
    let bytes: Point32 = hex::decode(s)?
        .try_into()
        .map_err(|_| anyhow!("expected 32 bytes"))?;
    crypto::decompress(&bytes).ok_or_else(|| anyhow!("not a valid point"))?;
    Ok(bytes)
}

#[cfg(all(test, feature = "fast-mining"))]
mod tests {
    use super::*;
    use crate::core::state::apply_batch;
    use crate::core::template::build_template;
    use crate::core::{BatchHeader, State};
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};

    /// A chain built block by block, as a node would hold it.
    #[derive(Clone)]
    struct Chain {
        state: State,
        ts: Vec<u64>,
        blocks: Vec<Batch>,
    }

    impl Chain {
        fn new() -> Self {
            let mut state = State::genesis();
            apply_batch(&mut state, Batch::genesis(), &[]).unwrap();
            Chain {
                state,
                ts: vec![Batch::genesis().timestamp],
                blocks: vec![Batch::genesis().clone()],
            }
        }

        fn mine(&mut self, to: &StealthAddress, txs: &[Transaction]) {
            let b = build_template(&self.state, &self.ts, txs, to, None)
                .unwrap()
                .mine_blocking();
            apply_batch(&mut self.state, &b, &self.ts).unwrap();
            self.ts.push(b.timestamp);
            self.blocks.push(b);
        }

        fn mine_to_stranger(&mut self, n: usize) {
            let stranger = WalletKeys::random().address();
            for _ in 0..n {
                self.mine(&stranger, &[]);
            }
        }
    }

    #[derive(Default)]
    struct Served {
        blocks: Vec<Batch>,
        mempool: Vec<Transaction>,
        /// Every transaction `/tx` accepted, in order.
        submitted: Vec<Transaction>,
        syncing: bool,
        /// Nodes from before `/mempool/txs` answer it with a 404.
        no_mempool_txs: bool,
    }

    /// A node's RPC answered from blocks held in memory, for driving
    /// [`Wallet::sync`] through the real client.
    #[derive(Clone, Default)]
    struct FakeNode(Arc<Mutex<Served>>);

    impl FakeNode {
        fn start() -> (Self, RpcClient) {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let node = FakeNode::default();
            let served = node.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    served.answer(stream);
                }
            });
            (node, RpcClient::new(addr.to_string()))
        }

        fn set(&self, f: impl FnOnce(&mut Served)) {
            f(&mut self.0.lock().unwrap());
        }

        fn submitted(&self) -> Vec<Transaction> {
            self.0.lock().unwrap().submitted.clone()
        }

        fn answer(&self, mut stream: std::net::TcpStream) {
            use std::io::{BufRead, BufReader, Read, Write};
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut words = line.split_whitespace();
            let (method, path) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
            let mut len = 0;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                if header.trim().is_empty() {
                    break;
                }
                if let Some(v) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; len];
            reader.read_exact(&mut body).unwrap();
            let (status, reply) = self.route(method, path, &body);
            let text = reply.to_string();
            let _ = write!(
                stream,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                text.len()
            );
        }

        fn route(&self, method: &str, path: &str, body: &[u8]) -> (u16, Value) {
            let mut s = self.0.lock().unwrap();
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            let range =
                |a: &str, n: &str| (a.parse::<usize>().unwrap(), n.parse::<usize>().unwrap());
            let hash = |t: &Transaction| hex::encode(t.hash());
            match (method, parts.as_slice()) {
                ("GET", ["state"]) => (
                    200,
                    json!({ "height": s.blocks.len(), "syncing": s.syncing }),
                ),
                ("GET", ["finality"]) => (200, json!({ "pruned_below": 0 })),
                ("GET", ["headers", a, n]) => {
                    let (a, n) = range(a, n);
                    let headers: Vec<BatchHeader> = (a..(a + n).min(s.blocks.len()))
                        .map(|h| BatchHeader {
                            height: h as u64,
                            ..s.blocks[h].header()
                        })
                        .collect();
                    let hex = hex::encode(bincode::serialize(&headers).unwrap());
                    (200, json!({ "start": a, "headers_hex": hex }))
                }
                ("GET", ["blocks", a, n]) => {
                    let (a, n) = range(a, n);
                    let blocks: Vec<String> = s
                        .blocks
                        .iter()
                        .skip(a)
                        .take(n)
                        .map(|b| hex::encode(bincode::serialize(b).unwrap()))
                        .collect();
                    (200, json!({ "start": a, "blocks": blocks }))
                }
                ("GET", ["mempool"]) => {
                    let hashes: Vec<String> = s.mempool.iter().map(hash).collect();
                    (
                        200,
                        json!({ "count": hashes.len(), "transactions": hashes }),
                    )
                }
                ("POST", ["mempool", "txs"]) if !s.no_mempool_txs => {
                    let asked: Value = serde_json::from_slice(body).unwrap();
                    let asked: Vec<&str> = asked["hashes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|h| h.as_str().unwrap())
                        .collect();
                    let txs: Vec<Value> = s
                        .mempool
                        .iter()
                        .filter(|t| asked.contains(&hash(t).as_str()))
                        .map(|t| json!({ "hash": hash(t), "tx_hex": hex::encode(bincode::serialize(t).unwrap()) }))
                        .collect();
                    (200, json!({ "transactions": txs }))
                }
                ("POST", ["tx"]) => {
                    let asked: Value = serde_json::from_slice(body).unwrap();
                    let bytes = hex::decode(asked["tx_hex"].as_str().unwrap()).unwrap();
                    let tx: Transaction = bincode::deserialize(&bytes).unwrap();
                    if s.mempool.iter().any(|t| t.hash() == tx.hash()) {
                        return (400, json!({ "error": "transaction already in pool" }));
                    }
                    s.submitted.push(tx.clone());
                    s.mempool.push(tx.clone());
                    (200, json!({ "accepted": true, "tx_hash": hash(&tx) }))
                }
                _ => (404, json!("")),
            }
        }
    }

    fn cli_wallet(dir: &tempfile::TempDir, name: &str) -> Wallet {
        Wallet::create(&dir.path().join(name), "pw", 1).unwrap().0
    }

    /// A payment confirmed in a block that a reorganisation then takes away
    /// keeps its coins reserved, is broadcast again, and confirms on the new
    /// chain; nothing about it is spendable twice in between.
    #[test]
    fn a_reorg_keeps_a_payment_reserved_until_the_new_chain_confirms_it() {
        let dir = tempfile::tempdir().unwrap();
        let (node, client) = FakeNode::start();
        let mut w = cli_wallet(&dir, "w.mww");
        let mut chain = Chain::new();
        chain.mine(&w.address(), &[]);
        chain.mine_to_stranger(COINBASE_MATURITY as usize);
        node.set(|s| s.blocks = chain.blocks.clone());
        let r = w.sync(&client).unwrap();
        assert_eq!(r.blocks, chain.blocks.len() as u64);
        assert_eq!(r.received.len(), 1, "the block reward: {:?}", r.received);
        let funds = w.balance(r.tip).spendable;
        assert_eq!(funds, crate::core::types::block_reward(1));

        // Paid, and waiting in the node's mempool.
        let bob = WalletKeys::random().address();
        let tx = w.build_send(&bob, 1_000, None, r.tip).unwrap();
        let hash = hex::encode(tx.hash());
        client.submit(&tx).unwrap();
        w.save().unwrap();
        let r = w.sync(&client).unwrap();
        assert!(r.mempool);
        assert!(w.incoming().is_empty(), "its own payment is not income");
        assert_eq!(w.balance(r.tip).pending, funds);
        assert!(r.rebroadcast.is_empty(), "the mempool has it");

        // Confirmed.
        let fork = chain.clone();
        chain.mine(&WalletKeys::random().address(), &[tx.clone()]);
        let confirmed_at = chain.blocks.len() as u64 - 1;
        node.set(|s| {
            s.blocks = chain.blocks.clone();
            s.mempool.clear();
        });
        let r = w.sync(&client).unwrap();
        assert_eq!(r.confirmed, vec![(hash.clone(), confirmed_at)]);
        assert!(r.received.is_empty(), "change is not income");
        let change = w.balance(r.tip).spendable;
        assert!(change > 0 && change < funds);
        assert_eq!(w.balance(r.tip).pending, 0);

        // A longer chain without it: the node lost the payment, too.
        let mut other = fork.clone();
        other.mine_to_stranger(2);
        node.set(|s| s.blocks = other.blocks.clone());
        w.data.sent[0].created_at -= REBROADCAST_SECS; // broadcast a while ago
        let r = w.sync(&client).unwrap();
        assert!(r.rolled_back_to.unwrap() <= confirmed_at, "{r:?}");
        assert!(!r.rescanned);
        assert_eq!(r.unconfirmed, vec![hash.clone()]);
        assert!(r.confirmed.is_empty() && r.lost.is_empty(), "{r:?}");
        assert_eq!(r.rebroadcast, vec![hash.clone()]);
        assert_eq!(node.submitted().last().map(|t| t.hash()), Some(tx.hash()));
        let b = w.balance(r.tip);
        assert_eq!((b.spendable, b.pending), (0, funds), "reserved again");
        assert!(w.build_send(&bob, 1, None, r.tip).is_err());
        assert!(w.payments()[0].is_pending());

        // Reopened, the file still has it all.
        let mut w = Wallet::open(&dir.path().join("w.mww"), "pw").unwrap();
        assert_eq!(w.balance(r.tip).pending, funds);

        // The new chain confirms it: change again.
        other.mine(&WalletKeys::random().address(), &[tx.clone()]);
        node.set(|s| {
            s.blocks = other.blocks.clone();
            s.mempool.clear();
        });
        let r = w.sync(&client).unwrap();
        assert_eq!(r.confirmed, vec![(hash, other.blocks.len() as u64 - 1)]);
        let b = w.balance(r.tip);
        assert_eq!((b.spendable, b.pending), (change, 0));
    }

    /// Past the block hashes the wallet keeps, it cannot tell where the
    /// chains part: it rescans from its birth height.
    #[test]
    fn a_reorg_past_the_recorded_blocks_rescans_from_birth() {
        let dir = tempfile::tempdir().unwrap();
        let (node, client) = FakeNode::start();
        let mut w = cli_wallet(&dir, "w.mww");
        let mut chain = Chain::new();
        chain.mine(&w.address(), &[]);
        let fork = chain.clone();
        chain.mine_to_stranger(15);
        chain.mine(&w.address(), &[]);
        node.set(|s| s.blocks = chain.blocks.clone());
        w.sync(&client).unwrap();
        let reward = |h: u64| crate::core::types::block_reward(h);
        let b = w.balance(chain.state.height);
        assert_eq!(b.spendable + b.immature, reward(1) + reward(17));
        // As if the window had moved on: only the last three are known.
        let scanned = w.scanned_height();
        w.data.recent.retain(|(h, _)| *h + 3 >= scanned);

        let mut other = fork;
        other.mine_to_stranger(20);
        node.set(|s| s.blocks = other.blocks.clone());
        let r = w.sync(&client).unwrap();
        assert!(r.rescanned, "{r:?}");
        assert_eq!(r.rolled_back_to, Some(0));
        assert_eq!(
            r.lost,
            vec![(reward(17), true)],
            "the reward of the lost block"
        );
        assert!(r.received.is_empty(), "block 1's reward is not news");
        let b = w.balance(other.state.height);
        assert_eq!(b.spendable + b.immature, reward(1));
        assert_eq!(w.scanned_height(), other.blocks.len() as u64);
    }

    /// A payment whose coins only the lost chain had can never confirm: it
    /// fails, and nothing of it stays reserved or is broadcast.
    #[test]
    fn a_payment_whose_coins_a_reorg_took_can_no_longer_confirm() {
        let dir = tempfile::tempdir().unwrap();
        let (node, client) = FakeNode::start();
        let mut w = cli_wallet(&dir, "w.mww");
        let mut chain = Chain::new();
        chain.mine_to_stranger(1);
        let fork = chain.clone();
        chain.mine(&w.address(), &[]);
        chain.mine_to_stranger(COINBASE_MATURITY as usize);
        node.set(|s| s.blocks = chain.blocks.clone());
        let r = w.sync(&client).unwrap();
        let tx = w
            .build_send(&WalletKeys::random().address(), 1_000, None, r.tip)
            .unwrap();
        let hash = hex::encode(tx.hash());
        chain.mine(&WalletKeys::random().address(), &[tx]);
        let confirmed_at = chain.blocks.len() as u64 - 1;
        node.set(|s| s.blocks = chain.blocks.clone());
        let r = w.sync(&client).unwrap();
        assert_eq!(r.confirmed.len(), 1);

        let mut other = fork;
        other.mine_to_stranger(8);
        node.set(|s| s.blocks = other.blocks.clone());
        w.data.sent[0].created_at -= REBROADCAST_SECS;
        let submitted = node.submitted().len();
        let r = w.sync(&client).unwrap();
        assert_eq!(r.orphaned, vec![hash.clone()], "{r:?}");
        assert!(r.failed.is_empty() && r.unconfirmed.is_empty(), "{r:?}");
        assert!(r.rebroadcast.is_empty() && r.refused.is_empty(), "{r:?}");
        assert_eq!(node.submitted().len(), submitted);
        assert!(!w.payments()[0].is_pending());
        assert_eq!(w.balance(r.tip).pending, 0);
        let r = w.sync(&client).unwrap();
        assert!(r.orphaned.is_empty(), "reported once");

        // Back on the chain that has its coins (grown heavier), it is
        // confirmed again.
        chain.mine_to_stranger(5);
        node.set(|s| s.blocks = chain.blocks.clone());
        let r = w.sync(&client).unwrap();
        assert_eq!(r.confirmed, vec![(hash, confirmed_at)], "{r:?}");
        assert!(r.orphaned.is_empty());
    }

    #[test]
    fn payments_waiting_in_the_mempool_show_as_incoming() {
        let dir = tempfile::tempdir().unwrap();
        let (node, client) = FakeNode::start();
        let mut alice = cli_wallet(&dir, "alice.mww");
        let mut bob = cli_wallet(&dir, "bob.mww");
        let mut chain = Chain::new();
        chain.mine(&alice.address(), &[]);
        chain.mine_to_stranger(COINBASE_MATURITY as usize);
        node.set(|s| s.blocks = chain.blocks.clone());
        alice.sync(&client).unwrap();
        let tx = alice
            .build_send(&bob.address(), 5_000, None, chain.state.height)
            .unwrap();
        client.submit(&tx).unwrap();

        let r = bob.sync(&client).unwrap();
        assert!(r.mempool);
        assert_eq!(
            bob.incoming(),
            &[Incoming {
                tx_hash: hex::encode(tx.hash()),
                value: 5_000
            }]
        );
        let b = bob.balance(r.tip);
        assert_eq!((b.spendable, b.incoming), (0, 5_000));
        assert!(r.received.is_empty());
        // Alice's own payment, change and all, is not income to her.
        alice.sync(&client).unwrap();
        assert!(alice.incoming().is_empty());

        // A block confirms it: spendable, and no longer incoming.
        chain.mine(&WalletKeys::random().address(), &[tx]);
        node.set(|s| {
            s.blocks = chain.blocks.clone();
            s.mempool.clear();
        });
        let r = bob.sync(&client).unwrap();
        assert_eq!(r.received, vec![(5_000, false, chain.state.height - 1)]);
        let b = bob.balance(r.tip);
        assert_eq!((b.spendable, b.incoming), (5_000, 0));

        // A node from before `/mempool/txs` cannot show it.
        let tx = alice
            .build_send(&bob.address(), 7_000, None, chain.state.height)
            .unwrap_or_else(|_| {
                alice.sync(&client).unwrap();
                alice
                    .build_send(&bob.address(), 7_000, None, chain.state.height)
                    .unwrap()
            });
        client.submit(&tx).unwrap();
        node.set(|s| s.no_mempool_txs = true);
        let r = bob.sync(&client).unwrap();
        assert!(!r.mempool);
        assert_eq!(bob.balance(r.tip).incoming, 0);
    }

    #[test]
    fn a_node_on_another_chain_is_refused_until_a_rescan() {
        let dir = tempfile::tempdir().unwrap();
        let (node, client) = FakeNode::start();
        let mut w = cli_wallet(&dir, "w.mww");
        let mut chain = Chain::new();
        chain.mine(&w.address(), &[]);
        chain.mine_to_stranger(COINBASE_MATURITY as usize);
        node.set(|s| s.blocks = chain.blocks.clone());
        w.sync(&client).unwrap();
        assert_eq!(w.data.genesis, Some(Batch::genesis().extension.final_hash));

        // As if it had been synced on a network since relaunched.
        w.data.genesis = Some([7; 32]);
        let tx = w
            .build_send(
                &WalletKeys::random().address(),
                1_000,
                None,
                chain.state.height,
            )
            .unwrap();
        drop(tx);
        let e = w.sync(&client).unwrap_err().to_string();
        assert!(e.contains("another chain"), "{e}");
        assert!(w.rescan(&client, None).unwrap(), "it was on another chain");
        assert!(w.payments().is_empty() && w.coins().is_empty());
        let r = w.sync(&client).unwrap();
        assert_eq!(r.blocks, chain.blocks.len() as u64);
        assert_eq!(w.data.genesis, Some(Batch::genesis().extension.final_hash));
        assert_eq!(
            w.balance(r.tip).spendable,
            crate::core::types::block_reward(1)
        );

        // On the same chain, a rescan keeps its payments: they are found
        // again.
        let tx = w
            .build_send(&WalletKeys::random().address(), 1_000, None, r.tip)
            .unwrap();
        chain.mine(&WalletKeys::random().address(), &[tx]);
        node.set(|s| s.blocks = chain.blocks.clone());
        w.sync(&client).unwrap();
        assert!(!w.rescan(&client, Some(0)).unwrap());
        assert!(w.rescan(&client, Some(w.scanned_height() + 1)).is_err());
        let r = w.sync(&client).unwrap();
        assert_eq!(r.blocks, chain.blocks.len() as u64);
        assert!(r.confirmed.is_empty(), "already known: {r:?}");
        assert_eq!(w.payments().len(), 1);
        assert!(w.payments()[0].height.is_some());
    }

    #[test]
    fn a_node_behind_the_wallet_is_waited_for() {
        let dir = tempfile::tempdir().unwrap();
        let (node, client) = FakeNode::start();
        let mut w = cli_wallet(&dir, "w.mww");
        let mut chain = Chain::new();
        chain.mine(&w.address(), &[]);
        chain.mine_to_stranger(COINBASE_MATURITY as usize + 3);
        node.set(|s| s.blocks = chain.blocks.clone());
        w.sync(&client).unwrap();
        let scanned = w.scanned_height();
        let coins = w.coins().len();
        node.set(|s| {
            s.blocks.truncate(3);
            s.syncing = true;
        });
        let r = w.sync(&client).unwrap();
        assert!(r.behind && r.node_syncing);
        assert_eq!((w.scanned_height(), w.coins().len()), (scanned, coins));
        assert!(r.rolled_back_to.is_none());
    }

    #[test]
    fn a_released_payment_frees_its_coins_and_still_confirms() {
        let dir = tempfile::tempdir().unwrap();
        let (node, client) = FakeNode::start();
        let mut w = cli_wallet(&dir, "w.mww");
        let mut chain = Chain::new();
        chain.mine(&w.address(), &[]);
        chain.mine_to_stranger(COINBASE_MATURITY as usize);
        node.set(|s| s.blocks = chain.blocks.clone());
        let r = w.sync(&client).unwrap();
        let funds = w.balance(r.tip).spendable;
        let tx = w
            .build_send(&WalletKeys::random().address(), 1_000, None, r.tip)
            .unwrap();
        let hash = hex::encode(tx.hash());
        assert_eq!(w.balance(r.tip).spendable, 0);
        assert!(w.cancel_pending(&hash));
        assert!(!w.cancel_pending(&hash), "once");
        assert_eq!(w.balance(r.tip).spendable, funds);
        assert!(w.payments()[0].cancelled);
        w.data.sent[0].created_at -= REBROADCAST_SECS;
        let r = w.sync(&client).unwrap();
        assert!(r.rebroadcast.is_empty(), "released: not broadcast");

        // It was out there after all.
        chain.mine(&WalletKeys::random().address(), &[tx]);
        node.set(|s| s.blocks = chain.blocks.clone());
        let r = w.sync(&client).unwrap();
        assert_eq!(r.confirmed.len(), 1);
        assert!(w.balance(r.tip).spendable < funds);

        // Refused outright, a payment leaves no trace.
        let tx = w
            .build_send(&WalletKeys::random().address(), 1_000, None, r.tip)
            .unwrap();
        w.discard_send(&hex::encode(tx.hash()));
        assert_eq!(w.payments().len(), 1);
        assert_eq!(w.balance(r.tip).pending, 0);
    }

    #[test]
    fn create_open_scan_send() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.dat");
        let (mut w, mnemonic) = Wallet::create(&path, "pw", 1).unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 24);
        assert!(Wallet::open(&path, "wrong").is_err());

        let mut state = State::genesis();
        apply_batch(&mut state, Batch::genesis(), &[]).unwrap();
        let mut chain = vec![Batch::genesis().clone()];
        let mut ts = vec![Batch::genesis().timestamp];
        for i in 0..=COINBASE_MATURITY {
            let to = if i == 0 {
                w.address()
            } else {
                WalletKeys::random().address()
            };
            let b = build_template(&state, &ts, &[], &to, None)
                .unwrap()
                .mine_blocking();
            apply_batch(&mut state, &b, &ts).unwrap();
            ts.push(b.timestamp);
            chain.push(b);
        }
        let fetch = |s: u64, n: u64| {
            Ok(chain
                .iter()
                .skip(s as usize)
                .take(n as usize)
                .cloned()
                .collect())
        };
        w.sync_with(state.height, fetch).unwrap();
        let reward = crate::core::types::block_reward(1);
        assert_eq!(w.balance(state.height).spendable, reward);
        w.save().unwrap();

        // Reopen: same address, same coins.
        let mut w2 = Wallet::open(&path, "pw").unwrap();
        assert_eq!(w2.address(), w.address());
        assert_eq!(w2.balance(state.height).spendable, reward);

        let bob = WalletKeys::random().address();
        let tx = w2.build_send(&bob, 1_000, None, state.height).unwrap();
        tx.validate(crate::core::mw::Context::Relay).unwrap();
        assert_eq!(w2.balance(state.height).pending, reward);
        assert!(w2.build_send(&bob, 1, None, state.height).is_err());

        // Rollback forgets the coin.
        w2.rollback_to(1);
        assert_eq!(
            w2.balance(state.height).spendable + w2.balance(state.height).pending,
            0
        );

        // Restoring from the mnemonic recovers the same keys.
        let restored = Wallet::restore(&dir.path().join("r.dat"), "x", &mnemonic, 0, 1).unwrap();
        assert_eq!(restored.address(), w.address());
    }
}
