//! The wallet, free of JavaScript types so that it can be tested natively.
//!
//! It is `src/wallet`'s wallet (keys from a BIP39 mnemonic, view-key
//! scanning of whole blocks, largest-first coin selection, payments to
//! stealth addresses) minus the file and the RPC client: the browser feeds
//! it blocks fetched over the light protocol and stores [`WalletCore::seal`]ed
//! bytes. Those bytes are the CLI's wallet file format, `MWWALLET1`
//! (Argon2id, XChaCha20-Poly1305, the same JSON), so a wallet moves between
//! the browser and `midwimble wallet` as a file.
//!
//! The JSON has two fields the CLI does not know, `birth_height` and `sent`
//! (this wallet's own payments, for its history). The CLI ignores them when
//! it opens a file and drops them when it saves one.

use anyhow::{anyhow, bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use midwimble::core::mss;
use midwimble::core::mw::crypto::Point32;
use midwimble::core::mw::stealth::scan_output;
use midwimble::core::mw::{
    build_transaction, Output, Payment, Spendable, StealthAddress, Transaction, ViewKey, WalletKeys,
};
use midwimble::core::recovery;
use midwimble::core::types::{
    COINBASE_MATURITY, INPUT_WEIGHT, KERNEL_WEIGHT, MIN_FEE_PER_WEIGHT, OUTPUT_WEIGHT,
};
use midwimble::core::Batch;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use zeroize::Zeroize;

/// Wallet files start with this (`src/wallet/mod.rs`).
pub const FILE_MAGIC: &[u8] = b"MWWALLET1";
pub const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
/// Recent block hashes kept for reorg detection, as the CLI keeps.
const REORG_WINDOW: usize = 200;
/// What `scan_block` fails with when a block does not extend the chain this
/// wallet scanned: the caller rolls back and scans again.
pub const REORG: &str = "reorg detected";

// ── Stored data ─────────────────────────────────────────────────────────────

/// One output this wallet owns (the CLI's `WalletCoin`).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletCoin {
    output: Output,
    value: u64,
    height: u64,
    coinbase: bool,
    /// Height of the block that spent it.
    spent_height: Option<u64>,
    /// Hash of an unconfirmed transaction spending it.
    pending_tx: Option<String>,
}

/// A payment made from this wallet.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Sent {
    tx_hash: String,
    /// The transaction's kernel id: the block that carries it confirmed it.
    kernel: [u8; 32],
    to: String,
    amount: u64,
    fee: u64,
    inputs: Vec<Point32>,
    /// The change output, which history folds into the payment.
    change: Option<Point32>,
    /// Unix seconds.
    created_at: u64,
    /// Kept for rebroadcasting until a block confirms it.
    tx_hex: Option<String>,
    /// Height of the block that confirmed it.
    height: Option<u64>,
    /// Height of a block that spent its inputs without it: another
    /// transaction (from another copy of this wallet) got there first.
    failed_at: Option<u64>,
    /// Released by the user: its coins are spendable again.
    cancelled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletData {
    version: u32,
    mnemonic: String,
    /// MSS master public key for post-quantum recovery (`core/recovery.rs`).
    recovery_key: [u8; 32],
    recovery_height: u32,
    /// Next height to scan.
    scanned_height: u64,
    /// (height, block hash) of recently scanned blocks, for reorg detection.
    recent: Vec<(u64, [u8; 32])>,
    coins: Vec<WalletCoin>,
    /// Where a rescan starts. Web wallet only.
    #[serde(default)]
    birth_height: u64,
    /// Web wallet only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    sent: Vec<Sent>,
}

impl Drop for WalletData {
    fn drop(&mut self) {
        self.mnemonic.zeroize();
    }
}

// ── What the wallet reports ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Balance {
    pub spendable: u64,
    pub immature: u64,
    /// This wallet's coins in its own payments still waiting for a block.
    pub pending: u64,
    /// Payments to this wallet still waiting for a block (not spendable
    /// until one confirms them).
    pub incoming: u64,
}

/// What one block changed.
#[derive(Debug, Default, Serialize)]
pub struct ScanReport {
    /// New coins, change from this wallet's own payments aside:
    /// (commitment, value, coinbase).
    pub received: Vec<(String, u64, bool)>,
    pub spent: Vec<String>,
    /// Hashes of this wallet's payments that the block confirmed.
    pub confirmed: Vec<String>,
    /// Hashes of payments whose coins the block spent some other way.
    pub failed: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CoinView {
    pub commitment: String,
    pub value: u64,
    pub height: u64,
    pub coinbase: bool,
    /// "spendable", "immature", "pending" or "spent".
    pub status: &'static str,
    pub matures_at: Option<u64>,
    pub spent_height: Option<u64>,
    pub pending_tx: Option<String>,
    /// False if the sender built the coin's recovery commitment wrongly: it
    /// spends normally, but could not be claimed in a recovery epoch until
    /// it is sent on (to this wallet, say).
    pub recovery_ok: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct HistoryEntry {
    /// "received", "mined", "sent".
    pub kind: &'static str,
    /// "pending", "confirmed", "failed", "cancelled"; for coins received,
    /// "immature" until a coinbase matures.
    pub status: &'static str,
    pub height: Option<u64>,
    /// Coins received or paid to the recipient (fees separate).
    pub value: u64,
    pub fee: Option<u64>,
    pub to: Option<String>,
    pub tx_hash: Option<String>,
    pub commitment: Option<String>,
    pub created_at: Option<u64>,
    /// False for a payment reconstructed from the chain alone (made before
    /// a restore, or from another copy of the wallet): its value is the net
    /// the block took from this wallet, fee included.
    pub detailed: bool,
}

#[derive(Debug, Serialize)]
pub struct Quote {
    pub amount: u64,
    pub fee: u64,
    pub inputs: usize,
    pub change: u64,
}

#[derive(Debug, Serialize)]
pub struct BuiltSend {
    pub tx_hash: String,
    pub tx_hex: String,
    pub amount: u64,
    pub fee: u64,
    pub inputs: usize,
    pub change: u64,
}

#[derive(Debug, Serialize)]
pub struct PendingTx {
    pub tx_hash: String,
    pub tx_hex: String,
    pub created_at: u64,
}

// ── Free functions ──────────────────────────────────────────────────────────

/// Minimal fee for a transaction of the usual shape (n inputs, 2 outputs):
/// `src/wallet`'s `suggested_fee`.
pub fn suggested_fee(inputs: u64) -> u64 {
    (inputs * INPUT_WEIGHT + 2 * OUTPUT_WEIGHT + KERNEL_WEIGHT) * MIN_FEE_PER_WEIGHT
}

/// A fresh 24-word mnemonic, as `midwimble wallet create` makes.
pub fn generate_mnemonic() -> String {
    let mut entropy: [u8; 32] = rand::random();
    let m = bip39::Mnemonic::from_entropy(&entropy)
        .expect("32 bytes is a valid BIP39 entropy length")
        .to_string();
    entropy.zeroize();
    m
}

/// The canonical spelling of a typed mnemonic (lower case, single spaces),
/// or why it is not one.
pub fn normalize_mnemonic(typed: &str) -> Result<String> {
    let mut lower = typed.to_lowercase();
    let words: Vec<&str> = lower.split_whitespace().collect();
    let joined = words.join(" ");
    lower.zeroize();
    let parsed = bip39::Mnemonic::parse_normalized(&joined);
    let mut joined = joined;
    let result = parsed
        .map(|m| m.to_string())
        .map_err(|e| anyhow!("not a valid recovery phrase: {e}"));
    joined.zeroize();
    result
}

/// The 64-byte BIP39 seed (no passphrase), as the CLI derives it.
fn seed_of(mnemonic: &str) -> Result<[u8; 64]> {
    let m = bip39::Mnemonic::parse_normalized(mnemonic)
        .map_err(|e| anyhow!("invalid mnemonic: {e}"))?;
    Ok(m.to_seed(""))
}

/// The secret seed of the wallet's recovery key; see [`recovery_leaves`].
pub fn recovery_master_seed(mnemonic: &str) -> Result<[u8; 32]> {
    let mut seed = seed_of(&normalize_mnemonic(mnemonic)?)?;
    let master = recovery::recovery_master_seed(&seed);
    seed.zeroize();
    Ok(master)
}

/// Leaves `start..start + count` of the recovery key's tree. The leaves are
/// independent, so the browser computes them on several workers.
pub fn recovery_leaves(master_seed: &[u8; 32], start: u64, count: u64) -> Vec<[u8; 32]> {
    (start..start + count)
        .map(|i| mss::leaf_public_key(master_seed, i))
        .collect()
}

/// The recovery key over all of a tree's leaves.
pub fn recovery_root(leaves: &[[u8; 32]]) -> Result<[u8; 32]> {
    mss::root_from_leaves(leaves)
}

/// The recovery key, all at once (`recovery::derive_recovery_keypair`).
pub fn recovery_key(mnemonic: &str, height: u32) -> Result<[u8; 32]> {
    let mut seed = seed_of(&normalize_mnemonic(mnemonic)?)?;
    let key = recovery::derive_recovery_keypair(&seed, height)?.public_key();
    seed.zeroize();
    Ok(key)
}

/// The file key: Argon2id with OWASP's baseline (19 MiB, 2 passes, 1 lane),
/// exactly the CLI's.
pub fn derive_file_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(19_456, 2, 1, Some(32)).map_err(|e| anyhow!("argon2 params: {e}"))?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("argon2: {e}"))?;
    Ok(key)
}

/// `(salt, nonce, ciphertext)` of a wallet file.
fn split_file(file: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    if file.len() < FILE_MAGIC.len() + SALT_LEN + NONCE_LEN || !file.starts_with(FILE_MAGIC) {
        bail!("not a midwimble wallet file");
    }
    let body = &file[FILE_MAGIC.len()..];
    let (salt, rest) = body.split_at(SALT_LEN);
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
    Ok((salt, nonce, ciphertext))
}

/// The salt a wallet file's key was derived with.
pub fn file_salt(file: &[u8]) -> Result<[u8; SALT_LEN]> {
    Ok(split_file(file)?.0.try_into().expect("SALT_LEN bytes"))
}

/// A block as the light protocol's `get_block` sends it.
pub fn block_from_hex(hex_str: &str) -> Result<Batch> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| anyhow!("block is not hex: {e}"))?;
    bincode::deserialize(&bytes).map_err(|e| anyhow!("not a block: {e}"))
}

/// Blocks as `get_blocks` sends them: one bincode `Vec<Batch>`.
pub fn blocks_from_hex(hex_str: &str) -> Result<Vec<Batch>> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| anyhow!("blocks are not hex: {e}"))?;
    bincode::deserialize(&bytes).map_err(|e| anyhow!("not a list of blocks: {e}"))
}

/// Mempool transactions as `get_mempool_txs` sends them: one bincode
/// `Vec<Transaction>`.
pub fn txs_from_hex(hex_str: &str) -> Result<Vec<Transaction>> {
    let bytes =
        hex::decode(hex_str.trim()).map_err(|e| anyhow!("transactions are not hex: {e}"))?;
    bincode::deserialize(&bytes).map_err(|e| anyhow!("not a list of transactions: {e}"))
}

/// The outputs of `get_utxos` pages: JSON `[{output_hex, height, coinbase}]`.
pub fn unspent_from_json(json: &str) -> Result<Vec<(Output, u64, bool)>> {
    #[derive(Deserialize)]
    struct Entry {
        output_hex: String,
        height: u64,
        coinbase: bool,
    }
    let entries: Vec<Entry> =
        serde_json::from_str(json).map_err(|e| anyhow!("not a list of unspent outputs: {e}"))?;
    entries
        .into_iter()
        .map(|e| {
            let bytes =
                hex::decode(&e.output_hex).map_err(|e| anyhow!("output is not hex: {e}"))?;
            let output: Output =
                bincode::deserialize(&bytes).map_err(|e| anyhow!("not an output: {e}"))?;
            Ok((output, e.height, e.coinbase))
        })
        .collect()
}

/// A block's id, the hash its successor links to.
pub fn block_id(batch: &Batch) -> [u8; 32] {
    batch.extension.final_hash
}

pub fn check_address(s: &str) -> Result<StealthAddress> {
    StealthAddress::decode(s.trim())
}

// ── The wallet ──────────────────────────────────────────────────────────────

pub struct WalletCore {
    data: WalletData,
    keys: WalletKeys,
    view: ViewKey,
    /// Payments to this wallet still waiting in a node's mempool. Not
    /// stored: the mempool is asked again after a reload.
    incoming: Vec<Incoming>,
    /// Coins a rollback forgot: found again on the new chain, they are not
    /// news.
    forgotten: HashSet<Point32>,
}

/// A transaction in a mempool that pays this wallet.
#[derive(Clone, Debug)]
struct Incoming {
    tx_hash: String,
    /// (commitment, value) of each output it pays this wallet.
    outputs: Vec<(Point32, u64)>,
    /// Unix seconds when this wallet first saw it.
    seen_at: u64,
}

/// A payment seen in the mempool: [`WalletCore::scan_mempool`] reports each
/// one once.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct IncomingView {
    pub tx_hash: String,
    pub value: u64,
}

impl WalletCore {
    /// A wallet over `mnemonic`, whose recovery key (`recovery_root`) is
    /// `recovery_key` at `recovery_height`, scanning from `birth_height`.
    pub fn new(
        mnemonic: &str,
        recovery_key: [u8; 32],
        recovery_height: u32,
        birth_height: u64,
    ) -> Result<Self> {
        Self::from_data(WalletData {
            version: 1,
            mnemonic: normalize_mnemonic(mnemonic)?,
            recovery_key,
            recovery_height,
            scanned_height: birth_height,
            recent: Vec::new(),
            coins: Vec::new(),
            birth_height,
            sent: Vec::new(),
        })
    }

    fn from_data(data: WalletData) -> Result<Self> {
        let mut seed = seed_of(&data.mnemonic)?;
        let keys = WalletKeys::from_seed(&seed, data.recovery_key);
        seed.zeroize();
        let view = keys.view_only();
        Ok(Self {
            data,
            keys,
            view,
            incoming: Vec::new(),
            forgotten: HashSet::new(),
        })
    }

    /// Opens a wallet file (the CLI's or [`Self::seal`]'s) with the key
    /// [`derive_file_key`] made from its password and [`file_salt`].
    pub fn open(file: &[u8], key: &[u8; 32]) -> Result<Self> {
        let (_, nonce, ciphertext) = split_file(file)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
        let mut plain = cipher
            .decrypt(XNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow!("wrong password or corrupted wallet"))?;
        let parsed = serde_json::from_slice::<WalletData>(&plain);
        plain.zeroize();
        Self::from_data(parsed.map_err(|e| anyhow!("unreadable wallet data: {e}"))?)
    }

    /// The wallet as a wallet file. Each call draws a new nonce; the salt is
    /// the caller's, so that a key derived once serves every save.
    pub fn seal(&self, key: &[u8; 32], salt: &[u8; SALT_LEN]) -> Result<Vec<u8>> {
        let nonce: [u8; NONCE_LEN] = rand::random();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
        let mut plain = serde_json::to_vec(&self.data)?;
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), plain.as_slice())
            .map_err(|_| anyhow!("encryption failed"));
        plain.zeroize();
        let ciphertext = ciphertext?;
        let mut out =
            Vec::with_capacity(FILE_MAGIC.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(FILE_MAGIC);
        out.extend_from_slice(salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn mnemonic(&self) -> &str {
        &self.data.mnemonic
    }

    pub fn address(&self) -> StealthAddress {
        self.keys.address()
    }

    pub fn view_key(&self) -> String {
        self.view.encode()
    }

    pub fn recovery_key(&self) -> [u8; 32] {
        self.data.recovery_key
    }

    pub fn recovery_height(&self) -> u32 {
        self.data.recovery_height
    }

    pub fn scanned_height(&self) -> u64 {
        self.data.scanned_height
    }

    pub fn birth_height(&self) -> u64 {
        self.data.birth_height
    }

    /// The block hash recorded at `height`, if still in the window.
    pub fn recorded_hash(&self, height: u64) -> Option<[u8; 32]> {
        self.data
            .recent
            .iter()
            .find(|(h, _)| *h == height)
            .map(|(_, x)| *x)
    }

    /// Forgets everything learned from blocks at or above `height`. A
    /// payment those blocks settled is waiting for a block again: its coins
    /// are reserved for it once more, and it is broadcast again (the node
    /// usually puts it back in its mempool itself). Returns whether anything
    /// the wallet shows changed.
    pub fn rollback_to(&mut self, height: u64) -> bool {
        let before = self.data.coins.len();
        for c in self.data.coins.iter().filter(|c| c.height >= height) {
            self.forgotten.insert(c.output.commitment);
        }
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

    /// Starts over from `height` (the birth height for a full rescan).
    pub fn rescan_from(&mut self, height: u64) {
        self.rollback_to(height);
        self.data.scanned_height = height;
        self.data.birth_height = self.data.birth_height.min(height);
    }

    /// Applies block `height`, which must be the next one to scan. Fails
    /// with [`REORG`] if it does not build on the block scanned before it.
    pub fn scan_block(&mut self, height: u64, batch: &Batch) -> Result<ScanReport> {
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
        let mut report = ScanReport::default();

        let spent: HashSet<Point32> = batch.body.input_commitments().copied().collect();
        for coin in &mut self.data.coins {
            if coin.spent_height.is_none() && spent.contains(&coin.output.commitment) {
                coin.spent_height = Some(height);
                coin.pending_tx = None;
                report.spent.push(hex::encode(coin.output.commitment));
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
                report.confirmed.push(s.tx_hash.clone());
            } else if s.inputs.iter().any(|c| spent.contains(c)) {
                s.failed_at = Some(height);
                report.failed.push(s.tx_hash.clone());
            }
        }

        let mut known: HashSet<Point32> = self
            .data
            .coins
            .iter()
            .map(|c| c.output.commitment)
            .collect();
        let change = self.change_outputs();
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
            // The view key rejects foreign outputs at one scalar
            // multiplication each; the full keys then confirm that this
            // wallet can sign for the owner key.
            let Some((value, _)) = self.view.scan(output) else {
                continue;
            };
            if scan_output(&self.keys, output).is_none() {
                continue;
            }
            known.insert(output.commitment);
            let again = self.forgotten.remove(&output.commitment);
            if !change.contains(&output.commitment) && !again {
                report
                    .received
                    .push((hex::encode(output.commitment), value, coinbase));
            }
            self.data.coins.push(WalletCoin {
                output: output.clone(),
                value,
                height,
                coinbase,
                spent_height: None,
                pending_tx: self.reserved_for(&output.commitment),
            });
        }

        // Payments in the mempool that this block confirmed are coins now.
        self.incoming
            .retain(|i| !i.outputs.iter().any(|(c, _)| known.contains(c)));
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
        Ok(report)
    }

    /// Scans transactions waiting in a node's mempool for payments to this
    /// wallet, with the view key, as blocks are scanned. `live` holds the
    /// hash of every transaction the mempool lists now: a payment whose
    /// transaction is gone is forgotten (a block took it, and scanning that
    /// block finds its coins, or the node dropped it). This wallet's own
    /// payments, and anything spending its coins (another copy of it, whose
    /// change is not income), are left out. Returns the payments seen for
    /// the first time.
    pub fn scan_mempool(
        &mut self,
        txs: &[Transaction],
        live: &HashSet<String>,
        now: u64,
    ) -> Vec<IncomingView> {
        self.incoming.retain(|i| live.contains(&i.tx_hash));
        let known: HashSet<Point32> = self
            .data
            .coins
            .iter()
            .map(|c| c.output.commitment)
            .collect();
        let own: HashSet<[u8; 32]> = self.data.sent.iter().map(|s| s.kernel).collect();
        let mut fresh = Vec::new();
        for tx in txs {
            let tx_hash = hex::encode(tx.hash());
            if !live.contains(&tx_hash) || self.incoming.iter().any(|i| i.tx_hash == tx_hash) {
                continue;
            }
            if tx.kernel_ids().iter().any(|k| own.contains(k))
                || tx.input_commitments().any(|c| known.contains(c))
            {
                continue;
            }
            let mut outputs = Vec::new();
            for output in tx.outputs() {
                if known.contains(&output.commitment) {
                    continue;
                }
                let Some((value, _)) = self.view.scan(output) else {
                    continue;
                };
                if scan_output(&self.keys, output).is_none() {
                    continue;
                }
                outputs.push((output.commitment, value));
            }
            if outputs.is_empty() {
                continue;
            }
            fresh.push(IncomingView {
                tx_hash: tx_hash.clone(),
                value: outputs.iter().map(|(_, v)| v).sum(),
            });
            self.incoming.push(Incoming {
                tx_hash,
                outputs,
                seen_at: now,
            });
        }
        fresh
    }

    /// Rebuilds the wallet from the chain's unspent outputs
    /// `(output, height, coinbase)` instead of its blocks, for a node that
    /// has pruned the blocks this wallet would scan (the CLI's
    /// `scan_unspent`, `docs/PRUNING.md`). Coins it knew that are no longer
    /// unspent are marked spent at `tip_height`, and so are its own pending
    /// payments' coins; payments it never recorded cannot be recovered this
    /// way. Scanning carries on from `tip_height`.
    pub fn scan_unspent(&mut self, outputs: &[(Output, u64, bool)], tip_height: u64) -> ScanReport {
        let mut report = ScanReport::default();
        let mut known: HashSet<Point32> = self
            .data
            .coins
            .iter()
            .map(|c| c.output.commitment)
            .collect();
        let live: HashSet<Point32> = outputs.iter().map(|(o, _, _)| o.commitment).collect();
        let change = self.change_outputs();
        for (output, height, coinbase) in outputs {
            if known.contains(&output.commitment) {
                continue;
            }
            let Some((value, _)) = self.view.scan(output) else {
                continue;
            };
            if scan_output(&self.keys, output).is_none() {
                continue;
            }
            known.insert(output.commitment);
            if !change.contains(&output.commitment) {
                report
                    .received
                    .push((hex::encode(output.commitment), value, *coinbase));
            }
            self.data.coins.push(WalletCoin {
                output: output.clone(),
                value,
                height: *height,
                coinbase: *coinbase,
                spent_height: None,
                pending_tx: self.reserved_for(&output.commitment),
            });
        }
        for coin in &mut self.data.coins {
            if coin.spent_height.is_none() && !live.contains(&coin.output.commitment) {
                coin.spent_height = Some(tip_height);
                coin.pending_tx = None;
                report.spent.push(hex::encode(coin.output.commitment));
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
                report.confirmed.push(s.tx_hash.clone());
            }
        }
        self.data.scanned_height = tip_height;
        self.data.recent.clear();
        report
    }

    /// The payment still waiting for a block that spends this coin, if any:
    /// a coin found again after a rollback stays reserved for it.
    fn reserved_for(&self, commitment: &Point32) -> Option<String> {
        self.data
            .sent
            .iter()
            .find(|s| {
                s.height.is_none()
                    && s.failed_at.is_none()
                    && !s.cancelled
                    && s.inputs.contains(commitment)
            })
            .map(|s| s.tx_hash.clone())
    }

    /// The change outputs of this wallet's own payments: coming back, they
    /// are not income.
    fn change_outputs(&self) -> HashSet<Point32> {
        self.data.sent.iter().filter_map(|s| s.change).collect()
    }

    fn is_mature(c: &WalletCoin, tip_height: u64) -> bool {
        !c.coinbase || tip_height >= c.height + COINBASE_MATURITY
    }

    /// `tip_height` is the height of the next block (`get_state`'s height).
    pub fn balance(&self, tip_height: u64) -> Balance {
        let mut b = Balance::default();
        for c in self.data.coins.iter().filter(|c| c.spent_height.is_none()) {
            if c.pending_tx.is_some() {
                b.pending += c.value;
            } else if !Self::is_mature(c, tip_height) {
                b.immature += c.value;
            } else {
                b.spendable += c.value;
            }
        }
        b.incoming = self
            .incoming
            .iter()
            .flat_map(|i| i.outputs.iter())
            .map(|(_, v)| v)
            .sum();
        b
    }

    pub fn coins(&self, tip_height: u64) -> Vec<CoinView> {
        let mut out: Vec<CoinView> = self
            .data
            .coins
            .iter()
            .map(|c| {
                let status = if c.spent_height.is_some() {
                    "spent"
                } else if c.pending_tx.is_some() {
                    "pending"
                } else if !Self::is_mature(c, tip_height) {
                    "immature"
                } else {
                    "spendable"
                };
                CoinView {
                    commitment: hex::encode(c.output.commitment),
                    value: c.value,
                    height: c.height,
                    coinbase: c.coinbase,
                    status,
                    matures_at: c.coinbase.then_some(c.height + COINBASE_MATURITY),
                    spent_height: c.spent_height,
                    pending_tx: c.pending_tx.clone(),
                    recovery_ok: self.view.scan(&c.output).map_or(false, |(_, ok)| ok),
                }
            })
            .collect();
        out.sort_by(|a, b| b.height.cmp(&a.height).then(b.value.cmp(&a.value)));
        out
    }

    /// Unspent, unreserved, mature coins, largest first.
    fn candidates(&self, tip_height: u64) -> Vec<&WalletCoin> {
        let mut v: Vec<&WalletCoin> = self
            .data
            .coins
            .iter()
            .filter(|c| {
                c.spent_height.is_none() && c.pending_tx.is_none() && Self::is_mature(c, tip_height)
            })
            .collect();
        v.sort_by(|a, b| b.value.cmp(&a.value));
        v
    }

    /// The CLI's selection: largest coins until they cover the amount plus
    /// the fee for however many inputs that took.
    fn select(
        &self,
        amount: u64,
        fee: Option<u64>,
        tip_height: u64,
    ) -> Result<(Vec<&WalletCoin>, u64)> {
        if amount == 0 {
            bail!("amount must be positive");
        }
        let fee_for = |n: usize| fee.unwrap_or_else(|| suggested_fee(n.max(1) as u64));
        let mut chosen = Vec::new();
        let mut total = 0u64;
        for c in self.candidates(tip_height) {
            let need = amount
                .checked_add(fee_for(chosen.len()))
                .ok_or_else(|| anyhow!("amount overflow"))?;
            if total >= need {
                break;
            }
            total += c.value;
            chosen.push(c);
        }
        let fee = fee_for(chosen.len());
        let need = amount
            .checked_add(fee)
            .ok_or_else(|| anyhow!("amount overflow"))?;
        if total < need {
            bail!(
                "insufficient spendable funds: have {}, need {} (amount plus a {} fee)",
                midwimble::core::types::format_amount(total),
                midwimble::core::types::format_amount(need),
                midwimble::core::types::format_amount(fee)
            );
        }
        Ok((chosen, fee))
    }

    /// What sending `amount` would take, without reserving anything.
    pub fn quote(&self, amount: u64, tip_height: u64) -> Result<Quote> {
        let (chosen, fee) = self.select(amount, None, tip_height)?;
        let total: u64 = chosen.iter().map(|c| c.value).sum();
        Ok(Quote {
            amount,
            fee,
            inputs: chosen.len(),
            change: total - amount - fee,
        })
    }

    /// The most one payment can send (everything worth more than its fee).
    pub fn max_sendable(&self, tip_height: u64) -> u64 {
        let mut best = 0u64;
        let mut total = 0u64;
        for (i, c) in self.candidates(tip_height).iter().enumerate() {
            total += c.value;
            best = best.max(total.saturating_sub(suggested_fee(i as u64 + 1)));
        }
        best
    }

    /// Builds a payment and reserves its coins until a block confirms it or
    /// [`Self::cancel_pending`] releases them. `tip_height` is the height of
    /// the next block; `now` is unix seconds, for history.
    pub fn build_send(
        &mut self,
        to: &str,
        amount: u64,
        fee: Option<u64>,
        tip_height: u64,
        now: u64,
    ) -> Result<BuiltSend> {
        let address = check_address(to)?;
        let (chosen, fee) = self.select(amount, fee, tip_height)?;
        let mut spend = Vec::with_capacity(chosen.len());
        for c in &chosen {
            let owned = scan_output(&self.keys, &c.output)
                .ok_or_else(|| anyhow!("a stored coin no longer opens"))?;
            spend.push(Spendable {
                commitment: c.output.commitment,
                value: owned.value,
                blinding: owned.blinding,
                owner_secret: owned.owner_secret,
            });
        }
        let built = build_transaction(
            &spend,
            &[Payment {
                to: address,
                value: amount,
            }],
            &self.address(),
            fee,
            tip_height,
        )?;
        let tx: &Transaction = &built.tx;
        let tx_hash = hex::encode(tx.hash());
        let tx_hex = hex::encode(bincode::serialize(tx)?);
        let inputs: Vec<Point32> = spend.iter().map(|s| s.commitment).collect();
        for coin in &mut self.data.coins {
            if inputs.contains(&coin.output.commitment) {
                coin.pending_tx = Some(tx_hash.clone());
            }
        }
        let change = built.change.map_or(0, |(_, v)| v);
        self.data.sent.push(Sent {
            tx_hash: tx_hash.clone(),
            kernel: tx.body.kernels[0].id(),
            to: address.encode(),
            amount,
            fee,
            inputs: inputs.clone(),
            change: built.change.map(|(c, _)| c),
            created_at: now,
            tx_hex: Some(tx_hex.clone()),
            height: None,
            failed_at: None,
            cancelled: false,
        });
        Ok(BuiltSend {
            tx_hash,
            tx_hex,
            amount,
            fee,
            inputs: inputs.len(),
            change,
        })
    }

    /// Releases the coins of a payment that will never confirm (the node
    /// refused it, or it fell out of every mempool). If it confirms after
    /// all, scanning still records it.
    pub fn cancel_pending(&mut self, tx_hash: &str) {
        for coin in &mut self.data.coins {
            if coin.pending_tx.as_deref() == Some(tx_hash) {
                coin.pending_tx = None;
            }
        }
        for s in &mut self.data.sent {
            if s.tx_hash == tx_hash && s.height.is_none() {
                s.cancelled = true;
                s.tx_hex = None;
            }
        }
    }

    /// Forgets a payment the node refused outright: it never left this
    /// wallet, so it is not history.
    pub fn discard_send(&mut self, tx_hash: &str) {
        self.cancel_pending(tx_hash);
        self.data
            .sent
            .retain(|s| !(s.tx_hash == tx_hash && s.height.is_none()));
    }

    /// Payments still waiting for a block, to broadcast again.
    pub fn pending_txs(&self) -> Vec<PendingTx> {
        self.data
            .sent
            .iter()
            .filter(|s| s.height.is_none() && s.failed_at.is_none() && !s.cancelled)
            .filter_map(|s| {
                s.tx_hex.as_ref().map(|tx_hex| PendingTx {
                    tx_hash: s.tx_hash.clone(),
                    tx_hex: tx_hex.clone(),
                    created_at: s.created_at,
                })
            })
            .collect()
    }

    /// Received coins and payments, newest first. Change is folded into the
    /// payment that made it. Coins spent by payments this wallet has no
    /// record of (made before a restore, or by another copy of the wallet)
    /// become one undetailed payment per block, net of whatever that block
    /// paid back.
    pub fn history(&self, tip_height: u64) -> Vec<HistoryEntry> {
        let change: HashSet<Point32> = self.data.sent.iter().filter_map(|s| s.change).collect();
        let recorded_inputs: HashSet<Point32> = self
            .data
            .sent
            .iter()
            .filter(|s| s.failed_at.is_none())
            .flat_map(|s| s.inputs.iter().copied())
            .collect();
        // Per block, coins spent without a record, and the coins that block
        // paid this wallet that are not change of a recorded payment.
        let mut unknown_spends: BTreeMap<u64, u64> = BTreeMap::new();
        for c in &self.data.coins {
            if let Some(h) = c.spent_height {
                if !recorded_inputs.contains(&c.output.commitment) {
                    *unknown_spends.entry(h).or_default() += c.value;
                }
            }
        }
        let mut entries = Vec::new();
        let mut folded: BTreeMap<u64, u64> = BTreeMap::new();
        for c in &self.data.coins {
            if change.contains(&c.output.commitment) {
                continue;
            }
            if !c.coinbase && unknown_spends.contains_key(&c.height) {
                *folded.entry(c.height).or_default() += c.value;
                continue;
            }
            entries.push(HistoryEntry {
                kind: if c.coinbase { "mined" } else { "received" },
                status: if Self::is_mature(c, tip_height) {
                    "confirmed"
                } else {
                    "immature"
                },
                height: Some(c.height),
                value: c.value,
                fee: None,
                to: None,
                tx_hash: None,
                commitment: Some(hex::encode(c.output.commitment)),
                created_at: None,
                detailed: true,
            });
        }
        for (h, spent) in unknown_spends {
            let back = folded.get(&h).copied().unwrap_or(0);
            let (kind, value) = if spent >= back {
                ("sent", spent - back)
            } else {
                ("received", back - spent)
            };
            if value == 0 {
                continue;
            }
            entries.push(HistoryEntry {
                kind,
                status: "confirmed",
                height: Some(h),
                value,
                fee: None,
                to: None,
                tx_hash: None,
                commitment: None,
                created_at: None,
                detailed: false,
            });
        }
        for i in &self.incoming {
            entries.push(HistoryEntry {
                kind: "received",
                status: "pending",
                height: None,
                value: i.outputs.iter().map(|(_, v)| v).sum(),
                fee: None,
                to: None,
                tx_hash: Some(i.tx_hash.clone()),
                commitment: i.outputs.first().map(|(c, _)| hex::encode(c)),
                created_at: Some(i.seen_at),
                detailed: true,
            });
        }
        for s in &self.data.sent {
            entries.push(HistoryEntry {
                kind: "sent",
                status: if s.height.is_some() {
                    "confirmed"
                } else if s.cancelled {
                    "cancelled"
                } else if s.failed_at.is_some() {
                    "failed"
                } else {
                    "pending"
                },
                height: s.height.or(s.failed_at),
                value: s.amount,
                fee: Some(s.fee),
                to: Some(s.to.clone()),
                tx_hash: Some(s.tx_hash.clone()),
                commitment: None,
                created_at: Some(s.created_at),
                detailed: true,
            });
        }
        // Unconfirmed first, then newest block first; within a block,
        // payments before receipts.
        entries.sort_by(|a, b| {
            let ka = a.height.unwrap_or(u64::MAX);
            let kb = b.height.unwrap_or(u64::MAX);
            kb.cmp(&ka)
                .then_with(|| b.created_at.cmp(&a.created_at))
                .then_with(|| (b.kind == "sent").cmp(&(a.kind == "sent")))
        });
        entries
    }
}
