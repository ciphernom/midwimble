//! midwimble's browser wallet, compiled to WebAssembly.
//!
//! [`wallet`] holds the wallet; this file is its JavaScript face. Amounts and
//! heights cross as JS numbers (every value the chain can hold, 10^14 base
//! units at most, is exact in a double), structured results as JSON strings,
//! and binary data as `Uint8Array`s.

use wasm_bindgen::prelude::*;

pub mod wallet;

use wallet::WalletCore;

fn err(e: anyhow::Error) -> JsError {
    JsError::new(&format!("{e:#}"))
}

/// A JS number that must be a whole, non-negative, exactly represented value.
fn whole(x: f64, what: &str) -> Result<u64, JsError> {
    if x.is_finite() && x >= 0.0 && x.fract() == 0.0 && x <= 9_007_199_254_740_991.0 {
        Ok(x as u64)
    } else {
        Err(JsError::new(&format!(
            "{what} must be a whole number of base units"
        )))
    }
}

fn json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).expect("wallet views serialize")
}

fn bytes32(b: &[u8], what: &str) -> Result<[u8; 32], JsError> {
    b.try_into()
        .map_err(|_| JsError::new(&format!("{what} must be 32 bytes")))
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32], JsError> {
    let v = hex::decode(s.trim()).map_err(|_| JsError::new(&format!("{what} is not hex")))?;
    bytes32(&v, what)
}

// ── Keys and amounts ────────────────────────────────────────────────────────

/// A fresh 24-word recovery phrase.
#[wasm_bindgen]
pub fn generate_mnemonic() -> String {
    wallet::generate_mnemonic()
}

/// The canonical form of a typed phrase; throws if it is not a valid one.
#[wasm_bindgen]
pub fn normalize_mnemonic(typed: &str) -> Result<String, JsError> {
    wallet::normalize_mnemonic(typed).map_err(err)
}

/// The secret seed of a phrase's recovery key, for `recovery_leaves`.
#[wasm_bindgen]
pub fn recovery_master_seed(mnemonic: &str) -> Result<Vec<u8>, JsError> {
    Ok(wallet::recovery_master_seed(mnemonic)
        .map_err(err)?
        .to_vec())
}

/// Leaves `start..start + count` of the recovery key's tree, 32 bytes each.
#[wasm_bindgen]
pub fn recovery_leaves(master_seed: &[u8], start: u32, count: u32) -> Result<Vec<u8>, JsError> {
    let seed = bytes32(master_seed, "the recovery seed")?;
    Ok(wallet::recovery_leaves(&seed, start as u64, count as u64).concat())
}

/// The recovery key (hex) over every leaf of its tree, in order.
#[wasm_bindgen]
pub fn recovery_root(leaves: &[u8]) -> Result<String, JsError> {
    if leaves.len() % 32 != 0 {
        return Err(JsError::new("leaves come in 32-byte pieces"));
    }
    let leaves: Vec<[u8; 32]> = leaves
        .chunks_exact(32)
        .map(|c| c.try_into().expect("32 bytes"))
        .collect();
    Ok(hex::encode(wallet::recovery_root(&leaves).map_err(err)?))
}

/// Throws unless `address` is a v1 midwimble address.
#[wasm_bindgen]
pub fn check_address(address: &str) -> Result<(), JsError> {
    wallet::check_address(address).map(|_| ()).map_err(err)
}

/// Base units in an amount of coins, e.g. "0.5" → 50000000.
#[wasm_bindgen]
pub fn parse_amount(coins: &str) -> Result<f64, JsError> {
    Ok(midwimble::core::types::parse_amount(coins).map_err(err)? as f64)
}

#[wasm_bindgen]
pub fn format_amount(units: f64) -> Result<String, JsError> {
    Ok(midwimble::core::types::format_amount(whole(
        units,
        "an amount",
    )?))
}

/// The relay minimum fee for a payment spending `inputs` coins.
#[wasm_bindgen]
pub fn suggested_fee(inputs: u32) -> f64 {
    wallet::suggested_fee(inputs as u64) as f64
}

/// Chain constants the page needs, as JSON.
#[wasm_bindgen]
pub fn chain_constants() -> String {
    use midwimble::core::types;
    json(&serde_json::json!({
        "network": String::from_utf8_lossy(types::NETWORK_MAGIC),
        "coin": types::COIN,
        "coinbase_maturity": types::COINBASE_MATURITY,
        "target_block_time": types::TARGET_BLOCK_TIME,
        "recovery_height": midwimble::core::recovery::DEFAULT_RECOVERY_HEIGHT,
        "fast_mining": cfg!(feature = "fast-mining"),
    }))
}

// ── Files ───────────────────────────────────────────────────────────────────

/// The Argon2id key of a wallet file (slow on purpose: ~19 MiB of work).
#[wasm_bindgen]
pub fn derive_file_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, JsError> {
    Ok(wallet::derive_file_key(password, salt)
        .map_err(err)?
        .to_vec())
}

/// The salt a wallet file was sealed with.
#[wasm_bindgen]
pub fn file_salt(file: &[u8]) -> Result<Vec<u8>, JsError> {
    Ok(wallet::file_salt(file).map_err(err)?.to_vec())
}

/// A fresh random salt for a new wallet file.
#[wasm_bindgen]
pub fn new_salt() -> Vec<u8> {
    rand::random::<[u8; wallet::SALT_LEN]>().to_vec()
}

// ── Blocks ──────────────────────────────────────────────────────────────────

/// The id (hex) of a block in `get_block`'s hex form.
#[wasm_bindgen]
pub fn block_id(block_hex: &str) -> Result<String, JsError> {
    Ok(hex::encode(wallet::block_id(
        &wallet::block_from_hex(block_hex).map_err(err)?,
    )))
}

/// The block ids (JSON list of hex) of headers in `get_headers`' hex form:
/// how the page checks that a node is on its network (header 0 is the
/// genesis block, whose id the network's manifest publishes).
#[wasm_bindgen]
pub fn header_ids(headers_hex: &str) -> Result<String, JsError> {
    let bytes = hex::decode(headers_hex.trim()).map_err(|_| JsError::new("headers are not hex"))?;
    let headers: Vec<midwimble::core::BatchHeader> = bincode::deserialize(&bytes)
        .map_err(|e| JsError::new(&format!("not a list of headers: {e}")))?;
    let ids: Vec<String> = headers
        .iter()
        .map(|h| hex::encode(h.extension.final_hash))
        .collect();
    Ok(json(&ids))
}

// ── The wallet ──────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub struct Wallet(WalletCore);

#[wasm_bindgen]
impl Wallet {
    /// A new wallet over `mnemonic`, whose recovery key (`recovery_root`)
    /// is `recovery_key_hex` at `recovery_height`, scanning from
    /// `birth_height`.
    #[wasm_bindgen(constructor)]
    pub fn new(
        mnemonic: &str,
        recovery_key_hex: &str,
        recovery_height: u32,
        birth_height: f64,
    ) -> Result<Wallet, JsError> {
        Ok(Wallet(
            WalletCore::new(
                mnemonic,
                hex32(recovery_key_hex, "the recovery key")?,
                recovery_height,
                whole(birth_height, "the birth height")?,
            )
            .map_err(err)?,
        ))
    }

    /// Opens a wallet file with the key `derive_file_key` made.
    pub fn open(file: &[u8], key: &[u8]) -> Result<Wallet, JsError> {
        Ok(Wallet(
            WalletCore::open(file, &bytes32(key, "the file key")?).map_err(err)?,
        ))
    }

    /// The wallet as a wallet file (the CLI opens it too).
    pub fn seal(&self, key: &[u8], salt: &[u8]) -> Result<Vec<u8>, JsError> {
        let salt: [u8; wallet::SALT_LEN] = salt
            .try_into()
            .map_err(|_| JsError::new("the salt must be 16 bytes"))?;
        self.0
            .seal(&bytes32(key, "the file key")?, &salt)
            .map_err(err)
    }

    pub fn mnemonic(&self) -> String {
        self.0.mnemonic().to_string()
    }

    pub fn address(&self) -> String {
        self.0.address().encode()
    }

    pub fn view_key(&self) -> String {
        self.0.view_key()
    }

    pub fn recovery_key(&self) -> String {
        hex::encode(self.0.recovery_key())
    }

    pub fn recovery_height(&self) -> u32 {
        self.0.recovery_height()
    }

    pub fn scanned_height(&self) -> f64 {
        self.0.scanned_height() as f64
    }

    pub fn birth_height(&self) -> f64 {
        self.0.birth_height() as f64
    }

    /// The id of the block scanned at `height`, while it is recent.
    pub fn recorded_hash(&self, height: f64) -> Result<Option<String>, JsError> {
        Ok(self
            .0
            .recorded_hash(whole(height, "a height")?)
            .map(hex::encode))
    }

    /// Forgets blocks from `height` on (a reorganisation). Returns whether
    /// anything the wallet shows changed.
    pub fn rollback_to(&mut self, height: f64) -> Result<bool, JsError> {
        Ok(self.0.rollback_to(whole(height, "a height")?))
    }

    pub fn rescan_from(&mut self, height: f64) -> Result<(), JsError> {
        self.0.rescan_from(whole(height, "a height")?);
        Ok(())
    }

    /// Applies block `height` (hex bincode, as `get_block` sends it), the
    /// next one to scan. Returns JSON {received, spent, confirmed, failed}.
    /// Throws "reorg detected…" if it does not build on the last block.
    pub fn scan_block(&mut self, height: f64, block_hex: &str) -> Result<String, JsError> {
        let batch = wallet::block_from_hex(block_hex).map_err(err)?;
        let report = self
            .0
            .scan_block(whole(height, "a height")?, &batch)
            .map_err(err)?;
        Ok(json(&report))
    }

    /// Applies consecutive blocks from `start` (one hex bincode
    /// `Vec<Batch>`, as `get_blocks` sends them). Returns JSON
    /// {scanned, received, spent, confirmed, failed}; on a reorg it applies
    /// the blocks before it and reports {reorg: true}.
    pub fn scan_blocks(&mut self, start: f64, blocks_hex: &str) -> Result<String, JsError> {
        let start = whole(start, "a height")?;
        let blocks = wallet::blocks_from_hex(blocks_hex).map_err(err)?;
        let mut total = wallet::ScanReport::default();
        let mut scanned = 0u64;
        let mut reorg = false;
        for (i, b) in blocks.iter().enumerate() {
            match self.0.scan_block(start + i as u64, b) {
                Ok(r) => {
                    scanned += 1;
                    total.received.extend(r.received);
                    total.spent.extend(r.spent);
                    total.confirmed.extend(r.confirmed);
                    total.failed.extend(r.failed);
                }
                Err(e) if e.to_string().starts_with(wallet::REORG) => {
                    reorg = true;
                    break;
                }
                Err(e) => return Err(err(e)),
            }
        }
        Ok(json(&serde_json::json!({
            "scanned": scanned,
            "reorg": reorg,
            "received": total.received,
            "spent": total.spent,
            "confirmed": total.confirmed,
            "failed": total.failed,
        })))
    }

    /// Rebuilds from unspent outputs (JSON [{output_hex, height, coinbase}],
    /// all of `get_utxos`' pages together) when the node has pruned the
    /// blocks this wallet would scan. Returns JSON {received, spent,
    /// confirmed, failed}; scanning carries on from `tip_height`.
    pub fn scan_unspent(&mut self, outputs_json: &str, tip_height: f64) -> Result<String, JsError> {
        let outputs = wallet::unspent_from_json(outputs_json).map_err(err)?;
        let report = self
            .0
            .scan_unspent(&outputs, whole(tip_height, "a height")?);
        Ok(json(&report))
    }

    /// Scans mempool transactions (one hex bincode `Vec<Transaction>`, as
    /// `get_mempool_txs` sends them; empty for none) for payments to this
    /// wallet. `live_json` lists every hash `get_mempool` returned: payments
    /// no longer among them are forgotten. Returns JSON [{tx_hash, value}]
    /// of the payments seen for the first time.
    pub fn scan_mempool(
        &mut self,
        txs_hex: &str,
        live_json: &str,
        now: f64,
    ) -> Result<String, JsError> {
        let txs = if txs_hex.trim().is_empty() {
            Vec::new()
        } else {
            wallet::txs_from_hex(txs_hex).map_err(err)?
        };
        let live: std::collections::HashSet<String> = serde_json::from_str(live_json)
            .map_err(|e| JsError::new(&format!("not a list of transaction hashes: {e}")))?;
        let fresh = self
            .0
            .scan_mempool(&txs, &live, whole(now.floor(), "the time")?);
        Ok(json(&fresh))
    }

    /// JSON {spendable, immature, pending, incoming}; `tip_height` is the
    /// height of the next block.
    pub fn balance(&self, tip_height: f64) -> Result<String, JsError> {
        Ok(json(&self.0.balance(whole(tip_height, "a height")?)))
    }

    pub fn coins(&self, tip_height: f64) -> Result<String, JsError> {
        Ok(json(&self.0.coins(whole(tip_height, "a height")?)))
    }

    pub fn history(&self, tip_height: f64) -> Result<String, JsError> {
        Ok(json(&self.0.history(whole(tip_height, "a height")?)))
    }

    /// JSON {amount, fee, inputs, change} for sending `amount`; throws if
    /// the wallet cannot.
    pub fn quote(&self, amount: f64, tip_height: f64) -> Result<String, JsError> {
        let q = self
            .0
            .quote(whole(amount, "the amount")?, whole(tip_height, "a height")?)
            .map_err(err)?;
        Ok(json(&q))
    }

    pub fn max_sendable(&self, tip_height: f64) -> Result<f64, JsError> {
        Ok(self.0.max_sendable(whole(tip_height, "a height")?) as f64)
    }

    /// Builds a payment and reserves its coins. Returns JSON
    /// {tx_hash, tx_hex, amount, fee, inputs, change}.
    pub fn build_send(
        &mut self,
        to: &str,
        amount: f64,
        tip_height: f64,
        now: f64,
    ) -> Result<String, JsError> {
        let built = self
            .0
            .build_send(
                to,
                whole(amount, "the amount")?,
                None,
                whole(tip_height, "a height")?,
                whole(now.floor(), "the time")?,
            )
            .map_err(err)?;
        Ok(json(&built))
    }

    /// Releases a payment's coins (it will never confirm).
    pub fn cancel_pending(&mut self, tx_hash: &str) {
        self.0.cancel_pending(tx_hash);
    }

    /// Forgets a payment the node refused.
    pub fn discard_send(&mut self, tx_hash: &str) {
        self.0.discard_send(tx_hash);
    }

    /// JSON [{tx_hash, tx_hex, created_at}] of payments awaiting a block.
    pub fn pending_txs(&self) -> String {
        json(&self.0.pending_txs())
    }
}
