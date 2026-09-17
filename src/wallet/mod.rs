//! Wallet: keys, encrypted storage, chain scanning, spending.
//!
//! Keys come from a BIP39 mnemonic (pluribit's wallet does the same). The
//! wallet file is encrypted with Argon2id + XChaCha20-Poly1305 (midstate uses
//! Argon2id with AES-GCM; the AEAD is swapped for the one the payload
//! encryption already uses). Only public output data is stored; blinding
//! factors and owner secrets are re-derived from the seed when spending.

use crate::core::mw::crypto::{self, Point32};
use crate::core::mw::stealth::scan_output;
use crate::core::mw::{
    build_transaction, Output, Payment, Spendable, StealthAddress, Transaction, WalletKeys,
};
use crate::core::recovery::{derive_recovery_keypair, ClaimedOutput, RecoveryClaim};
use crate::core::types::COINBASE_MATURITY;
use crate::core::Batch;
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const FILE_MAGIC: &[u8] = b"MWWALLET1";
const REORG_WINDOW: usize = 200;

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
    pub pending: u64,
}

pub struct Wallet {
    path: PathBuf,
    password: String,
    data: WalletData,
    keys: WalletKeys,
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
            },
            keys,
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
        let data: WalletData = serde_json::from_slice(&plain)?;
        plain.zeroize();
        let mut seed = seed_of(&data.mnemonic)?;
        let keys = WalletKeys::from_seed(&seed, data.recovery_key);
        seed.zeroize();
        Ok(Self {
            path: path.to_path_buf(),
            password: password.to_string(),
            data,
            keys,
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

    pub fn mnemonic(&self) -> &str {
        &self.data.mnemonic
    }

    pub fn address(&self) -> StealthAddress {
        self.keys.address()
    }

    pub fn scanned_height(&self) -> u64 {
        self.data.scanned_height
    }

    pub fn coins(&self) -> &[WalletCoin] {
        &self.data.coins
    }

    /// The block hash we recorded at `height`, if still in the window.
    pub fn recorded_hash(&self, height: u64) -> Option<[u8; 32]> {
        self.data
            .recent
            .iter()
            .find(|(h, _)| *h == height)
            .map(|(_, x)| *x)
    }

    /// Forgets everything learned from blocks at or above `height`.
    pub fn rollback_to(&mut self, height: u64) {
        self.data.coins.retain(|c| c.height < height);
        for c in &mut self.data.coins {
            if c.spent_height.map_or(false, |h| h >= height) {
                c.spent_height = None;
            }
        }
        self.data.recent.retain(|(h, _)| *h < height);
        self.data.scanned_height = self.data.scanned_height.min(height);
    }

    /// Applies one block at `height` (must equal `scanned_height`).
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
                    bail!("reorg detected below height {}", height);
                }
            }
        }
        let spent: Vec<Point32> = batch.body.input_commitments().copied().collect();
        for coin in &mut self.data.coins {
            if coin.spent_height.is_none() && spent.contains(&coin.output.commitment) {
                coin.spent_height = Some(height);
                coin.pending_tx = None;
            }
        }
        let body = batch.body.outputs().map(|o| (o, false));
        let reward = batch
            .coinbase
            .iter()
            .flat_map(|c| c.outputs.outputs.iter())
            .map(|o| (o, true));
        for (output, coinbase) in body.chain(reward) {
            if self
                .data
                .coins
                .iter()
                .any(|c| c.output.commitment == output.commitment)
            {
                continue;
            }
            if let Some(owned) = scan_output(&self.keys, output) {
                self.data.coins.push(WalletCoin {
                    output: output.clone(),
                    value: owned.value,
                    height,
                    coinbase,
                    spent_height: None,
                    pending_tx: None,
                });
            }
        }
        self.data.recent.push((height, batch.extension.final_hash));
        if self.data.recent.len() > REORG_WINDOW {
            self.data.recent.remove(0);
        }
        self.data.scanned_height = height + 1;
        Ok(())
    }

    /// Syncs from a node, choosing how by what that node still has: block
    /// scanning normally, the unspent-output set if it has pruned the blocks
    /// this wallet would need.
    pub fn sync_from_node(&mut self, client: &crate::rpc::RpcClient) -> Result<u64> {
        let tip = client.height()?;
        let pruned_below = client
            .get("/finality")
            .map(|f| f["pruned_below"].as_u64().unwrap_or(0))
            .unwrap_or(0);
        if self.scanned_height() >= pruned_below {
            let n = self.sync_with(tip, |start, count| client.blocks(start, count))?;
            self.save()?;
            return Ok(n);
        }
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
        let found = self.scan_unspent(&outputs, tip)?;
        self.save()?;
        Ok(found)
    }

    /// Rebuilds the wallet from the chain's *unspent* outputs, for nodes that
    /// have pruned the block bodies this wallet would otherwise scan
    /// (`docs/PRUNING.md`). Coins it knew that are no longer unspent are
    /// marked spent; outgoing history cannot be recovered this way.
    pub fn scan_unspent(
        &mut self,
        outputs: &[(Output, u64, bool)],
        tip_height: u64,
    ) -> Result<u64> {
        let mut found = 0;
        let mut live = std::collections::HashSet::new();
        for (output, height, coinbase) in outputs {
            live.insert(output.commitment);
            if self
                .data
                .coins
                .iter()
                .any(|c| c.output.commitment == output.commitment)
            {
                continue;
            }
            if let Some(owned) = scan_output(&self.keys, output) {
                found += 1;
                self.data.coins.push(WalletCoin {
                    output: output.clone(),
                    value: owned.value,
                    height: *height,
                    coinbase: *coinbase,
                    spent_height: None,
                    pending_tx: None,
                });
            }
        }
        for coin in &mut self.data.coins {
            if coin.spent_height.is_none() && !live.contains(&coin.output.commitment) {
                coin.spent_height = Some(tip_height);
                coin.pending_tx = None;
            }
        }
        self.data.scanned_height = tip_height;
        self.data.recent.clear();
        Ok(found)
    }

    /// Scans blocks produced by `fetch(start, count)` up to `tip_height`
    /// (exclusive), rolling back on reorgs. Returns the number of blocks
    /// scanned.
    pub fn sync_with<F>(&mut self, tip_height: u64, mut fetch: F) -> Result<u64>
    where
        F: FnMut(u64, u64) -> Result<Vec<Batch>>,
    {
        let mut scanned = 0;
        // Reorg check: the block we last scanned must still be there.
        while self.data.scanned_height > 0 {
            let last = self.data.scanned_height - 1;
            let Some(recorded) = self.recorded_hash(last) else {
                break;
            };
            let current = fetch(last, 1)?.into_iter().next();
            if current.map(|b| b.extension.final_hash) == Some(recorded) {
                break;
            }
            let back = last.saturating_sub(10);
            self.rollback_to(back);
        }
        while self.data.scanned_height < tip_height {
            let start = self.data.scanned_height;
            let batches = fetch(start, (tip_height - start).min(64))?;
            if batches.is_empty() {
                break;
            }
            for (i, b) in batches.iter().enumerate() {
                match self.scan_block(start + i as u64, b) {
                    Ok(()) => scanned += 1,
                    Err(e) if e.to_string().contains("reorg") => {
                        self.rollback_to((start + i as u64).saturating_sub(10));
                        break;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(scanned)
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
        b
    }

    /// Builds a payment and marks the spent coins pending. `tip_height` is
    /// the height of the next block. Without an explicit `fee`, pays the relay
    /// minimum for however many inputs end up selected.
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
        let tx_hash = hex::encode(built.tx.hash());
        for coin in &mut self.data.coins {
            if chosen
                .iter()
                .any(|s| s.commitment == coin.output.commitment)
            {
                coin.pending_tx = Some(tx_hash.clone());
            }
        }
        Ok(built.tx)
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

    /// Releases coins held by a transaction that will never confirm.
    pub fn cancel_pending(&mut self, tx_hash: &str) {
        for coin in &mut self.data.coins {
            if coin.pending_tx.as_deref() == Some(tx_hash) {
                coin.pending_tx = None;
            }
        }
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
    use crate::core::State;

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
