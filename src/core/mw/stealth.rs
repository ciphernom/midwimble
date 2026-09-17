//! Non-interactive stealth payments.
//!
//! # Provenance
//!
//! From pluribit `src/stealth.rs` and `src/wallet.rs`: an ephemeral key `R`
//! per output, an ECDH shared secret with the recipient's scan key, a one-byte
//! view tag for fast scanning, and an XChaCha20-Poly1305 payload carrying the
//! value and blinding factor.
//!
//! # The ownership fix
//!
//! In pluribit the sender invents the recipient's blinding factor and encrypts
//! it to them. In MimbleWimble the blinding factor *is* the spending secret,
//! so the sender could spend the payment at any time before the recipient
//! moved it, and anyone holding only the scan key could spend it too.
//! Pluribit's wallet derives a spend key and never uses it.
//!
//! Here every output also carries a one-time **owner key**
//!
//! ```text
//!   t   = H(r·A) = H(a·R)          shared secret (A = a·G is the scan key)
//!   Ko  = H_s(t)·G + B             B = b·G is the recipient's spend key
//!   ko  = H_s(t) + b               known only to the holder of b
//! ```
//!
//! and spending requires a signature by `ko` (see `transaction.rs`). The
//! sender still learns the blinding factor, but that is no longer enough to
//! spend. A scan-only (view) wallet can find and value outputs but cannot
//! spend them.

use super::crypto::{
    commit, compress, decompress, hash_to_scalar, random_scalar, scalar_from_bytes, Point32,
};
use super::transaction::Output;
use crate::core::recovery::{recovery_commitment, recovery_salt};
use crate::core::types::hash_domain;
use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use zeroize::Zeroize;

const NONCE_LEN: usize = 24;
const PLAINTEXT_LEN: usize = 8 + 32;
const TAG_LEN: usize = 16;

/// Exact payload size. Fixed so that every output is the same shape.
pub const PAYLOAD_LEN: usize = NONCE_LEN + PLAINTEXT_LEN + TAG_LEN;

const ADDRESS_HRP: bech32::Hrp = bech32::Hrp::parse_unchecked("mw");
/// v1: scan key, spend key and post-quantum recovery key.
const ADDRESS_VERSION: u8 = 1;
const ADDRESS_LEN: usize = 1 + 32 + 32 + 32;

// ── Addresses ───────────────────────────────────────────────────────────────

/// A recipient address: scan key `A` and spend key `B`.
///
/// Pluribit's address held only the scan key, which was all its (unsafe)
/// scheme needed. The spend key must now be public so senders can derive
/// owner keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct StealthAddress {
    pub scan: Point32,
    pub spend: Point32,
    /// MSS master public key that can claim this address's outputs if the
    /// curve is ever broken (`core/recovery.rs`).
    pub recovery: [u8; 32],
}

impl StealthAddress {
    /// Bech32m, human-readable part `mw`, payload `version ‖ A ‖ B ‖ R`.
    pub fn encode(&self) -> String {
        let mut data = Vec::with_capacity(ADDRESS_LEN);
        data.push(ADDRESS_VERSION);
        data.extend_from_slice(&self.scan);
        data.extend_from_slice(&self.spend);
        data.extend_from_slice(&self.recovery);
        bech32::encode::<bech32::Bech32m>(ADDRESS_HRP, &data)
            .expect("a 97-byte payload is well within bech32m limits")
    }

    pub fn decode(s: &str) -> Result<Self> {
        let (hrp, data) = bech32::decode(s).map_err(|e| anyhow!("invalid address: {e}"))?;
        if hrp != ADDRESS_HRP {
            bail!("address must start with '{}1'", ADDRESS_HRP);
        }
        if data.len() != ADDRESS_LEN || data[0] != ADDRESS_VERSION {
            bail!("unsupported address version or length (v1 addresses carry a recovery key)");
        }
        let mut scan = [0u8; 32];
        let mut spend = [0u8; 32];
        let mut recovery = [0u8; 32];
        scan.copy_from_slice(&data[1..33]);
        spend.copy_from_slice(&data[33..65]);
        recovery.copy_from_slice(&data[65..97]);
        let addr = Self {
            scan,
            spend,
            recovery,
        };
        addr.points()?;
        Ok(addr)
    }

    pub(crate) fn points(&self) -> Result<(RistrettoPoint, RistrettoPoint)> {
        let scan = decompress(&self.scan).ok_or_else(|| anyhow!("invalid scan key"))?;
        let spend = decompress(&self.spend).ok_or_else(|| anyhow!("invalid spend key"))?;
        if scan.is_identity() || spend.is_identity() {
            bail!("address keys must not be the identity");
        }
        Ok((scan, spend))
    }
}

impl std::fmt::Display for StealthAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.encode())
    }
}

// ── Wallet keys ─────────────────────────────────────────────────────────────

/// Scan (`a`) and spend (`b`) secrets. Zeroized on drop.
#[derive(Clone)]
pub struct WalletKeys {
    scan_secret: Scalar,
    spend_secret: Scalar,
    /// MSS master public key (derived from the seed by
    /// `recovery::derive_recovery_keypair`, which is expensive, so wallets
    /// store it).
    recovery_key: [u8; 32],
}

impl WalletKeys {
    /// Domain-separated derivation from a BIP39 seed (pluribit derived both
    /// keys from the seed the same way, but reduced a 32-byte hash).
    /// Keys from a seed plus that seed's recovery root.
    pub fn from_seed(seed: &[u8], recovery_key: [u8; 32]) -> Self {
        Self {
            scan_secret: hash_to_scalar(b"midwimble.wallet.scan.v1", &[seed]),
            spend_secret: hash_to_scalar(b"midwimble.wallet.spend.v1", &[seed]),
            recovery_key,
        }
    }

    /// Random curve keys with a random (unusable) recovery key. For tests and
    /// tools that never need recovery.
    pub fn random() -> Self {
        Self {
            scan_secret: random_scalar(),
            spend_secret: random_scalar(),
            recovery_key: rand::random(),
        }
    }

    /// Random curve keys with a given recovery key.
    pub fn random_with_recovery(recovery_key: [u8; 32]) -> Self {
        Self {
            scan_secret: random_scalar(),
            spend_secret: random_scalar(),
            recovery_key,
        }
    }

    pub fn recovery_key(&self) -> [u8; 32] {
        self.recovery_key
    }

    pub fn address(&self) -> StealthAddress {
        StealthAddress {
            scan: compress(&RistrettoPoint::mul_base(&self.scan_secret)),
            spend: compress(&RistrettoPoint::mul_base(&self.spend_secret)),
            recovery: self.recovery_key,
        }
    }

    /// A watch-only view: can detect and value outputs, cannot spend them.
    pub fn view_only(&self) -> ViewKey {
        ViewKey {
            scan_secret: self.scan_secret,
            address: self.address(),
        }
    }
}

impl Drop for WalletKeys {
    fn drop(&mut self) {
        self.scan_secret.zeroize();
        self.spend_secret.zeroize();
    }
}

/// Scan secret plus public spend key.
#[derive(Clone)]
pub struct ViewKey {
    scan_secret: Scalar,
    address: StealthAddress,
}

impl Drop for ViewKey {
    fn drop(&mut self) {
        self.scan_secret.zeroize();
    }
}

// ── Output creation ─────────────────────────────────────────────────────────

/// A freshly created output together with the opening its creator knows.
pub struct NewOutput {
    pub output: Output,
    pub value: u64,
    pub blinding: Scalar,
    /// The sender's ephemeral secret `r`; with it anyone can check what the
    /// output pays to whom (see [`PayoutReceipt`]).
    pub ephemeral_secret: Scalar,
}

/// A sender's proof that `output` pays `value` to an address, checkable with
/// public data only. Pools hand these to miners so they can audit their share
/// of a coinbase before hashing on it. It reveals the output's opening, which
/// its recipient learns anyway; it grants no spending power (that needs the
/// recipient's spend key).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PayoutReceipt {
    pub output_index: usize,
    pub value: u64,
    pub blinding: [u8; 32],
    pub ephemeral_secret: [u8; 32],
}

impl PayoutReceipt {
    /// True iff `output` is spendable by `to` and commits to `self.value`.
    pub fn verify(&self, to: &StealthAddress, output: &Output) -> bool {
        let (Ok((scan, spend)), Some(r), Some(blinding)) = (
            to.points(),
            scalar_from_bytes(&self.ephemeral_secret),
            scalar_from_bytes(&self.blinding),
        ) else {
            return false;
        };
        if compress(&RistrettoPoint::mul_base(&r)) != output.ephemeral_key {
            return false;
        }
        let t = shared_secret(&(r * scan));
        let owner = RistrettoPoint::mul_base(&owner_tweak(&t)) + spend;
        compress(&owner) == output.owner_key
            && compress(&commit(self.value, &blinding)) == output.commitment
            && view_tag(&t) == output.view_tag
            && output.recovery_commitment
                == recovery_commitment(&to.recovery, self.value, &self.blinding, &recovery_salt(&t))
    }
}

/// Creates a stealth output paying `value` to `to`.
pub fn new_output(to: &StealthAddress, value: u64) -> Result<NewOutput> {
    let (scan, spend) = to.points()?;
    // A fresh ephemeral key per output gives every output its own shared
    // secret, so two outputs to the same address never share an owner key.
    let r = random_scalar();
    let ephemeral = RistrettoPoint::mul_base(&r);
    let t = shared_secret(&(r * scan));
    let owner_key = RistrettoPoint::mul_base(&owner_tweak(&t)) + spend;
    let blinding = random_scalar();
    let salt = recovery_salt(&t);

    let output = Output {
        commitment: compress(&commit(value, &blinding)),
        owner_key: compress(&owner_key),
        ephemeral_key: compress(&ephemeral),
        view_tag: view_tag(&t),
        payload: seal_payload(&t, value, &blinding),
        recovery_commitment: recovery_commitment(&to.recovery, value, &blinding.to_bytes(), &salt),
    };
    Ok(NewOutput {
        output,
        value,
        blinding,
        ephemeral_secret: r,
    })
}

// ── Output scanning ─────────────────────────────────────────────────────────

/// What a wallet learns about one of its outputs.
#[derive(Clone)]
pub struct OwnedOutput {
    pub value: u64,
    pub blinding: Scalar,
    /// `ko`: signs inputs spending this output.
    pub owner_secret: Scalar,
    /// Salt of the output's recovery commitment (needed to claim it).
    pub recovery_salt: [u8; 32],
    /// Whether the sender built the recovery commitment correctly. A wallet
    /// should move funds out of outputs where this is false: they could not
    /// be claimed in a recovery epoch.
    pub recovery_ok: bool,
}

impl Drop for OwnedOutput {
    fn drop(&mut self) {
        self.blinding.zeroize();
        self.owner_secret.zeroize();
    }
}

/// Recognises and opens an output addressed to `keys`.
///
/// Returns `None` unless the view tag matches, the payload decrypts, the
/// decrypted opening reproduces the on-chain commitment, **and** the owner key
/// is one we can sign for. The last check matters: without it a sender could
/// pay us an output whose owner key belongs to someone else, which we would
/// count in our balance but never be able to spend.
pub fn scan_output(keys: &WalletKeys, output: &Output) -> Option<OwnedOutput> {
    let address = keys.address();
    let (value, blinding, tweak, salt) = detect(&keys.scan_secret, &address.spend, output)?;
    let owner_secret = tweak + keys.spend_secret;
    if compress(&RistrettoPoint::mul_base(&owner_secret)) != output.owner_key {
        return None;
    }
    let recovery_ok = output.recovery_commitment
        == recovery_commitment(&address.recovery, value, &blinding.to_bytes(), &salt);
    Some(OwnedOutput {
        value,
        blinding,
        owner_secret,
        recovery_salt: salt,
        recovery_ok,
    })
}

/// Watch-only scan: the value of outputs addressed to this view key.
pub fn scan_output_view_only(view: &ViewKey, output: &Output) -> Option<u64> {
    detect(&view.scan_secret, &view.address.spend, output).map(|(v, _, _, _)| v)
}

fn detect(
    scan_secret: &Scalar,
    spend_public: &Point32,
    output: &Output,
) -> Option<(u64, Scalar, Scalar, [u8; 32])> {
    let ephemeral = decompress(&output.ephemeral_key)?;
    let t = shared_secret(&(scan_secret * ephemeral));
    if view_tag(&t) != output.view_tag {
        return None;
    }
    let (value, blinding) = open_payload(&t, &output.payload)?;
    if compress(&commit(value, &blinding)) != output.commitment {
        return None;
    }
    let tweak = owner_tweak(&t);
    let expected_owner = RistrettoPoint::mul_base(&tweak) + decompress(spend_public)?;
    if compress(&expected_owner) != output.owner_key {
        return None;
    }
    Some((value, blinding, tweak, recovery_salt(&t)))
}

// ── Derivations ─────────────────────────────────────────────────────────────

fn shared_secret(point: &RistrettoPoint) -> [u8; 32] {
    hash_domain(b"midwimble.stealth.shared.v1", &[&compress(point)])
}

fn owner_tweak(t: &[u8; 32]) -> Scalar {
    hash_to_scalar(b"midwimble.stealth.owner.v1", &[t])
}

/// Pluribit's view tag: the first byte of a hash of the shared secret. Lets a
/// wallet discard 255/256 of foreign outputs before attempting decryption.
fn view_tag(t: &[u8; 32]) -> u8 {
    hash_domain(b"midwimble.stealth.view-tag.v1", &[t])[0]
}

fn payload_cipher(t: &[u8; 32]) -> XChaCha20Poly1305 {
    let mut key = hash_domain(b"midwimble.stealth.payload-key.v1", &[t]);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    key.zeroize();
    cipher
}

/// `nonce(24) ‖ AEAD(value_be(8) ‖ blinding(32))`, as in pluribit, but with
/// the key derived through a KDF rather than using the shared scalar's bytes.
fn seal_payload(t: &[u8; 32], value: u64, blinding: &Scalar) -> Vec<u8> {
    let nonce: [u8; NONCE_LEN] = rand::random();
    let mut plaintext = [0u8; PLAINTEXT_LEN];
    plaintext[..8].copy_from_slice(&value.to_be_bytes());
    plaintext[8..].copy_from_slice(blinding.as_bytes());
    let ciphertext = payload_cipher(t)
        .encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
        .expect("XChaCha20-Poly1305 encryption is infallible for this input size");
    plaintext.zeroize();

    let mut out = Vec::with_capacity(PAYLOAD_LEN);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    debug_assert_eq!(out.len(), PAYLOAD_LEN);
    out
}

fn open_payload(t: &[u8; 32], payload: &[u8]) -> Option<(u64, Scalar)> {
    if payload.len() != PAYLOAD_LEN {
        return None;
    }
    let (nonce, ciphertext) = payload.split_at(NONCE_LEN);
    let mut plaintext = payload_cipher(t)
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .ok()?;
    if plaintext.len() != PLAINTEXT_LEN {
        plaintext.zeroize();
        return None;
    }
    let value = u64::from_be_bytes(plaintext[..8].try_into().ok()?);
    let mut blind_bytes = [0u8; 32];
    blind_bytes.copy_from_slice(&plaintext[8..]);
    plaintext.zeroize();
    let blinding = scalar_from_bytes(&blind_bytes);
    blind_bytes.zeroize();
    Some((value, blinding?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_roundtrip() {
        let keys = WalletKeys::random();
        let addr = keys.address();
        let s = addr.encode();
        assert!(s.starts_with("mw1"), "{s}");
        assert_eq!(StealthAddress::decode(&s).unwrap(), addr);
        // Single-character corruption is caught by the checksum.
        let mut bad = s.clone().into_bytes();
        let i = bad.len() - 3;
        bad[i] = if bad[i] == b'q' { b'p' } else { b'q' };
        assert!(StealthAddress::decode(std::str::from_utf8(&bad).unwrap()).is_err());
    }

    #[test]
    fn recipient_finds_and_can_spend_output() {
        let bob = WalletKeys::random();
        let created = new_output(&bob.address(), 12_345).unwrap();
        let owned = scan_output(&bob, &created.output).expect("bob sees his output");
        assert_eq!(owned.value, 12_345);
        assert_eq!(owned.blinding, created.blinding);
        assert_eq!(
            compress(&RistrettoPoint::mul_base(&owned.owner_secret)),
            created.output.owner_key
        );
    }

    #[test]
    fn payout_receipts_prove_value_and_owner() {
        let bob = WalletKeys::random();
        let eve = WalletKeys::random();
        let created = new_output(&bob.address(), 500).unwrap();
        let receipt = PayoutReceipt {
            output_index: 0,
            value: 500,
            blinding: created.blinding.to_bytes(),
            ephemeral_secret: created.ephemeral_secret.to_bytes(),
        };
        assert!(receipt.verify(&bob.address(), &created.output));
        assert!(!receipt.verify(&eve.address(), &created.output));
        let mut lie = receipt.clone();
        lie.value = 501;
        assert!(!lie.verify(&bob.address(), &created.output));
    }

    #[test]
    fn recipient_detects_a_bad_recovery_commitment() {
        let bob = WalletKeys::random();
        let good = new_output(&bob.address(), 9).unwrap();
        assert!(scan_output(&bob, &good.output).unwrap().recovery_ok);
        // A sender who uses the wrong recovery key (or value) is caught.
        let mut wrong_key = bob.address();
        wrong_key.recovery = [0x42; 32];
        let bad = new_output(&wrong_key, 9).unwrap();
        let seen = scan_output(&bob, &bad.output).unwrap();
        assert_eq!(seen.value, 9);
        assert!(!seen.recovery_ok);
    }

    #[test]
    fn stranger_sees_nothing() {
        let bob = WalletKeys::random();
        let eve = WalletKeys::random();
        let created = new_output(&bob.address(), 1).unwrap();
        assert!(scan_output(&eve, &created.output).is_none());
    }

    #[test]
    fn view_key_values_but_cannot_derive_owner_secret() {
        let bob = WalletKeys::random();
        let view = bob.view_only();
        let created = new_output(&bob.address(), 77).unwrap();
        assert_eq!(scan_output_view_only(&view, &created.output), Some(77));
        // The view key alone never exposes b, so it cannot produce ko.
    }

    #[test]
    fn owner_key_redirect_is_rejected_by_scanner() {
        let bob = WalletKeys::random();
        let eve = WalletKeys::random();
        let mut created = new_output(&bob.address(), 5).unwrap();
        created.output.owner_key = eve.address().spend;
        assert!(scan_output(&bob, &created.output).is_none());
    }

    #[test]
    fn outputs_to_same_address_have_distinct_owner_keys() {
        let bob = WalletKeys::random();
        let a = new_output(&bob.address(), 1).unwrap();
        let b = new_output(&bob.address(), 1).unwrap();
        assert_ne!(a.output.owner_key, b.output.owner_key);
        assert_ne!(a.output.ephemeral_key, b.output.ephemeral_key);
    }

    #[test]
    fn tampered_payload_fails_to_open() {
        let bob = WalletKeys::random();
        let mut created = new_output(&bob.address(), 9).unwrap();
        created.output.payload[30] ^= 1;
        assert!(scan_output(&bob, &created.output).is_none());
    }
}
