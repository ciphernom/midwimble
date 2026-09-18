//! Dormant post-quantum recovery (`docs/ANCHORING.md` §5–6).
//!
//! Every output carries
//!
//! ```text
//!   rc = H("midwimble.recovery.v1", NETWORK_MAGIC, R, value, blinding, salt)
//! ```
//!
//! where `R` is the recipient's MSS master public key (Midstate's hash-based
//! Merkle signature scheme) and `salt` comes from the stealth shared secret.
//!
//! In a recovery epoch, which a future hard fork activates at an anchored
//! checkpoint, elliptic-curve ownership is switched off, and an output can
//! only be claimed by:
//!
//! * proving its UTXO leaf (which commits to `rc`) is in the checkpoint;
//! * revealing `value`, `blinding` and `salt` that hash to `rc`, and that
//!   still open the Pedersen commitment. Because `rc` was fixed while the
//!   commitment was binding, this freezes the one true opening even after
//!   binding is gone;
//! * signing the claim with `R`'s MSS key, with each MSS leaf used once.
//!
//! Nothing here consults a Schnorr signature, an owner key or an ECDH value.

use super::anchor::Checkpoint;
use super::mmr::{verify_utxo_proof, UtxoProof};
use super::mss::{self, MssKeypair, MssSignature};
use super::mw::crypto::{compress, gen_g, gen_h, scalar_from_bytes, Point32, Scalar32};
use super::types::{hash_domain, utxo_leaf, State, StateRootParts, UtxoEntry, NETWORK_MAGIC};
use anyhow::{anyhow, bail, Result};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Default MSS height for wallet recovery keys: 1,024 claims, each of which
/// may cover many outputs.
pub const DEFAULT_RECOVERY_HEIGHT: u32 = 10;

/// Per-output salt, known to sender and recipient only (until a break).
pub fn recovery_salt(shared_secret: &[u8; 32]) -> [u8; 32] {
    hash_domain(b"midwimble.recovery.salt.v1", &[shared_secret])
}

pub fn recovery_commitment(
    recovery_key: &[u8; 32],
    value: u64,
    blinding: &Scalar32,
    salt: &[u8; 32],
) -> [u8; 32] {
    hash_domain(
        b"midwimble.recovery.v1",
        &[
            NETWORK_MAGIC,
            recovery_key,
            &value.to_le_bytes(),
            blinding,
            salt,
        ],
    )
}

/// The wallet's recovery key pair. Expensive (2^height WOTS key
/// generations); wallets store the public key and regenerate the pair only
/// if a recovery epoch ever happens.
pub fn derive_recovery_keypair(seed: &[u8], height: u32) -> Result<MssKeypair> {
    let mss_seed = hash_domain(b"midwimble.wallet.recovery.v1", &[seed]);
    mss::keygen(&mss_seed, height)
}

/// The Pedersen generators recovery checks openings against. Always
/// [`Generators::standard`] in consensus; tests substitute generators with a
/// known discrete-log relation to model a broken curve.
#[derive(Clone, Copy, Debug)]
pub struct Generators {
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
}

impl Generators {
    pub fn standard() -> Self {
        Self {
            g: gen_g(),
            h: gen_h(),
        }
    }

    pub fn commit(&self, value: u64, blinding: &Scalar) -> Point32 {
        compress(&(Scalar::from(value) * self.g + blinding * self.h))
    }
}

/// One output being claimed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimedOutput {
    pub commitment: Point32,
    pub entry: UtxoEntry,
    pub value: u64,
    pub blinding: Scalar32,
    pub salt: [u8; 32],
    /// Membership of `utxo_leaf(commitment, entry)` in the checkpoint's UTXO root.
    pub proof: UtxoProof,
}

impl ClaimedOutput {
    /// Builds the claim data for an output of `state` (the checkpoint state).
    pub fn from_state(
        state: &State,
        commitment: Point32,
        value: u64,
        blinding: Scalar32,
        salt: [u8; 32],
    ) -> Result<Self> {
        let entry = *state
            .utxos
            .get(&commitment)
            .ok_or_else(|| anyhow!("output not in the checkpoint state"))?;
        let proof = state
            .utxo_set
            .prove(&utxo_leaf(&commitment, &entry), true)?;
        Ok(Self {
            commitment,
            entry,
            value,
            blinding,
            salt,
            proof,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryClaim {
    pub checkpoint_id: [u8; 32],
    pub recovery_key: [u8; 32],
    pub outputs: Vec<ClaimedOutput>,
    /// Post-quantum destination for the recovered value (for example a
    /// Midstate address or a fresh MSS key).
    pub destination: [u8; 32],
    pub signature: MssSignature,
}

pub fn claim_digest(
    checkpoint_id: &[u8; 32],
    recovery_key: &[u8; 32],
    destination: &[u8; 32],
    outputs: &[ClaimedOutput],
) -> [u8; 32] {
    let values: Vec<[u8; 8]> = outputs.iter().map(|o| o.value.to_le_bytes()).collect();
    let mut parts: Vec<&[u8]> = vec![NETWORK_MAGIC, checkpoint_id, recovery_key, destination];
    for (o, v) in outputs.iter().zip(&values) {
        parts.push(&o.commitment);
        parts.push(v);
    }
    hash_domain(b"midwimble.recovery-claim.v1", &parts)
}

impl RecoveryClaim {
    /// Signs a claim with the wallet's recovery key (consumes one MSS leaf).
    pub fn build(
        key: &mut MssKeypair,
        checkpoint_id: [u8; 32],
        outputs: Vec<ClaimedOutput>,
        destination: [u8; 32],
    ) -> Result<Self> {
        let recovery_key = key.public_key();
        let digest = claim_digest(&checkpoint_id, &recovery_key, &destination, &outputs);
        let signature = key.sign(&digest)?;
        Ok(Self {
            checkpoint_id,
            recovery_key,
            outputs,
            destination,
            signature,
        })
    }

    pub fn digest(&self) -> [u8; 32] {
        claim_digest(
            &self.checkpoint_id,
            &self.recovery_key,
            &self.destination,
            &self.outputs,
        )
    }
}

/// The recovery epoch's state: which outputs and MSS leaves are spent, and
/// what has been credited to whom.
pub struct RecoveryState {
    pub checkpoint: Checkpoint,
    pub parts: StateRootParts,
    gens: Generators,
    claimed: HashSet<Point32>,
    used_leaves: HashSet<([u8; 32], u64)>,
    pub total_claimed: u64,
    pub credited: Vec<([u8; 32], u64)>,
}

impl RecoveryState {
    /// Starts recovery from an anchored checkpoint. `parts` must hash to the
    /// checkpoint's state root; they supply the UTXO root and the supply cap.
    pub fn activate(
        checkpoint: Checkpoint,
        parts: StateRootParts,
        gens: Generators,
    ) -> Result<Self> {
        if parts.root() != checkpoint.mw_state_root {
            bail!("state-root parts do not match the checkpoint");
        }
        Ok(Self {
            checkpoint,
            parts,
            gens,
            claimed: HashSet::new(),
            used_leaves: HashSet::new(),
            total_claimed: 0,
            credited: Vec::new(),
        })
    }

    pub fn is_claimed(&self, commitment: &Point32) -> bool {
        self.claimed.contains(commitment)
    }

    /// Validates and applies a claim, returning the value credited. On error
    /// nothing changes.
    pub fn apply(&mut self, claim: &RecoveryClaim) -> Result<u64> {
        if claim.checkpoint_id != self.checkpoint.id() {
            bail!("claim is for a different checkpoint");
        }
        if claim.outputs.is_empty() {
            bail!("claim has no outputs");
        }
        if self
            .used_leaves
            .contains(&(claim.recovery_key, claim.signature.leaf_index))
        {
            bail!(
                "recovery key leaf {} was already used",
                claim.signature.leaf_index
            );
        }
        let mut seen = HashSet::new();
        let mut total = 0u64;
        for o in &claim.outputs {
            if !seen.insert(o.commitment) || self.claimed.contains(&o.commitment) {
                bail!("output {} is already claimed", hex::encode(o.commitment));
            }
            let leaf = utxo_leaf(&o.commitment, &o.entry);
            if !verify_utxo_proof(&leaf, &o.proof, &self.parts.utxo_root, true) {
                bail!(
                    "output {} is not in the checkpoint's UTXO set",
                    hex::encode(o.commitment)
                );
            }
            if o.entry.recovery_commitment
                != recovery_commitment(&claim.recovery_key, o.value, &o.blinding, &o.salt)
            {
                bail!(
                    "recovery commitment mismatch for output {}",
                    hex::encode(o.commitment)
                );
            }
            let blinding =
                scalar_from_bytes(&o.blinding).ok_or_else(|| anyhow!("non-canonical blinding"))?;
            if self.gens.commit(o.value, &blinding) != o.commitment {
                bail!(
                    "revealed opening does not match output {}",
                    hex::encode(o.commitment)
                );
            }
            total = total
                .checked_add(o.value)
                .ok_or_else(|| anyhow!("value overflow"))?;
        }
        let new_total = self
            .total_claimed
            .checked_add(total)
            .ok_or_else(|| anyhow!("value overflow"))?;
        if new_total > self.parts.supply {
            bail!("claims would exceed the checkpoint's supply");
        }
        if !mss::verify(&claim.signature, &claim.digest(), &claim.recovery_key) {
            bail!("invalid recovery signature");
        }
        self.used_leaves
            .insert((claim.recovery_key, claim.signature.leaf_index));
        for o in &claim.outputs {
            self.claimed.insert(o.commitment);
        }
        self.total_claimed = new_total;
        self.credited.push((claim.destination, total));
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_binds_every_field() {
        let base = recovery_commitment(&[1; 32], 5, &[2; 32], &[3; 32]);
        assert_ne!(base, recovery_commitment(&[9; 32], 5, &[2; 32], &[3; 32]));
        assert_ne!(base, recovery_commitment(&[1; 32], 6, &[2; 32], &[3; 32]));
        assert_ne!(base, recovery_commitment(&[1; 32], 5, &[9; 32], &[3; 32]));
        assert_ne!(base, recovery_commitment(&[1; 32], 5, &[2; 32], &[9; 32]));
    }

    #[test]
    fn recovery_keys_sign_and_verify() {
        let mut kp = derive_recovery_keypair(b"seed", 1).unwrap();
        let again = derive_recovery_keypair(b"seed", 1).unwrap();
        assert_eq!(kp.public_key(), again.public_key());
        assert_ne!(
            kp.public_key(),
            derive_recovery_keypair(b"other", 1).unwrap().public_key()
        );
        let sig = kp.sign(&[7; 32]).unwrap();
        assert!(mss::verify(&sig, &[7; 32], &kp.public_key()));
        assert!(!mss::verify(&sig, &[8; 32], &kp.public_key()));
    }
}
