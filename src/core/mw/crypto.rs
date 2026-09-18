//! MimbleWimble cryptographic primitives on Ristretto255.
//!
//! # Provenance
//!
//! Ported from pluribit `src/mimblewimble.rs`: Pedersen commitments over the
//! `bulletproofs` generators, aggregated Bulletproof range proofs, and
//! `(e, s)`-form Schnorr signatures. Changes from the original, each of which
//! closes a concrete problem found in review:
//!
//! 1. **Key-prefixed challenges.** Pluribit hashed `R ‖ m` only. Without the
//!    public key in the challenge, a signature `(e, s)` for `P` converts into a
//!    valid signature `(e, s + e·k)` for `P + k·H` on the same message, which
//!    makes kernels malleable. Every challenge here hashes the public key(s).
//! 2. **Hedged nonces.** `k = H(secret ‖ msg ‖ 32 random bytes)` instead of a
//!    bare RNG draw, so a weak RNG cannot leak a key through nonce reuse.
//! 3. **Wide scalar reduction.** 64-byte BLAKE3 XOF output reduced mod ℓ,
//!    instead of reducing a 32-byte hash (slightly biased).
//! 4. **Power-of-two padding.** `RangeProof::prove_multiple` only accepts
//!    power-of-two batch sizes; pluribit would fail on a 3-output transaction.
//!    Groups are padded with zero commitments that both prover and verifier
//!    reconstruct locally.
//! 5. **Transcript binding.** Each range proof's Merlin transcript absorbs a
//!    hash of the non-commitment output fields (owner key, ephemeral key, view
//!    tag, payload). Changing any of them invalidates the proof, and producing
//!    a new proof requires the openings, so a relay cannot redirect an output
//!    to its own owner key. This leans on Bulletproofs being
//!    simulation-extractable (Dao & Grubbs, Eurocrypt 2023). If you prefer not
//!    to rely on that result, add an explicit sender signature per group.
//! 6. **Two-excess kernel proof** ([`kernel_sign`]), needed by the ownership
//!    fix; see `mw/mod.rs`.
//!
//! # Generators
//!
//! `G` is the Ristretto basepoint (also the value generator `PedersenGens::B`)
//! and is used for wallet keys, owner keys and owner excesses. `H` is
//! `PedersenGens::B_blinding` and is used for blinding factors and the
//! Pedersen kernel excess. A commitment is `C = v·G + r·H`.

use crate::core::types::hash_domain;
use anyhow::{bail, Result};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, IsIdentity, VartimeMultiscalarMul};
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Bit width of every committed value.
pub const RANGE_BITS: usize = 64;

/// Largest number of outputs one aggregated range proof may cover.
/// Also the party capacity of the shared [`BulletproofGens`].
pub const MAX_GROUP_OUTPUTS: usize = 32;

const RANGE_PROOF_LABEL: &[u8] = b"midwimble.range-proof.v1";
const SCHNORR_CHALLENGE: &[u8] = b"midwimble.schnorr.challenge.v1";
const SCHNORR_NONCE: &[u8] = b"midwimble.schnorr.nonce.v1";
const KERNEL_CHALLENGE: &[u8] = b"midwimble.kernel.challenge.v1";
const KERNEL_NONCE: &[u8] = b"midwimble.kernel.nonce.v1";

/// A compressed Ristretto point.
pub type Point32 = [u8; 32];
/// A canonically encoded scalar.
pub type Scalar32 = [u8; 32];

/// The encoding of the Ristretto identity point.
pub const IDENTITY: Point32 = [0u8; 32];

// ── Generators ──────────────────────────────────────────────────────────────

pub fn pc_gens() -> &'static PedersenGens {
    static GENS: OnceLock<PedersenGens> = OnceLock::new();
    GENS.get_or_init(PedersenGens::default)
}

pub fn bp_gens() -> &'static BulletproofGens {
    static GENS: OnceLock<BulletproofGens> = OnceLock::new();
    GENS.get_or_init(|| BulletproofGens::new(RANGE_BITS, MAX_GROUP_OUTPUTS))
}

/// Value / key generator (the Ristretto basepoint).
pub fn gen_g() -> RistrettoPoint {
    pc_gens().B
}

/// Blinding generator.
pub fn gen_h() -> RistrettoPoint {
    pc_gens().B_blinding
}

// ── Encoding helpers ────────────────────────────────────────────────────────

pub fn decompress(bytes: &Point32) -> Option<RistrettoPoint> {
    CompressedRistretto(*bytes).decompress()
}

pub fn compress(point: &RistrettoPoint) -> Point32 {
    point.compress().to_bytes()
}

/// Parses a scalar, rejecting non-canonical encodings (which would otherwise
/// give one value several byte representations and make hashes malleable).
pub fn scalar_from_bytes(bytes: &Scalar32) -> Option<Scalar> {
    Option::from(Scalar::from_canonical_bytes(*bytes))
}

/// Domain-separated, length-prefixed hash to a uniformly distributed scalar.
pub fn hash_to_scalar(domain: &[u8], parts: &[&[u8]]) -> Scalar {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    let mut wide = [0u8; 64];
    hasher.finalize_xof().fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

pub fn random_scalar() -> Scalar {
    let mut wide = [0u8; 64];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

// ── Pedersen commitments ────────────────────────────────────────────────────

pub fn commit(value: u64, blinding: &Scalar) -> RistrettoPoint {
    pc_gens().commit(Scalar::from(value), *blinding)
}

/// Sums a list of compressed points, failing on any invalid encoding.
pub fn sum_points<'a>(points: impl IntoIterator<Item = &'a Point32>) -> Result<RistrettoPoint> {
    let mut acc = RistrettoPoint::identity();
    for p in points {
        match decompress(p) {
            Some(pt) => acc += pt,
            None => bail!("invalid point encoding {}", hex::encode(p)),
        }
    }
    Ok(acc)
}

// ── Aggregated range proofs ─────────────────────────────────────────────────

/// Serialized length of an aggregated proof over `n` values (after padding).
///
/// A dalek Bulletproof over `m = n.next_power_of_two()` 64-bit values holds
/// four points, three scalars and two inner-product vectors of `log2(64·m)`
/// points each: `(9 + 2·log2(64·m)) · 32` bytes. For one value that is 672.
pub fn range_proof_len(n: usize) -> usize {
    let m = n.max(1).next_power_of_two();
    let rounds = (RANGE_BITS * m).trailing_zeros() as usize;
    (9 + 2 * rounds) * 32
}

fn range_transcript(real_count: usize, binding: &[u8; 32]) -> Transcript {
    let mut t = Transcript::new(RANGE_PROOF_LABEL);
    t.append_u64(b"outputs", real_count as u64);
    t.append_message(b"binding", binding);
    t
}

/// Proves that every `values[i]` lies in `[0, 2^64)` for the commitments
/// `values[i]·G + blindings[i]·H`, bound to `binding`.
pub fn prove_range(values: &[u64], blindings: &[Scalar], binding: &[u8; 32]) -> Result<Vec<u8>> {
    let n = values.len();
    if n == 0 || n > MAX_GROUP_OUTPUTS {
        bail!(
            "range proof must cover 1..={} values, got {}",
            MAX_GROUP_OUTPUTS,
            n
        );
    }
    if blindings.len() != n {
        bail!("{} values but {} blindings", n, blindings.len());
    }
    let m = n.next_power_of_two();
    let mut padded_values = values.to_vec();
    let mut padded_blindings = blindings.to_vec();
    padded_values.resize(m, 0);
    padded_blindings.resize(m, Scalar::ZERO);

    let mut transcript = range_transcript(n, binding);
    let (proof, _commitments) = RangeProof::prove_multiple(
        bp_gens(),
        pc_gens(),
        &mut transcript,
        &padded_values,
        &padded_blindings,
        RANGE_BITS,
    )
    .map_err(|e| anyhow::anyhow!("range proof generation failed: {:?}", e))?;
    Ok(proof.to_bytes())
}

/// Verifies a proof produced by [`prove_range`].
pub fn verify_range(proof_bytes: &[u8], commitments: &[Point32], binding: &[u8; 32]) -> bool {
    let n = commitments.len();
    if n == 0 || n > MAX_GROUP_OUTPUTS || proof_bytes.len() != range_proof_len(n) {
        return false;
    }
    let proof = match RangeProof::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let m = n.next_power_of_two();
    let mut padded: Vec<CompressedRistretto> = commitments
        .iter()
        .map(|c| CompressedRistretto(*c))
        .collect();
    // Zero-value, zero-blinding padding: the identity point. Reconstructed by
    // the verifier, never read from the wire.
    padded.resize(m, CompressedRistretto(IDENTITY));

    let mut transcript = range_transcript(n, binding);
    proof
        .verify_multiple(bp_gens(), pc_gens(), &mut transcript, &padded, RANGE_BITS)
        .is_ok()
}

// ── Schnorr signatures (single key on G) ────────────────────────────────────

/// `(e, s)`-form Schnorr signature, as in pluribit, with a key-prefixed
/// challenge `e = H(P ‖ R ‖ m)` and `R = s·G − e·P`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SchnorrSig {
    pub e: Scalar32,
    pub s: Scalar32,
}

pub fn schnorr_sign(secret: &Scalar, msg: &[u8; 32]) -> SchnorrSig {
    let public = RistrettoPoint::mul_base(secret).compress().to_bytes();
    let aux: [u8; 32] = rand::random();
    let k = hash_to_scalar(SCHNORR_NONCE, &[secret.as_bytes(), &public, msg, &aux]);
    let r = RistrettoPoint::mul_base(&k).compress().to_bytes();
    let e = hash_to_scalar(SCHNORR_CHALLENGE, &[&public, &r, msg]);
    let s = k + e * secret;
    SchnorrSig {
        e: e.to_bytes(),
        s: s.to_bytes(),
    }
}

pub fn schnorr_verify(public: &Point32, msg: &[u8; 32], sig: &SchnorrSig) -> bool {
    let p = match decompress(public) {
        Some(p) if !p.is_identity() => p,
        _ => return false,
    };
    let (e, s) = match (scalar_from_bytes(&sig.e), scalar_from_bytes(&sig.s)) {
        (Some(e), Some(s)) => (e, s),
        _ => return false,
    };
    // R' = s·G − e·P
    let r = RistrettoPoint::vartime_double_scalar_mul_basepoint(&(-e), &p, &s);
    let expected = hash_to_scalar(SCHNORR_CHALLENGE, &[public, &r.compress().to_bytes(), msg]);
    expected == e
}

// ── Kernel proof: knowledge of both excess keys ─────────────────────────────

/// Proof of knowledge of `e` with `E = e·H` **and** `e'` with `E' = e'·G`,
/// bound to a kernel message.
///
/// AND-composition of two Schnorr proofs sharing one challenge, each with its
/// own nonce commitment:
///
/// ```text
///   R1 = k1·H,  R2 = k2·G
///   c  = Hash(E ‖ E' ‖ R1 ‖ R2 ‖ m)
///   s1 = k1 + c·e,  s2 = k2 + c·e'
/// verify:
///   R1 = s1·H − c·E,  R2 = s2·G − c·E',  c =? Hash(E ‖ E' ‖ R1 ‖ R2 ‖ m)
/// ```
///
/// Keeping `R1` and `R2` separate matters. A single combined commitment
/// `R = k1·H + k2·G` would only prove knowledge of *some* representation of
/// `E + E'`, which an attacker can satisfy while knowing neither discrete log.
/// With separate commitments, two accepting transcripts with the same
/// `(R1, R2)` yield `e` and `e'` individually.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct KernelSig {
    pub c: Scalar32,
    pub s1: Scalar32,
    pub s2: Scalar32,
}

pub fn kernel_sign(
    excess_secret: &Scalar,
    owner_secret: &Scalar,
    excess: &Point32,
    owner_excess: &Point32,
    msg: &[u8; 32],
) -> KernelSig {
    let aux: [u8; 32] = rand::random();
    let k1 = hash_to_scalar(
        KERNEL_NONCE,
        &[
            b"H",
            excess_secret.as_bytes(),
            owner_secret.as_bytes(),
            msg,
            &aux,
        ],
    );
    let k2 = hash_to_scalar(
        KERNEL_NONCE,
        &[
            b"G",
            excess_secret.as_bytes(),
            owner_secret.as_bytes(),
            msg,
            &aux,
        ],
    );
    let r1 = compress(&(k1 * gen_h()));
    let r2 = compress(&RistrettoPoint::mul_base(&k2));
    let c = hash_to_scalar(KERNEL_CHALLENGE, &[excess, owner_excess, &r1, &r2, msg]);
    KernelSig {
        c: c.to_bytes(),
        s1: (k1 + c * excess_secret).to_bytes(),
        s2: (k2 + c * owner_secret).to_bytes(),
    }
}

pub fn kernel_verify(
    excess: &Point32,
    owner_excess: &Point32,
    msg: &[u8; 32],
    sig: &KernelSig,
) -> bool {
    let (e_pt, o_pt) = match (decompress(excess), decompress(owner_excess)) {
        (Some(a), Some(b)) => (a, b),
        _ => return false,
    };
    let (c, s1, s2) = match (
        scalar_from_bytes(&sig.c),
        scalar_from_bytes(&sig.s1),
        scalar_from_bytes(&sig.s2),
    ) {
        (Some(c), Some(s1), Some(s2)) => (c, s1, s2),
        _ => return false,
    };
    let r1 = RistrettoPoint::vartime_multiscalar_mul([s1, -c], [gen_h(), e_pt]);
    let r2 = RistrettoPoint::vartime_double_scalar_mul_basepoint(&(-c), &o_pt, &s2);
    let expected = hash_to_scalar(
        KERNEL_CHALLENGE,
        &[excess, owner_excess, &compress(&r1), &compress(&r2), msg],
    );
    expected == c
}

/// Hash used as a binding key for anything that is not itself a point/scalar.
pub fn binding_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    hash_domain(domain, parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_generator_is_the_basepoint() {
        assert_eq!(
            gen_g(),
            curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT
        );
        assert_ne!(gen_g(), gen_h());
    }

    #[test]
    fn range_proof_roundtrip_with_padding() {
        for n in [1usize, 2, 3, 5, 8] {
            let values: Vec<u64> = (0..n as u64).map(|i| 1000 + i).collect();
            let blindings: Vec<Scalar> = (0..n).map(|_| random_scalar()).collect();
            let commitments: Vec<Point32> = values
                .iter()
                .zip(&blindings)
                .map(|(v, b)| compress(&commit(*v, b)))
                .collect();
            let binding = [7u8; 32];
            let proof = prove_range(&values, &blindings, &binding).unwrap();
            assert_eq!(proof.len(), range_proof_len(n), "n = {n}");
            assert!(verify_range(&proof, &commitments, &binding), "n = {n}");

            // Changing the bound metadata breaks the proof.
            assert!(!verify_range(&proof, &commitments, &[8u8; 32]));
            // Dropping a commitment breaks it.
            if n > 1 {
                assert!(!verify_range(&proof, &commitments[1..], &binding));
            }
        }
    }

    #[test]
    fn range_proof_len_matches_known_sizes() {
        assert_eq!(range_proof_len(1), 672);
        assert_eq!(range_proof_len(2), 736);
        assert_eq!(range_proof_len(3), 800);
        assert_eq!(range_proof_len(32), 992);
    }

    #[test]
    fn schnorr_roundtrip_and_key_binding() {
        let sk = random_scalar();
        let pk = compress(&RistrettoPoint::mul_base(&sk));
        let msg = [3u8; 32];
        let sig = schnorr_sign(&sk, &msg);
        assert!(schnorr_verify(&pk, &msg, &sig));
        assert!(!schnorr_verify(&pk, &[4u8; 32], &sig));

        // The pluribit malleation (s' = s + e·k for P' = P + k·G) must fail.
        let k = Scalar::from(5u64);
        let e = scalar_from_bytes(&sig.e).unwrap();
        let s = scalar_from_bytes(&sig.s).unwrap();
        let mauled = SchnorrSig {
            e: sig.e,
            s: (s + e * k).to_bytes(),
        };
        let pk2 = compress(&(decompress(&pk).unwrap() + RistrettoPoint::mul_base(&k)));
        assert!(!schnorr_verify(&pk2, &msg, &mauled));
    }

    #[test]
    fn schnorr_rejects_identity_key() {
        let s = random_scalar();
        let r = compress(&RistrettoPoint::mul_base(&s));
        let e = hash_to_scalar(SCHNORR_CHALLENGE, &[&IDENTITY, &r, &[0u8; 32]]);
        let sig = SchnorrSig {
            e: e.to_bytes(),
            s: s.to_bytes(),
        };
        assert!(!schnorr_verify(&IDENTITY, &[0u8; 32], &sig));
    }

    #[test]
    fn kernel_proof_roundtrip() {
        let e = random_scalar();
        let o = random_scalar();
        let ep = compress(&(e * gen_h()));
        let op = compress(&RistrettoPoint::mul_base(&o));
        let msg = [9u8; 32];
        let sig = kernel_sign(&e, &o, &ep, &op, &msg);
        assert!(kernel_verify(&ep, &op, &msg, &sig));
        assert!(!kernel_verify(&ep, &op, &[1u8; 32], &sig));
        // Swapping which excess sits on which generator must fail.
        let wrong = compress(&RistrettoPoint::mul_base(&e));
        assert!(!kernel_verify(&wrong, &op, &msg, &sig));
    }

    #[test]
    fn kernel_proof_with_zero_owner_excess() {
        let e = random_scalar();
        let ep = compress(&(e * gen_h()));
        let msg = [1u8; 32];
        let sig = kernel_sign(&e, &Scalar::ZERO, &ep, &IDENTITY, &msg);
        assert!(kernel_verify(&ep, &IDENTITY, &msg, &sig));
    }

    /// The combined-commitment variant that the separate `R1`/`R2` design
    /// avoids: with `R = k1·H + k2·G` an attacker who knows only a
    /// representation of `E + E'` could sign. Demonstrate that our verifier
    /// rejects such a forgery attempt.
    #[test]
    fn kernel_proof_requires_each_discrete_log() {
        // Attacker picks E' with unknown log and E = y·G − E'.
        let unknown = compress(&RistrettoPoint::mul_base(&random_scalar()));
        let y = random_scalar();
        let e_pt = RistrettoPoint::mul_base(&y) - decompress(&unknown).unwrap();
        let excess = compress(&e_pt);
        let msg = [2u8; 32];
        // Best effort: sign as if E + E' = y·G were all that mattered.
        let sig = kernel_sign(&Scalar::ZERO, &y, &excess, &unknown, &msg);
        assert!(!kernel_verify(&excess, &unknown, &msg, &sig));
    }
}
