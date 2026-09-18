//! MimbleWimble transactions.
//!
//! # Provenance
//!
//! Shape from pluribit `src/transaction.rs`: inputs referencing commitments,
//! outputs with stealth fields, one aggregated range proof per output set,
//! kernels carrying `fee` and `min_height`. Additions and why:
//!
//! * **Owner keys and input signatures** (the ownership fix, see
//!   `stealth.rs`).
//! * **Owner excess + owner offset.** A copied input signature must not be
//!   reusable in someone else's transaction. The *owner sum* forces whoever
//!   builds a transaction to know the owner secrets of everything it spends:
//!
//!   ```text
//!     Σ Ko(inputs) = Σ E'(kernels) + x·G
//!   ```
//!
//!   and every kernel proves knowledge of its `e'` (`crypto::kernel_sign`).
//!   A thief who knows a victim's blinding factor and copies the victim's
//!   input signature would need `Σ ko − x`, which they cannot compute. The
//!   random offset `x` keeps aggregated blocks from being split back into
//!   transactions by subset-sum on owner keys. Adapted from Litecoin MWEB's
//!   stealth excess, simplified to use the owner keys directly.
//! * **Kernel offset** `o` (Grin), for the same reason on the Pedersen side.
//!   Pluribit had none, so its aggregated blocks were trivially separable.
//! * **Canonical ordering and uniqueness** so aggregation is a merge and a
//!   block has exactly one serialization.
//! * Dropped the per-kernel wall-clock `timestamp`: it leaked timing
//!   information and made validity depend on the validator's clock.
//!
//! # Balance equations
//!
//! With `C = v·G + r·H`, kernel excess `E = e·H` and owner excess `E' = e'·G`:
//!
//! ```text
//!   Pedersen:  Σ C_out − Σ C_in + fee·G  =  Σ E + o·H
//!   Owner:     Σ Ko_in                   =  Σ E' + x·G
//! ```
//!
//! Both hold for a single transaction and, because they are linear, for any
//! aggregate of transactions with offsets added.

use super::crypto::{
    self, compress, decompress, gen_g, gen_h, kernel_sign, kernel_verify, prove_range,
    range_proof_len, scalar_from_bytes, schnorr_sign, schnorr_verify, sum_points, verify_range,
    KernelSig, Point32, Scalar32, SchnorrSig, IDENTITY, MAX_GROUP_OUTPUTS,
};
use super::stealth::PAYLOAD_LEN;
use crate::core::types::{
    hash_domain, INPUT_WEIGHT, KERNEL_WEIGHT, MAX_BLOCK_WEIGHT, MAX_TX_WEIGHT, NETWORK_MAGIC,
    OUTPUT_WEIGHT,
};
use anyhow::{anyhow, bail, Result};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Upper bound on a range proof's serialized size (32 outputs).
pub const MAX_RANGE_PROOF_LEN: usize = 992;

// ── Outputs ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Output {
    /// Pedersen commitment `v·G + r·H`.
    pub commitment: Point32,
    /// One-time owner key `Ko`; spending requires a signature by `ko`.
    pub owner_key: Point32,
    /// Sender's ephemeral ECDH key `R`.
    pub ephemeral_key: Point32,
    /// First byte of `H(shared secret)`, for fast wallet scanning.
    pub view_tag: u8,
    /// Encrypted `(value, blinding)`, exactly [`PAYLOAD_LEN`] bytes.
    pub payload: Vec<u8>,
    /// Dormant post-quantum claim on this output (`core/recovery.rs`):
    /// `H(R, value, blinding, salt)` for the recipient's recovery key `R`.
    pub recovery_commitment: [u8; 32],
}

impl Output {
    /// Hash of every field that the range proof does not bind by itself (the
    /// Bulletproof transcript already absorbs the commitment).
    pub fn metadata_hash(&self) -> [u8; 32] {
        hash_domain(
            b"midwimble.output.metadata.v1",
            &[
                &self.owner_key,
                &self.ephemeral_key,
                &[self.view_tag],
                &self.payload,
                &self.recovery_commitment,
            ],
        )
    }

    fn check_encoding(&self) -> Result<()> {
        match decompress(&self.commitment) {
            Some(p) if !p.is_identity() => {}
            _ => bail!("output commitment is not a valid non-identity point"),
        }
        match decompress(&self.owner_key) {
            Some(p) if !p.is_identity() => {}
            _ => bail!("output owner key is not a valid non-identity point"),
        }
        if decompress(&self.ephemeral_key).is_none() {
            bail!("output ephemeral key is not a valid point");
        }
        if self.payload.len() != PAYLOAD_LEN {
            bail!(
                "output payload must be {} bytes, got {}",
                PAYLOAD_LEN,
                self.payload.len()
            );
        }
        Ok(())
    }
}

/// Outputs created together, covered by one aggregated range proof
/// (pluribit's "V2 aggregated range proofs").
///
/// Trade-off inherited from that design: outputs in one group are visibly
/// linked (typically payment + change). Inputs and kernels are not linked to
/// groups once transactions are aggregated.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct OutputGroup {
    pub outputs: Vec<Output>,
    pub range_proof: Vec<u8>,
}

impl OutputGroup {
    /// Builds the group and proves it. `values`/`blindings` align with `outputs`.
    pub fn prove(outputs: Vec<Output>, values: &[u64], blindings: &[Scalar]) -> Result<Self> {
        if outputs.len() != values.len() {
            bail!("{} outputs but {} values", outputs.len(), values.len());
        }
        let binding = Self::binding_for(&outputs);
        let range_proof = prove_range(values, blindings, &binding)?;
        Ok(Self {
            outputs,
            range_proof,
        })
    }

    fn binding_for(outputs: &[Output]) -> [u8; 32] {
        let hashes: Vec<[u8; 32]> = outputs.iter().map(Output::metadata_hash).collect();
        Self::binding_for_hashes(&hashes)
    }

    /// The transcript binding, from members' metadata hashes alone (all a
    /// pruned group still has for its spent members).
    pub fn binding_for_hashes(hashes: &[[u8; 32]]) -> [u8; 32] {
        let count = (hashes.len() as u64).to_le_bytes();
        let mut parts: Vec<&[u8]> = Vec::with_capacity(hashes.len() + 2);
        parts.push(NETWORK_MAGIC);
        parts.push(&count);
        parts.extend(hashes.iter().map(|h| h.as_slice()));
        hash_domain(b"midwimble.output.group.v1", &parts)
    }

    pub fn commitments(&self) -> Vec<Point32> {
        self.outputs.iter().map(|o| o.commitment).collect()
    }

    pub fn sort_key(&self) -> Point32 {
        self.outputs
            .first()
            .map(|o| o.commitment)
            .unwrap_or(IDENTITY)
    }

    pub fn verify_range_proof(&self) -> bool {
        verify_range(
            &self.range_proof,
            &self.commitments(),
            &Self::binding_for(&self.outputs),
        )
    }

    fn check_structure(&self) -> Result<()> {
        let n = self.outputs.len();
        if n == 0 || n > MAX_GROUP_OUTPUTS {
            bail!(
                "output group must hold 1..={} outputs, got {}",
                MAX_GROUP_OUTPUTS,
                n
            );
        }
        if self.range_proof.len() != range_proof_len(n) {
            bail!(
                "range proof for {} outputs must be {} bytes",
                n,
                range_proof_len(n)
            );
        }
        for o in &self.outputs {
            o.check_encoding()?;
        }
        Ok(())
    }
}

/// A member of a stored output group (`docs/PRUNING.md` §2.1).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupMember {
    Unspent(Output),
    /// Spent: only what the group's range proof still needs.
    Spent {
        commitment: Point32,
        metadata_hash: [u8; 32],
    },
}

impl GroupMember {
    pub fn commitment(&self) -> Point32 {
        match self {
            GroupMember::Unspent(o) => o.commitment,
            GroupMember::Spent { commitment, .. } => *commitment,
        }
    }

    pub fn metadata_hash(&self) -> [u8; 32] {
        match self {
            GroupMember::Unspent(o) => o.metadata_hash(),
            GroupMember::Spent { metadata_hash, .. } => *metadata_hash,
        }
    }
}

/// An output group as a pruning node stores it: the original range proof,
/// with spent members reduced to `(commitment, metadata hash)`. The proof
/// still verifies, so every unspent member stays provably in range.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredGroup {
    pub range_proof: Vec<u8>,
    pub members: Vec<GroupMember>,
}

impl StoredGroup {
    pub fn from_group(group: &OutputGroup) -> Self {
        Self {
            range_proof: group.range_proof.clone(),
            members: group
                .outputs
                .iter()
                .cloned()
                .map(GroupMember::Unspent)
                .collect(),
        }
    }

    /// Stable while members are pruned: hashes the proof and all commitments.
    pub fn id(&self) -> [u8; 32] {
        let commitments: Vec<Point32> = self.members.iter().map(GroupMember::commitment).collect();
        let mut parts: Vec<&[u8]> = vec![&self.range_proof];
        parts.extend(commitments.iter().map(|c| c.as_slice()));
        hash_domain(b"midwimble.output-group.id.v1", &parts)
    }

    pub fn verify(&self) -> bool {
        let n = self.members.len();
        if n == 0 || n > MAX_GROUP_OUTPUTS || self.range_proof.len() != range_proof_len(n) {
            return false;
        }
        if self
            .members
            .iter()
            .any(|m| matches!(m, GroupMember::Unspent(o) if o.check_encoding().is_err()))
        {
            return false;
        }
        let commitments: Vec<Point32> = self.members.iter().map(GroupMember::commitment).collect();
        let hashes: Vec<[u8; 32]> = self
            .members
            .iter()
            .map(GroupMember::metadata_hash)
            .collect();
        verify_range(
            &self.range_proof,
            &commitments,
            &OutputGroup::binding_for_hashes(&hashes),
        )
    }

    /// Marks member `index` spent. Fails if it is not an unspent member.
    pub fn spend(&mut self, index: usize) -> Result<()> {
        match self.members.get(index) {
            Some(GroupMember::Unspent(o)) => {
                let pruned = GroupMember::Spent {
                    commitment: o.commitment,
                    metadata_hash: o.metadata_hash(),
                };
                self.members[index] = pruned;
                Ok(())
            }
            _ => bail!("group member {} is not unspent", index),
        }
    }

    pub fn is_fully_spent(&self) -> bool {
        self.members
            .iter()
            .all(|m| matches!(m, GroupMember::Spent { .. }))
    }

    pub fn unspent(&self) -> impl Iterator<Item = (usize, &Output)> {
        self.members
            .iter()
            .enumerate()
            .filter_map(|(i, m)| match m {
                GroupMember::Unspent(o) => Some((i, o)),
                GroupMember::Spent { .. } => None,
            })
    }
}

// ── Inputs ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Input {
    /// Commitment of the UTXO being spent.
    pub commitment: Point32,
    /// Owner key of that UTXO. Must match the chain's record; carried so the
    /// signature can be checked without state, in parallel.
    pub owner_key: Point32,
    /// Schnorr signature by `ko` over [`Input::message`].
    pub signature: SchnorrSig,
}

impl Input {
    /// Binds the signature to the specific output, so it cannot be moved onto
    /// another output that happens to share the owner key.
    pub fn message(commitment: &Point32, owner_key: &Point32) -> [u8; 32] {
        hash_domain(
            b"midwimble.input.v1",
            &[NETWORK_MAGIC, commitment, owner_key],
        )
    }

    pub fn sign(commitment: Point32, owner_secret: &Scalar) -> Self {
        let owner_key = compress(&RistrettoPoint::mul_base(owner_secret));
        let signature = schnorr_sign(owner_secret, &Self::message(&commitment, &owner_key));
        Self {
            commitment,
            owner_key,
            signature,
        }
    }

    pub fn verify_signature(&self) -> bool {
        schnorr_verify(
            &self.owner_key,
            &Self::message(&self.commitment, &self.owner_key),
            &self.signature,
        )
    }
}

// ── Kernels ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KernelFeatures {
    Plain,
    Coinbase,
}

impl KernelFeatures {
    fn tag(self) -> u8 {
        match self {
            KernelFeatures::Plain => 0,
            KernelFeatures::Coinbase => 1,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Kernel {
    pub features: KernelFeatures,
    pub fee: u64,
    /// Earliest block height that may include this kernel (pluribit's
    /// `min_height`).
    pub min_height: u64,
    /// `E = e·H`.
    pub excess: Point32,
    /// `E' = e'·G`; the identity for coinbase kernels.
    pub owner_excess: Point32,
    pub signature: KernelSig,
}

impl Kernel {
    pub fn message(features: KernelFeatures, fee: u64, min_height: u64) -> [u8; 32] {
        hash_domain(
            b"midwimble.kernel.v1",
            &[
                NETWORK_MAGIC,
                &[features.tag()],
                &fee.to_le_bytes(),
                &min_height.to_le_bytes(),
            ],
        )
    }

    /// Consensus identifier; must be unique across the whole chain, which
    /// stops an old transaction being replayed if its inputs ever reappear.
    pub fn id(&self) -> [u8; 32] {
        hash_domain(
            b"midwimble.kernel.id.v1",
            &[&self.excess, &self.owner_excess],
        )
    }

    pub fn new(
        features: KernelFeatures,
        fee: u64,
        min_height: u64,
        excess_secret: &Scalar,
        owner_secret: &Scalar,
    ) -> Self {
        let excess = compress(&(excess_secret * gen_h()));
        let owner_excess = compress(&RistrettoPoint::mul_base(owner_secret));
        let msg = Self::message(features, fee, min_height);
        let signature = kernel_sign(excess_secret, owner_secret, &excess, &owner_excess, &msg);
        Self {
            features,
            fee,
            min_height,
            excess,
            owner_excess,
            signature,
        }
    }

    pub fn verify_signature(&self) -> bool {
        let msg = Self::message(self.features, self.fee, self.min_height);
        kernel_verify(&self.excess, &self.owner_excess, &msg, &self.signature)
    }

    pub(crate) fn check_rules(&self) -> Result<()> {
        match decompress(&self.excess) {
            Some(p) if !p.is_identity() => {}
            _ => bail!("kernel excess is not a valid non-identity point"),
        }
        if decompress(&self.owner_excess).is_none() {
            bail!("kernel owner excess is not a valid point");
        }
        match self.features {
            KernelFeatures::Plain => {
                // An identity owner excess would force x = Σ ko, publishing
                // the owner secrets' sum (and with one input, the key itself).
                if self.owner_excess == IDENTITY {
                    bail!("plain kernel must carry a non-identity owner excess");
                }
            }
            KernelFeatures::Coinbase => {
                if self.owner_excess != IDENTITY || self.fee != 0 || self.min_height != 0 {
                    bail!(
                        "coinbase kernel must have zero fee, zero min_height and no owner excess"
                    );
                }
            }
        }
        Ok(())
    }
}

// ── Transactions ────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TxBody {
    /// Strictly ascending by commitment.
    pub inputs: Vec<Input>,
    /// Strictly ascending by first output commitment.
    pub outputs: Vec<OutputGroup>,
    /// Strictly ascending by [`Kernel::id`].
    pub kernels: Vec<Kernel>,
}

/// Where a transaction is being validated. A block body is itself a
/// transaction (the aggregate of everything it includes) and may be empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    Relay,
    Block,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Transaction {
    pub body: TxBody,
    /// Pedersen offset `o`.
    pub kernel_offset: Scalar32,
    /// Owner offset `x`.
    pub owner_offset: Scalar32,
}

impl Default for Transaction {
    fn default() -> Self {
        Self::empty()
    }
}

impl Transaction {
    pub fn empty() -> Self {
        Self {
            body: TxBody::default(),
            kernel_offset: [0u8; 32],
            owner_offset: [0u8; 32],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.body.inputs.is_empty() && self.body.outputs.is_empty() && self.body.kernels.is_empty()
    }

    pub fn outputs(&self) -> impl Iterator<Item = &Output> {
        self.body.outputs.iter().flat_map(|g| g.outputs.iter())
    }

    pub fn output_count(&self) -> usize {
        self.body.outputs.iter().map(|g| g.outputs.len()).sum()
    }

    pub fn input_commitments(&self) -> impl Iterator<Item = &Point32> {
        self.body.inputs.iter().map(|i| &i.commitment)
    }

    pub fn output_commitments(&self) -> impl Iterator<Item = &Point32> {
        self.outputs().map(|o| &o.commitment)
    }

    pub fn kernel_ids(&self) -> Vec<[u8; 32]> {
        self.body.kernels.iter().map(Kernel::id).collect()
    }

    pub fn fee(&self) -> Result<u64> {
        self.body
            .kernels
            .iter()
            .try_fold(0u64, |acc, k| acc.checked_add(k.fee))
            .ok_or_else(|| anyhow!("fee overflow"))
    }

    /// Highest `min_height` among the kernels: the earliest block that may
    /// include this transaction.
    pub fn lock_height(&self) -> u64 {
        self.body
            .kernels
            .iter()
            .map(|k| k.min_height)
            .max()
            .unwrap_or(0)
    }

    /// Grin-style weight: inputs are cheap, outputs (range proofs) expensive.
    pub fn weight(&self) -> u64 {
        self.body.inputs.len() as u64 * INPUT_WEIGHT
            + self.output_count() as u64 * OUTPUT_WEIGHT
            + self.body.kernels.len() as u64 * KERNEL_WEIGHT
    }

    /// Stable identifier over the full serialization.
    pub fn hash(&self) -> [u8; 32] {
        let bytes = bincode::serialize(self).expect("transaction serialization cannot fail");
        hash_domain(b"midwimble.tx.v1", &[&bytes])
    }

    /// Cheap checks: counts, encodings, ordering, uniqueness, kernel rules.
    pub fn validate_structure(&self, ctx: Context) -> Result<()> {
        let b = &self.body;
        match ctx {
            Context::Relay => {
                if b.inputs.is_empty() || b.outputs.is_empty() || b.kernels.is_empty() {
                    bail!("transaction needs at least one input, output and kernel");
                }
                if self.weight() > MAX_TX_WEIGHT {
                    bail!(
                        "transaction weight {} exceeds {}",
                        self.weight(),
                        MAX_TX_WEIGHT
                    );
                }
            }
            Context::Block => {
                if self.weight() > MAX_BLOCK_WEIGHT {
                    bail!(
                        "block body weight {} exceeds {}",
                        self.weight(),
                        MAX_BLOCK_WEIGHT
                    );
                }
            }
        }
        if b.kernels.is_empty() && !(b.inputs.is_empty() && b.outputs.is_empty()) {
            bail!("inputs or outputs without any kernel");
        }
        if scalar_from_bytes(&self.kernel_offset).is_none()
            || scalar_from_bytes(&self.owner_offset).is_none()
        {
            bail!("offsets must be canonical scalars");
        }

        if !b
            .inputs
            .windows(2)
            .all(|w| w[0].commitment < w[1].commitment)
        {
            bail!("inputs must be strictly ascending by commitment");
        }
        if !b
            .outputs
            .windows(2)
            .all(|w| w[0].sort_key() < w[1].sort_key())
        {
            bail!("output groups must be strictly ascending by first commitment");
        }
        for group in &b.outputs {
            group.check_structure()?;
        }

        let mut commitments = HashSet::new();
        let mut owner_keys = HashSet::new();
        for o in self.outputs() {
            if !commitments.insert(o.commitment) {
                bail!("duplicate output commitment {}", hex::encode(o.commitment));
            }
            if !owner_keys.insert(o.owner_key) {
                bail!("duplicate output owner key");
            }
        }
        for i in &b.inputs {
            if commitments.contains(&i.commitment) {
                // Would be cut-through material. Aggregated range proofs cannot
                // drop one output, so spending in the same body is disallowed.
                bail!("input spends an output created in the same body");
            }
        }

        let ids = self.kernel_ids();
        if !ids.windows(2).all(|w| w[0] < w[1]) {
            bail!("kernels must be strictly ascending by id");
        }
        for k in &b.kernels {
            if k.features != KernelFeatures::Plain {
                bail!("only plain kernels are allowed in a transaction body");
            }
            k.check_rules()?;
        }
        Ok(())
    }

    /// Both balance equations. No signature or proof checks.
    pub fn verify_sums(&self) -> Result<()> {
        let offset =
            scalar_from_bytes(&self.kernel_offset).ok_or_else(|| anyhow!("bad kernel offset"))?;
        let owner_offset =
            scalar_from_bytes(&self.owner_offset).ok_or_else(|| anyhow!("bad owner offset"))?;
        let fee = self.fee()?;

        let outputs = sum_points(self.output_commitments())?;
        let inputs = sum_points(self.input_commitments())?;
        let excesses = sum_points(self.body.kernels.iter().map(|k| &k.excess))?;
        if outputs - inputs + Scalar::from(fee) * gen_g() != excesses + offset * gen_h() {
            bail!("Pedersen balance check failed");
        }

        let owner_in = sum_points(self.body.inputs.iter().map(|i| &i.owner_key))?;
        let owner_excesses = sum_points(self.body.kernels.iter().map(|k| &k.owner_excess))?;
        if owner_in != owner_excesses + RistrettoPoint::mul_base(&owner_offset) {
            bail!("owner sum check failed");
        }
        Ok(())
    }

    /// Range proofs, input signatures and kernel signatures, in parallel.
    pub fn verify_crypto(&self) -> Result<()> {
        let b = &self.body;
        if !b.outputs.par_iter().all(OutputGroup::verify_range_proof) {
            bail!("invalid range proof");
        }
        if !b.inputs.par_iter().all(Input::verify_signature) {
            bail!("invalid input ownership signature");
        }
        if !b.kernels.par_iter().all(Kernel::verify_signature) {
            bail!("invalid kernel signature");
        }
        Ok(())
    }

    /// Full stateless validation.
    pub fn validate(&self, ctx: Context) -> Result<()> {
        self.validate_structure(ctx)?;
        self.verify_sums()?;
        self.verify_crypto()
    }

    /// Merges transactions into one (MimbleWimble's native aggregation).
    ///
    /// Offsets add, lists merge in canonical order. Fails on any shared input,
    /// output or kernel, since the result could never be valid.
    pub fn aggregate<'a>(txs: impl IntoIterator<Item = &'a Transaction>) -> Result<Transaction> {
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        let mut kernels = Vec::new();
        let mut offset = Scalar::ZERO;
        let mut owner_offset = Scalar::ZERO;
        for tx in txs {
            inputs.extend(tx.body.inputs.iter().cloned());
            outputs.extend(tx.body.outputs.iter().cloned());
            kernels.extend(tx.body.kernels.iter().cloned());
            offset +=
                scalar_from_bytes(&tx.kernel_offset).ok_or_else(|| anyhow!("bad kernel offset"))?;
            owner_offset +=
                scalar_from_bytes(&tx.owner_offset).ok_or_else(|| anyhow!("bad owner offset"))?;
        }
        inputs.sort_by(|a: &Input, b: &Input| a.commitment.cmp(&b.commitment));
        if inputs
            .windows(2)
            .any(|w| w[0].commitment == w[1].commitment)
        {
            bail!("aggregate would double-spend an input");
        }
        outputs.sort_by_key(OutputGroup::sort_key);
        kernels.sort_by_cached_key(Kernel::id);
        if kernels.windows(2).any(|w| w[0].id() == w[1].id()) {
            bail!("aggregate would duplicate a kernel");
        }
        let agg = Transaction {
            body: TxBody {
                inputs,
                outputs,
                kernels,
            },
            kernel_offset: offset.to_bytes(),
            owner_offset: owner_offset.to_bytes(),
        };
        // Output uniqueness and same-body spends are checked here.
        agg.validate_structure(Context::Block)?;
        Ok(agg)
    }
}

// ── Coinbase ────────────────────────────────────────────────────────────────

/// Block reward outputs and their kernel.
///
/// Kept apart from the aggregated body so the reward rule is a separate,
/// offset-free equation (as Grin does):
///
/// ```text
///   Σ C_coinbase − (reward + fees)·G = E_coinbase
/// ```
///
/// Together with the body's Pedersen equation this pins the declared fees to
/// what the transactions actually left over.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Coinbase {
    pub outputs: OutputGroup,
    pub kernel: Kernel,
    /// Free miner data committed by the block hash (a pool's share-score
    /// Merkle root, or a merged-mining commitment when midwimble is itself the
    /// parent). Not interpreted by consensus.
    #[serde(default)]
    pub extra: [u8; 32],
}

impl Coinbase {
    pub fn weight(&self) -> u64 {
        self.outputs.outputs.len() as u64 * OUTPUT_WEIGHT + KERNEL_WEIGHT
    }

    pub fn hash(&self) -> [u8; 32] {
        let bytes = bincode::serialize(self).expect("coinbase serialization cannot fail");
        hash_domain(b"midwimble.coinbase.v1", &[&bytes])
    }

    pub fn validate_structure(&self) -> Result<()> {
        self.outputs.check_structure()?;
        let mut seen_c = HashSet::new();
        let mut seen_k = HashSet::new();
        for o in &self.outputs.outputs {
            if !seen_c.insert(o.commitment) || !seen_k.insert(o.owner_key) {
                bail!("duplicate coinbase output");
            }
        }
        if self.kernel.features != KernelFeatures::Coinbase {
            bail!("coinbase must carry a coinbase kernel");
        }
        self.kernel.check_rules()
    }

    pub fn verify_sum(&self, amount: u64) -> Result<()> {
        let outputs = sum_points(self.outputs.outputs.iter().map(|o| &o.commitment))?;
        let excess =
            decompress(&self.kernel.excess).ok_or_else(|| anyhow!("bad coinbase excess"))?;
        if outputs - Scalar::from(amount) * gen_g() != excess {
            bail!("coinbase does not pay exactly {}", amount);
        }
        Ok(())
    }

    pub fn verify_crypto(&self) -> Result<()> {
        if !self.outputs.verify_range_proof() {
            bail!("invalid coinbase range proof");
        }
        if !self.kernel.verify_signature() {
            bail!("invalid coinbase kernel signature");
        }
        Ok(())
    }
}

/// Re-exported for callers that need the raw check.
pub fn is_valid_point(p: &Point32) -> bool {
    crypto::decompress(p).is_some()
}
