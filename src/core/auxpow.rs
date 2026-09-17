//! Merged mining with midstate.
//!
//! A midwimble block may carry its proof of work in a **midstate** block (the
//! "parent") that commits to it. Midstate needs no change: its miners already
//! choose every coinbase salt, and its `/block_template` RPC takes the whole
//! coinbase from the caller and computes the state root itself.
//!
//! # Commitment
//!
//! One parent coinbase output, normally the last, has
//!
//! ```text
//!   salt = H("midwimble.merge-mining.v1", NETWORK_MAGIC, aux_mining_hash)
//! ```
//!
//! where `aux_mining_hash` is the midwimble block's own header hash, which
//! commits to every byte of the block and to its target.
//!
//! # Why the parent's work is valid here
//!
//! Midstate's mining hash is built as
//!
//! ```text
//!   m = prev_midstate
//!   m = H(m ‖ item)        for each transaction item, then each coinbase coin id
//!   m = H(m ‖ state_root)  (when non-zero)
//!   mining_hash = H(prev_header_hash ‖ m ‖ state_root ‖ timestamp ‖ target)
//!   final       = H^N(H(mining_hash ‖ nonce))
//! ```
//!
//! and midwimble's native proof of work is the same function with the same N.
//! The proof carries the fold state just before the committing output (the
//! prefix cannot affect the binding), that output's address and value, the
//! coin ids after it, and the parent's header fields. A verifier recomputes
//! the parent mining hash and the whole chain, and requires
//! `final < midwimble target`.
//!
//! As with Bitcoin/Namecoin AuxPoW, the parent need not be valid on midstate;
//! only its work counts, and only against midwimble's own target. A parent can
//! commit to several midwimble blocks (several salts), so an aux block's id is
//! `H(parent_final ‖ aux_mining_hash)`, never the bare parent hash.

use super::extension::{create_extension, verify_extension};
use super::simd_mining::pow_seed;
use super::types::{
    compute_header_hash, hash, hash_concat, hash_domain, BatchHeader, Extension, NETWORK_MAGIC,
};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Parent coinbase outputs allowed after the committing one. Keeps headers
/// small; merged miners put the commitment last so this is normally zero.
pub const MAX_COINBASE_AFTER: usize = 16;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AuxPow {
    /// Parent fold state after its transactions and the coinbase outputs that
    /// precede the committing one.
    pub pre_commit_midstate: [u8; 32],
    /// The committing output (its salt is [`merge_commitment`]).
    pub commit_address: [u8; 32],
    pub commit_value: u64,
    /// Coin ids of parent coinbase outputs after the committing one.
    pub coinbase_after: Vec<[u8; 32]>,
    pub state_root: [u8; 32],
    pub prev_header_hash: [u8; 32],
    pub timestamp: u64,
    pub target: [u8; 32],
    pub nonce: u64,
    /// The parent's proof-of-work result.
    pub final_hash: [u8; 32],
}

/// The salt a parent coinbase output carries to commit to `aux_mining_hash`.
pub fn merge_commitment(aux_mining_hash: &[u8; 32]) -> [u8; 32] {
    hash_domain(
        b"midwimble.merge-mining.v1",
        &[NETWORK_MAGIC, aux_mining_hash],
    )
}

/// Midstate's `compute_coin_id`.
pub fn midstate_coin_id(address: &[u8; 32], value: u64, salt: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(address);
    hasher.update(&value.to_le_bytes());
    hasher.update(salt);
    *hasher.finalize().as_bytes()
}

/// Identity of a merged-mined block (stored as its `extension.final_hash`).
pub fn aux_block_id(parent_final_hash: &[u8; 32], aux_mining_hash: &[u8; 32]) -> [u8; 32] {
    hash_domain(
        b"midwimble.aux-block-id.v1",
        &[parent_final_hash, aux_mining_hash],
    )
}

impl AuxPow {
    /// The midstate header hash this proof's work was computed over.
    pub fn parent_mining_hash(&self, aux_mining_hash: &[u8; 32]) -> [u8; 32] {
        let salt = merge_commitment(aux_mining_hash);
        let mut m = hash_concat(
            &self.pre_commit_midstate,
            &midstate_coin_id(&self.commit_address, self.commit_value, &salt),
        );
        for id in &self.coinbase_after {
            m = hash_concat(&m, id);
        }
        if self.state_root != [0u8; 32] {
            m = hash_concat(&m, &self.state_root);
        }
        compute_header_hash(&BatchHeader {
            height: 0,
            prev_midstate: [0u8; 32],
            post_tx_midstate: m,
            extension: Extension {
                nonce: 0,
                final_hash: [0u8; 32],
            },
            timestamp: self.timestamp,
            target: self.target,
            state_root: self.state_root,
            prev_header_hash: self.prev_header_hash,
            aux_pow: None,
        })
    }

    /// Seed of the parent's hash chain (for batched SIMD verification).
    pub fn pow_seed(&self, aux_mining_hash: &[u8; 32]) -> [u8; 32] {
        pow_seed(&self.parent_mining_hash(aux_mining_hash), self.nonce)
    }

    pub fn block_id(&self, aux_mining_hash: &[u8; 32]) -> [u8; 32] {
        aux_block_id(&self.final_hash, aux_mining_hash)
    }

    /// Everything except the expensive chain recomputation.
    pub fn check_claims(
        &self,
        aux_mining_hash: &[u8; 32],
        extension: &Extension,
        target: &[u8; 32],
    ) -> Result<()> {
        if self.coinbase_after.len() > MAX_COINBASE_AFTER {
            bail!("merged-mining proof lists too many trailing coinbase outputs");
        }
        if extension.nonce != 0 || extension.final_hash != self.block_id(aux_mining_hash) {
            bail!("merged-mined block id does not match its proof");
        }
        if self.final_hash >= *target {
            bail!("merged-mining proof does not meet the target");
        }
        Ok(())
    }
}

/// Verifies a block's proof of work, native or merged.
pub fn verify_pow(
    mining_hash: [u8; 32],
    extension: &Extension,
    target: &[u8; 32],
    aux: Option<&AuxPow>,
) -> Result<()> {
    match aux {
        None => verify_extension(mining_hash, extension, target),
        Some(a) => {
            a.check_claims(&mining_hash, extension, target)?;
            let recomputed = create_extension(a.parent_mining_hash(&mining_hash), a.nonce);
            if recomputed.final_hash != a.final_hash {
                bail!("merged-mining proof of work is invalid");
            }
            Ok(())
        }
    }
}

// ── Building proofs from a midstate template ────────────────────────────────

/// A midstate block template with one coinbase output chosen to carry the
/// commitment: everything a proof needs except the nonce and final hash.
#[derive(Clone, Debug)]
pub struct ParentTemplate {
    pub pre_commit_midstate: [u8; 32],
    pub commit_address: [u8; 32],
    pub commit_value: u64,
    pub commit_salt: [u8; 32],
    pub coinbase_after: Vec<[u8; 32]>,
    pub state_root: [u8; 32],
    pub prev_header_hash: [u8; 32],
    pub timestamp: u64,
    pub target: [u8; 32],
}

impl ParentTemplate {
    /// Reconstructs midstate's fold from its `batch_template` JSON.
    pub fn from_midstate_json(batch: &Value, commit_index: usize) -> Result<Self> {
        let mut m = bytes32(&batch["prev_midstate"])?;
        for tx in batch["transactions"]
            .as_array()
            .ok_or_else(|| anyhow!("template has no transactions array"))?
        {
            m = hash_concat(&m, &tx_fold_item(tx)?);
        }
        let coinbase = batch["coinbase"]
            .as_array()
            .ok_or_else(|| anyhow!("template has no coinbase array"))?;
        if commit_index >= coinbase.len() {
            bail!(
                "commit index {} outside a coinbase of {}",
                commit_index,
                coinbase.len()
            );
        }
        let mut after = Vec::new();
        let mut commit = None;
        for (i, cb) in coinbase.iter().enumerate() {
            let address = bytes32(&cb["address"])?;
            let value = cb["value"]
                .as_u64()
                .ok_or_else(|| anyhow!("coinbase value missing"))?;
            let salt = bytes32(&cb["salt"])?;
            match i.cmp(&commit_index) {
                std::cmp::Ordering::Less => {
                    m = hash_concat(&m, &midstate_coin_id(&address, value, &salt))
                }
                std::cmp::Ordering::Equal => commit = Some((address, value, salt)),
                std::cmp::Ordering::Greater => after.push(midstate_coin_id(&address, value, &salt)),
            }
        }
        let (commit_address, commit_value, commit_salt) = commit.expect("index checked");
        if after.len() > MAX_COINBASE_AFTER {
            bail!("too many coinbase outputs after the commitment");
        }
        Ok(Self {
            pre_commit_midstate: m,
            commit_address,
            commit_value,
            commit_salt,
            coinbase_after: after,
            state_root: bytes32(&batch["state_root"])?,
            prev_header_hash: bytes32(&batch["prev_header_hash"])?,
            timestamp: batch["timestamp"]
                .as_u64()
                .ok_or_else(|| anyhow!("timestamp missing"))?,
            target: bytes32(&batch["target"])?,
        })
    }

    /// The proof for a found nonce.
    pub fn proof(&self, nonce: u64, final_hash: [u8; 32]) -> AuxPow {
        AuxPow {
            pre_commit_midstate: self.pre_commit_midstate,
            commit_address: self.commit_address,
            commit_value: self.commit_value,
            coinbase_after: self.coinbase_after.clone(),
            state_root: self.state_root,
            prev_header_hash: self.prev_header_hash,
            timestamp: self.timestamp,
            target: self.target,
            nonce,
            final_hash,
        }
    }

    /// Checks that this template commits to `aux_mining_hash` and reproduces
    /// the parent node's own mining hash. A merged miner must not hash until
    /// this passes: any divergence from midstate's rules would otherwise
    /// silently waste the work.
    pub fn check(&self, aux_mining_hash: &[u8; 32], parent_mining_hash: &[u8; 32]) -> Result<()> {
        if self.commit_salt != merge_commitment(aux_mining_hash) {
            bail!("the chosen coinbase output does not carry the merge commitment");
        }
        let ours = self.proof(0, [0u8; 32]).parent_mining_hash(aux_mining_hash);
        if &ours != parent_mining_hash {
            bail!(
                "cannot reproduce midstate's header hash (ours {}, node {})",
                hex::encode(ours),
                hex::encode(parent_mining_hash)
            );
        }
        Ok(())
    }
}

pub(crate) fn tx_fold_item(tx: &Value) -> Result<[u8; 32]> {
    if let Some(c) = tx.get("Commit") {
        return bytes32(&c["commitment"]);
    }
    let body = tx
        .get("Reveal")
        .or_else(|| tx.get("Consolidate"))
        .ok_or_else(|| anyhow!("unknown midstate transaction kind"))?;
    let mut hasher = blake3::Hasher::new();
    for input in body["inputs"]
        .as_array()
        .ok_or_else(|| anyhow!("inputs missing"))?
    {
        hasher.update(&input_coin_id(input)?);
    }
    for output in body["outputs"]
        .as_array()
        .ok_or_else(|| anyhow!("outputs missing"))?
    {
        hasher.update(&output_commit_hash(output)?);
    }
    hasher.update(&bytes32(&body["salt"])?);
    Ok(*hasher.finalize().as_bytes())
}

fn input_coin_id(input: &Value) -> Result<[u8; 32]> {
    let bytecode = bytes(&input["predicate"]["Script"]["bytecode"])?;
    let address = hash(&bytecode);
    let salt = bytes32(&input["salt"])?;
    match &input["commitment"] {
        Value::Null => {
            let value = input["value"]
                .as_u64()
                .ok_or_else(|| anyhow!("input value missing"))?;
            Ok(midstate_coin_id(&address, value, &salt))
        }
        c => Ok(confidential_id(&address, &bytes32(c)?, &salt)),
    }
}

fn confidential_id(address: &[u8; 32], commitment: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CONFIDENTIAL");
    hasher.update(address);
    hasher.update(commitment);
    hasher.update(salt);
    *hasher.finalize().as_bytes()
}

fn output_commit_hash(output: &Value) -> Result<[u8; 32]> {
    if let Some(o) = output.get("Standard") {
        let value = o["value"]
            .as_u64()
            .ok_or_else(|| anyhow!("output value missing"))?;
        return Ok(midstate_coin_id(
            &bytes32(&o["address"])?,
            value,
            &bytes32(&o["salt"])?,
        ));
    }
    if let Some(o) = output.get("Confidential") {
        return Ok(confidential_id(
            &bytes32(&o["address"])?,
            &bytes32(&o["commitment"])?,
            &bytes32(&o["salt"])?,
        ));
    }
    if let Some(o) = output.get("DataBurn") {
        let value = o["value_burned"]
            .as_u64()
            .ok_or_else(|| anyhow!("burn value missing"))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"DATABURN");
        hasher.update(&value.to_le_bytes());
        hasher.update(&bytes(&o["payload"])?);
        return Ok(*hasher.finalize().as_bytes());
    }
    bail!("unknown midstate output kind")
}

/// A byte string from JSON: an array of numbers (serde's default) or hex.
pub fn bytes(v: &Value) -> Result<Vec<u8>> {
    match v {
        Value::String(s) => Ok(hex::decode(s)?),
        Value::Array(items) => items
            .iter()
            .map(|x| {
                x.as_u64()
                    .filter(|b| *b <= 255)
                    .map(|b| b as u8)
                    .ok_or_else(|| anyhow!("not a byte"))
            })
            .collect(),
        _ => bail!("expected bytes, got {}", v),
    }
}

pub fn bytes32(v: &Value) -> Result<[u8; 32]> {
    bytes(v)?
        .try_into()
        .map_err(|_| anyhow!("expected 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arr(b: &[u8]) -> Value {
        Value::Array(b.iter().map(|x| Value::from(*x)).collect())
    }

    /// A parent whose proof of work we can find quickly: the aux target is
    /// the ceiling, and `fast-mining` (or patience) does the rest.
    fn solved(aux_hash: &[u8; 32], target: [u8; 32]) -> AuxPow {
        let parent = ParentTemplate {
            pre_commit_midstate: [7; 32],
            commit_address: [1; 32],
            commit_value: 64,
            commit_salt: merge_commitment(aux_hash),
            coinbase_after: vec![[2; 32]],
            state_root: [3; 32],
            prev_header_hash: [4; 32],
            timestamp: 1_000,
            target: [0xff; 32],
        };
        let mining = parent.proof(0, [0; 32]).parent_mining_hash(aux_hash);
        let mut nonce = 0;
        loop {
            let ext = create_extension(mining, nonce);
            if ext.final_hash < target {
                return parent.proof(nonce, ext.final_hash);
            }
            nonce += 1;
        }
    }

    #[test]
    fn valid_proof_verifies_and_binds_to_the_block() {
        let aux_hash = [9u8; 32];
        let target = [0xff; 32];
        let aux = solved(&aux_hash, target);
        let ext = Extension {
            nonce: 0,
            final_hash: aux.block_id(&aux_hash),
        };
        verify_pow(aux_hash, &ext, &target, Some(&aux)).unwrap();

        // Same proof, different block: the commitment no longer matches.
        let other = [8u8; 32];
        let ext_other = Extension {
            nonce: 0,
            final_hash: aux.block_id(&other),
        };
        assert!(verify_pow(other, &ext_other, &target, Some(&aux)).is_err());

        // Wrong id, wrong nonce, tampered fields: all rejected.
        assert!(verify_pow(
            aux_hash,
            &Extension {
                nonce: 0,
                final_hash: aux.final_hash
            },
            &target,
            Some(&aux)
        )
        .is_err());
        assert!(verify_pow(
            aux_hash,
            &Extension {
                nonce: 1,
                final_hash: ext.final_hash
            },
            &target,
            Some(&aux)
        )
        .is_err());
        let mut tampered = aux.clone();
        tampered.commit_value += 1;
        let ext_t = Extension {
            nonce: 0,
            final_hash: tampered.block_id(&aux_hash),
        };
        assert!(verify_pow(aux_hash, &ext_t, &target, Some(&tampered)).is_err());
        let mut long = aux.clone();
        long.coinbase_after = vec![[0; 32]; MAX_COINBASE_AFTER + 1];
        assert!(verify_pow(
            aux_hash,
            &Extension {
                nonce: 0,
                final_hash: long.block_id(&aux_hash)
            },
            &target,
            Some(&long)
        )
        .is_err());
    }

    #[test]
    fn proof_must_meet_the_aux_target() {
        let aux_hash = [5u8; 32];
        let aux = solved(&aux_hash, [0xff; 32]);
        let ext = Extension {
            nonce: 0,
            final_hash: aux.block_id(&aux_hash),
        };
        let mut strict = [0u8; 32];
        strict[31] = 1;
        assert!(verify_pow(aux_hash, &ext, &strict, Some(&aux)).is_err());
    }

    #[test]
    fn distinct_blocks_from_one_parent_get_distinct_ids() {
        assert_ne!(
            aux_block_id(&[1; 32], &[2; 32]),
            aux_block_id(&[1; 32], &[3; 32])
        );
    }

    #[test]
    fn json_fold_handles_every_midstate_item_and_both_byte_encodings() {
        let aux_hash = [6u8; 32];
        let salt = merge_commitment(&aux_hash);
        let batch = serde_json::json!({
            "prev_midstate": arr(&[1; 32]),
            "transactions": [
                { "Commit": { "commitment": arr(&[2; 32]), "spam_nonce": 5 } },
                { "Reveal": {
                    "inputs": [
                        { "predicate": { "Script": { "bytecode": [1, 2, 3] } }, "value": 8, "salt": arr(&[3; 32]), "commitment": null },
                        { "predicate": { "Script": { "bytecode": [4] } }, "value": 0, "salt": hex::encode([4u8; 32]), "commitment": arr(&[5; 32]) }
                    ],
                    "witnesses": [],
                    "outputs": [
                        { "Standard": { "address": arr(&[6; 32]), "value": 4, "salt": arr(&[7; 32]) } },
                        { "Confidential": { "address": arr(&[8; 32]), "commitment": arr(&[9; 32]), "salt": arr(&[10; 32]) } },
                        { "DataBurn": { "payload": [1, 1], "value_burned": 2 } }
                    ],
                    "salt": arr(&[11; 32])
                } }
            ],
            "coinbase": [
                { "address": arr(&[12; 32]), "value": 16, "salt": arr(&[13; 32]) },
                { "address": arr(&[14; 32]), "value": 32, "salt": arr(&salt) }
            ],
            "extension": { "nonce": 0, "final_hash": arr(&[0; 32]) },
            "timestamp": 123,
            "target": arr(&[0xff; 32]),
            "state_root": arr(&[15; 32]),
            "prev_header_hash": arr(&[16; 32])
        });
        let parent = ParentTemplate::from_midstate_json(&batch, 1).unwrap();

        // Independent recomputation following midstate's Batch::header().
        let mut m = hash_concat(&[1; 32], &[2; 32]);
        let mut h = blake3::Hasher::new();
        h.update(&midstate_coin_id(&hash(&[1, 2, 3]), 8, &[3; 32]));
        h.update(&confidential_id(&hash(&[4]), &[5; 32], &[4; 32]));
        h.update(&midstate_coin_id(&[6; 32], 4, &[7; 32]));
        h.update(&confidential_id(&[8; 32], &[9; 32], &[10; 32]));
        let mut burn = blake3::Hasher::new();
        burn.update(b"DATABURN");
        burn.update(&2u64.to_le_bytes());
        burn.update(&[1, 1]);
        h.update(burn.finalize().as_bytes());
        h.update(&[11; 32]);
        m = hash_concat(&m, h.finalize().as_bytes());
        m = hash_concat(&m, &midstate_coin_id(&[12; 32], 16, &[13; 32]));
        assert_eq!(parent.pre_commit_midstate, m);

        let m = hash_concat(
            &hash_concat(&m, &midstate_coin_id(&[14; 32], 32, &salt)),
            &[15; 32],
        );
        let expected = compute_header_hash(&BatchHeader {
            height: 0,
            prev_midstate: [0; 32],
            post_tx_midstate: m,
            extension: Extension {
                nonce: 0,
                final_hash: [0; 32],
            },
            timestamp: 123,
            target: [0xff; 32],
            state_root: [15; 32],
            prev_header_hash: [16; 32],
            aux_pow: None,
        });
        parent.check(&aux_hash, &expected).unwrap();
        assert!(parent.check(&[0; 32], &expected).is_err());
        assert!(ParentTemplate::from_midstate_json(&batch, 0)
            .unwrap()
            .check(&aux_hash, &expected)
            .is_err());
    }
}
