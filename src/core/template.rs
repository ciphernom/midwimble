//! Block templates: aggregate the chosen transactions, pay the coinbase,
//! commit to the resulting state, and hand the miner a header hash to grind.
//!
//! Mirrors midstate's `build_template_prefix` / `finish_template` split in
//! `node.rs`, reduced to the MimbleWimble case. The state root comes from
//! [`apply_body`], the same function consensus uses, so a template can never
//! disagree with validation about it.

use super::bond::{
    authorization_message, check_miner_authorization, BondRegistration, MinerAuth, MinerBond,
    BONDED_MINING_FROM,
};
use super::extension::create_extension;
use super::mw::{build_coinbase_with, PayoutReceipt, StealthAddress, Transaction};
use super::state::{apply_body, current_timestamp, min_next_timestamp, validate_block_contents};
use super::types::*;
use anyhow::{anyhow, bail, Result};

#[derive(Clone, Debug)]
pub struct BlockTemplate {
    /// The batch with a zeroed extension.
    pub batch: Batch,
    /// What `extension.final_hash` must be derived from.
    pub mining_hash: [u8; 32],
    pub height: u64,
    pub fees: u64,
}

impl BlockTemplate {
    /// Attaches a solved extension.
    pub fn seal(&self, extension: Extension) -> Batch {
        let mut batch = self.batch.clone();
        batch.extension = extension;
        batch
    }

    /// Attaches a merged-mining proof (the block's work is in a midstate block).
    pub fn seal_aux(&self, aux: crate::core::auxpow::AuxPow) -> Batch {
        let mut batch = self.batch.clone();
        batch.extension = Extension {
            nonce: 0,
            final_hash: aux.block_id(&self.mining_hash),
        };
        batch.aux_pow = Some(aux);
        batch
    }

    /// Single-threaded grind for tests and tiny devnets.
    pub fn mine_blocking(&self) -> Batch {
        let target = self.batch.target;
        let mut nonce = 0u64;
        loop {
            let ext = create_extension(self.mining_hash, nonce);
            if ext.final_hash < target {
                return self.seal(ext);
            }
            nonce = nonce.wrapping_add(1);
        }
    }
}

/// Picks transactions greedily by fee per weight until the block is full,
/// skipping any that conflict with one already chosen or that are not yet
/// valid at `height`.
pub fn select_transactions(
    candidates: &[Transaction],
    height: u64,
    weight_budget: u64,
) -> Vec<Transaction> {
    let mut order: Vec<&Transaction> = candidates.iter().collect();
    order.sort_by(|a, b| {
        let ra = a.fee().unwrap_or(0) as u128 * b.weight().max(1) as u128;
        let rb = b.fee().unwrap_or(0) as u128 * a.weight().max(1) as u128;
        rb.cmp(&ra)
    });
    let mut chosen = Vec::new();
    let mut used = 0u64;
    let mut spent = std::collections::HashSet::new();
    let mut created = std::collections::HashSet::new();
    let mut kernels = std::collections::HashSet::new();
    for tx in order {
        if tx.lock_height() > height || used + tx.weight() > weight_budget {
            continue;
        }
        let conflicts = tx
            .input_commitments()
            .any(|c| spent.contains(c) || created.contains(c))
            || tx
                .output_commitments()
                .any(|c| created.contains(c) || spent.contains(c))
            || tx.kernel_ids().iter().any(|k| kernels.contains(k));
        if conflicts {
            continue;
        }
        spent.extend(tx.input_commitments().copied());
        created.extend(tx.output_commitments().copied());
        kernels.extend(tx.kernel_ids());
        used += tx.weight();
        chosen.push(tx.clone());
    }
    chosen
}

/// Builds a template on top of `state` paying everything to `payout`.
///
/// `txs` must already be individually valid; the caller (mempool) is
/// responsible for that. Transactions that turn out to conflict with chain
/// state make the whole template fail, so callers should pre-filter.
pub fn build_template(
    state: &State,
    previous_timestamps: &[u64],
    txs: &[Transaction],
    payout: &StealthAddress,
    timestamp: Option<u64>,
) -> Result<BlockTemplate> {
    Ok(build_template_with(
        state,
        previous_timestamps,
        txs,
        &[(*payout, 1)],
        [0u8; 32],
        timestamp,
    )?
    .0)
}

/// Splits `total` by weight (floor), giving the rounding remainder to the
/// first entry. Zero-weight and zero-amount entries are dropped.
///
/// Every weighted payee is given one base unit before the split when the
/// total stretches that far. During the slow start a block is worth a few
/// hundred base units, and a plain proportional split would round the
/// smallest of a pool's 31 payees to nothing — which their own audit reads as
/// the pool refusing to pay them (`pool::audit_job`), so they would stop
/// hashing on day one. One base unit each costs the split at most 32 units.
pub fn split_by_weight(
    total: u64,
    weights: &[(StealthAddress, u64)],
) -> Result<Vec<(StealthAddress, u64)>> {
    let sum: u128 = weights.iter().map(|(_, w)| *w as u128).sum();
    if sum == 0 {
        bail!("payout weights sum to zero");
    }
    let payees = weights.iter().filter(|(_, w)| *w > 0).count() as u64;
    let floor = if payees > 0 && total >= payees { 1 } else { 0 };
    let rest = (total - floor * payees) as u128;
    let mut out: Vec<(StealthAddress, u64)> = weights
        .iter()
        .map(|(a, w)| {
            let share = ((rest * *w as u128) / sum) as u64;
            (*a, if *w > 0 { share + floor } else { share })
        })
        .collect();
    let paid: u64 = out.iter().map(|(_, v)| *v).sum();
    let first = weights
        .iter()
        .position(|(_, w)| *w > 0)
        .expect("a positive weight exists");
    out[first].1 += total - paid;
    out.retain(|(_, v)| *v > 0);
    Ok(out)
}

/// [`build_template`] with the reward split across weighted payouts and
/// miner data in the coinbase `extra` field. Also returns one receipt per
/// surviving payout, in coinbase output order.
pub fn build_template_with(
    state: &State,
    previous_timestamps: &[u64],
    txs: &[Transaction],
    payouts: &[(StealthAddress, u64)],
    extra: [u8; 32],
    timestamp: Option<u64>,
) -> Result<(BlockTemplate, Vec<(StealthAddress, PayoutReceipt)>)> {
    build_template_bonded(state, previous_timestamps, txs, payouts, extra, timestamp, None)
}

/// [`build_template_with`], mined under `bond`: the block carries the bond's
/// registration until the chain has it, and is signed by its mining key.
pub fn build_template_bonded(
    state: &State,
    previous_timestamps: &[u64],
    txs: &[Transaction],
    payouts: &[(StealthAddress, u64)],
    extra: [u8; 32],
    timestamp: Option<u64>,
    bond: Option<&MinerBond>,
) -> Result<(BlockTemplate, Vec<(StealthAddress, PayoutReceipt)>)> {
    let height = state.height;
    if height == 0 {
        bail!("genesis is not mined");
    }
    if payouts.is_empty() || payouts.len() > crate::core::mw::crypto::MAX_GROUP_OUTPUTS {
        bail!(
            "a coinbase pays 1..={} addresses",
            crate::core::mw::crypto::MAX_GROUP_OUTPUTS
        );
    }
    // Bonded mining: from BONDED_MINING_FROM a template needs a bond to sign
    // with, and carries that bond's registration until the chain has it.
    if height >= BONDED_MINING_FROM && bond.is_none() {
        bail!(
            "bonded mining is required from height {BONDED_MINING_FROM}: configure a mining bond"
        );
    }
    let registrations: Vec<BondRegistration> = match bond {
        Some(b) if !state.bonds.contains_key(&b.bond_id) => match &b.registration {
            Some(registration) => vec![registration.clone()],
            None => bail!("the mining bond is not registered on this chain and no registration is configured"),
        },
        _ => Vec::new(),
    };
    let body = Transaction::aggregate(txs)?;
    let fees = body.fee()?;
    let amount = block_reward(height)
        .checked_add(fees)
        .ok_or_else(|| anyhow!("reward overflow"))?;
    // After the last coin is issued, a block with no fees pays nobody and
    // carries no coinbase at all (`state::validate_block_contents`).
    let (coinbase, receipts) = if amount == 0 {
        (None, Vec::new())
    } else {
        let split = split_by_weight(amount, payouts)?;
        let (cb, receipts) = build_coinbase_with(&split, extra)?;
        let receipts: Vec<(StealthAddress, PayoutReceipt)> =
            split.iter().map(|(a, _)| *a).zip(receipts).collect();
        (Some(cb), receipts)
    };

    let mut next = apply_body(state, &body, coinbase.as_ref())?;
    super::state::apply_registrations(&mut next, &registrations)?;
    let state_root = next.state_root();
    let timestamp = timestamp
        .unwrap_or_else(|| current_timestamp().max(min_next_timestamp(previous_timestamps)));

    let mut batch = Batch {
        prev_midstate: state.mw_midstate,
        prev_header_hash: state.header_hash,
        body,
        coinbase,
        registrations,
        miner: None,
        extension: Extension {
            nonce: 0,
            final_hash: [0u8; 32],
        },
        timestamp,
        target: state.target,
        state_root,
        aux_pow: None,
    };
    // Structural self-check (skip proofs: they were verified on admission and
    // the coinbase was just built here).
    validate_block_contents(&batch, height, true)?;
    if let Some(bond) = bond {
        let message = authorization_message(&state.mw_midstate, &batch);
        batch.miner = Some(MinerAuth {
            bond_id: bond.bond_id,
            signature: bond.sign(&message),
        });
        check_miner_authorization(&next.bonds, &state.mw_midstate, &batch)?;
    }

    let mut header = batch.header();
    header.height = height;
    let mining_hash = compute_header_hash(&header);
    batch.extension.final_hash = [0u8; 32];
    Ok((
        BlockTemplate {
            batch,
            mining_hash,
            height,
            fees,
        },
        receipts,
    ))
}
