//! Building transactions and coinbases (the wallet side of `transaction.rs`).
//!
//! Follows pluribit's `Wallet::create_transaction` flow (select inputs, pay the
//! recipient, return change to self, one aggregated range proof, one kernel)
//! and adds the pieces the ownership fix needs: input signatures, the owner
//! excess and both offsets.

use super::crypto::{compress, random_scalar, Point32};
use super::stealth::{new_output, NewOutput, PayoutReceipt, StealthAddress};
use super::transaction::{
    Coinbase, Context, Input, Kernel, KernelFeatures, OutputGroup, Transaction, TxBody,
};
use anyhow::{anyhow, bail, Result};
use curve25519_dalek::scalar::Scalar;
use rand::seq::SliceRandom;

/// An unspent output the wallet can spend.
#[derive(Clone)]
pub struct Spendable {
    pub commitment: Point32,
    pub value: u64,
    pub blinding: Scalar,
    pub owner_secret: Scalar,
}

#[derive(Clone, Debug)]
pub struct Payment {
    pub to: StealthAddress,
    pub value: u64,
}

/// A built transaction plus what the sender needs to remember about it.
pub struct BuiltTransaction {
    pub tx: Transaction,
    /// Commitment and value of the change output, if any.
    pub change: Option<(Point32, u64)>,
}

/// Builds and self-validates a transaction.
///
/// ```text
///   e  = Σ r_out − Σ r_in − o        so  Σ C_out − Σ C_in + fee·G = e·H + o·H
///   e' = Σ ko_in − x                 so  Σ Ko_in = e'·G + x·G
/// ```
pub fn build_transaction(
    spend: &[Spendable],
    payments: &[Payment],
    change_to: &StealthAddress,
    fee: u64,
    min_height: u64,
) -> Result<BuiltTransaction> {
    if spend.is_empty() {
        bail!("no inputs selected");
    }
    if payments.is_empty() {
        bail!("no payments");
    }
    if payments.iter().any(|p| p.value == 0) {
        bail!("payment values must be positive");
    }
    let total_in = spend
        .iter()
        .try_fold(0u64, |acc, s| acc.checked_add(s.value))
        .ok_or_else(|| anyhow!("input value overflow"))?;
    let total_out = payments
        .iter()
        .try_fold(fee, |acc, p| acc.checked_add(p.value))
        .ok_or_else(|| anyhow!("output value overflow"))?;
    if total_in < total_out {
        bail!("insufficient funds: have {}, need {}", total_in, total_out);
    }
    let change = total_in - total_out;

    let mut created: Vec<NewOutput> = Vec::with_capacity(payments.len() + 1);
    for p in payments {
        created.push(new_output(&p.to, p.value)?);
    }
    let change_commitment = if change > 0 {
        let c = new_output(change_to, change)?;
        let commitment = c.output.commitment;
        created.push(c);
        Some((commitment, change))
    } else {
        None
    };
    // Position inside the group must not reveal which output is change.
    created.shuffle(&mut rand::thread_rng());

    let sum_out: Scalar = created.iter().map(|c| c.blinding).sum();
    let sum_in: Scalar = spend.iter().map(|s| s.blinding).sum();
    let sum_owner: Scalar = spend.iter().map(|s| s.owner_secret).sum();

    let values: Vec<u64> = created.iter().map(|c| c.value).collect();
    let blindings: Vec<Scalar> = created.iter().map(|c| c.blinding).collect();
    let outputs = created.iter().map(|c| c.output.clone()).collect();
    let group = OutputGroup::prove(outputs, &values, &blindings)?;

    let mut inputs: Vec<Input> = spend
        .iter()
        .map(|s| Input::sign(s.commitment, &s.owner_secret))
        .collect();
    inputs.sort_by(|a, b| a.commitment.cmp(&b.commitment));

    // Re-draw in the (negligible) case of an identity excess, which the
    // consensus rules reject.
    let (offset, owner_offset, kernel) = loop {
        let offset = random_scalar();
        let owner_offset = random_scalar();
        let e = sum_out - sum_in - offset;
        let e_owner = sum_owner - owner_offset;
        if e != Scalar::ZERO && e_owner != Scalar::ZERO {
            break (
                offset,
                owner_offset,
                Kernel::new(KernelFeatures::Plain, fee, min_height, &e, &e_owner),
            );
        }
    };

    let tx = Transaction {
        body: TxBody {
            inputs,
            outputs: vec![group],
            kernels: vec![kernel],
        },
        kernel_offset: offset.to_bytes(),
        owner_offset: owner_offset.to_bytes(),
    };
    tx.validate(Context::Relay)?;
    Ok(BuiltTransaction {
        tx,
        change: change_commitment,
    })
}

/// Builds a coinbase paying `amount` split across `payouts` (the split must
/// sum to `amount`). Most miners pass a single payout.
pub fn build_coinbase(payouts: &[(StealthAddress, u64)]) -> Result<Coinbase> {
    Ok(build_coinbase_with(payouts, [0u8; 32])?.0)
}

/// [`build_coinbase`] with miner data in `extra`, also returning one
/// [`PayoutReceipt`] per payout (same order as `payouts`).
pub fn build_coinbase_with(
    payouts: &[(StealthAddress, u64)],
    extra: [u8; 32],
) -> Result<(Coinbase, Vec<PayoutReceipt>)> {
    if payouts.is_empty() {
        bail!("coinbase needs at least one payout");
    }
    let mut created = Vec::with_capacity(payouts.len());
    for (to, value) in payouts {
        if *value == 0 {
            bail!("coinbase payouts must be positive");
        }
        created.push(new_output(to, *value)?);
    }
    let values: Vec<u64> = created.iter().map(|c| c.value).collect();
    let blindings: Vec<Scalar> = created.iter().map(|c| c.blinding).collect();
    let excess_secret: Scalar = blindings.iter().sum();
    let receipts = created
        .iter()
        .enumerate()
        .map(|(i, c)| PayoutReceipt {
            output_index: i,
            value: c.value,
            blinding: c.blinding.to_bytes(),
            ephemeral_secret: c.ephemeral_secret.to_bytes(),
        })
        .collect();
    let outputs = created.iter().map(|c| c.output.clone()).collect();
    let group = OutputGroup::prove(outputs, &values, &blindings)?;
    let kernel = Kernel::new(
        KernelFeatures::Coinbase,
        0,
        0,
        &excess_secret,
        &Scalar::ZERO,
    );
    let cb = Coinbase {
        outputs: group,
        kernel,
        extra,
    };
    cb.validate_structure()?;
    Ok((cb, receipts))
}

/// Convenience for tests and tools: the owner key a secret signs for.
pub fn owner_key_of(owner_secret: &Scalar) -> Point32 {
    compress(&curve25519_dalek::ristretto::RistrettoPoint::mul_base(
        owner_secret,
    ))
}
