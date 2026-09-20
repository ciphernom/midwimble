//! Checkpoints of Midwimble state and evidence that Midstate recorded them
//! (`docs/ANCHORING.md` §3–4). Midstate is not modified: to it an anchor is an
//! ordinary Commit transaction or coinbase salt.

use super::auxpow::{bytes32, merge_commitment, midstate_coin_id, tx_fold_item};
use super::extension::create_extension;
use super::state::calculate_work;
use super::types::{
    compute_header_hash, hash_concat, hash_domain, network_anchor, BatchHeader, Extension,
};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CHECKPOINT_VERSION: u8 = 1;

/// A Midwimble state commitment small enough to notarise anywhere.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Checkpoint {
    pub version: u8,
    pub network: [u8; 32],
    /// Blocks in the checkpointed chain.
    pub mw_height: u64,
    /// Id of block `mw_height - 1`.
    pub mw_header_hash: [u8; 32],
    /// State root committed by that block's header.
    pub mw_state_root: [u8; 32],
    pub mw_cumulative_work: u128,
    pub previous_checkpoint: [u8; 32],
}

impl Checkpoint {
    /// Checkpoint at `tip` (a header with its height filled in).
    pub fn new(tip: &BatchHeader, cumulative_work: u128, previous_checkpoint: [u8; 32]) -> Self {
        Self {
            version: CHECKPOINT_VERSION,
            network: network_anchor(),
            mw_height: tip.height + 1,
            mw_header_hash: tip.extension.final_hash,
            mw_state_root: tip.state_root,
            mw_cumulative_work: cumulative_work,
            previous_checkpoint,
        }
    }

    pub fn id(&self) -> [u8; 32] {
        let bytes = bincode::serialize(self).expect("checkpoint serialization cannot fail");
        hash_domain(b"midwimble.midstate-anchor.v1", &[&bytes])
    }

    /// Checks the checkpoint describes this node's own chain.
    pub fn matches(&self, tip: &BatchHeader, cumulative_work: u128) -> Result<()> {
        if self.version != CHECKPOINT_VERSION || self.network != network_anchor() {
            bail!("checkpoint is for another network or version");
        }
        if tip.height + 1 != self.mw_height
            || tip.extension.final_hash != self.mw_header_hash
            || tip.state_root != self.mw_state_root
            || cumulative_work != self.mw_cumulative_work
        {
            bail!(
                "checkpoint does not describe this chain at height {}",
                self.mw_height
            );
        }
        Ok(())
    }
}

/// What the anchored 32-byte item is.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnchoredItem {
    /// A Midstate Commit transaction whose commitment is a checkpoint id.
    Commit,
    /// A Midstate coinbase output whose salt merge-commits to a Midwimble
    /// header (see `auxpow.rs`); the output's address and value.
    MergeMined { address: [u8; 32], value: u64 },
}

impl AnchoredItem {
    /// The fold item a payload produces (payload: a checkpoint id, or a
    /// Midwimble mining hash for merge-mined anchors).
    pub fn fold_item(&self, payload: &[u8; 32]) -> [u8; 32] {
        match self {
            AnchoredItem::Commit => *payload,
            AnchoredItem::MergeMined { address, value } => {
                midstate_coin_id(address, *value, &merge_commitment(payload))
            }
        }
    }
}

/// A later Midstate header, linked by `prev_header_hash = previous final hash`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeaderLink {
    pub post_tx_midstate: [u8; 32],
    pub state_root: [u8; 32],
    pub timestamp: u64,
    pub target: [u8; 32],
    pub nonce: u64,
    pub final_hash: [u8; 32],
}

/// The mining hash a Midstate header link commits its proof of work to.
pub(crate) fn link_mining_hash(prev: [u8; 32], link: &HeaderLink) -> [u8; 32] {
    compute_header_hash(&BatchHeader {
        height: 0,
        prev_midstate: [0; 32],
        post_tx_midstate: link.post_tx_midstate,
        extension: Extension {
            nonce: 0,
            final_hash: [0; 32],
        },
        timestamp: link.timestamp,
        target: link.target,
        state_root: link.state_root,
        prev_header_hash: prev,
        aux_pow: None,
    })
}

pub(crate) fn header_pow_ok(prev: [u8; 32], link: &HeaderLink, min_work: u128) -> bool {
    let mining = link_mining_hash(prev, link);
    link.final_hash < link.target
        && calculate_work(&link.target) >= min_work
        && create_extension(mining, link.nonce).final_hash == link.final_hash
}

/// Proof that a 32-byte item is folded into a Midstate block's mining hash,
/// plus later headers as confirmations.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MidstateInclusion {
    pub midstate_height: u64,
    pub kind: AnchoredItem,
    pub pre_item_midstate: [u8; 32],
    pub items_after: Vec<[u8; 32]>,
    pub prev_header_hash: [u8; 32],
    /// The anchor block's own header fields (its post-tx midstate is
    /// recomputed from the fold).
    pub block: HeaderLink,
    pub confirmations: Vec<HeaderLink>,
}

impl MidstateInclusion {
    /// Verifies that `payload` is anchored in a Midstate block with valid
    /// proof of work and at least `depth` blocks (itself included), each
    /// carrying at least `min_work`.
    ///
    /// This is SPV-level assurance: it proves real work was spent on these
    /// headers, not that they are on Midstate's best chain. Cross-check with a
    /// trusted Midstate node where that matters.
    pub fn verify(&self, payload: &[u8; 32], depth: usize, min_work: u128) -> Result<()> {
        let mut m = hash_concat(&self.pre_item_midstate, &self.kind.fold_item(payload));
        for item in &self.items_after {
            m = hash_concat(&m, item);
        }
        if self.block.state_root != [0u8; 32] {
            m = hash_concat(&m, &self.block.state_root);
        }
        if m != self.block.post_tx_midstate {
            bail!("the anchored item does not fold into the Midstate block");
        }
        if !header_pow_ok(self.prev_header_hash, &self.block, min_work) {
            bail!("the Midstate block's proof of work is invalid or too weak");
        }
        let mut prev = self.block.final_hash;
        for (i, link) in self.confirmations.iter().enumerate() {
            if !header_pow_ok(prev, link, min_work) {
                bail!("confirmation {} is invalid, unlinked or too weak", i + 1);
            }
            prev = link.final_hash;
        }
        if self.confirmations.len() + 1 < depth {
            bail!(
                "anchor has {} confirmation(s), {} required",
                self.confirmations.len() + 1,
                depth
            );
        }
        Ok(())
    }

    /// Builds evidence from Midstate `/batch/{h}` JSON: the anchor block at
    /// `height` and the blocks that follow it.
    pub fn from_midstate_json(
        height: u64,
        block: &Value,
        kind: AnchoredItem,
        payload: &[u8; 32],
        following: &[Value],
    ) -> Result<Self> {
        let (prev_midstate, items) = midstate_fold_items(block)?;
        let wanted = kind.fold_item(payload);
        let idx = items
            .iter()
            .position(|x| *x == wanted)
            .ok_or_else(|| anyhow!("item not in Midstate block {height}"))?;
        let mut pre = prev_midstate;
        for item in &items[..idx] {
            pre = hash_concat(&pre, item);
        }
        let mut prev = bytes32(&block["extension"]["final_hash"])?;
        let mut confirmations = Vec::with_capacity(following.len());
        for b in following {
            if bytes32(&b["prev_header_hash"])? != prev {
                bail!("following Midstate blocks do not link");
            }
            let link = midstate_header_link(b)?;
            prev = link.final_hash;
            confirmations.push(link);
        }
        Ok(Self {
            midstate_height: height,
            kind,
            pre_item_midstate: pre,
            items_after: items[idx + 1..].to_vec(),
            prev_header_hash: bytes32(&block["prev_header_hash"])?,
            block: midstate_header_link(block)?,
            confirmations,
        })
    }
}

/// A Midstate block's fold inputs: its previous midstate, then every
/// transaction item and coinbase coin id in order.
pub fn midstate_fold_items(batch: &Value) -> Result<([u8; 32], Vec<[u8; 32]>)> {
    let prev = bytes32(&batch["prev_midstate"])?;
    let mut items = Vec::new();
    for tx in batch["transactions"]
        .as_array()
        .ok_or_else(|| anyhow!("no transactions array"))?
    {
        items.push(tx_fold_item(tx)?);
    }
    for cb in batch["coinbase"].as_array().cloned().unwrap_or_default() {
        let value = cb["value"]
            .as_u64()
            .ok_or_else(|| anyhow!("coinbase value missing"))?;
        items.push(midstate_coin_id(
            &bytes32(&cb["address"])?,
            value,
            &bytes32(&cb["salt"])?,
        ));
    }
    Ok((prev, items))
}

/// A Midstate block's header fields, recomputing its post-tx midstate.
pub fn midstate_header_link(batch: &Value) -> Result<HeaderLink> {
    let (mut m, items) = midstate_fold_items(batch)?;
    for item in &items {
        m = hash_concat(&m, item);
    }
    let state_root = bytes32(&batch["state_root"])?;
    if state_root != [0u8; 32] {
        m = hash_concat(&m, &state_root);
    }
    Ok(HeaderLink {
        post_tx_midstate: m,
        state_root,
        timestamp: batch["timestamp"]
            .as_u64()
            .ok_or_else(|| anyhow!("timestamp missing"))?,
        target: bytes32(&batch["target"])?,
        nonce: batch["extension"]["nonce"]
            .as_u64()
            .ok_or_else(|| anyhow!("nonce missing"))?,
        final_hash: bytes32(&batch["extension"]["final_hash"])?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{Batch, State};

    #[test]
    fn checkpoint_ids_bind_every_field() {
        let mut g = Batch::genesis().header();
        g.height = 0;
        let a = Checkpoint::new(&g, 5, [0; 32]);
        a.matches(&g, 5).unwrap();
        assert!(a.matches(&g, 6).is_err());
        let mut b = a.clone();
        b.mw_state_root[0] ^= 1;
        assert_ne!(a.id(), b.id());
        let mut c = a.clone();
        c.previous_checkpoint = [1; 32];
        assert_ne!(a.id(), c.id());
        let _ = State::genesis();
    }
}
