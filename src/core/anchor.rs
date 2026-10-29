//! Checkpoints of Midwimble state and evidence that Midstate recorded them
//! (`docs/ANCHORING.md` §3–4). Midstate is not modified: to it an anchor is an
//! ordinary Commit transaction or coinbase salt.

use super::auxpow::{bytes32, merge_commitment, midstate_coin_id, tx_fold_item};
use super::simd_mining::{check_pow_jobs, PowCheck, PowJob};
use super::state::calculate_work;
use super::types::{
    hash_concat, hash_domain, midstate_header_hash, midstate_pow_algo_at, network_anchor,
    BatchHeader, PowAlgo,
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

/// Identifies a Midstate header whose proof of work has been checked under
/// `algo`: its mining hash (which commits to its predecessor and every
/// field), nonce and final hash. Equal keys mean the same proof-of-work
/// computation. Keys of BLAKE3-chain headers are what they always were.
pub fn link_key(mining_hash: &[u8; 32], link: &HeaderLink, algo: PowAlgo) -> [u8; 32] {
    let domain: &[u8] = match algo {
        PowAlgo::Blake3Chain => b"midwimble.checked-midstate-header.v1",
        PowAlgo::Walk => b"midwimble.checked-midstate-header.walk.v1",
    };
    hash_domain(
        domain,
        &[mining_hash, &link.nonce.to_le_bytes(), &link.final_hash],
    )
}

/// The mining hash a Midstate header link commits its proof of work to.
pub(crate) fn link_mining_hash(prev: [u8; 32], link: &HeaderLink) -> [u8; 32] {
    midstate_header_hash(
        &prev,
        &link.post_tx_midstate,
        &link.state_root,
        link.timestamp,
        &link.target,
    )
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
    ///
    /// The two halves are also available separately, so a caller can tell
    /// evidence that is merely weaker than it asks for
    /// ([`MidstateInclusion::check_policy`]) from evidence that is forged
    /// ([`MidstateInclusion::verify_proofs`]).
    pub fn verify(&self, payload: &[u8; 32], depth: usize, min_work: u128) -> Result<()> {
        self.check_policy(depth, min_work)?;
        self.verify_proofs(payload)
    }

    /// The headers: the anchor block, then its confirmations.
    pub fn links(&self) -> impl Iterator<Item = &HeaderLink> {
        std::iter::once(&self.block).chain(&self.confirmations)
    }

    /// The configurable, cheap half of [`MidstateInclusion::verify`]: enough
    /// confirmations, and at least `min_work` claimed by every header. Nothing
    /// here hashes a chain, so it runs before anything that does. Failing it
    /// says the evidence is weaker than this node asks for, not that it is
    /// forged: another node may be configured to accept it.
    pub fn check_policy(&self, depth: usize, min_work: u128) -> Result<()> {
        if self.confirmations.len() + 1 < depth {
            bail!(
                "anchor has {} confirmation(s), {} required",
                self.confirmations.len() + 1,
                depth
            );
        }
        if let Some(i) = self
            .links()
            .position(|l| calculate_work(&l.target) < min_work)
        {
            bail!("Midstate header {i} of the anchor evidence claims too little work");
        }
        Ok(())
    }

    /// The half of [`MidstateInclusion::verify`] that proves the evidence
    /// genuine: `payload` folds into the anchor block, every header meets its
    /// own target, and every header's proof of work holds over its
    /// predecessor (which is also what links them). Failing it means the
    /// evidence was forged.
    ///
    /// Cheap checks come first, then the proofs of work: the first alone, so
    /// a forged record costs one extension to reject, then the rest in
    /// parallel SIMD batches.
    ///
    /// Each header is checked with the proof of work midstate requires at the
    /// height the evidence gives it (`midstate_height`, then one more for each
    /// confirmation). Like everything else here that height is the prover's
    /// claim: a forger may label headers below midstate's switch to Midstate
    /// Walk and do BLAKE3-chain work, as forging cost before the switch.
    pub fn verify_proofs(&self, payload: &[u8; 32]) -> Result<()> {
        self.verify_proofs_with(payload, |_| false).map(|_| ())
    }

    /// [`MidstateInclusion::verify_proofs`], skipping the proof of work of
    /// headers whose [`link_key`] `known` recognises (headers the caller has
    /// already checked: consecutive anchors share nearly all of theirs).
    /// Returns the keys of every header, to remember once the whole
    /// evidence has been accepted.
    pub fn verify_proofs_with(
        &self,
        payload: &[u8; 32],
        known: impl Fn(&[u8; 32]) -> bool,
    ) -> Result<Vec<[u8; 32]>> {
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
        let mut prev = self.prev_header_hash;
        let mut keys = Vec::with_capacity(self.confirmations.len() + 1);
        let mut jobs = Vec::new();
        let mut index = Vec::new();
        for (i, link) in self.links().enumerate() {
            if link.final_hash >= link.target {
                bail!("Midstate header {i} of the anchor evidence misses its own target");
            }
            let algo = midstate_pow_algo_at(self.midstate_height.saturating_add(i as u64));
            let mining = link_mining_hash(prev, link);
            let key = link_key(&mining, link, algo);
            if !known(&key) {
                jobs.push(PowJob {
                    algo,
                    mining_hash: mining,
                    nonce: link.nonce,
                    final_hash: link.final_hash,
                });
                index.push(i);
            }
            keys.push(key);
            prev = link.final_hash;
        }
        match check_pow_jobs(&jobs) {
            Ok(()) => Ok(keys),
            Err(PowCheck::Bad(j)) => bail!(
                "Midstate header {} of the anchor evidence fails its proof of work",
                index[j]
            ),
            Err(PowCheck::Abandoned) => bail!("anchor verification abandoned"),
        }
    }

    /// Drops confirmations beyond the `depth` (anchor block included) a
    /// verifier asks for: they add nothing to the evidence, and a record
    /// stored and passed on should cost the next node no more than needed.
    pub fn trim(&mut self, depth: usize) {
        self.confirmations.truncate(depth.saturating_sub(1));
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
    use crate::core::extension::create_extension_with;
    use crate::core::types::{hash, Batch, State};

    /// Genuine evidence for `payload` (a Commit) with `confirmations` more
    /// headers, on the easiest target so each header is a single extension.
    fn evidence(payload: &[u8; 32], n: usize) -> MidstateInclusion {
        evidence_at(10, payload, n)
    }

    /// [`evidence`] for a block at midstate height `height`, each header
    /// mined with the proof of work midstate requires at its height.
    fn evidence_at(height: u64, payload: &[u8; 32], n: usize) -> MidstateInclusion {
        let mine = |prev: [u8; 32], post: [u8; 32], i: u64| {
            let mut link = HeaderLink {
                post_tx_midstate: post,
                state_root: [0; 32],
                timestamp: 1_800_000_000 + i,
                target: [0xff; 32],
                nonce: 0,
                final_hash: [0; 32],
            };
            let algo = midstate_pow_algo_at(height + i);
            link.final_hash =
                create_extension_with(algo, link_mining_hash(prev, &link), 0).final_hash;
            link
        };
        let pre = hash(b"pre");
        let prev = hash(b"prev");
        let block = mine(prev, hash_concat(&pre, payload), 0);
        let mut confirmations = Vec::new();
        let mut last = block.final_hash;
        for i in 0..n {
            let link = mine(last, hash(&(i as u64).to_le_bytes()), 1 + i as u64);
            last = link.final_hash;
            confirmations.push(link);
        }
        MidstateInclusion {
            midstate_height: height,
            kind: AnchoredItem::Commit,
            pre_item_midstate: pre,
            items_after: vec![],
            prev_header_hash: prev,
            block,
            confirmations,
        }
    }

    /// Evidence straddling midstate's switch to Midstate Walk: its headers
    /// carry the chain below the switch and the Walk from it, and the same
    /// headers given another height fail.
    #[test]
    fn evidence_follows_midstates_switch_to_the_walk() {
        use crate::core::types::MIDSTATE_WALK_ACTIVATION_HEIGHT as SWITCH;
        let payload = hash(b"straddling");
        let ev = evidence_at(SWITCH - 1, &payload, 2);
        ev.verify_proofs(&payload).unwrap();
        let mut shifted = ev.clone();
        shifted.midstate_height = SWITCH;
        assert!(shifted.verify_proofs(&payload).is_err());
        // A key remembered for one algorithm does not vouch for the other.
        let mining = link_mining_hash(ev.prev_header_hash, &ev.block);
        assert_ne!(
            link_key(&mining, &ev.block, PowAlgo::Blake3Chain),
            link_key(&mining, &ev.block, PowAlgo::Walk)
        );
    }

    #[test]
    fn evidence_policy_and_proofs_are_separate_checks() {
        let payload = hash(b"checkpoint id");
        let ev = evidence(&payload, 2);
        ev.verify(&payload, 3, 1).unwrap();
        // Asking for more than it has is policy: the evidence is still genuine.
        assert!(ev.check_policy(4, 1).is_err());
        assert!(ev.check_policy(3, u128::MAX).is_err());
        ev.verify_proofs(&payload).unwrap();
        // A tampered header is forgery.
        let mut forged = ev.clone();
        forged.confirmations[1].nonce ^= 1;
        let err = forged.verify_proofs(&payload).unwrap_err().to_string();
        assert!(err.contains("proof of work"), "{err}");
        // So is a header that misses its own target, caught before hashing.
        let mut lazy = ev.clone();
        lazy.block.target = [0; 32];
        assert!(lazy
            .verify_proofs(&payload)
            .unwrap_err()
            .to_string()
            .contains("own target"));
        // Another payload does not fold in.
        assert!(ev.verify_proofs(&hash(b"another")).is_err());
        // Headers already checked are skipped; the rest are still checked,
        // and a tampered header never matches a checked one's key.
        let keys = ev.verify_proofs_with(&payload, |_| false).unwrap();
        assert_eq!(keys.len(), 3);
        assert_eq!(
            ev.verify_proofs_with(&payload, |k| keys.contains(k))
                .unwrap(),
            keys
        );
        let err = forged
            .verify_proofs_with(&payload, |k| keys.contains(k))
            .unwrap_err()
            .to_string();
        assert!(err.contains("header 2"), "{err}");
        // Trimming keeps exactly what a verifier asks for.
        let mut trimmed = ev.clone();
        trimmed.trim(2);
        assert_eq!(trimmed.confirmations.len(), 1);
        trimmed.verify(&payload, 2, 1).unwrap();
    }

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
