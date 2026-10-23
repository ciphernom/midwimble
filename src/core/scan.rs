//! What a light wallet reads instead of whole blocks.
//!
//! A wallet finds its payments by trying its view key on every output: one
//! scalar multiplication on the output's ephemeral key gives the shared
//! secret, and the view tag (`stealth.rs`) then rules out 255 of 256 foreign
//! outputs before anything is decrypted. That takes 33 bytes of an output,
//! its ephemeral key and view tag, out of the several hundred it occupies in
//! a block. A wallet sees its coins spent by their commitments among a
//! block's inputs, and a prefix of each commitment does as well.
//!
//! So a light wallet reads each block's [`ScanBlock`] and asks for the whole
//! block only when one of its outputs carries the wallet's view tag (or one
//! in 256 foreign outputs, by chance) or one of its inputs may spend a coin
//! of the wallet's. Most blocks it never downloads. The scan data names each
//! block's header hash, which commits to the block's transactions and
//! coinbase, so a whole block can come from any node: the wallet checks it
//! against the scan data before using it.
//!
//! Compact block filters (`filter.rs`) cannot find stealth payments: a
//! filter answers whether a block holds a given item, and a wallet cannot
//! name its outputs' items before it has found them.

use super::mw::crypto::Point32;
use super::types::{compute_header_hash, Batch};
use anyhow::{anyhow, Result};
use bincode::Options;
use serde::{Deserialize, Serialize};

/// Bytes kept of each input's commitment: a coin of the wallet's and an
/// unrelated input share them by chance once in 2^64 comparisons, and then
/// the wallet only downloads a block it did not need.
pub const INPUT_PREFIX: usize = 8;

/// A block, as much of it as a wallet needs to tell whether the block
/// concerns it: about 100 bytes for a block with nothing but its reward.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanBlock {
    /// The block's id (`extension.final_hash`): what the next block's
    /// `prev_header_hash` names.
    pub id: [u8; 32],
    /// The hash its proof of work is over ([`compute_header_hash`]), which
    /// commits to its transactions and coinbase, and to the block before it.
    pub header_hash: [u8; 32],
    /// `(ephemeral key, view tag)` of every output, the body's and then the
    /// coinbase's.
    pub outputs: Vec<(Point32, u8)>,
    /// The first [`INPUT_PREFIX`] bytes of every input's commitment.
    pub inputs: Vec<[u8; INPUT_PREFIX]>,
}

impl ScanBlock {
    pub fn of(batch: &Batch) -> Self {
        let coinbase = batch.coinbase.iter().flat_map(|c| c.outputs.outputs.iter());
        Self {
            id: batch.extension.final_hash,
            header_hash: compute_header_hash(&batch.header()),
            outputs: batch
                .body
                .outputs()
                .chain(coinbase)
                .map(|o| (o.ephemeral_key, o.view_tag))
                .collect(),
            inputs: batch.body.input_commitments().map(input_prefix).collect(),
        }
    }
}

/// Consecutive blocks' scan data, as `get_scan_data` sends it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRun {
    /// The id of the block the first one builds on; each of the others
    /// builds on the one before it.
    pub prev: [u8; 32],
    pub blocks: Vec<ScanBlock>,
}

impl ScanRun {
    /// The scan data of consecutive blocks, the first built on `prev`.
    pub fn of(prev: [u8; 32], batches: &[Batch]) -> Self {
        Self {
            prev,
            blocks: batches.iter().map(ScanBlock::of).collect(),
        }
    }

    /// The id of the block that block `i` builds on.
    pub fn prev_of(&self, i: usize) -> [u8; 32] {
        match i {
            0 => self.prev,
            _ => self.blocks[i - 1].id,
        }
    }

    /// Whether `batch` is block `i` of the run. Its header hash binds the
    /// block's contents and its link to the block before, and everything
    /// else here is read from them, so a block from one node that matches
    /// another node's scan data is the block both nodes hold, and scan data
    /// that left something out does not match the block it came from.
    pub fn describes(&self, i: usize, batch: &Batch) -> bool {
        i < self.blocks.len()
            && batch.prev_header_hash == self.prev_of(i)
            && self.blocks[i] == ScanBlock::of(batch)
    }

    /// bincode with variable-length integers: a list's length takes one
    /// byte rather than eight, a tenth of a bare block's scan data.
    pub fn encode(&self) -> Vec<u8> {
        encoding()
            .serialize(self)
            .expect("scan data always serializes")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        encoding()
            .deserialize(bytes)
            .map_err(|e| anyhow!("not scan data: {e}"))
    }

    /// The encoded size `block` adds to a run.
    pub fn size_of(block: &ScanBlock) -> usize {
        encoding().serialized_size(block).unwrap_or(u64::MAX) as usize
    }
}

fn encoding() -> impl Options {
    bincode::DefaultOptions::new()
        .with_varint_encoding()
        .with_limit(64 << 20)
}

/// The part of a commitment that [`ScanBlock::inputs`] keeps.
pub fn input_prefix(commitment: &Point32) -> [u8; INPUT_PREFIX] {
    commitment[..INPUT_PREFIX]
        .try_into()
        .expect("a commitment is longer than its prefix")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::mw::stealth::{new_output, WalletKeys};
    use crate::core::types::hash;

    fn block_paying(to: &crate::core::mw::StealthAddress) -> Batch {
        let mut b = Batch::genesis().clone();
        let paid = new_output(to, 5).unwrap().output;
        b.body.body.outputs.push(crate::core::mw::OutputGroup {
            outputs: vec![paid],
            range_proof: Vec::new(),
        });
        b
    }

    #[test]
    fn scan_data_carries_what_a_wallet_needs_and_nothing_else() {
        let bob = WalletKeys::random();
        let block = block_paying(&bob.address());
        let run = ScanRun::of(block.prev_header_hash, std::slice::from_ref(&block));
        let scan = &run.blocks[0];
        assert_eq!(scan.id, block.extension.final_hash);
        assert_eq!(scan.header_hash, compute_header_hash(&block.header()));
        let out = block.body.outputs().next().unwrap();
        assert_eq!(scan.outputs, vec![(out.ephemeral_key, out.view_tag)]);
        assert!(scan.inputs.is_empty());
        assert!(run.describes(0, &block));
        assert!(!run.describes(1, &block));
        assert_eq!(ScanRun::decode(&run.encode()).unwrap(), run);
        assert!(ScanRun::decode(&[0xff; 7]).is_err());
        // Two hashes, one output, two short lengths.
        assert_eq!(ScanRun::size_of(scan), 32 + 32 + 1 + 33 + 1);
        let whole = bincode::serialized_size(&block).unwrap() as usize;
        assert!(ScanRun::size_of(scan) * 3 < whole, "of {whole} bytes");
    }

    #[test]
    fn a_block_that_differs_from_its_scan_data_is_caught() {
        let block = block_paying(&WalletKeys::random().address());
        let run = ScanRun::of(block.prev_header_hash, std::slice::from_ref(&block));

        // Another output in its place, under the same ephemeral key and tag,
        // changes the header hash.
        let mut swapped = block.clone();
        swapped.body.body.outputs[0].outputs[0].commitment = hash(b"another coin");
        assert!(!run.describes(0, &swapped));

        // Scan data that leaves an output out does not describe the block.
        let mut short = run.clone();
        short.blocks[0].outputs.clear();
        assert!(!short.describes(0, &block));

        // Nor does scan data for another block at the same place, or for
        // the same block on another chain.
        let mut other = block.clone();
        other.timestamp += 1;
        assert!(!run.describes(0, &other));
        let mut elsewhere = run.clone();
        elsewhere.prev = hash(b"another chain");
        assert!(!elsewhere.describes(0, &block));
    }

    #[test]
    fn view_tags_pick_out_a_wallets_outputs() {
        let bob = WalletKeys::random();
        let view = bob.view_only();
        let mine = new_output(&bob.address(), 7).unwrap().output;
        assert!(view.may_own(&mine.ephemeral_key, mine.view_tag));
        assert!(!view.may_own(&mine.ephemeral_key, mine.view_tag.wrapping_add(1)));
        // Foreign outputs pass one time in 256.
        let strangers = (0..2048)
            .map(|_| {
                new_output(&WalletKeys::random().address(), 1)
                    .unwrap()
                    .output
            })
            .filter(|o| view.may_own(&o.ephemeral_key, o.view_tag))
            .count();
        assert!(strangers < 40, "{strangers} of 2048 foreign outputs passed");
        // An ephemeral key that is not a point owns nothing.
        assert!(!view.may_own(&[0xff; 32], 0));
    }
}
