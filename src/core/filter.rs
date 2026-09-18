//! Golomb-coded compact block filters, ported from midstate
//! `src/core/filter.rs` with MimbleWimble-specific filter items.

use crate::core::types::{hash_concat, Batch};
use std::collections::HashSet;

/// False Positive Rate = 1 / FPR_INVERSE (1 in 1,000,000)
const FPR_INVERSE: u64 = 1_000_000;
/// Golomb-Rice parameter: 2^P ≈ FPR_INVERSE. For 1,000,000, P = 20.
const P: u8 = 20;

pub struct CompactFilter {
    pub data: Vec<u8>,
}

impl CompactFilter {
    /// Returns the canonical set of items that `build` will fold into the
    /// filter for `batch`. The element count is `items_in(batch).len()`.
    ///
    /// Single source of truth: `build` should call this internally, and any
    /// caller that needs the count alongside the filter (light client push,
    /// GetFilters RPC) should call it here. Drift between filter contents
    /// and reported element count is a consensus break for light clients.
    pub fn items_in(batch: &Batch) -> HashSet<[u8; 32]> {
        // MimbleWimble has no addresses on chain, so a wallet cannot look for
        // payments this way (it scans outputs with its view key instead).
        // The filter answers the questions a light wallet *can* ask with data
        // it already holds: did my output get spent, did my output get mined,
        // did my transaction's kernel confirm.
        let mut items = HashSet::new();
        for input in &batch.body.body.inputs {
            items.insert(input.commitment);
            items.insert(input.owner_key);
        }
        for output in batch.body.outputs() {
            items.insert(output.commitment);
            items.insert(output.owner_key);
        }
        for id in batch.body.kernel_ids() {
            items.insert(id);
        }
        if let Some(cb) = &batch.coinbase {
            for output in &cb.outputs.outputs {
                items.insert(output.commitment);
                items.insert(output.owner_key);
            }
            items.insert(cb.kernel.id());
        }
        items
    }

    /// Build a Golomb-Coded Set filter for a given Batch
    pub fn build(batch: &Batch) -> Self {
        // 1. Get the canonical item set. HashSet already deduplicates, so the
        // explicit sort+dedup the old code did is now subsumed by collection.
        let items = Self::items_in(batch);
        let n = items.len() as u64;
        if n == 0 {
            return Self { data: vec![] };
        }

        // 2. Hash items into a uniform distribution [0, N * FPR]
        let modulus = n * FPR_INVERSE;
        let mut hashes: Vec<u64> = items
            .into_iter()
            .map(|item| {
                // Key the hash with the block's final_hash to prevent precomputation attacks
                let h = hash_concat(&batch.extension.final_hash, &item);
                let raw = u64::from_le_bytes(h[..8].try_into().unwrap());
                raw % modulus
            })
            .collect();

        // 3. Sort hashes to encode deltas
        hashes.sort();

        // 4. Golomb-Rice encoding of the deltas
        let mut writer = BitWriter::new();
        let mut last = 0u64;
        for h in hashes {
            let diff = h - last;
            encode_golomb(&mut writer, diff);
            last = h;
        }

        Self {
            data: writer.into_bytes(),
        }
    }
}

// ── Bit Fiddling Helpers ────────────────────────────────────────────────────

struct BitWriter {
    buffer: Vec<u8>,
    current_byte: u8,
    bits_in_byte: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            current_byte: 0,
            bits_in_byte: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        if bit {
            self.current_byte |= 1 << (7 - self.bits_in_byte);
        }
        self.bits_in_byte += 1;
        if self.bits_in_byte == 8 {
            self.buffer.push(self.current_byte);
            self.current_byte = 0;
            self.bits_in_byte = 0;
        }
    }

    fn write_bits(&mut self, value: u64, count: u8) {
        for i in (0..count).rev() {
            self.write_bit((value >> i) & 1 == 1);
        }
    }

    fn into_bytes(mut self) -> Vec<u8> {
        if self.bits_in_byte > 0 {
            self.buffer.push(self.current_byte);
        }
        self.buffer
    }
}

/// Golomb-Rice encoding: Quotient as unary, remainder as binary
fn encode_golomb(writer: &mut BitWriter, value: u64) {
    let quotient = value >> P;
    let remainder = value & ((1 << P) - 1);

    // Unary encode quotient (Q '1's followed by a '0')
    for _ in 0..quotient {
        writer.write_bit(true);
    }
    writer.write_bit(false);

    // Binary encode remainder
    writer.write_bits(remainder, P);
}

// ── Client-side filter matching ─────────────────────────────────────────────

struct BitReader<'a> {
    data: &'a [u8],
    byte_index: usize,
    bit_index: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_index: 0,
            bit_index: 0,
        }
    }

    fn read_bit(&mut self) -> Option<bool> {
        if self.byte_index >= self.data.len() {
            return None;
        }
        let bit = (self.data[self.byte_index] >> (7 - self.bit_index)) & 1 == 1;
        self.bit_index += 1;
        if self.bit_index == 8 {
            self.bit_index = 0;
            self.byte_index += 1;
        }
        Some(bit)
    }

    fn read_bits(&mut self, count: u8) -> Option<u64> {
        let mut value = 0u64;
        for _ in 0..count {
            value = (value << 1) | (self.read_bit()? as u64);
        }
        Some(value)
    }
}

/// Decode a single Golomb-Rice coded value.
fn decode_golomb(reader: &mut BitReader) -> Option<u64> {
    // Unary: count '1' bits until '0'
    let mut quotient = 0u64;
    loop {
        match reader.read_bit() {
            Some(true) => quotient += 1,
            Some(false) => break,
            None => return None,
        }
    }
    // Binary: read P-bit remainder
    let remainder = reader.read_bits(P)?;
    Some((quotient << P) | remainder)
}

/// Decode an entire filter into the sorted list of hash values.
// only every called by unit tests.
#[allow(dead_code)]
fn decode_filter(data: &[u8], n: u64) -> Vec<u64> {
    if data.is_empty() || n == 0 {
        return vec![];
    }

    // Cap the pre-allocation to prevent OOM panics from malicious RPC nodes.
    // A Golomb-Rice encoded element takes at least 1 bit, so data.len() * 8
    // is the absolute theoretical maximum number of elements.
    let max_possible = (data.len() * 8) as usize;
    let safe_capacity = std::cmp::min(n as usize, max_possible);

    let mut reader = BitReader::new(data);
    let mut values = Vec::with_capacity(safe_capacity);
    let mut cumulative = 0u64;

    for _ in 0..n {
        match decode_golomb(&mut reader) {
            Some(delta) => {
                cumulative += delta;
                values.push(cumulative);
            }
            None => break,
        }
    }
    values
}

/// Check if ANY of the given items might be present in a compact filter.
///
/// `filter_data`: raw Golomb-coded bytes from `CompactFilter::build()` or
///                from the `/filters` RPC endpoint.
/// `block_hash`:  the `extension.final_hash` of the block this filter covers.
///                Required because the filter uses it as a hash key.
/// `n`:           the number of elements encoded in the filter.
/// `items`:       set of 32-byte items to test (addresses, coin_ids, etc).
///
/// Returns `true` if there's a potential match (may be a false positive at
/// rate 1/FPR_INVERSE). Returns `false` only if NO item is in the filter.
pub fn match_any(filter_data: &[u8], block_hash: &[u8; 32], n: u64, items: &[[u8; 32]]) -> bool {
    if filter_data.is_empty() || n == 0 || items.is_empty() {
        return false;
    }

    let modulus = n * FPR_INVERSE;

    // Hash the query items the same way build() does
    let mut query_hashes: Vec<u64> = items
        .iter()
        .map(|item| {
            let h = hash_concat(block_hash, item);
            let raw = u64::from_le_bytes(h[..8].try_into().unwrap());
            raw % modulus
        })
        .collect();
    query_hashes.sort_unstable();
    query_hashes.dedup();

    // Zero-allocation intersection: Decode and compare on the fly
    let mut reader = BitReader::new(filter_data);
    let mut cumulative = 0u64;
    let mut qi = 0;

    for _ in 0..n {
        if qi >= query_hashes.len() {
            break;
        }
        match decode_golomb(&mut reader) {
            Some(delta) => {
                cumulative += delta;
                while qi < query_hashes.len() && query_hashes[qi] < cumulative {
                    qi += 1;
                }
                if qi < query_hashes.len() && query_hashes[qi] == cumulative {
                    return true;
                }
            }
            None => break,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::mw::{build_coinbase, WalletKeys};

    fn batch_with_coinbase() -> Batch {
        let mut batch = Batch::genesis().clone();
        let miner = WalletKeys::random();
        batch.coinbase = Some(build_coinbase(&[(miner.address(), 50)]).unwrap());
        batch.extension.final_hash = [1u8; 32];
        batch
    }

    #[test]
    fn empty_batch_yields_empty_filter() {
        assert!(CompactFilter::build(Batch::genesis()).data.is_empty());
    }

    #[test]
    fn filter_matches_coinbase_items_only() {
        let batch = batch_with_coinbase();
        let cb = batch.coinbase.as_ref().unwrap();
        let items = CompactFilter::items_in(&batch);
        assert_eq!(items.len(), 3);
        let filter = CompactFilter::build(&batch);
        let n = items.len() as u64;
        let key = batch.extension.final_hash;
        assert!(match_any(
            &filter.data,
            &key,
            n,
            &[cb.outputs.outputs[0].commitment]
        ));
        assert!(match_any(&filter.data, &key, n, &[cb.kernel.id()]));
        assert!(!match_any(&filter.data, &key, n, &[[0xAB; 32]]));
        // Keyed by the block hash: the same items under another key miss.
        assert!(!match_any(&filter.data, &[2u8; 32], n, &[cb.kernel.id()]));
    }

    #[test]
    fn golomb_roundtrip() {
        let batch = batch_with_coinbase();
        let n = CompactFilter::items_in(&batch).len() as u64;
        let values = decode_filter(&CompactFilter::build(&batch).data, n);
        assert_eq!(values.len() as u64, n);
        assert!(values.windows(2).all(|w| w[0] <= w[1]));
    }
}
