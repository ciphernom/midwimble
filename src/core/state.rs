//! Consensus state transitions.
//!
//! # Provenance
//!
//! Ported from midstate `src/core/state.rs`: ASERT difficulty
//! ([`calculate_target`]), median-time-past rules ([`validate_timestamp`]),
//! [`calculate_work`], the three `apply_batch` entry points and
//! [`choose_best_state`]. `apply_batch_internal` keeps midstate's order of
//! checks (linkage → structure → timestamp → parallel signature checks →
//! state transition → state root → proof of work → finalize) with
//! MimbleWimble validation in place of commit/reveal.
//!
//! Differences from midstate worth knowing:
//!
//! * The transition runs on an O(1) clone and is committed only on success,
//!   so a rejected block can never leave `state` half-updated. Midstate
//!   mutated in place and relied on callers passing a scratch copy.
//! * The next target is computed inside `apply_batch`. Midstate left that to
//!   every caller (`state.target = adjust_difficulty(&state)`), which is easy
//!   to forget; the call is still harmless because it is idempotent.
//! * Genesis is recognised by equality with [`Batch::genesis`] and does not
//!   need to meet the target.

use super::auxpow::verify_pow;
use super::mw::crypto::{compress, decompress, scalar_from_bytes};
use super::mw::{Coinbase, Context, Output, Transaction};
use super::types::*;
use anyhow::{anyhow, bail, Result};
use primitive_types::U256;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

// ── Difficulty (midstate, unchanged apart from constants) ───────────────────

/// ASERT (BCH aserti3-2d) anchored at genesis, integer-only.
///
/// `height` and `timestamp` are the *parent's*: the result is the target for
/// block `height`.
pub fn calculate_target(height: u64, timestamp: u64) -> [u8; 32] {
    asert_target(&GENESIS_TARGET, GENESIS_TIMESTAMP, height, timestamp)
}

/// [`calculate_target`] for a chain whose genesis (height 0) had
/// `genesis_target` and `genesis_timestamp`: midstate's own rule, which the
/// midstate relay holds relayed headers to (`relay::midstate_target`).
pub fn asert_target(
    genesis_target: &[u8; 32],
    genesis_timestamp: u64,
    height: u64,
    timestamp: u64,
) -> [u8; 32] {
    if height == 0 {
        return *genesis_target;
    }
    let ideal_time = (height.min(i64::MAX as u64) as i64).saturating_mul(TARGET_BLOCK_TIME as i64);
    let actual_time =
        (timestamp.min(i64::MAX as u64) as i64).saturating_sub(genesis_timestamp as i64);
    let drift = actual_time.saturating_sub(ideal_time);

    let exponent = drift.saturating_mul(65536) / ASERT_HALF_LIFE;
    let shifts = exponent >> 16;
    let frac = exponent & 0xFFFF;

    let mut factor = 65536i64;
    factor += (frac * 45426) >> 16;
    factor += (frac * frac * 15746) >> 32;
    factor += (frac * frac * frac * 3643) >> 48;

    let mut target = U256::from_big_endian(genesis_target);
    let f = U256::from(factor as u64);
    let base = U256::from(65536u64);
    target = target / base * f + (target % base) * f / base;

    let ceiling = U256::from_big_endian(&[0xff; 32]);
    if shifts > 0 {
        let s = (shifts as usize).min(255);
        let headroom = ceiling >> s;
        target = if target > headroom {
            ceiling
        } else {
            target << s
        };
    } else if shifts < 0 {
        let s = ((-shifts) as usize).min(255);
        target >>= s;
    }
    if target > ceiling {
        target = ceiling;
    } else if target.is_zero() {
        target = U256::one();
    }
    target.to_big_endian()
}

pub fn adjust_difficulty(state: &State) -> [u8; 32] {
    calculate_target(state.height, state.timestamp)
}

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Why a block's timestamp was refused, as a typed error inside the
/// `anyhow::Error` that validation returns, so callers can tell the two apart
/// without reading message text.
///
/// [`TimestampError::TooFarInFuture`] is relative to the validating node's
/// own clock: the same block becomes valid a few minutes later, and an honest
/// peer whose clock runs ahead can relay it. [`TimestampError::NotAfterMedian`]
/// is a property of the block and its chain alone, so no honest node relays
/// one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TimestampError {
    TooFarInFuture { timestamp: u64, now: u64 },
    NotAfterMedian { timestamp: u64, floor: u64 },
}

impl std::fmt::Display for TimestampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimestampError::TooFarInFuture { timestamp, now } => write!(
                f,
                "Block timestamp too far in future: {} > {} (max future: {}s)",
                timestamp, now, MAX_FUTURE_BLOCK_TIME
            ),
            TimestampError::NotAfterMedian { timestamp, floor } => write!(
                f,
                "Block timestamp {} must be greater than {}",
                timestamp, floor
            ),
        }
    }
}

impl std::error::Error for TimestampError {}

/// Whether `e` refused a block only because its timestamp is ahead of this
/// node's clock (the one refusal that is not the block's fault).
pub fn is_future_timestamp(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<TimestampError>(),
            Some(TimestampError::TooFarInFuture { .. })
        )
    })
}

/// Midstate's timestamp rule with its timewarp fix always active:
/// no more than 15 minutes in the future, and strictly above the median of
/// the last 11 blocks (or above the last block while fewer exist).
pub fn validate_timestamp(
    new_timestamp: u64,
    previous_timestamps: &[u64],
    current_time: u64,
) -> Result<()> {
    if new_timestamp > current_time.saturating_add(MAX_FUTURE_BLOCK_TIME) {
        return Err(TimestampError::TooFarInFuture {
            timestamp: new_timestamp,
            now: current_time,
        }
        .into());
    }
    let floor = median_time_floor(previous_timestamps);
    if let Some(floor) = floor {
        if new_timestamp <= floor {
            return Err(TimestampError::NotAfterMedian {
                timestamp: new_timestamp,
                floor,
            }
            .into());
        }
    }
    Ok(())
}

/// The value a new timestamp must exceed, if any.
fn median_time_floor(previous_timestamps: &[u64]) -> Option<u64> {
    if previous_timestamps.len() >= MEDIAN_TIME_PAST_WINDOW {
        let mut recent: Vec<u64> = previous_timestamps
            .iter()
            .rev()
            .take(MEDIAN_TIME_PAST_WINDOW)
            .copied()
            .collect();
        recent.sort_unstable();
        Some(recent[MEDIAN_TIME_PAST_WINDOW / 2])
    } else {
        previous_timestamps.last().copied()
    }
}

/// Smallest timestamp the next block may use.
pub fn min_next_timestamp(previous_timestamps: &[u64]) -> u64 {
    median_time_floor(previous_timestamps).map_or(0, |f| f + 1)
}

/// Work represented by a target, saturating at `u128::MAX` (midstate).
pub fn calculate_work(target: &[u8; 32]) -> u128 {
    let t = U256::from_big_endian(target);
    if t.is_zero() {
        return 0;
    }
    let w = U256::MAX / t;
    if w > U256::from(u128::MAX) {
        u128::MAX
    } else {
        let lo = w.low_u64() as u128;
        let hi = (w >> 64).low_u64() as u128;
        (hi << 64) | lo
    }
}

// ── Block application ───────────────────────────────────────────────────────

/// Full validation, proof of work included.
pub fn apply_batch(state: &mut State, batch: &Batch, previous_timestamps: &[u64]) -> Result<()> {
    apply_batch_internal(state, batch, previous_timestamps, None, false)
}

/// Skips recomputing the proof of work.
///
/// # Safety
/// `verified_mining_hash` must be the exact header hash already checked with
/// `verify_extension` (e.g. by the parallel header verifier). The function
/// still confirms that this batch reduces to that hash.
pub fn apply_batch_skip_pow(
    state: &mut State,
    batch: &Batch,
    previous_timestamps: &[u64],
    verified_mining_hash: [u8; 32],
) -> Result<()> {
    apply_batch_internal(
        state,
        batch,
        previous_timestamps,
        Some(verified_mining_hash),
        false,
    )
}

/// Skips proof of work, range proofs and signatures.
///
/// # Safety
/// Only for replaying blocks this node already validated and stored on its
/// own disk. Balance equations and every stateful rule are still enforced.
pub fn apply_batch_trusted(
    state: &mut State,
    batch: &Batch,
    previous_timestamps: &[u64],
    verified_mining_hash: [u8; 32],
) -> Result<()> {
    apply_batch_internal(
        state,
        batch,
        previous_timestamps,
        Some(verified_mining_hash),
        true,
    )
}

/// Stateless rules for a block's contents: structure, weight, cross-checks
/// between body and coinbase, both balance equations and (unless skipped)
/// every proof and signature.
pub fn validate_block_contents(batch: &Batch, height: u64, skip_crypto: bool) -> Result<()> {
    let is_genesis = height == 0;
    let body = &batch.body;
    body.validate_structure(Context::Block)?;

    // Bond registrations: at most one a block. Each is checked against the
    // midstate relay when the block is applied (`apply_batch`).
    if batch.registrations.len() > super::bond::MAX_REGISTRATIONS_PER_BLOCK {
        bail!(
            "block carries {} bond registrations; at most {} are allowed",
            batch.registrations.len(),
            super::bond::MAX_REGISTRATIONS_PER_BLOCK
        );
    }
    // Relayed midstate headers: their linkage and claimed work are checked
    // against the relay when the block is applied; here, every proof of work.
    if let Some(relayed) = &batch.relay {
        if relayed.headers.is_empty()
            || relayed.headers.len() > super::relay::MAX_RELAY_HEADERS_PER_BLOCK
        {
            bail!(
                "a block relays 1..={} midstate headers, not {}",
                super::relay::MAX_RELAY_HEADERS_PER_BLOCK,
                relayed.headers.len()
            );
        }
        if !skip_crypto {
            relayed.verify_pow()?;
        }
    }

    // What this block is allowed to pay out. Once issuance has reached
    // MAX_SUPPLY (about 95 years in) a block with no fees has nothing to
    // claim, and a coinbase would have to invent a zero-valued output to
    // exist at all — so at that point it is dropped instead. Fees must still
    // always be claimed: an unclaimed fee would leave the chain's Pedersen
    // audit (`State::verify_supply`) unbalanced forever.
    let fees = body.fee()?;
    let amount = block_reward(height)
        .checked_add(fees)
        .ok_or_else(|| anyhow!("reward overflow"))?;

    let coinbase = match (&batch.coinbase, is_genesis) {
        (Some(cb), false) => {
            if amount == 0 {
                bail!("block {} carries a coinbase with nothing to claim", height);
            }
            cb
        }
        (None, true) => {
            if !body.is_empty() {
                bail!("genesis must be empty");
            }
            return Ok(());
        }
        (None, false) => {
            if amount != 0 {
                bail!(
                    "block {} has no coinbase but {} to claim",
                    height,
                    format_amount(amount)
                );
            }
            if batch.weight() > MAX_BLOCK_WEIGHT {
                bail!(
                    "block weight {} exceeds {}",
                    batch.weight(),
                    MAX_BLOCK_WEIGHT
                );
            }
            body.verify_sums()?;
            if !skip_crypto {
                body.verify_crypto()?;
            }
            return Ok(());
        }
        (Some(_), true) => bail!("genesis must not carry a coinbase"),
    };
    coinbase.validate_structure()?;
    if batch.weight() > MAX_BLOCK_WEIGHT {
        bail!(
            "block weight {} exceeds {}",
            batch.weight(),
            MAX_BLOCK_WEIGHT
        );
    }

    // Uniqueness across body and coinbase.
    let body_commitments: HashSet<&[u8; 32]> = body.output_commitments().collect();
    let body_owner_keys: HashSet<&[u8; 32]> = body.outputs().map(|o| &o.owner_key).collect();
    let spent: HashSet<&[u8; 32]> = body.input_commitments().collect();
    for o in &coinbase.outputs.outputs {
        if body_commitments.contains(&o.commitment) || body_owner_keys.contains(&o.owner_key) {
            bail!("coinbase output duplicates a body output");
        }
        if spent.contains(&o.commitment) {
            bail!("block spends its own coinbase");
        }
    }
    let cb_id = coinbase.kernel.id();
    if body.body.kernels.iter().any(|k| k.id() == cb_id) {
        bail!("coinbase kernel duplicates a body kernel");
    }

    // Balance: the body balances on its own, and the coinbase claims exactly
    // reward + declared fees.
    body.verify_sums()?;
    coinbase.verify_sum(amount)?;

    if !skip_crypto {
        let (a, b) = rayon::join(|| body.verify_crypto(), || coinbase.verify_crypto());
        a?;
        b?;
    }
    Ok(())
}

/// Stateful rules and the UTXO/kernel transition for a block at
/// `state.height`. Returns the updated copy; `state` is untouched.
///
/// Does not touch the chain-linkage fields (`midstate`, `header_hash`,
/// `chain_mmr`, `depth`, `height`, `timestamp`, `target`), so the result's
/// [`State::state_root`] is exactly what the block must commit to.
pub fn apply_body(state: &State, body: &Transaction, coinbase: Option<&Coinbase>) -> Result<State> {
    let height = state.height;
    let mut next = state.clone();

    for kernel in &body.body.kernels {
        if kernel.min_height > height {
            bail!(
                "kernel is time-locked until height {} (block is {})",
                kernel.min_height,
                height
            );
        }
    }

    for input in &body.body.inputs {
        let entry = *next.utxos.get(&input.commitment).ok_or_else(|| {
            anyhow!(
                "input {} not found or already spent",
                hex::encode(input.commitment)
            )
        })?;
        // The ownership check. Without it anyone who knows an output's
        // blinding factor (its sender, in pluribit's scheme) could spend it by
        // signing with a key of their own choosing.
        if entry.owner_key != input.owner_key {
            bail!("input owner key does not match the output being spent");
        }
        if entry.coinbase && height < entry.height.saturating_add(COINBASE_MATURITY) {
            bail!(
                "coinbase output from height {} is immature at height {} (needs {})",
                entry.height,
                height,
                COINBASE_MATURITY
            );
        }
        next.utxo_set
            .remove(&utxo_leaf(&input.commitment, &entry), true);
        next.utxos.remove(&input.commitment);
    }

    let add_output = |next: &mut State, output: &Output, is_coinbase: bool| -> Result<()> {
        if next.utxos.contains_key(&output.commitment) {
            bail!(
                "output commitment {} already exists",
                hex::encode(output.commitment)
            );
        }
        let entry = UtxoEntry {
            output_hash: output.metadata_hash(),
            owner_key: output.owner_key,
            recovery_commitment: output.recovery_commitment,
            height,
            coinbase: is_coinbase,
        };
        next.utxo_set
            .insert(utxo_leaf(&output.commitment, &entry), true);
        next.utxos.insert(output.commitment, entry);
        Ok(())
    };
    for output in body.outputs() {
        add_output(&mut next, output, false)?;
    }
    if let Some(cb) = coinbase {
        for output in &cb.outputs.outputs {
            add_output(&mut next, output, true)?;
        }
    }

    let mut excess_sum =
        decompress(&next.kernel_excess_sum).ok_or_else(|| anyhow!("corrupt kernel excess sum"))?;
    for kernel in body.body.kernels.iter().chain(coinbase.map(|c| &c.kernel)) {
        // Kernel uniqueness is the replay defence: an old transaction whose
        // inputs reappear cannot be mined a second time.
        if !next.kernels.insert(kernel.id(), true) {
            bail!("kernel {} is already on chain", hex::encode(kernel.id()));
        }
        excess_sum += decompress(&kernel.excess).ok_or_else(|| anyhow!("invalid kernel excess"))?;
    }
    next.kernel_excess_sum = compress(&excess_sum);

    let total = scalar_from_bytes(&next.total_kernel_offset)
        .ok_or_else(|| anyhow!("corrupt total offset"))?;
    let offset =
        scalar_from_bytes(&body.kernel_offset).ok_or_else(|| anyhow!("invalid kernel offset"))?;
    next.total_kernel_offset = (total + offset).to_bytes();

    // The supply is a pure function of height: whatever the block's shape,
    // it mints exactly what the schedule allows, and nothing after the cap.
    next.supply = next
        .supply
        .checked_add(block_reward(height))
        .ok_or_else(|| anyhow!("supply overflow"))?;
    if next.supply != issued_before(height + 1) {
        bail!(
            "supply {} does not match the emission schedule at height {}",
            next.supply,
            height
        );
    }
    Ok(next)
}

fn apply_batch_internal(
    state: &mut State,
    batch: &Batch,
    previous_timestamps: &[u64],
    preverified_hash: Option<[u8; 32]>,
    skip_crypto: bool,
) -> Result<()> {
    let height = state.height;
    let is_genesis = height == 0;

    // 1. Parent linkage.
    if batch.prev_midstate != state.mw_midstate {
        bail!(
            "Block parent mismatch: expected {}, got {}",
            hex::encode(state.mw_midstate),
            hex::encode(batch.prev_midstate)
        );
    }
    if batch.prev_header_hash != state.header_hash {
        bail!(
            "Block header hash mismatch: expected {}, got {}",
            hex::encode(state.header_hash),
            hex::encode(batch.prev_header_hash)
        );
    }
    if batch.target != state.target {
        bail!(
            "Batch target mismatch: expected {}, got {}",
            hex::encode(state.target),
            hex::encode(batch.target)
        );
    }

    // 2. Genesis identity / timestamp.
    if is_genesis {
        if batch != Batch::genesis() {
            bail!("genesis block does not match this network's genesis");
        }
    } else {
        validate_timestamp(batch.timestamp, previous_timestamps, current_timestamp())?;
    }

    // 3. Proof of work, before anything expensive. The mining hash commits to
    //    every byte of the block (body, registrations and signature are folded
    //    into the midstate), so a block costs its sender real work before it
    //    can cost this node any.
    let post_tx_midstate = super::types::fold_block(&state.mw_midstate, batch);
    let candidate_header = BatchHeader {
        height,
        prev_header_hash: state.header_hash,
        prev_midstate: state.mw_midstate,
        post_tx_midstate,
        extension: batch.extension.clone(),
        timestamp: batch.timestamp,
        target: batch.target,
        state_root: batch.state_root,
        signer: batch.miner.as_ref().map(|auth| auth.bond_id),
        chain_weight: batch.chain_weight,
        aux_pow: None,
    };
    let mining_hash = compute_header_hash(&candidate_header);
    if !is_genesis {
        match preverified_hash {
            None => verify_pow(
                mining_hash,
                &batch.extension,
                &batch.target,
                batch.aux_pow.as_ref(),
            )?,
            Some(expected) => {
                if mining_hash != expected {
                    bail!(
                        "CRITICAL: Batch integrity failure! Computed header hash {} does not match pre-verified PoW hash {}",
                        hex::encode(mining_hash),
                        hex::encode(expected)
                    );
                }
            }
        }
    }

    // 4. Bonds that can no longer sign leave the set before anything reads
    //    it: no timestamp this block or a later one may carry would make them
    //    eligible again.
    let mut base = state.clone();
    let mut removed = base
        .bonds
        .prune_expired(min_next_timestamp(previous_timestamps));

    // 4a. Relayed midstate headers, cheap checks first (their proofs of work
    //     are checked with the block's other proofs below). A heavier branch
    //     revokes every bond proven against a header it replaced.
    let mut relay_change = super::relay::RelayChange::default();
    if let Some(relayed) = &batch.relay {
        relay_change = base.relay.extend(relayed, batch.timestamp)?;
        if let Some(fork) = relay_change.fork_from {
            removed.extend(base.bonds.revoke_above(fork));
        }
    }

    // 4b. Registrations, against the relay as this block leaves it.
    super::bond::precheck_registrations(&base.bonds, &batch.registrations, batch.timestamp)?;
    let registered: Vec<([u8; 32], super::bond::BondEntry)> = batch
        .registrations
        .iter()
        .map(|r| Ok((r.bond_id(), r.verify(&base.relay, &batch.target)?)))
        .collect::<Result<_>>()?;
    let mut bonds = base.bonds.clone();
    for (id, entry) in &registered {
        if bonds.insert(*id, *entry).is_some() {
            bail!("bond {} is already registered", hex::encode(id));
        }
    }

    // 5. Bonded mining. An authorisation is checked in full whenever a block
    //     carries one. From BONDED_MINING_FROM a block must carry one whenever
    //     a registered bond (one this block registers included) could sign
    //     it; while none can, it may be unsigned, and counts for a sliver.
    if !is_genesis {
        if batch.miner.is_some() {
            super::bond::check_miner_authorization(&bonds, &state.mw_midstate, batch)?;
        } else if height >= super::bond::BONDED_MINING_FROM
            && super::bond::any_can_sign(&bonds, batch.timestamp)
        {
            bail!("block {height} is unsigned, but a registered bond could sign it");
        }
    }

    // 5a. The chain weight the header claims, which headers-first sync went
    //     by, must be what fork choice gives the chain with this block: its
    //     work as far as the work cap allows, less what the per-bond cap
    //     withholds from its signer (or, unsigned, all but the sliver).
    let signer = batch.miner.as_ref().map(|auth| auth.bond_id);
    let work = calculate_work(&batch.target);
    let mut floor = base.work_floor.clone();
    let creditable = super::bond::cap_work(&mut floor, height, work);
    let (mut recent, mut counts) = (base.recent_signers.clone(), base.signer_counts.clone());
    let credited = super::bond::credit_in_window(
        &mut recent,
        &mut counts,
        &bonds,
        height,
        signer,
        creditable,
        batch.timestamp,
    );
    let weight = base.weight().saturating_add(credited);
    if batch.chain_weight != weight {
        bail!(
            "block claims chain weight {}, but the chain weighs {} with it",
            batch.chain_weight,
            weight
        );
    }

    // 5b. Contents: structure, balances, proofs and signatures.
    validate_block_contents(batch, height, skip_crypto)?;

    // 6. State transition and root.
    let mut next = apply_body(&base, &batch.body, batch.coinbase.as_ref())?;
    next.bonds = bonds;
    next.effects = std::sync::Arc::new(BlockEffects {
        bonds_added: registered,
        bonds_removed: removed,
        relay_added: relay_change.added,
        relay_removed: relay_change.removed,
    });
    let expected_root = next.state_root();
    if batch.state_root != expected_root {
        bail!(
            "State root mismatch: expected {}, got {}",
            hex::encode(expected_root),
            hex::encode(batch.state_root)
        );
    }

    // 7. Finalize.
    next.mw_midstate = post_tx_midstate;
    next.header_hash = batch.extension.final_hash;
    next.chain_mmr.append(&batch.extension.final_hash, true);
    next.recent_signers = recent;
    next.signer_counts = counts;
    next.work_floor = floor;
    next.depth = next.depth.saturating_add(work);
    next.capped = next.capped.saturating_add(work - credited);
    debug_assert_eq!(next.weight(), weight);
    next.height = height + 1;
    next.timestamp = batch.timestamp;
    next.target = calculate_target(next.height, next.timestamp);
    *state = next;
    Ok(())
}

/// Fork choice: most cumulative work, then the lower midstate (midstate).
pub fn choose_best_state<'a>(a: &'a State, b: &'a State) -> &'a State {
    match a.weight().cmp(&b.weight()) {
        std::cmp::Ordering::Greater => a,
        std::cmp::Ordering::Less => b,
        std::cmp::Ordering::Equal => {
            if a.mw_midstate < b.mw_midstate {
                a
            } else {
                b
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_at_schedule_is_genesis_target() {
        let t = calculate_target(10, GENESIS_TIMESTAMP + 10 * TARGET_BLOCK_TIME);
        assert_eq!(t, GENESIS_TARGET);
    }

    #[test]
    fn asert_halves_and_doubles_per_half_life() {
        let at = |h: u64, extra: i64| {
            let ts = (GENESIS_TIMESTAMP as i64 + (h * TARGET_BLOCK_TIME) as i64 + extra) as u64;
            U256::from_big_endian(&calculate_target(h, ts))
        };
        let base = at(1000, 0);
        // One half-life slow: target doubles (easier), unless already at the ceiling.
        let slower = at(1000, ASERT_HALF_LIFE);
        let faster = at(1000, -ASERT_HALF_LIFE);
        let ceiling = U256::from_big_endian(&[0xff; 32]);
        assert!(slower == base * 2 || slower == ceiling);
        assert_eq!(faster, base / 2);
    }

    #[test]
    fn target_is_clamped() {
        assert_eq!(calculate_target(1, u64::MAX / 2), [0xff; 32]);
        assert_ne!(
            calculate_target(u64::MAX / 1_000, GENESIS_TIMESTAMP),
            [0u8; 32]
        );
    }

    #[test]
    fn timestamp_rules() {
        let now = 1_000_000;
        assert!(validate_timestamp(now + MAX_FUTURE_BLOCK_TIME, &[], now).is_ok());
        assert!(validate_timestamp(now + MAX_FUTURE_BLOCK_TIME + 1, &[], now).is_err());
        assert!(validate_timestamp(10, &[10], now).is_err());
        assert!(validate_timestamp(11, &[10], now).is_ok());
        let window: Vec<u64> = (100..111).collect();
        assert_eq!(min_next_timestamp(&window), 106);
        assert!(validate_timestamp(105, &window, now).is_err());
        assert!(validate_timestamp(106, &window, now).is_ok());
        assert!(validate_timestamp(u64::MAX, &[], u64::MAX - 1).is_ok());
    }

    /// Only a clock-relative refusal is excused, and the type survives being
    /// wrapped in context by callers.
    #[test]
    fn future_timestamps_are_told_apart_by_type() {
        let now = 1_000_000;
        let ahead = validate_timestamp(now + MAX_FUTURE_BLOCK_TIME + 1, &[], now).unwrap_err();
        assert!(is_future_timestamp(&ahead));
        assert!(is_future_timestamp(&ahead.context("header 7")));
        let stale = validate_timestamp(10, &[10], now).unwrap_err();
        assert!(!is_future_timestamp(&stale));
        assert!(!is_future_timestamp(&anyhow!(
            "timestamp mentioned in some other error"
        )));
    }

    #[test]
    fn work_is_monotone_in_difficulty() {
        let easy = [0xff; 32];
        let mut hard = [0xff; 32];
        hard[0] = 0x0f;
        assert!(calculate_work(&hard) > calculate_work(&easy));
        assert_eq!(calculate_work(&[0u8; 32]), 0);
    }

    #[test]
    fn fork_choice_prefers_depth_then_lower_midstate() {
        let mut a = State::genesis();
        let mut b = State::genesis();
        a.depth = 10;
        b.depth = 9;
        assert_eq!(choose_best_state(&a, &b).depth, 10);
        b.depth = 10;
        a.mw_midstate = [2; 32];
        b.mw_midstate = [1; 32];
        assert_eq!(choose_best_state(&a, &b).mw_midstate, [1; 32]);
    }

    #[test]
    fn genesis_applies() {
        let mut state = State::genesis();
        apply_batch(&mut state, Batch::genesis(), &[]).unwrap();
        assert_eq!(state.height, 1);
        assert_eq!(state.header_hash, Batch::genesis().extension.final_hash);
        assert_eq!(state.target, calculate_target(1, GENESIS_TIMESTAMP));
        state.verify_supply().unwrap();

        // A tampered genesis is refused.
        let mut fake = Batch::genesis().clone();
        fake.timestamp += 1;
        assert!(apply_batch(&mut State::genesis(), &fake, &[]).is_err());
    }
}

/// Adds a block's verified bond registrations
/// (`bond::BondRegistration::verify`) to the bond set. A bond is in the set
/// at most once; it leaves when it can no longer sign, or when the midstate
/// header it was proven against is replaced.
pub fn apply_registrations(
    next: &mut State,
    registered: &[([u8; 32], super::bond::BondEntry)],
) -> Result<()> {
    for (id, entry) in registered {
        if next.bonds.contains_key(id) {
            bail!("bond {} is already registered", hex::encode(id));
        }
        next.bonds.insert(*id, *entry);
    }
    Ok(())
}
