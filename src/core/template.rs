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
use super::relay::{
    MidstateHeaders, RelayFeed, RelayHeaders, RELAY_MAX_FUTURE, RELAY_WEIGHT_PER_HEADER,
};
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
    /// What this block's coinbase may mint: the scheduled reward, less
    /// whatever the per-bond cap tapered away (`bond::capped_subsidy`). A
    /// pool proportions its payouts against this, not against the schedule,
    /// or it pays out more than the block actually mints.
    pub subsidy: u64,
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

/// A copy of `template` with `extra` in its coinbase, signed again under the
/// same bond, and its mining hash. Pools give each miner such a copy, binding
/// its work to the miner: a nonce found for one copy is worthless for any
/// other. Only the coinbase's `extra` and the signature change; outputs,
/// state root and everything else stay as they were. A template without a
/// coinbase (a block with nothing to claim) has nothing to bind and is
/// returned unchanged.
pub fn rebind(
    template: &BlockTemplate,
    extra: [u8; 32],
    bond: Option<&MinerBond>,
) -> Result<BlockTemplate> {
    let mut batch = template.batch.clone();
    let Some(coinbase) = batch.coinbase.as_mut() else {
        return Ok(template.clone());
    };
    coinbase.extra = extra;
    if let Some(auth) = &template.batch.miner {
        let bond =
            bond.ok_or_else(|| anyhow!("the template is signed but no mining bond is configured"))?;
        let message = authorization_message(&batch.prev_midstate, &batch);
        batch.miner = Some(MinerAuth {
            bond_id: auth.bond_id,
            signature: bond.sign(&message),
        });
    }
    let mut header = batch.header();
    header.height = template.height;
    Ok(BlockTemplate {
        mining_hash: compute_header_hash(&header),
        batch,
        height: template.height,
        fees: template.fees,
        subsidy: template.subsidy,
    })
}

/// Block weight kept free for a registration when choosing what to relay.
const REGISTRATION_ROOM: u64 = 256;

/// The midstate headers a block on `state` timestamped `timestamp` should
/// relay, in at most `room` headers: what the producer's feed, or else its
/// bonds' own headers, have that extends the chain's relay and the relay
/// would accept. A run stops before any header timestamped too far past the
/// block ([`RELAY_MAX_FUTURE`]); a later block relays it.
fn choose_relay(
    state: &State,
    feed: Option<&RelayFeed>,
    bond: Option<&MinerBond>,
    room: usize,
    timestamp: u64,
) -> Option<RelayHeaders> {
    let accepts = |run: &RelayHeaders| state.relay.clone().extend(run, timestamp).is_ok();
    let latest = timestamp.saturating_add(RELAY_MAX_FUTURE);
    let trimmed = |mut run: RelayHeaders| {
        let fits = run
            .headers
            .iter()
            .take(room)
            .take_while(|h| h.timestamp <= latest)
            .count();
        run.headers.truncate(fits);
        (!run.headers.is_empty()).then_some(run)
    };
    if let Some(run) = feed
        .and_then(|f| f.next_for(&state.relay))
        .and_then(trimmed)
    {
        if accepts(&run) {
            return Some(run);
        }
    }
    // The bonds' own headers, for registrations the relay cannot back yet.
    let carried: Vec<&MidstateHeaders> = bond
        .into_iter()
        .flat_map(|b| {
            std::iter::once((b.bond_id, b.midstate.as_ref()))
                .chain(b.co_bonds.iter().map(|c| (c.bond_id, c.midstate.as_ref())))
        })
        .filter(|(id, _)| !state.bonds.contains_key(id))
        .filter_map(|(_, headers)| headers)
        .collect();
    for headers in carried {
        let mut own = RelayFeed::default();
        own.add(headers, true);
        if let Some(run) = own.next_for(&state.relay).and_then(trimmed) {
            if accepts(&run) {
                return Some(run);
            }
        }
    }
    None
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

/// Splits `total` in proportion to weight, without per-address minimums.
/// Floors each exact entitlement, then assigns the remaining base units to
/// the largest fractional entitlements. Ties follow the input order.
/// Zero-valued outputs are omitted. Payees can be addresses or anything
/// standing for them (the pool's audit splits by hashed owner id).
pub fn split_by_weight<K: Copy>(total: u64, weights: &[(K, u64)]) -> Result<Vec<(K, u64)>> {
    let sum: u128 = weights.iter().map(|(_, w)| *w as u128).sum();
    if sum == 0 {
        bail!("payout weights sum to zero");
    }
    let mut out = Vec::with_capacity(weights.len());
    let mut remainders = Vec::with_capacity(weights.len());
    let mut paid = 0u64;
    for (address, weight) in weights {
        // The product of two u64 values fits in u128, even at their maxima.
        let numerator = total as u128 * *weight as u128;
        let whole = (numerator / sum) as u64;
        out.push((*address, whole));
        remainders.push(numerator % sum);
        paid += whole;
    }
    // Sum of floors <= total; at most weights.len() - 1 units remain.
    let mut order: Vec<usize> = (0..weights.len()).collect();
    order.sort_by(|&a, &b| remainders[b].cmp(&remainders[a]).then_with(|| a.cmp(&b)));
    for index in order.into_iter().take((total - paid) as usize) {
        out[index].1 += 1;
    }
    out.retain(|(_, value)| *value > 0);
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
    build_template_bonded(
        state,
        previous_timestamps,
        txs,
        payouts,
        extra,
        timestamp,
        None,
    )
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
    build_template_relayed(
        state,
        previous_timestamps,
        txs,
        payouts,
        extra,
        timestamp,
        bond,
        None,
    )
}

/// [`build_template_bonded`] that also relays midstate headers from `feed`
/// (a producer's midstate node) where the chain's relay lacks them. Headers
/// the bond and its co-bonds carry for their own registrations are relayed
/// too when needed.
#[allow(clippy::too_many_arguments)]
pub fn build_template_relayed(
    state: &State,
    previous_timestamps: &[u64],
    txs: &[Transaction],
    payouts: &[(StealthAddress, u64)],
    extra: [u8; 32],
    timestamp: Option<u64>,
    bond: Option<&MinerBond>,
    feed: Option<&RelayFeed>,
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
    let timestamp = timestamp
        .unwrap_or_else(|| current_timestamp().max(min_next_timestamp(previous_timestamps)));
    // Bonds that can no longer sign leave the set before the block is built,
    // exactly as `apply_batch` removes them.
    let mut pruned = state.clone();
    pruned
        .bonds
        .prune_expired(min_next_timestamp(previous_timestamps));
    let state = &pruned;

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

    // Midstate headers to relay: whatever the producer's feed and its bonds'
    // own headers have that extends the chain's relay, in the room the block
    // has left (a registration may still need some).
    let used = body.weight()
        + coinbase
            .as_ref()
            .map_or(0, crate::core::mw::Coinbase::weight)
        + REGISTRATION_ROOM;
    let room = (MAX_BLOCK_WEIGHT.saturating_sub(used) / RELAY_WEIGHT_PER_HEADER) as usize;
    let relay = choose_relay(state, feed, bond, room, timestamp);
    let mut relayed = state.clone();
    if let Some(r) = &relay {
        let change = relayed
            .relay
            .extend(r, timestamp)
            .expect("choose_relay only proposes runs the relay accepts");
        if let Some(fork) = change.fork_from {
            relayed.bonds.revoke_above(fork);
        }
    }
    let state_after_relay = &relayed;

    // The producer's own registration, until the chain has it: it must verify
    // against the relay as this block leaves it. Until it does, the block
    // can only be mined unsigned, which the chain allows while no registered
    // bond could sign it (checked below).
    let mut registrations: Vec<BondRegistration> = Vec::new();
    let mut not_ready: Option<anyhow::Error> = None;
    // The producer's own bond can no longer sign at all: smaller than the
    // network now asks (its early phase over), or its lock run down. It is
    // not waiting for anything, so it does not hold up its co-bonds.
    let mut retired = false;
    if let Some(b) = bond.filter(|b| !state_after_relay.bonds.contains_key(&b.bond_id)) {
        match &b.registration {
            // Eligibility only runs down with time (`Bond::eligible_at`): a
            // bond that cannot sign now never can again.
            Some(registration) if !registration.eligible_at(timestamp) => retired = true,
            Some(registration) => {
                let ready = crate::core::bond::precheck_registrations(
                    &state_after_relay.bonds,
                    std::slice::from_ref(registration),
                    timestamp,
                )
                .and_then(|()| {
                    registration
                        .verify(&state_after_relay.relay, &state.target)
                        .map(|_| ())
                });
                match ready {
                    Ok(()) => registrations.push(registration.clone()),
                    Err(e) => {
                        not_ready = Some(anyhow!(
                            "the mining bond's registration does not verify yet ({e:#}): the \
                             relay must hold its midstate header under a day of work. Run the \
                             node with --midstate-rpc, or re-run `midwimble bond register` so the \
                             bond file carries the headers"
                        ))
                    }
                }
            }
            None => {
                not_ready = Some(anyhow!(
                "the mining bond is not registered on this chain and no registration is configured"
            ))
            }
        }
    }
    // Co-bonds' registrations ride along too, one a block, once the
    // producer's own bond is on chain (or can never be). One the chain would
    // refuse is skipped rather than allowed to stop this producer mining.
    if registrations.is_empty() && not_ready.is_none() {
        if let Some(b) = bond {
            let pending = b
                .co_bonds
                .iter()
                .filter(|c| !state_after_relay.bonds.contains_key(&c.bond_id))
                .filter_map(|c| c.registration.as_ref())
                .find(|r| {
                    crate::core::bond::precheck_registrations(
                        &state_after_relay.bonds,
                        std::slice::from_ref(*r),
                        timestamp,
                    )
                    .is_ok()
                        && r.verify(&state_after_relay.relay, &state.target).is_ok()
                });
            if let Some(r) = pending {
                registrations.push(r.clone());
            }
        }
    }
    let registered: Vec<([u8; 32], crate::core::bond::BondEntry)> = registrations
        .iter()
        .map(|r| {
            Ok((
                r.bond_id(),
                r.verify(&state_after_relay.relay, &state.target)?,
            ))
        })
        .collect::<Result<_>>()?;

    // The bond set this block leaves behind. Both the signer and the cap its
    // pay is judged against have to be settled before the coinbase is built,
    // so the registrations this block carries are folded in here rather than
    // waiting for `apply_registrations` below (which repeats the duplicate
    // check and is where a clash is reported).
    let mut bonds_after = state_after_relay.bonds.clone();
    for (id, entry) in &registered {
        bonds_after.insert(*id, *entry);
    }

    // The signer: whichever of the producer's bonds can sign, or none. From
    // BONDED_MINING_FROM a block must be signed whenever any registered bond
    // could sign it (`state::apply_batch`), so a producer none of whose bonds
    // can sign mines only while no other bond can either. A producer with a
    // bond holds to that before then too, rather than mine unsigned blocks
    // its bond was configured to sign.
    let signer = bond.and_then(|b| b.signer_for(&bonds_after, &state.signer_counts, timestamp));
    if signer.is_none()
        && (bond.is_some() || height >= BONDED_MINING_FROM)
        && crate::core::bond::any_can_sign(&bonds_after, timestamp)
    {
        return Err(not_ready.unwrap_or_else(|| match bond {
            Some(_) if retired => anyhow!(
                "this producer's mining bond is not eligible at this block's time and never will \
                 be again (smaller than the network now requires, or its lock ends too soon); \
                 none of its co-bonds can sign, and other registered bonds can: lock and \
                 register a new bond"
            ),
            Some(_) => anyhow!(
                "none of this producer's bonds can sign at this time, and other registered bonds can"
            ),
            None => anyhow!(
                "bonded mining is required from height {BONDED_MINING_FROM}: configure a mining bond"
            ),
        }));
    }
    // The chain weight the header claims: the block's work as far as the
    // work cap allows, less what the per-bond cap withholds from its signer
    // (or, unsigned, all but the sliver).
    let mut floor = state.work_floor.clone();
    let work = crate::core::state::calculate_work(&state.target);
    let creditable = crate::core::bond::cap_work(&mut floor, height, work);
    let (mut recent, mut counts) = (state.recent_signers.clone(), state.signer_counts.clone());
    let credited = crate::core::bond::credit_in_window(
        &mut recent,
        &mut counts,
        &bonds_after,
        height,
        signer,
        creditable,
        timestamp,
    );

    // What this block may mint, by the rule `state::apply_batch` will judge
    // it against: `credit_in_window` has just counted this block, so
    // `counts[signer]` is `n`. Past the cap the subsidy tapers and the
    // remainder is burned, so the coinbase paid above -- which claimed the
    // whole scheduled reward -- has to be paid again at the lower figure, or
    // the chain rejects this producer's own block.
    let subsidy = match signer {
        Some(id) if timestamp >= crate::core::bond::EARLY_BONDS_UNTIL => {
            let n = counts.get(&id).copied().unwrap_or(0) as usize;
            let cap = crate::core::bond::signer_cap(&bonds_after, timestamp);
            crate::core::bond::capped_subsidy(block_reward(height), n, cap)
        }
        _ => block_reward(height),
    };
    // Re-pay the coinbase at the tapered figure. It can only ever shrink (a
    // smaller total drops payouts, never adds them), so the block cannot
    // outgrow the room the relay was chosen for: a lighter coinbase leaves
    // headers unrelayed, never a block over weight.
    let (coinbase, receipts) = if subsidy == block_reward(height) {
        (coinbase, receipts)
    } else {
        let amount = subsidy
            .checked_add(fees)
            .ok_or_else(|| anyhow!("reward overflow"))?;
        if amount == 0 {
            (None, Vec::new())
        } else {
            let split = split_by_weight(amount, payouts)?;
            let (cb, cb_receipts) = build_coinbase_with(&split, extra)?;
            let cb_receipts: Vec<(StealthAddress, PayoutReceipt)> =
                split.iter().map(|(a, _)| *a).zip(cb_receipts).collect();
            (Some(cb), cb_receipts)
        }
    };

    let mut next = apply_body(state_after_relay, &body, coinbase.as_ref(), subsidy)?;
    super::state::apply_registrations(&mut next, &registered)?;
    let state_root = next.state_root();
    let mut batch = Batch {
        prev_midstate: state.mw_midstate,
        prev_header_hash: state.header_hash,
        body,
        coinbase,
        registrations,
        miner: None,
        relay,
        chain_weight: state.weight().saturating_add(credited),
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
    validate_block_contents(&batch, height, true, subsidy)?;
    if let (Some(bond), Some(signer)) = (bond, signer) {
        let message = authorization_message(&state.mw_midstate, &batch);
        batch.miner = Some(MinerAuth {
            bond_id: signer,
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
            subsidy,
        },
        receipts,
    ))
}
