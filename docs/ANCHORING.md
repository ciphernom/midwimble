# Midwimble: a privacy chain anchored to the existing Midstate protocol

Status: implemented in this crate (checkpoints, anchoring evidence, recovery
commitments, claim verification). The recovery *epoch* is a future hard fork;
its rules exist here as a dormant, tested state machine.

## 1. Goals and non-goals

Midwimble uses elliptic-curve cryptography for everything a private payment
needs:

- **Pedersen commitments:** computationally binding.
- **Schnorr ownership and kernels.**
- **ECDH stealth addresses.**

A discrete-log break destroys all of it. This design lets Midwimble survive
such a break by relying on Midstate, whose ownership and accumulators are
hash-based.

- **Midstate is an immutable external dependency.** No Midstate consensus
  change. Midstate nodes never interpret Midwimble data; to them an anchor is
  an ordinary Commit transaction or coinbase salt.
- **Midwimble depends on Midstate one way.** Only Midwimble nodes read anchors.
- **Recovery restores both history and ownership.** Rolling back to a trusted
  state is useless if the attacker can simply re-steal the restored outputs.
  So every output also carries a dormant, hash-based claim to its value.
- **Non-goal: automatic detection of a break.** Choosing the recovery point is
  a social / fork decision. Anchors make every candidate immutable and
  ordered; they cannot say which one predates the break.

## 2. Threat model

A discrete-log (quantum) attacker can:

1. **Forge spends.** They can compute every owner key's secret and every
   ECDH secret.
2. **Open any commitment to any value.** Once `log_G(H)` is known, a
   commitment no longer binds its value. The attacker can create and spend
   outputs with balanced but false amounts, and the supply audit cannot
   notice.
3. **Link outputs to addresses.** They can recompute stealth shared secrets.

The attacker can **not**:

- **Rewrite history cheaply.** Proof of work is sequential BLAKE3, the same
  function on both chains, and Grover's quadratic speed-up applies equally to
  honest miners.
- **Invert or collide BLAKE3.**
- **Forge WOTS/MSS signatures.**

The damage therefore appears *on the main chain*: valid-looking theft and
inflation mined by honest miners. Recovery means agreeing on a pre-break
state and re-establishing ownership without elliptic curves.

## 3. Checkpoints

```rust
struct Checkpoint {
    version: u8,                 // 1
    network: [u8; 32],           // network_anchor()
    mw_height: u64,              // blocks in the checkpointed chain
    mw_header_hash: [u8; 32],    // id of block mw_height - 1
    mw_state_root: [u8; 32],     // state root committed by that block's header
    mw_cumulative_work: u128,
    previous_checkpoint: [u8; 32],
}
checkpoint_id = H("midwimble.midstate-anchor.v1", bincode(checkpoint))
```

**The state root is the one the tip header commits to:**

```text
H("midwimble.state-root.v1",
  utxo_root, kernel_root, chain_mmr_root(blocks 0..mw_height-2),
  kernel_excess_sum, total_kernel_offset, supply)
```

- **Verifiable from headers alone:** a node can check a checkpoint without any
  state.
- **Enough for claims:** a claimant proves UTXO membership against
  `utxo_root` and supplies the other five components.
- **Supply cap:** `supply` bounds everything recoverable.

**Chaining.** `previous_checkpoint` chains checkpoints so gaps and
equivocation are visible. Two anchored checkpoints for the same height are
resolved by Midwimble's own chain: only the one matching the node's headers
is valid for that node.

## 4. Anchoring channels (Midstate unchanged)

### 4.1 Commit transactions (default, explicit)

Midstate accepts `Transaction::Commit { commitment, spam_nonce }` through
`POST /commit`. The anchor client proceeds as follows:

1. **Commitment.** Sets `commitment = checkpoint_id`.
2. **Proof of work.** Mines `spam_nonce = (anchor_height << 32) | nonce` so
   that `H(block_hash(anchor_height) ‖ commitment ‖ nonce_le32)` has at least
   the node's required leading zeros. That is 24 bits plus congestion, with
   the anchor height within the last 1,000 blocks.
3. **Search.** Scans later Midstate blocks (`GET /batch/{h}`) for a Commit
   whose commitment equals the checkpoint id.
4. **Evidence.** Stores inclusion evidence (below).

The commitment is never revealed, so Midstate eventually forgets it from
*state*, but the block that contains it remains in history.

### 4.2 Merged-mined parents (free, implicit)

Every merged-mined Midwimble block commits to its own header through a
Midstate coinbase salt (see `core/auxpow.rs`). When that parent block is
accepted by Midstate, the Midwimble header, and therefore its state root, is
anchored at no extra cost.

### 4.3 Inclusion evidence

Both channels reduce to one proof: a 32-byte fold item inside a Midstate
block's mining hash.

```rust
struct MidstateInclusion {
    pre_item_midstate: [u8; 32],      // fold state before the item
    item: [u8; 32],                   // commitment (4.1) or coin id (4.2)
    items_after: Vec<[u8; 32]>,       // remaining tx items and coinbase coin ids
    state_root, prev_header_hash, timestamp, target, nonce, final_hash,
    confirmations: Vec<MidstateHeaderLink>,   // later headers
}
```

A verifier does the following:

1. **Fold.** Recomputes Midstate's fold from the pieces.
2. **Header.** Recomputes the header hash.
3. **Proof of work.** Checks it with the shared extension function.
4. **Depth.** Checks each confirmation links to the previous final hash, has
   valid proof of work, and that their count reaches the required depth.

This is SPV-level assurance, which can be strengthened by cross-checking a
trusted local Midstate node. Midwimble stores the evidence itself because
Midstate may prune old block bodies.

## 5. Recovery commitments

### 5.1 Recovery identity

Each wallet derives an MSS key pair (Midstate's hash-based Merkle signature
scheme; WOTS with w = 2¹⁶ at the leaves) from its seed. Its master public key
`R` is published in the address:

```text
address v1 = bech32m("mw", 0x01 ‖ A ‖ B ‖ R)     // scan, spend, recovery
```

MSS is many-time (2^height signatures), which matters because each recovery
claim consumes one leaf.

### 5.2 Per-output commitment

Every output carries 32 more bytes:

```text
salt = H("midwimble.recovery.salt.v1", t)      // t = ECDH shared secret
rc   = H("midwimble.recovery.v1", NETWORK_MAGIC, R, value_le, blinding, salt)
```

- **Committed everywhere it matters.** `rc` is part of the output metadata
  bound into the range-proof transcript, of `UtxoEntry`, and of the UTXO leaf
  hash, so every checkpoint commits to it.
- **Unlinkable before a break.** The salt is secret, so `rc` reveals nothing
  and differs per output.

**Why the opening is inside the hash.** After a break, `C` no longer binds its
value. `rc` was fixed while binding still held, so it freezes the one true
opening. At recovery, consensus checks both `rc` and `C = value·G +
blinding·H`, so a claimant cannot choose a different opening. The recoverable
total therefore cannot exceed the checkpoint's supply, which is additionally
enforced as a running cap.

**Who creates it.** The sender does, since stealth outputs are created by the
payer. Consensus cannot check `rc` against the hidden value without heavy
zero-knowledge machinery, so the recipient's wallet does. On scanning it
recomputes `rc` and marks outputs whose commitment is wrong; the wallet
should move such funds to itself, since they would be unrecoverable. Change
and coinbase outputs are built by their owners and are always correct.

## 6. The recovery epoch (dormant)

**Activation.** A future hard fork activates recovery at a chosen, anchored
checkpoint `K`. From then on, elliptic-curve ownership is disabled.

**Claims.** A claim transaction takes this form:

```rust
struct RecoveryClaim {
    checkpoint_id: [u8; 32],
    recovery_key: [u8; 32],             // R
    outputs: Vec<ClaimedOutput>,        // C, entry, value, blinding, salt, SMT proof
    destination: [u8; 32],              // post-quantum destination (e.g. a Midstate address)
    signature: MssSignature,            // over the claim digest
}
```

**Validity.** A claim is valid iff all of the following hold:

1. The checkpoint's state root equals the hash of the supplied components.
2. Each output's leaf `utxo_leaf(C, entry)` is proven in `utxo_root`.
3. `entry.recovery_commitment = H(R, value, blinding, salt)`.
4. `C = value·G + blinding·H`.
5. Every claimed output is claimed for the first time.
6. The MSS leaf index has never been used by `R` before, since a WOTS leaf
   must never sign twice.
7. The MSS signature verifies under `R` over
   `H("midwimble.recovery-claim.v1", checkpoint_id, R, destination, outputs…)`.
8. Total claimed value, including this claim, stays at or below the
   checkpoint's supply.

No Schnorr signature, owner key or ECDH value is consulted. Recovered value is
credited to `destination` inside Midwimble; Midstate cannot mint it because
it knows nothing of Midwimble.

## 7. Choosing the recovery point

This is a social / fork choice, not a consensus rule. Pick the latest anchored
checkpoint that predates the earliest suspected exploitation. Any output
created after a secret break may carry a recovery commitment built from a
forged opening, so a checkpoint after the break is poisoned regardless of how
well it is anchored.

## 8. Privacy and costs

- **Before a break:** `rc` is indistinguishable from random, and the recovery
  key appears only in addresses, which are public anyway.
- **After a break:** the attacker can link outputs to addresses, since stealth
  secrets are recomputable. That is acceptable during an emergency.
- **Size:** each output grows by 32 bytes, and each address by 32 bytes (97
  bytes, about 165 characters).
- **Wallet creation:** one MSS key generation (height 10 means 1,024 leaves),
  seconds on a modern multi-core CPU with SIMD. Only the root is needed day to
  day; the full key is regenerated from the seed if recovery ever happens.
- **Claims:** one claim can cover many outputs, so 1,024 claims is not a
  limit on recoverable outputs.
