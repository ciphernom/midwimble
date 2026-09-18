# Anchored pruning (Midwimble v2)

Midwimble cannot use vanilla MimbleWimble cut-through. Removing spent
outputs from a block would also remove the owner keys and input signatures
that the ownership rules depend on. The non-interactive MW literature shows
that "compensating" terms for removed ownership data enable miner theft.
Litecoin MWEB waits for a horizon instead.

Midwimble uses its Midstate anchors as that horizon. It keeps full
validation for the live chain and forgets history once Midstate has recorded
the resulting state.

## 1. Rules that do not change

- **One definition of a valid block.** Every block above the finalized
  checkpoint is validated in full: ownership, owner sum, kernels, balance,
  range proofs, uniqueness and existence.
- **No cut-through inside a body.** Outputs cannot be spent in the block
  that creates them.
- **No compensating owner term.** There is no `cut_owner_sum` or anything
  like it.

## 2. What pruned nodes keep

| Data | Kept? | Why |
|---|---|---|
| Block headers | yes (full-verification nodes) | fork choice, anchors, sync service |
| Block bodies below the floor | **no** | the point of pruning |
| Kernels (full, with signatures) | yes, forever | supply audit without history |
| UTXO records | yes | spending |
| Range-proof groups containing an unspent output | yes, with spent members reduced to `(commitment, metadata hash)` | every unspent output stays provably in range |
| Undo records | back to the oldest retained checkpoint | reorgs above the floor; past UTXO sets for recovery claims |

### 2.1 Grouped range proofs with pruning bookkeeping

One Bulletproof covers a whole output group. It can only be verified with
**every** commitment in the group and every output's metadata hash. When a
member is spent, the node keeps only those 64 bytes:

```rust
enum GroupMember {
    Unspent(Output),
    Spent { commitment: Point32, metadata_hash: [u8; 32] },
}
struct StoredGroup { range_proof: Vec<u8>, members: Vec<GroupMember> }
```

- **Deletion:** a group is deleted when its last member is spent.
- **Id:** the group id hashes the proof and all member commitments, so it is
  stable while members are pruned.
- **Reversible:** undo records store a touched group's prior state, so reorgs
  restore it exactly.

### 2.2 UTXO leaves commit to the whole output

The UTXO leaf now also commits to the output's metadata hash:

```text
leaf = H(commitment, metadata_hash, owner_key, recovery_commitment, height, coinbase)
```

The metadata hash covers the owner key, ephemeral key, view tag, payload and
recovery commitment. A snapshot provider therefore cannot alter an unspent
output's scanning data. That would otherwise be a griefing attack open to the
output's *sender*, who knows its opening and could re-prove its group.

## 3. Finalized checkpoints

An anchor proves that a checkpoint was *published*, not that it is valid;
anyone can post a Commit. A checkpoint `C` at height `h` is **finalized** for
a node when all of the following hold:

1. **Anchored deep enough:** `C` is anchored in Midstate with at least
   `anchor_depth` blocks (SPV-verified evidence).
2. **On our chain:** `C` describes the node's own heaviest valid chain, and
   the tip is at least `finality_depth` blocks above `h`.
3. **No conflict:** no conflicting anchored checkpoint for any height ≤ `h`
   is known, meaning one whose header differs from the node's chain at that
   height.

The **floor** is the height of the newest finalized checkpoint.

- **No reorg below the floor:** a chain that forks below it is refused,
  whatever its work.
- **Conflicts:** they stop finalization at the last common checkpoint and are
  logged. A conflict means someone out-mined the anchored chain by more than
  `finality_depth` blocks. Earliest-anchored-wins is the intended resolution,
  but for now a node refuses to finalize either side.
- **Recovery:** the post-quantum recovery hard fork overrides the floor
  explicitly (`docs/ANCHORING.md` §6–7).

### 3.1 Pruning

- **Bodies:** once the floor rises, block bodies below it may be deleted.
- **Headers:** kept.
- **Undo records:** kept back to the `retained_checkpoints`-th newest
  finalized checkpoint, so past UTXO sets stay derivable for recovery claims
  and snapshots.

## 4. Snapshots

A snapshot at checkpoint `C` (height `H`) contains:

```rust
struct Snapshot {
    checkpoint: Checkpoint,
    headers: Vec<BatchHeader>,       // the last ≤ 60 headers, ending at H-1
    parts: StateRootParts,           // hash to C.mw_state_root
    mmr_peaks: Vec<[u8; 32]>,        // chain MMR over blocks 0..H-2 (peaks only)
    utxos: Vec<(Point32, UtxoEntry)>,
    groups: Vec<StoredGroup>,
    kernels: Vec<Kernel>,
}
```

**Verification.** An importer checks each of the following:

- the checkpoint id is the one it trusts;
- the headers link, carry valid proof of work, and end at `C`'s header and
  state root;
- `parts` hash to `C`'s state root;
- the UTXO leaves rebuild `utxo_root`;
- every kernel signature verifies, and the kernels rebuild `kernel_root` and
  the excess sum;
- every group's range proof verifies;
- every UTXO is covered by exactly one unspent group member with a matching
  metadata hash, owner key and recovery commitment;
- the MimbleWimble supply audit holds;
- the MMR peaks rebuild `chain_mmr_root`, before the tip's own hash is
  appended.

The importer then starts from that state with
`depth = C.mw_cumulative_work`.

## 5. Sync modes

- **Full verification (default).** Download and verify every header from
  genesis and every block body (or the verified snapshot at a finalized
  checkpoint, once available), then follow the chain. Trusts nothing but
  proof of work.
- **Checkpoint verification.** The operator supplies a trusted checkpoint id
  (`--checkpoint <id>`), from a release, a friend's node or a block explorer.
  - **What it checks:** the checkpoint must also carry valid Midstate anchor
    evidence (so a typo or an unpublished id fails). The snapshot is
    verified as in §4. Everything after `H` is validated in full.
  - **What it trusts:** the checkpoint's history and cumulative work ("weak
    subjectivity"). Such a node cannot serve history below `H`.
