# Bonded proof of work (v1 design)

> A midwimble block is valid only if it is signed by a mining key that an
> eligible midstate bond authorises. The bond is a gate, never a weight:
> proof of work alone decides who wins a block, and accumulated work alone
> decides which chain wins.

Bond value does not enter difficulty, block work, chain work or fork choice.
A miner with a 1,000 gMDS bond has exactly the mining power of one with the
minimum. There is no slashing in v1: a bond is locked capital and an admission
ticket, nothing more.

Status: the bond template, its midstate-side compiler, proof verification,
registration verification and the eligibility rule exist and are tested (`core/bond.rs` here; `script.rs`, `mmr.rs`,
`node.rs` and the RPC in midstate). Nothing is wired into block validation
yet; the consensus wiring is listed at the end.

## How this differs from the draft

The draft asked midstate for a new `MiningBond` output type, an unbonding state
machine, and per-epoch eligibility snapshots. None of the three is needed.

**No new midstate output type.** A bond is an ordinary P2SH coin. Midstate's VM
already has the height timelock and signature opcodes it needs, and because a
midstate address is the hash of its script, the address itself commits to the
mining key. Midstate consensus never learns what the coin is for.

**No unbonding state.** A bond is locked until a fixed height and counts only
while at least `MIN_REMAINING_BOND_LOCK` of that lock remains. It therefore stops
counting a month before its owner can spend it. Renewing means locking a new coin
further out.

**No epochs and no snapshots.** Nothing can spend a bond before
`bonded_until`, so a bond coin that existed at midstate height P still exists
at every height in `[P, bonded_until)`. One proof, against one buried header,
covers the bond's whole life. This is fortunate twice over. A midstate node
keeps only its current UTXO tree, so the per-epoch proofs against past
snapshot headers that the draft required could not have been produced at all.
And with no snapshots there is nothing for midwimble nodes to agree on per
epoch, so the draft's hardest problem disappears.

**Midstate outages cannot stop mining.** Eligibility is judged against
midwimble's own clock (below), so an unresponsive midstate network pauses only
*new* registrations. Existing bonds keep mining.

## The bond

```text
PUSH_DATA <mining key>    DROP              binds the key into the address
PUSH_INT  <bonded_until>  CHECKTIMEVERIFY   unspendable below that height
PUSH_DATA <owner key>     CHECKSIGVERIFY    only the owner can spend it
PUSH_INT  1
```

It is spent with a single witness item, the owner's signature, once midstate
reaches `bonded_until`. Midstate builds it with `script::compile_mining_bond`,
and midwimble recognises exactly this encoding (`bond::BondScript::parse`);
anything else, including the same script with a padded integer, is not a bond.
Both codebases carry the same test vector, which was also computed with an
independent BLAKE3:

```text
mining key 11…11, bonded_until 400000, owner key 22…22
script   0120001111…11 10 010300801a06 33 0120002222…22 32 01010001   (83 bytes)
address  22fd4a4255a093856e1b4a714deb228676742accbe4e3145a6fbcb50f757b67f
```

Midstate coin values are powers of two, so a bond is one coin and
`MIN_MINING_BOND` is a power of two. The bond's id is its midstate coin id,
which is unique per coin, so one bond cannot be counted twice.

## Registering a bond (once)

A registration is an item in a midwimble block carrying:

1. The `BondProof`: the coin (script, value, salt), the SMT inclusion proof, and
   the four roots its midstate header commits to (see below).
2. The proof's header `P` and the midstate headers built on it, checked for
   linkage and proof of work by the same code that checks anchors
   (`core/anchor.rs`). They must carry a day of work (see below).

It adds `bond_id → (mining key, bonded_until, value)` to a bond set committed
in midwimble's state root, and pays the ordinary fee by weight: about 8 KB of
SMT proof plus the header run. Registrations never expire in consensus terms;
entries simply stop being eligible and can be pruned.

A block may carry the registration for its own miner's bond, which is how the
first block after launch gets mined.

### What the proof must match

A midstate header's `state_root` commits to four roots:

```text
state_root = H( H( H(coins, commitments), chain_mmr ), burned_wots )
```

Two of them are easy to get wrong:

- `chain_mmr` is the chain root from *before* that block appended itself.
- `burned_wots` has been part of the commitment since V4 activation (163,675).

After checking a block's root, midstate also appends that block to the chain
MMR *and* garbage-collects expired commitments. The node's current roots
therefore only reproduce the tip's `state_root` when no commitment expired in
the tip block. The new `GET /utxo_proof/:coin_id` endpoint rebuilds the root
itself and checks it against the stored tip header before answering. When the
two differ, it asks the caller to retry after the next block, rather than
handing out a proof that verifies against nothing.

## Mining with a bond

The header gains `miner: { mining_key, signature }`. The signature is 64-byte
Ristretto Schnorr, the same scheme as midwimble's transactions: a quantum
attacker able to forge it could already forge coin ownership, so post-quantum
signatures here would add about 1.2 KB per header for no real gain.

The signature covers the header's mining hash computed with the signature field
zeroed. The proof of work then covers the signature, so a found block cannot be
re-attributed to another key. Merged mining keeps the same property, because
the midstate parent commits to the midwimble mining hash. Pools sign with the
operator's key; workers need nothing.

A block is authorised when its key belongs to a registered bond with:

```text
value        >= MIN_MINING_BOND
bonded_until >= est_midstate_height(block.timestamp) + MIN_REMAINING_BOND_LOCK
```

where

```text
est_midstate_height(t) = (t − MIDSTATE_GENESIS_TIMESTAMP) / 60 + CLOCK_MARGIN
```

Midstate's ASERT, like midwimble's, is anchored to its genesis time, so its
height tracks this schedule. It runs ahead of it by `240 · log2(hashrate /
calibration)` blocks: about 3,500 at today's roughly 28,000×, and still under
10,000 at a million times the calibration. `CLOCK_MARGIN` of 7 days (10,080
blocks) always estimates midstate's height *high*. The error therefore only ever
retires a bond early, never lets one mine after it could have been spent.

The timestamp is in every header and bounded by midwimble's own rules
(median-time-past and the 15-minute future limit), so eligibility is
deterministic from midwimble's chain alone.

## Proposed constants

| Constant | Value | Reason |
|---|---|---|
| `MIN_MINING_BOND` | 2^34 units (16 gMDS) | About 11 days of revenue for a miner with 0.1% of midstate's hashrate: real capital, within an enthusiast's reach. Must be a power of two. |
| `MIN_REMAINING_BOND_LOCK` | 43,200 blocks (30 days) | The effective unbonding delay. |
| `CLOCK_MARGIN` | 10,080 blocks (7 days) | Covers midstate running ahead of its schedule. |
| `REGISTRATION_WORK_BLOCKS` | 1,440 | A day, in blocks of the registering block's target. |
| `REGISTRATION_MIN_HEADERS` | 60 | Caps any one header at 1/60 of the requirement. |
| `REGISTRATION_MAX_HEADERS` | 4,000 | Bounds size (144 bytes a header) and verification cost. |

## How much work a registration needs

A registration's midstate headers are checked for proof of work, not for being
on midstate's canonical chain. Someone could create a bond coin on a *private*
midstate fork, bury it, register it, and never lock real capital. The defence is
to make that burial cost more than a bond is worth. The rule, implemented in
`BondRegistration::verify`:

```text
required = 1440 × work(target of the registering midwimble block)
credited = Σ over the headers above P of min(work(header's target), required / 60)
registration is valid only if credited ≥ required
```

Three details matter:

- **The yardstick is midwimble's own target, not the headers'.** The headers are
  the registrant's to choose, and on a private fork they could claim easy targets
  and make "a day" cheap. Midwimble's target is consensus: nobody can lower it
  without out-hashing midwimble. Both chains run the same proof of work at the
  same spacing, so the target is in the same units and measures the merged
  hashrate. Forging a registration costs at least a day of midwimble's whole
  network's work, however far midstate's block reward has decayed. That decay
  was the flaw in a fixed block count.
- **No header counts for more than 1/60 of the day.** A registration therefore
  needs at least 60 headers' worth of real work, and one improbably lucky hash
  on a very hard target cannot stand in for it.
- **Cheap checks come first.** The work sum and the bond proof are checked
  before any header's proof of work, and each of those costs a full extension
  (one mining attempt). Forcing that cost onto a node costs the sender real
  hashing.

Strictly, this is a day of the *merged* share of midstate's hashrate rather than
of midstate's whole network. An honest run is correspondingly about
`1440 × share` headers. At a 50% share that is roughly 720 headers, 104 KB and
720 extensions to verify. Midstate reports about 100 attempts a second on a
Raspberry Pi 5, so that is around seven seconds on a Pi, once per bond. To
demand a full midstate day instead, scale `REGISTRATION_WORK_BLOCKS` by
`1 / share`.

## Privacy

Every block becomes attributable to a persistent bonded identity with visible
capital on a transparent chain, so the set of midwimble miners is publicly
enumerable. The wallet tooling should make the private path the default:

- fund bonds through midstate's CoinJoin;
- use a fresh owner key and a fresh mining key for every bond;
- never reuse a bond's keys or addresses for anything else.

## Launch interaction

If bonded mining is active from genesis, only MDS holders can mine midwimble.
The 30-day slow start then also serves as the window to acquire MDS and
register. Fewer miners can take part on day one, so calibrate the genesis target
with a lower `--merge-share` (0.1 to 0.25 rather than 0.5).

## Still to build

Consensus:

- the header's `miner` field;
- the bond set in midwimble's state (committed in its root);
- registration items in blocks (validated by `BondRegistration::verify`);
- authorisation checks in block validation.

Mining:

- signing in templates, the miner, the pool and the merge miner.

Tooling:

- a wallet command that fetches `/utxo_proof` and `/headers` from a midstate
  node and builds the registration.

Tests:

- full-chain tests, including a merged-mined block from a bonded miner;
- a block from a bond that expired one second earlier, which must be rejected.
