# Bonded proof of work (v1 design)

> A midwimble block is valid only if it is signed by a mining key that an
> eligible midstate bond authorises. The bond is a gate, never a weight:
> proof of work alone decides who wins a block, and accumulated work alone
> decides which chain wins.

Bond value does not enter difficulty, block work, chain work or fork choice.
A miner with a 1,000 gMDS bond has exactly the mining power of one with the
minimum. There is no slashing in v1: a bond is locked capital and an admission
ticket, nothing more.

Status: bonded mining is wired into consensus and required from block 1 in
production builds (`bond::BONDED_MINING_FROM`). The bond template, its
midstate-side compiler, proof and registration verification, the bond set and
block authorisation all exist and are tested (`core/bond.rs`, `core/state.rs`,
`core/template.rs` here; `script.rs`, `mmr.rs`, `node.rs` and the RPC in
midstate). The node does not sign templates yet, so a production node cannot
mine until that plumbing lands (see the end).

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
at every height in `[P, bonded_until)`. One proof, against one buried header
on the relay's chain, covers the bond's whole life. This is fortunate twice over. A midstate node
keeps only its current UTXO tree, so the per-epoch proofs against past
snapshot headers that the draft required could not have been produced at all.
And with no snapshots there is nothing for midwimble nodes to agree on per
epoch, so the draft's hardest problem disappears.

**Midstate outages cannot stop mining.** Eligibility is judged against
midwimble's own clock (below), so an unresponsive midstate network, or a relay
nobody feeds, pauses only *new* registrations. Existing bonds keep mining.

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

A registration is an item in a midwimble block carrying the `BondProof`: the
coin (script, value, salt), the SMT inclusion proof, and the four roots its
midstate header commits to (see below). The header itself is not in the
registration. It must be on the **midstate relay**'s chain (below), buried
under a day of work.

It adds `bond_id → (mining key, bonded_until, value, the header it was proven
against)` to a bond set committed in midwimble's state root, and pays the
ordinary fee by weight: about 8 KB of SMT proof. A registration must be
eligible at its own block's time. Once a bond can no longer sign, it leaves the
set (see "The bond set" below), and if a heavier midstate branch replaces its
header, it is revoked.

A block may carry the registration for its own miner's bond, which is how the
first block after launch gets mined. The same block relays the midstate
headers the registration needs.

### The midstate relay

Proof of work on a bond's header is not enough on its own: anyone can mine a
private midstate fork whose state holds coins that were never locked, and one
such fork, buried once, could back any number of bonds. So midwimble consensus
keeps its own view of midstate's chain (`core/relay.rs`), fed by the blocks
producers mine:

- **Relaying.** A block may carry a run of midstate headers (at most a day's,
  1,440) that extends the relay's tip, or that forks from a header in its
  window and outweighs everything it replaces. Each must claim at least a
  sixteenth of the relaying block's work (real midstate headers carry more
  than a whole midwimble block's, since midwimble's target is easier by its
  merged-mining share) and have valid proof of work. Linkage and claimed work
  are checked first; the proofs of work with the block's other proofs, the
  first alone and the rest in parallel batches.
- **The chain.** The relay keeps the heaviest chain relayed so far, starting
  from the midstate block the genesis commits to (`MIDSTATE_BLOCK_*`), and the
  last two days of it (`RELAY_WINDOW`). Nothing older can be forked from or
  proven against. Each entry carries a digest chained through every entry
  before it, and the state root commits to the tip's.
- **Registrations** must be proven against a header on the relay's chain,
  buried by headers relayed above it (see "How much work a registration
  needs"). Checking one costs an SMT proof and a sum: no extensions.
- **Revocation.** When a heavier branch replaces relay headers, every bond
  proven against one of them leaves the bond set: its coin is no longer known
  to exist.

Keeping a fake bond therefore means keeping a fake midstate branch heavier
than the real one as producers relay it, which takes more than midstate's
whole hashrate for as long as the bond is to last. That needs producers to
relay: a node started with `--midstate-rpc` polls its midstate node and
relays new headers in every block it mines. A bond file can also carry the
headers its own registration needs (`midwimble bond register` writes them),
so a producer without a midstate node can still register.

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

A block carries `miner: { bond_id, signature }`. It is folded into
`post_tx_midstate` after everything else, so the header layout and the mining
hash are unchanged and merged mining works exactly as before. The signature is
Ristretto Schnorr, the same scheme as midwimble's transactions. A quantum
attacker able to forge it could already forge coin ownership, so post-quantum
signatures would add bytes without adding security.

The signature covers the mining hash the block would have without its
authorisation (`bond::authorization_message`): every other byte of the block.
The proof of work then covers the signature, so a found block cannot be
re-attributed to another bond, and merged mining keeps this because the
midstate parent commits to the full mining hash. Pools sign with the
operator's bond; workers need nothing.

Registered bonds live in the chain state, committed in its root. A block
carries at most one registration, checked against the block's own target.

### The bond set

The set holds only bonds that can still sign. Before a block is applied,
every bond that is not eligible at the earliest timestamp that block may carry
(one more than the median of the last eleven) is removed. A later block's
timestamp can only be higher, because the median never falls, so a removed
bond could never have signed again on that chain: removal changes nothing but
the size of the set, and the work of every rule that reads it.

- **Commitment.** The set is a sparse Merkle tree over one leaf per bond
  (`bond::bond_leaf`: its id and every field of its entry), updated as bonds
  come and go, so the state root never sorts or rehashes the whole set.
- **Storage.** Bonds have a table of their own. Each block's undo record holds
  only what it changed (`types::BlockEffects`: bonds added and removed), so a
  reorg restores the set without any record carrying a copy of it.
- **Snapshots** carry the set and check it against the state root.

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
| `MIN_MINING_BOND` | 2^37 units (128 gMDS) | About 9 days of revenue for a miner with 1% of midstate's hashrate (three months at 0.1%): real capital, within a committed miner's reach. It puts 32 gMDS behind every block that counts in full, so once 360 bonds are eligible a day of blocks is backed by 46,080 gMDS. Must be a power of two. A launch parameter (`--min-bond`): a testnet uses 2^24, since nobody will lock real money to test someone else's chain, and the bonded path is exercised just as well by a trivial coin. |
| `MIN_REMAINING_BOND_LOCK` | 43,200 blocks (30 days) | The effective unbonding delay. Also a launch parameter (`--bond-lock-days`); a testnet uses two days so testers' coins come back quickly. |
| `CLOCK_MARGIN` | 10,080 blocks (7 days) | Covers midstate running ahead of its schedule. |
| `REGISTRATION_WORK_BLOCKS` | 1,440 | A day, in blocks of the registering block's target. |
| `REGISTRATION_MIN_HEADERS` | 60 | Caps any one header at 1/60 of the requirement. |
| `MAX_RELAY_HEADERS_PER_BLOCK` | 1,440 | A day of midstate headers: enough to catch up, or to relay a launch's first bond with its burial. Bounds what a block can make every node verify. |
| `RELAY_WINDOW` | 2,880 | Two days of midstate headers kept: registrations and forks must be this recent. |
| `RELAY_MIN_WORK_DIVISOR` | 16 | A relayed header claims at least 1/16 of a midwimble block's work. |
| `CAP_WINDOW`, `CAP_K` | 1,440 blocks, 360 | Four full-weight blocks a bond a day (the per-bond cap, below). |
| `WORK_CAP_WINDOW` | 10,080 blocks (7 days) | No block counts for more than a quarter above the lowest of the week before it (the work cap, below). |

## How much work a registration needs

A registration's header must be on the relay's chain, and the relay follows
the heaviest midstate chain producers relay; a bond on a branch that loses is
revoked. The burial covers the time in between: to register a bond on a
private fork, someone must first make that fork the relay's chain (outweigh
what honest producers relay) and keep it so under a full burial. The rule,
implemented in `BondRegistration::verify`:

```text
required = 1440 × work(target of the registering midwimble block)
credited = Σ over the relay's headers above P of min(work(header's target), required / 60)
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
- **Nothing is hashed twice.** The relay checked each header's proof of work
  once, when it was relayed. A registration costs an SMT proof and a sum, so
  registrations cannot be used to make every node redo the same work.

Strictly, this is a day of the *merged* share of midstate's hashrate rather than
of midstate's whole network. An honest burial is correspondingly about
`1440 × share` midstate headers: at a 50% share, roughly 720 headers, which the
relay holds anyway. To demand a full midstate day instead, scale
`REGISTRATION_WORK_BLOCKS` by `1 / share`.

## Privacy

Every block becomes attributable to a persistent bonded identity with visible
capital on a transparent chain, so the set of midwimble miners is publicly
enumerable. The wallet tooling should make the private path the default:

- fund bonds through midstate's CoinJoin;
- use a fresh owner key and a fresh mining key for every bond;
- never reuse a bond's keys or addresses for anything else.

## Launch interaction

Bonded mining is required from block 1. Genesis is fixed data that nobody
mines, and block 1's producer registers its own bond in block 1 itself. The
genesis also commits to a midstate block (`MIDSTATE_BLOCK_*`), pinning the
midstate chain the launch was made against: it is the relay's root. Block 1
relays midstate's headers from there through the first bond's burial, so that
bond's proof must be taken above the anchor, and the burial must fit in one
block's relay (1,440 headers). Only MDS holders can mine at first,
so the 30-day slow start doubles as the window to acquire MDS and register, and
the launch script's default `--merge-share` is 0.25.

## Running a bonded producer

```sh
midwimble bond new --file bond.json
#   prints the mining key; the file holds its secret (mode 600)

midstate wallet generate-mss
#   the owner key: prints the MSS key's address *and its public key*. The bond
#   needs the public key. A bond locked to an address can never be spent, so
#   midwimble refuses anything in midstate's 72-character address format.

midwimble bond address --file bond.json --owner-pk <public key> --until <midstate height>
#   prints the bond script and the midstate address to lock the coin at

midstate wallet send --to <bond address>:<value>
#   value: one power of two, at least 2^37 units (128 gMDS). The wallet prints
#   every output paid to others:  -> <address>:<value>  salt <hex>  coin <hex>

midwimble bond register --file bond.json --owner-pk <key> --until <height> \
    --value <units> --salt <hex> --midstate-rpc 127.0.0.1:8545 [--midwimble-rpc <node>]
#   first run: takes the proof against midstate's tip and checks it
#   (four roots rebuild the header's state root; the SMT proof verifies)
#   later run: once a day of work is buried above it (plus a 25% margin),
#   fetches midstate's headers from the relay's tip (asked of the midwimble
#   node; before launch, the genesis's anchor) through the burial, verifies
#   every link and proof of work, and writes the registration and the
#   headers into bond.json

midwimble node --mining-bond bond.json --mine-to <payout address> \
    --midstate-rpc 127.0.0.1:8545
#   --midstate-rpc: relay midstate's headers in the blocks this node mines.
#   Every producer should: registrations, its own included, need them.
#   `GET /relay` on the node's RPC shows the relay and what it would relay.

# Once midstate reaches the lock height, spend the bond back to yourself:
midstate wallet spend-script --coin <bond coin id> --bytecode <script from `bond address`> \
    --inputs AUTO:<public key> --to <your address>:<value>
```

**Before locking a real bond, rehearse the exit.** Lock a small coin to a bond
script with the same owner key and a lock height a few blocks away, and spend
it back with `spend-script` once it unlocks. It costs almost nothing, and it
proves that key and wallet can open the lock you are about to put real money
behind.

The node signs every template it builds, including those served by
`/mining/template`. The pool and the merge miner take their templates from
the node, so they need nothing extra: run them against a node started with
`--mining-bond` (and `--midstate-rpc`). Until the bond is on chain, the node
reserves room in its blocks for the registration and carries it in the first
block it mines whose relay holds its header under a day of work, relaying the
headers the bond file carries if nothing else has.

## Co-bonding and the per-bond cap

A pool's block capacity scales with the bonds behind it. Anyone can lock a
bond naming the pool's mining key: they keep the owner key, so only they can
ever spend the coin, and the pool signs blocks with the bond.

**The cap is a fork-choice rule, not a validity rule.** Over any 1,440 blocks
(`CAP_WINDOW`), a bond adds full work to its chain's weight for at most
`ceil(1440 / min(eligible bonds, 360))` of them (`CAP_K = 360`): four blocks
a day once 360 or more bonds are eligible. Blocks beyond that stay valid and
pay, but add only 1/1024 of their work. So:

- the chain never stalls: a lone producer can always extend it, and a longer
  chain is always a heavier one;
- to outweigh the honest chain, an attacker needs more full-weight blocks
  than it, so bonds of its own for every block it replaces, as well as more
  hashrate than the honest miners. More hashrate cannot stand in for bonds:
  that takes the work cap, below;
- the cap counts *registered, eligible* bonds, not recent signers. On an
  attacker's private chain the attacker is the only signer, so a cap measured
  by signers would lift exactly where it is needed;
- a pool with a share `s` of the hashrate needs about `360 × s` bonds for all
  of its blocks to count in full: 108 bonds at 30%. Covering the whole
  network takes 360 bonds, so the capital locked behind block production
  grows with the hashrate it covers, while a miner with less than 1/360 of it
  needs only its one bond.

While the network has fewer than 360 eligible bonds, they share the window
equally, and a lone producer is uncapped. The window is the last 1,440 blocks,
the new one included. It is not part of the state root: nodes rebuild it from
their stored blocks. Cumulative work, which checkpoints and anchors measure, is
unchanged; fork choice compares it less the work the caps withheld.

### The work cap

The per-bond cap counts blocks, not work, so on its own it let hashrate stand
in for bonds. An attacker with `r` times the honest hashrate lets ASERT raise
its private chain's difficulty, which takes hours, and then each of its quota
slots carries `r` times an honest block's work. A day-long rewrite needed
about `1/r` of the bonds.

So fork choice also caps each block's work (`bond::cap_work`): a block counts
for at most a quarter more than the lowest-work block among the 10,080 before
it (`WORK_CAP_WINDOW`, a week). A fork younger than that inherits the floor
from the history it shares with the honest chain, so the difficulty it climbs
to buys it no weight, and outweighing the honest chain takes more full-weight
blocks, which takes bonds. The bonds an attacker needs, simulated with these
rules (4-hour ASERT half-life, an attacker that uses its quota greedily),
by the attacker's hashrate as a multiple of the honest miners':

| Bonds to rewrite | about 1× | 2× | 10× | 100× |
|---|---|---|---|---|
| an hour, without the work cap | 15 | 15 | 14 | 13 |
| an hour, with it | 15 | 15 | 14 | 14 |
| a day, without the work cap | 343 | 170 | 36 | 3 |
| a day, with it | 343 | 234 | 146 | 127 |

At 128 gMDS a bond, an hour's rewrite takes about 1,920 gMDS of the attacker's
own bonds, and a day's at least 16,256 gMDS even with a hundred times the
honest hashrate.

Honest difficulty that rises more than a quarter within a week is credited
late, alike on every branch that shares the window, so it never decides
between honest branches; the cap only ever lowers a block's credit, never to
zero. The window is rebuilt from the stored headers, like the signer window.

Every block header names the bond that signed the block and claims the
chain's weight with it (`BatchHeader::signer`, `chain_weight`), both under the
proof of work. Headers-first sync checks that each claim adds the header's
work as far as the work cap allows (the work window is in the headers too)
or, for a signed block, the over-cap sliver of that, and compares a peer's
chain with its own by those weights; applying the block checks the claim
exactly, so a block that claims the wrong weight is invalid. A node therefore
never downloads a chain that fork choice would refuse, nor ignores one it
would take because it has less raw work. Peers' `StateInfo` reports weight as
well as depth. Since the windows decide what the next block must claim, they
are consensus state: a snapshot carries a week of headers (10,080), from
which an importing node rebuilds both exactly (`docs/PRUNING.md` §4), and
storage treats a missing signer or header in either window as corruption.

A registration must lock at least `MIN_MINING_BOND`, and no further than a year
(`MAX_BOND_HORIZON`) past the block's estimated midstate height, so a forged
registration expires instead of holding a quota slot forever.

**Co-bonding, as a miner:**

```sh
midwimble bond new --file cobond.json --mining-pubkey <the pool's mining key>
#   a co-bond file: no secret, only the pool's key

midwimble bond address --file cobond.json --owner-pk <your public key> --until <height>
midstate wallet send --to <bond address>:<value>
midwimble bond register --file cobond.json --owner-pk <key> --until <height> \
    --value <units> --salt <hex> --midstate-rpc 127.0.0.1:8545 --midwimble-rpc <node>
#   then give cobond.json to the pool operator: it holds nothing secret
```

Unbonding is the same `spend-script` as for any bond, with your own key.

**As the pool operator:**

```sh
midwimble node --mining-bond bond.json --co-bond alice.json --co-bond bob.json ...
```

The node checks every co-bond file's proof against the midstate headers it
carries at startup, carries the registrations in its blocks one a block (each
once the relay buries its header), and signs each block with whichever bond,
its own or a co-bond, has the most quota left.

## Still to build

- **Paying co-bond contributors.** The node signs with co-bonds, but the
  pool does not yet record whose bond signed each block or pay its owner.
  A per-block rent to the signing bond's owner, or a share split by bond
  value, is pool policy still to decide and build.
- **One-step unbonding in the midstate wallet.** Spending a bond already
  works through `spend-script`, but a dedicated command could fill in the
  script and witness itself.
- **Mandatory authorisation in test builds.** The chain, storage and
  integration test harnesses still mine unsigned blocks. Once they mine bonded
  blocks, `BONDED_MINING_FROM` becomes 1 in test builds too, and the "optional
  but verified" mode goes away.
