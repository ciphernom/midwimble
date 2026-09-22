# Launching midwimble

This is the launch-day procedure, and the reasoning behind each parameter it
sets. The emission schedule is fixed in code (`src/core/types.rs`) and does not
change on launch day; four network-identity values do.

## What gets set on launch day

Everything lives in one generated block in `src/core/types.rs`, between
`// @launch-params:begin` and `// @launch-params:end`. Do not edit it by hand:
`scripts/set_launch_params.py` writes it and refuses values that would make an
obviously broken or unfair launch.

| Constant | Set to | Why |
|---|---|---|
| `NETWORK_MAGIC` | `MIDWIMBLE_MAINNET_V1` | Separates the network from devnets and testnets. Every signature, the merged-mining commitment and the DHT key depend on it. |
| `BITCOIN_BLOCK_*` | A Bitcoin block mined *after* the code freeze | The genesis commits to its hash, so the chain provably could not have existed earlier. |
| `MIDSTATE_BLOCK_*` | Midstate's tip at release | The same proof on midstate's one-minute clock, and it pins the midstate chain bonded mining is judged against. |
| `LAUNCH_GENESIS_TIMESTAMP` | When mining opens, shortly after that block | ASERT measures the whole schedule from this instant. |
| `LAUNCH_GENESIS_TARGET` | Midstate's live target ÷ expected merged-mining share | The reference hashrate ASERT adjusts around. |
| `LAUNCH_PARAMETERS_SET` | `true` | Until it is, the node warns that it is a devnet build. |

## The sequence

**Two weeks before.** Freeze the code. Run a public testnet from the frozen
code with a different magic (`--magic MIDWIMBLE_TESTNET_V1`). Announce the
launch date and the Bitcoin height *N* whose hash the genesis will commit to,
chosen to arrive an hour or so before mining is meant to open.

**The week before.** Rehearse bonded mining with real midstate
(`scripts/rehearse.py`, see `docs/REHEARSAL.md`). This proves the full chain
against production midwimble: locking a bond, registering it, mining, and a
peer validating. Anyone who will mine block 1 should run it, since block 1's
producer must already hold a registered bond.

Block-1 producers should take their bond proof early. A registration needs a
day of work above its proof, measured against the launch target, which is
roughly 450 midstate blocks at a 0.25 share. A proof taken days before launch
therefore registers instantly on the day. Run `midwimble bond register` with
the launch build: it measures against that build's genesis target, and a
registration assembled with a pre-launch build will be refused.

**The day before.** Make sure midstate's pool can merge-mine. Getting every
midstate miner earning midwimble from block 1 matters more for a fair start
than anything else on this page, and the 30-day slow start exists partly to buy
time for it.

**Launch.** When Bitcoin block *N* is mined, check its hash on at least two
explorers, then:

```sh
scripts/set_launch_params.py \
    --bitcoin-height N --bitcoin-hash <hash> --bitcoin-time <its timestamp, UTC> \
    --genesis-time <when mining opens, UTC> \
    --midstate-rpc 127.0.0.1:8545

cargo test --lib
cargo build --release
./target/release/midwimble params
```

`--midstate-rpc` reads both the live target and the midstate anchor. It
matches the tip's hash against `/headers` rather than trusting a height
convention, so the node must run the midstate patch that adds that endpoint.

Tag the release, publish the binaries, and publish the `genesis block` line
that `params` prints. Anyone can run `midwimble params` on their own build and
compare that one hash: it commits to the magic, the anchor, the genesis time and
the target together.

## Why the anchor must be unknown until release

The genesis is built from constants, so once the source is public anyone can
compute it. A miner could then start hashing *before* launch, stamping blocks
with times in the first fifteen minutes after `GENESIS_TIMESTAMP` (the most the
future-time rule allows) and releasing them the moment mining opens. ASERT makes
that exponentially expensive, but a well-resourced miner could still front-run
the chain by hundreds of blocks and stall it for hours while real time catches
up.

Committing to a Bitcoin block that has not been mined yet closes that window:
nobody can compute the genesis until the block exists. What remains is the gap
between the Bitcoin block and the release, which is why the script warns when
genesis is more than six hours after the anchor. The slow start makes the
residue economically meaningless: the first two thousand blocks together pay
about eleven coins.

## Calibrating the genesis target

Midstate and midwimble run the same proof of work at the same 60-second
spacing, so a midstate target maps directly onto a midwimble one:

```text
GENESIS_TARGET = midstate_target / expected share of midstate's hashrate mining midwimble
```

The two ways of getting it wrong are not symmetric:

- **Too easy** (the devnet placeholder is midstate's *genesis* target, roughly
  28,000 times too easy for today's network): blocks arrive far faster than 60
  seconds, ASERT needs around 240 blocks per doubling to catch up, and the chain
  ends up running hours to days ahead of its halving calendar for good. The
  script refuses targets this easy.
- **Too hard**: early blocks are slow until ASERT eases, about four hours per
  halving of the difficulty. During the slow start that costs almost nothing.

So err towards hard. Bonded mining is required from block 1, so only miners
who hold MDS and have registered a bond can take part at first. The script's
default `--merge-share` is therefore 0.25 rather than the 0.5 plain merged
mining would suggest.

## Choosing the date

Midstate halves every 525,600 blocks, around the end of February each year.
Midwimble halves every 126,000,000 seconds (a little under four years). The
script prints how far each of the first ten midwimble halvings falls from a
midstate halving and warns if any are within 30 days, since merged miners would
then take two revenue cuts at once. A launch between October and January keeps
them months apart for decades. Late February does not.

## The emission, briefly

- **Supply:** exactly 1,000,000.00000000 coins, with 8 decimal places.
- **Slow start:** the reward ramps linearly over the first 43,200 blocks
  (30 days). Day one pays about 5.7 coins and the whole month about 5,170.
- **Era 0:** after the ramp, 0.23932616 coins per block until block 2,100,000.
- **Halvings:** every 2,100,000 blocks, the same wall-clock length as
  Bitcoin's era. Because ASERT is anchored to genesis, halvings land within a
  day or two of their predicted dates.
- **Endgame:** issuance reaches the cap exactly at about block 49.7 million
  (roughly 95 years in). After that a block pays its fees, and a block with no
  fees carries no coinbase at all.

Any node can check any claimed supply against the schedule
(`types::issued_before`). Checkpoint-synced nodes do this for the snapshot they
start from, so the cap does not depend on trusting whoever served it.

## Still to decide before launch

These are carried over from the README and are not settled by this document:

- A cryptographic review of the ownership scheme, the merged-mining proof and
  the recovery commitments.
- A real minimum work for anchor verification (the CLI defaults to 0).
- The anchoring cadence, finality depth and archive-node policy.
- The minimum bond (`MIN_MINING_BOND`, proposed at 16 gMDS). Bonded mining
  itself is decided: it is required from block 1.
