# The midwimble testnet

A public rehearsal of the real thing, running the code mainnet will run, so
that its mistakes are made with coins worth nothing.

Mainnet is planned for **31 October 2026**, the whitepaper's anniversary. The
testnet runs from early October until the code is frozen for that.

## What a joiner risks

Almost nothing, by design. Testnet coins are worthless and the chain is thrown
away when it ends. Mining needs a bond, and bonds are real MDS on midstate
mainnet — but the testnet's bond is 2^24 units, about 0.016 gMDS, locked for
two days. Mainnet's is 16 gMDS for thirty.

That trade is deliberate: the bonded path is the newest code in the project, so
it should be exercised by many people, which means it has to be cheap to try.

## Joining

```sh
git clone https://github.com/ciphernom/midwimble && cd midwimble
python3 scripts/join_testnet.py                        # follow the chain
python3 scripts/join_testnet.py --mine                 # mine it too
```

The script builds midwimble from `scripts/testnet.json`, the published
parameters, and **refuses to run unless the binary it produces makes the
published genesis block**. That one check is what makes everyone provably the
same chain: the genesis commits to the magic, both anchors, the time and the
target together, so a single wrong value gives a different hash and the script
stops.

With `--mine` it also walks you through locking the bond and registering it,
which needs a midstate node running the bonded-mining patch
(`midstate-bonded-pow.patch`), and your midstate wallet.

## What we are trying to learn

The testnet exists to answer questions the unit tests cannot:

- **Does bonded mining work for strangers?** Everything so far has been one
  machine and one bond. Several independent bonds, registered from different
  midstate nodes, is the real test.
- **Does merged mining carry the chain?** Solo merge-mining is proven; the pool
  path (`docs/POOL_MERGED_MINING.md`) has only a test behind it. A midstate
  pool merge-mining the testnet is the thing to watch.
- **Does difficulty settle?** The genesis target is a guess about how much
  hashrate turns up. ASERT should absorb being wrong; watching it do so tells
  us how to calibrate mainnet's.
- **Do wallets, syncing and reorgs behave in the wild**, on real networks with
  real latency and nodes that come and go.

Please report what breaks, with the node log and the height it happened at.

## Running a seed node

Seeds are ordinary nodes with a stable address, listed in the manifest:

```sh
midwimble node --data-dir ~/midwimble-testnet --listen /ip4/0.0.0.0/tcp/9433 \
    --rpc 127.0.0.1:9434
```

The testnet's seed runs on the same host as midstate's bootstrap node.

## Launching it (for whoever starts the testnet)

```sh
scripts/set_launch_params.py --testnet \
    --bitcoin-height N --bitcoin-hash <hash> --bitcoin-time <its timestamp, UTC> \
    --genesis-time <a few minutes out, UTC> \
    --midstate-rpc 127.0.0.1:8545 --merge-share 0.01

cargo test --lib && cargo build --release
./target/release/midwimble params
```

Then fill `scripts/testnet.json` with exactly those values, the genesis block
id that `params` printed, and the seed's multiaddr, and publish it. Joiners
build from that file, so it must carry the target itself rather than a merge
share: a share recalculated against midstate's live target would give every
joiner a different chain.

Start a bonded producer before announcing, since block 1 needs a registered
bond, and take its bond proof a day ahead so registration is instant.

## Ending it

The testnet stops when mainnet's code is frozen, about a week before 31
October. Bonds unlock on their own two days after they are locked; nothing
needs winding down. Keep your midstate wallet — the bond coins come back to it
either way.
