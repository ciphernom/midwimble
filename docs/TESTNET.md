# The midwimble testnet, which becomes mainnet

The network launched on 16 October 2026 as the testnet (network magic
`MIDWIMBLE_TESTNET_V3`) **becomes mainnet on 31 October 2026 at 00:00 UTC**,
the whitepaper's anniversary. Nothing restarts: the chain carries on, and so
do the coins mined on it, the testnet's included. Mining it before then is how
early participants get in.

What changes at that moment is the bond. Blocks stamped before it are in the
*early phase*, and take a testnet-sized bond; blocks stamped from it on take
mainnet's:

| | Smallest bond | Must still be locked for |
|---|---|---|
| Early phase (blocks stamped before 2026-10-31 00:00 UTC) | 2^24 units, about 0.016 gMDS | 2 days |
| Mainnet (from then on) | 2^37 units, 128 gMDS | 30 days |

The rule is in consensus (`EARLY_BONDS_UNTIL` in `src/core/bond.rs`, set by
the launch parameters) and judged by each block's own timestamp, so every node
draws the line through the same blocks.

A month later, on **2026-11-30 00:00 UTC**, what a *new* bond must lock starts
following midwimble's own difficulty, doubling per 16-fold rise in its work
since genesis, from 128 gMDS up to 512 gMDS and no further
(`BOND_RETARGET_FROM`, `docs/BONDED_POW.md`). It applies to registrations
only, so the bond you lock before the switch keeps its price for as long as it
stays locked; it is a renewal, or a new bond, that pays the new figure. Before
locking a coin, `midwimble bond register` checks the chain's current figure
for you, and `/bonds` reports it as `registration_min_bond`.

## What a joiner risks

Very little. Mining needs a bond, and bonds are real MDS on midstate mainnet,
but the early phase's bond is 2^24 units, locked until a week or so past the
switch.
That trade is deliberate: the bonded path is the newest code in the project, so
it should be exercised by many people, which means it has to be cheap to try.

The coins are another matter: **they are real from 31 October**, so treat the
wallet as a real one. Write down its recovery phrase (`midwimble wallet
--wallet <file> phrase`), and if the join script made it before mainnet was
announced, it is protected by the script's old default password, `testnet`:
change that (`midwimble wallet --wallet <file> password`, below).

The early phase is also when the chain is cheapest to attack: a bond costs
almost nothing, so fork choice's cap on what each bond's blocks can count for
(`docs/BONDED_POW.md`) barely binds, and the history is protected by proof of
work alone. The slow start keeps the stakes small (about 1,270 coins, an
eighth of a percent of the supply, are issued before the switch), and a
checkpoint anchored in midstate after the switch makes the early history final
(below).

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

It also refuses a binary whose bond rules differ from the published ones
(`midwimble params` prints them): the genesis does not commit to those, so a
build could differ there alone, and would fork off at the switch.

With `--mine` it also walks you through locking the bond and registering it,
which needs a midstate node running the bonded-mining patch
(`midstate-bonded-pow.patch`), and your midstate wallet. During the early
phase it locks an early-phase bond until just past the switch, so it mines
until then. To keep mining after the switch, lock a mainnet bond before it:

```sh
python3 scripts/join_testnet.py --mine --full-bond [--mine-days 30]
```

That locks 128 gMDS for 30 days plus however long you mean to mine, and asks
before it does. From 2026-11-30 the chain may ask more of a new bond (above);
the script takes the figure from the node rather than assuming 128 gMDS. Registering a bond takes a while (a day of the network's work
must be buried above its proof, an hour or more of midstate blocks), so do it
well before the switch. After the switch the script locks a mainnet bond
anyway, and puts aside an early one that can no longer mine, printing the
command that spends its coin back once its lock opens.

## Upgrading

The switch is a consensus change: **every node must run a build with the early
phase before 31 October**. A node on an older build parts from the network at
the first block stamped after the switch, because the two builds disagree about
which bonds still count.

```sh
git pull
python3 scripts/join_testnet.py [--mine]     # rebuilds, then restart your node with it
```

The script rebuilds whenever the code or the published parameters changed
(it used to reuse its first build), and checks the new binary as above. If you
run a node some other way, rebuild it from the updated repository with
`scripts/set_launch_params.py` and the values in `scripts/testnet.json`, and
check that `midwimble params` prints the published genesis block and this
line:

```text
early phase          blocks stamped before 2026-10-31 00:00 UTC (1793404800) take bonds of at least 2^24 units, locked 2 more days
```

**Wallets.** The join script used to protect the wallet it made with the
password `testnet`. Give it one of your own (the new one is read from
`MIDWIMBLE_NEW_PASSWORD`, or asked for twice):

```sh
MIDWIMBLE_PASSWORD=testnet midwimble wallet --wallet ../midwimble-testnet/testnet.mww password
```

and from then on pass it to the script with `MIDWIMBLE_PASSWORD`. A wallet the
script makes now asks for a password, and shows its recovery phrase once.

## What we are trying to learn

Until the switch, the network exists to answer questions the unit tests
cannot:

- **Does bonded mining work for strangers?** Everything so far has been one
  machine and one bond. Several independent bonds, registered from different
  midstate nodes, is the real test.
- **Does merged mining carry the chain?** Solo merge-mining is proven; the pool
  path (`docs/POOL_MERGED_MINING.md`) has only a test behind it. A midstate
  pool merge-mining the testnet is the thing to watch.
- **Does difficulty settle?** The genesis target is a guess about how much
  hashrate turns up. ASERT should absorb being wrong, and watching it do so is
  the check: mainnet keeps this target.
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

## When nodes lose each other

A node that cannot hear the others mines a branch of its own, and the chain
splits. The signs: `"peers": []` (or few) in `/state`, a log warning "No peers
for N min", explorers that disagree about a block at the same height.

- `banned` in `/state` lists the peers this node has banned, why, and for how
  much longer. Bans end, an hour at first and twice as long for each further
  ban of the same peer, up to a day, so a mistaken ban heals by itself.
- "… hung up before saying what it is: it may have banned this node" means
  the other side is refusing this node. A midwimble peer's own log says why,
  in a line `Banning peer <this node's peer id> for …: <reason>`; midstate
  nodes refuse the whole subnet of any peer that is not one of theirs. Either
  way the address counts as a failed dial, so an unchecked one is not tried
  again.
- "Dropped …: it speaks none of midwimble's protocols (a midstate node?)" is
  harmless. Midstate's nodes share our transports, and the seed shares a
  machine with midstate's bootstrap node; they are kept out for a day each.
  Connections are logged as peers only once they identify as midwimble
  nodes; the rest are at debug level.
- `--peer`s are redialled for as long as they are not connected, so a node
  started while its seed was down finds it when it is back.
- Once the two sides hear each other, the heavier branch wins and the other
  side reorganises onto it, if it is no more than 1,000 blocks past the split.
  A node further out than that has to be synced again from scratch, so while
  a split lasts, the side that will lose should stop mining. Heavier means
  `weight` in `/state`, not height: under the per-bond cap a branch signed by
  many bonds outweighs a longer one signed by few.

## Browser wallets

`web-wallet/` is a wallet that runs in the browser and reaches nodes over
WebRTC-direct. A node serves it when built with the `webrtc` feature:

```sh
cargo build --release --features webrtc
midwimble node --data-dir ~/midwimble-testnet --listen /ip4/0.0.0.0/tcp/9433 ...
```

It listens for browsers on UDP at the TCP port plus two (9435 here: open it
in the firewall), keeps its WebRTC certificate in
`<data-dir>/webrtc_cert.pem` so that its address survives restarts, and logs
that address at start:

```text
Browser wallets can connect to /ip4/…/udp/9435/webrtc-direct/certhash/uEi…/p2p/12D3Koo…
```

The public form is also under `webrtc_addrs` in `/state`. Wallets find such
a node by themselves once it is connected to one they know: a node tells
browsers the WebRTC addresses of the nodes connected to it, and each wallet
spreads its requests over three nodes, so every node opened to browsers
takes a share of them. `web-wallet/config.json`'s `nodes` needs only a seed
or two to start from; anyone can also paste an address into the wallet's node
setting, to use only that.

Wallets read scan data (`get_scan_data`) rather than whole blocks, from nodes
with this release. A node from before it still serves them, with whole
blocks, as before.

## The explorer

Every node serves a block explorer at its RPC address: open
`http://127.0.0.1:9434/` on the machine running it. It follows an output from
the block that created it to the block that spent it, and shows each bond's
share of the fork-choice window. Its data is plain JSON under `/explorer/`.

To publish a seed's explorer, serve it on a listener of its own:

```sh
midwimble node ... --rpc 127.0.0.1:9434 --explorer 0.0.0.0:9435
```

That listener serves the explorer's page, `/state` and `/explorer/`, and
nothing that changes the node. Keep the RPC port local: it accepts
transactions and mining requests, and anyone who can reach it can redirect
the node's rewards. It answers only requests addressed to an IP address or
`localhost`; behind a proxy that passes its own host name, add
`--rpc-allow-host <name>`.

The first explorer request after a node starts reads every stored block to
build its index; after that, each request reads only the blocks that are new.

## How it was launched

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

The early phase came later, when the network was made the mainnet: the same
values with mainnet's bond (`--min-bond 137438953472 --bond-lock-days 30`) and
`--early-bonds-until 2026-10-31T00:00:00Z`, the early phase keeping the
testnet's 2^24 units and two days (`--early-min-bond`,
`--early-bond-lock-days`). The genesis does not commit to the bond rules, so
the genesis block, and the chain, stayed the same.

Start a bonded producer before announcing. Its bond's proof must be above
the genesis's midstate anchor, so take it after setting the parameters
(`midwimble bond register` with the new build) and start the producer with
`--midstate-rpc` straight away. Its blocks are unsigned until the proof is
buried, about 60 midstate blocks (an hour) later, while they relay midstate's
headers; then the bond registers by itself and every block after is signed.

## The switch

On 31 October 2026 at 00:00 UTC (Unix time 1793404800) the early phase ends.
For the operators of the network, in order:

1. **Before it.** Announce the date and the upgrade widely, and make sure the
   seeds, the explorers and every known producer run the new build. Producers
   who mean to keep mining lock and register a mainnet bond (`--full-bond`)
   at least a day ahead, so that the chain stays signed through the switch. A
   pool's node needs one too, its own or a co-bond
   (`docs/POOL_MERGED_MINING.md`); its miners need nothing new.
2. **At it.** Nothing to do. The first block stamped at or after the switch
   can only be signed by a mainnet bond; early-phase bonds stop counting and
   leave the bond set with the first block that cannot be stamped before it.
   If no mainnet bond is registered by then, blocks carry on unsigned, each
   counting for a sliver, until one is: the chain does not stop.
3. **After it.** Anchor a checkpoint from past the switch in midstate
   (`midwimble anchor --midstate-rpc ...`, `docs/ANCHORING.md`). The command
   hands the record to the local node, and nodes pass records on to each
   other. Once the anchor is 1,000 midstate blocks deep and the chain 100
   blocks past the checkpoint, every node that has it finalizes it
   (`docs/PRUNING.md` §3): no reorganisation reaches below it, however much
   work a competing chain carries, and the early phase's history is settled.

Early bonds' coins stay locked until their lock height, a week or so past the
switch; spend them back with `midstate wallet spend-script` (the join script
prints the command).

Mainnet keeps the testnet's network magic, `MIDWIMBLE_TESTNET_V3`, for good:
every signature commits to it, so it cannot change without a new chain.
