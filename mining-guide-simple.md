# mining midwimble: the dead simple guide

midwimble is a privacy chain. it's merge-mined with midstate and anchored to it. that means the same hashing can mine both chains at once.

this guide is about how to mine it, and nothing else. it isn't advice on whether you should.

**heads up: from block 86,400 (around mid-december 2026) the proof of work is midstate walk.** it runs on cpu cores, and a raspberry pi 5 is the smallest machine that mines it well. gpus stop helping: `--backend gpu` mines it on the cpu. run release v1.2-DIMEBAG or later before then. midstate makes the same switch a few hours later, at its block 420,000, and merged mining pauses in between.

---

## which one are you?

**a) small miner. laptop, one gpu, a hobby rig. most people.**
→ go to **path a: pool mining**. you don't need a bond. you don't need to lock anything.

**b) you want to solo mine midwimble on your own node.**
→ go to **path b: solo**. you need your own full bond (real MDS, locked on midstate).

**c) your pool operator asked you for a co-bond.**
→ go to **path c: co-bond**. only do this if the pool actually asked.

not sure? you're (a).

---

## key dates (all UTC)

| when | what happens |
|---|---|
| **31 oct 2026 00:00 UTC** | the early phase ends and the network becomes mainnet. early (tiny, 2^24 unit) bonds stop counting. from then on a bond needs **128 gMDS** with **more than 30 days** of its lock left. **anyone running a node must be on v1.1.2-WONKABURN by then.** older builds split off. |
| **30 nov 2026 00:00 UTC** | the minimum for **new** bonds starts following midwimble's difficulty: 128 gMDS, doubling for every 16x rise in work since genesis, capped at **512 gMDS**. bonds already registered keep the price they were registered at. |

pool miners (path a): nothing for you to do. but ask your pool whether its bonds clear the 31 oct bar. if they don't, its blocks stop counting, and so do your payouts.

---

## path a: pool mining (no bond)

the pool at **https://rpc.cypherpunk.gold/pool** is a midstate pool that merge-mines midwimble. you mine midstate shares like normal. if a share also clears midwimble's target, it's a midwimble block too. the pool's own bonds sign those blocks. you need nothing extra.

**easiest of all: mine in your browser.** open **https://ciphernom.github.io/midwimble/wallet/#/mine**, write down the 24 words, pick a password and tap start mining. it makes a midwimble wallet and mines for it on this pool, with nothing to install. payouts show up as "mined" in the wallet. the midstate part of your shares goes to the pool unless you give it a midstate (MSS) address under mine → midstate payouts. a browser earns very little until midstate walk (block 86,400). the steps below are the same thing with a real miner.

you don't need to download midwimble at all for this.

1. **get midstate.** grab the latest release from https://github.com/ciphernom/midstate/releases. the miner is built in: `midstate miner`.
2. **make a midstate payout address (an MSS one).** already pool mining midstate? you've got one, skip this.
   ```
   midstate wallet create          # only if you don't have a midstate wallet yet
   midstate wallet generate-mss --height 10 --label "Mining Payouts"
   ```
   use the `Address:` line it prints. it has to be an **MSS** address. pools pay you many times, and a normal one-time address can't take that: coins sent to it after the first become unspendable. don't use `wallet receive` for this.
3. **make a midwimble wallet.** easiest is the midwimble web wallet: **https://ciphernom.github.io/midwimble/wallet/**
   - hit create
   - write the **24 words** on paper. anyone with them can spend your coins, and they're the only way back in if you lose the browser data
   - go to receive and copy your address. it starts with `mw1`

   prefer the command line? `midwimble wallet --wallet w.mww create` prints the same kind of address and 24 words.
4. **start mining.**
   ```
   ./midstate miner --pool-url stratum+tcp://rpc.cypherpunk.gold:3333 \
       --payout-address <your midstate MSS address> \
       --midwimble-address <your mw1 address>
   ```
   leave off `--midwimble-address` and you still mine midstate as normal, but the pool keeps your midwimble share. press enter in the miner any time to see its status.
5. **that's it.** every share you submit earns midwimble score for your `mw1` address. when the pool finds a midwimble block, that block pays the scores straight to miners' addresses.

**seeing your midwimble coins:**

- **open the midwimble web wallet.** it shows your balance. it talks to the public node at mw.cypherpunk.gold for you, so you don't run anything. amounts on midwimble are hidden, so no explorer or public node can show your balance. only your own wallet can, because it holds your keys.
- **the pool page** (rpc.cypherpunk.gold/pool) lists the midwimble blocks the pool found and each address's share of them.
- **watch-only:** in the midwimble web wallet, "watch an address (view key)" takes a `mwview1…` view key. it sees what comes in but can't spend anything. good for a second device.
- the command-line wallet (`midwimble wallet ... balance`) can't use the public node. it only talks to a node at a plain `host:port`, so it needs your own midwimble node. the midwimble web wallet is the easy way.

**small miner?** a midwimble block pays at most 31 addresses. if you have at least 1/31 of the pool's score you're paid exactly. if you have less, payouts are a fair draw: exactly your share on average, but fewer, bigger payouts. a quiet stretch is normal.

you do **not** need a bond, a co-bond or a midwimble node to pool mine. your old early bond (if you made one) stops counting after 31 oct. pool mining never needed it.

---

## path b: solo mining (your own bond)

what you need:

- the midwimble release (v1.1.2-WONKABURN)
- your own midstate node, running any release from v4.2.0 on (the latest is fine). it has what bond registration needs built in
- a midstate wallet holding at least 128 gMDS
- a midwimble wallet (path a, step 3)

the exact numbers, from the code:

- **minimum bond:** 128 gMDS = 2^37 = `137438953472` units. from 30 nov, a *new* bond may need more, up to 512 gMDS = `549755813888` units. `midwimble bond register` checks the chain's live figure for you. a node's rpc `/bonds` shows it as `registration_min_bond`.
- **one coin.** a bond is a single midstate coin, and coin values are powers of two. so it's exactly 128 gMDS, not 130.
- **lock length:** a bond only counts while **more than 30 days (43,200 midstate blocks)** of its lock remain. so it stops mining 30 days before you can spend it. lock for 30 days plus however long you want to mine.
- **longest lock:** up to a year (525,600 blocks) past the chain's estimate of midstate's current height.

### the easy way: the join script

```
git clone https://github.com/ciphernom/midwimble && cd midwimble
python3 scripts/join_testnet.py --mine --full-bond --mine-days 30
```

it builds, checks you're on the real chain, then walks you through locking and registering a full bond. it asks before it locks anything. (the name still says "testnet". it joins the chain that becomes mainnet.)

### the manual way

1. **make the bond file.**
   ```
   midwimble bond new --file bond.json
   ```
   prints your mining key. `bond.json` holds that key's secret, so **keep it safe**: anyone with it can mine as your bond.

2. **make an owner key on midstate.**
   ```
   midstate wallet generate-mss
   ```
   it prints a `Public key:` line **and** an `Address:` line. you want the **public key**. if you give an address instead, midwimble refuses it, because a bond locked to an address can never be spent.

3. **get the bond address.** pick your lock height (`--until`, a midstate block height. see the lock rule above).
   ```
   midwimble bond address --file bond.json --owner-pk <your public key> --until <midstate height>
   ```
   prints the bond script and the midstate address to lock at. it warns you if the lock is too short. **save the script.** you need it to get your coins back.

4. **lock the coin on midstate.**
   ```
   midstate wallet send --to <bond address>:137438953472
   ```
   for the bond output, the wallet prints a line like `→ <address>:<value>  salt <hex>  coin <hex>`. **write down the salt and the coin id.** you need the salt to register and the coin id to get the coins back.

5. **register it (run this twice).**
   ```
   midwimble bond register --file bond.json --owner-pk <key> --until <height> \
       --value 137438953472 --salt <hex> --midstate-rpc 127.0.0.1:8545 --midwimble-rpc 127.0.0.1:9434
   ```
   the first run takes a proof. then wait: a day of midwimble's work has to be buried above it (the docs say an hour or more of midstate blocks). run the same command again. when it prints `Ready:`, you're done.

6. **mine.**
   ```
   midwimble node --mining-bond bond.json --mine-to <your midwimble address> \
       --midstate-rpc 127.0.0.1:8545 --backend gpu
   ```
   - `--mine-to`: your midwimble address (path a, step 3)
   - `--mining-bond`: the bond file
   - `--midstate-rpc`: your midstate node. every producer should set it, since registrations need the headers it relays
   - `--backend`: `auto` (default), `gpu` or `cpu`. gpu needs a build with gpu support. `midwimble gpu-info` tests your card

   want to mine midstate and midwimble in one search instead? start the node **without** `--mine-to` (so it doesn't hash on its own), then let `merge-mine` do the hashing:
   ```
   midwimble node --mining-bond bond.json --midstate-rpc 127.0.0.1:8545
   midwimble merge-mine --midstate-rpc 127.0.0.1:8545 \
       --midstate-address <your midstate address> --midwimble-address <your mw1 address>
   ```
   merge-mine tells the node where to pay, and the node signs with your bond.

7. **getting your coins back.** once midstate reaches your lock height:
   ```
   midstate wallet spend-script --coin <bond coin id> --bytecode <script from step 3> \
       --inputs AUTO:<public key> --to <your midstate address>:<value>
   ```

**do this first:** the docs say rehearse the exit before you lock a real bond. lock a tiny coin with the same owner key and a lock height a few blocks away, then spend it back. it proves your key can open the lock.

**privacy tip from the docs:** use a fresh owner key and a fresh mining key for every bond, and never reuse them for anything else.

**timing:** registering takes a while. if you want a bond counting on 31 oct, start well before.

---

## path c: co-bond (only if your pool asks)

a co-bond is a bond **you** lock that names **the pool's** mining key. you keep the owner key, so only you can ever spend the coin. the pool signs blocks with it.

1. get the pool's mining key (hex) from the operator.
2. make a co-bond file:
   ```
   midwimble bond new --file cobond.json --mining-pubkey <the pool's mining key>
   ```
   this file holds **no secret**.
3. do path b steps 2 to 5 using `cobond.json`: owner key, `bond address`, lock the coin, `bond register` twice.
4. send `cobond.json` to the pool operator. it's safe to share.
5. the operator adds it to their node with `--co-bond cobond.json` and restarts it. that's their job.

getting your coins back is the same `spend-script` as path b step 7, with your own key.

**heads up:** nothing tracks or pays co-bonders yet, in either the midwimble node or the midstate pool. midwimble's docs list it as "still to build". sort out with your pool what you get before you lock anything. [nick: fill in: your pool's co-bond terms, if any]

---

## myths and faq

**"a bigger bond earns more."**
no. a 1,000 gMDS bond has exactly the mining power of a 128 gMDS one. the cap is **per bond**. over the last 1,440 blocks (a day), each bond gets full weight for an equal share of the window, never less than 1/360 of it. once 360 or more bonds are eligible, that's 4 full-weight blocks a day. while there are fewer bonds, each one gets more. the minimum is a floor, not a power-up. more *bonds* can help a miner who has a lot of hashrate. a bigger bond never does.

**"do i need a bond to pool mine?"**
no. the pool's bonds sign the blocks.

**"does this change my midstate rewards?"**
no. bonds and caps only touch midwimble. midstate mining pays exactly as before.

**"how many bonds would i need?"**
about `360 × your share of midwimble's hashrate`. on a laptop that rounds to one, and only if you solo mine. if you pool mine, it's zero.

**"what happens if a bond goes over its cap?"**
the blocks are still valid. they just count for almost nothing in fork choice (1/1024 of their work), and from 31 oct the reward tapers: a bond that has signed `n` of the last 1,440 blocks (a day) against a cap of `cap` mints `reward × cap / n`. fees are always paid in full. the withheld part is never minted by anyone. nothing stops and there's no cliff.

**"i added a lot of hashrate and my blocks seem to count late."**
that's the work cap. no block counts for more than a quarter above the lowest-work block of the week before it (the last 10,080 blocks). if you add a lot of hashrate suddenly, the extra is credited over time, not all at once. it's there so raw hashrate can't stand in for bonds.

**"my early bond stopped working after 31 oct."**
that's expected. early bonds stop counting at 31 oct 00:00 UTC. pool miners can ignore it. solo miners need a full bond. the early bond's coin unlocks at its lock height, and you spend it back with `spend-script`.

**"i locked 128 before 30 nov. do i have to top up?"**
no. a registered bond keeps its price until its lock runs out. the new figure only applies to new bonds and renewals.

**"is midwimble a sidechain?"**
no. it's its own privacy chain, merge-mined with midstate and anchored to it.

---

*it's an experimental chain. the bonded path is the newest code in the project. only lock what you're fine having locked.*
