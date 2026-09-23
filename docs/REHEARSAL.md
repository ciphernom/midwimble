# Rehearsing bonded mining with real midstate

`scripts/rehearse.py` runs the whole bonded-mining lifecycle end to end against
your real midstate node. It uses production midwimble, as it will launch, on a
private rehearsal network. Everything midwimble checks on the real network is
checked here too:

- a real bond coin on midstate mainnet;
- a real proof from your node;
- real midstate headers, with their full proof of work;
- real signatures;
- a second node validating it all.

```sh
python3 scripts/rehearse.py --midstate-rpc 127.0.0.1:8545
```

It needs:

- your midstate node running with `midstate-bonded-pow.patch` applied;
- your midstate wallet;
- cargo;
- about two hours;
- 16 gMDS you are happy to lock for about 36 days.

## What happens

1. **Preflight.** It checks that your node answers and serves `/headers` and
   `/utxo_proof`.
2. **Build.** It copies the source into a separate work directory, so your tree
   is never touched. It sets launch parameters for a rehearsal network
   (`MIDWIMBLE_REHEARSAL_V1`) anchored to Bitcoin's current tip and your
   midstate node's tip, and builds a release binary. The difficulty is sized
   for one machine with `--merge-share 0.004`.
3. **Exit drill.** Before anything real is locked, you lock a tiny coin
   (2^24 units) to a bond script whose lock opens five blocks later, then spend
   it back with `midstate wallet spend-script`. This proves your owner key and
   wallet can open a bond lock. The one unrecoverable mistake, using an address
   instead of a public key as the owner key, fails here for almost nothing
   rather than later for 16 gMDS.
4. **Bond.** You lock 16 gMDS at the bond address for the minimum term plus a
   day. The script asks before this step.
5. **Registration.** `midwimble bond register` takes the proof from your node,
   then re-runs every five minutes until a day of work at the rehearsal
   difficulty is buried above it. The cap of 1/60 per header sets the
   requirement at about 75 midstate blocks.
6. **Bonded mining.** A producer and a peer start on the rehearsal network.
   The script checks, through the peer's RPC:
   - block 1 registers the bond;
   - every block is signed by it;
   - later blocks carry no registration;
   - the peer, which mined nothing, holds the same bond set, with the bond
     eligible.
7. **Merged mining.** The producer restarts with native mining off, so any
   block that appears afterwards can only have come from work done on
   midstate. The script then runs `midwimble merge-mine` against both nodes
   and waits for a block that `/miners` reports as merged, signed by the same
   bond, and accepted by the peer. This is the security argument in practice:
   midwimble's blocks are paid for by midstate's hashrate.

   Midstate blocks found along the way are real ones, paid to the midstate
   address you give. Their coinbase salts are written to
   `midstate_coinbase.jsonl` in the work directory: keep that file, because
   without it those coins cannot be spent.

The steps that need your midstate wallet are printed for you to run: sending to
an address, and `spend-script`. `wallet send` lists each output it pays to
others with its value, salt and coin ID; paste that line back when asked.
Progress is saved in the work directory, so stopping and re-running resumes
where you left off.

## Afterwards

The bond stays locked until the height the script printed. Once midstate
passes that height, spend it back the same way as in the exit drill; the script
prints the exact command.

A bond is eligible only while more than 30 days of its lock remain. The
rehearsal locks for the minimum term plus a day, so its bond can mine for about
a day, which is all the rehearsal needs. After that it simply waits out its
lock. For the real launch, lock a new bond shortly before launch day, with a
term covering as long as you mean to mine (`midwimble bond address --until`).
