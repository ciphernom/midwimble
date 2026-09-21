# midwimble

A privacy chain built from midstate's networking and consensus plus pluribit's
MimbleWimble transactions, with receiver-only spend authority. It is
merge-mineable with midstate, and anchored to midstate for post-quantum
disaster recovery.

**Status: devnet-quality research code. Not audited. Do not use for real value.**

About 23k lines of Rust. See `docs/ANCHORING.md` for the anchoring and
recovery design.

## What came from where

| Area | Source | Notes |
|---|---|---|
| `core/finality.rs`, `core/extension.rs`, `core/wots_simd.rs` | midstate | verbatim |
| `core/mmr.rs`, `core/simd_mining.rs` | midstate | plus marked additions (MMR prefix truncation, multi-seed SIMD verification) |
| `core/wots.rs`, `core/mss.rs` | midstate | key-reuse punishment section dropped; MSS checkpoint file keyed by seed (see *Upstream bug*) |
| `core/gpu_mining.rs` | midstate | wgpu 30 fix and opt-in software adapters (for testing only) |
| `network/amino.rs` | midstate | verbatim except the rendezvous label |
| `network/*`, `core/state.rs`, `core/types.rs`, `core/filter.rs` | midstate | MW payloads, `/midwimble/*` protocol ids, no activation heights |
| `sync.rs`, `node.rs`, `mempool.rs`, `storage.rs`, `miner.rs`, `pool.rs` | midstate (design) | re-implemented around the MW core |
| `core/mw/*` | pluribit | hardened, with the ownership fix |
| `core/auxpow.rs`, `merge_mine.rs` | new | merged mining with unmodified midstate nodes |
| `core/anchor.rs`, `core/recovery.rs`, `anchor.rs` | new | anchoring and dormant post-quantum recovery |
| `core/snapshot.rs`, `finality.rs` | new | anchored pruning: finalized checkpoints, snapshots, checkpoint sync |
| `wallet/`, `rpc.rs`, `bin/main.rs` | new | pluribit-style wallet, midstate-style RPC |

## Design summary

### Consensus (midstate)

- **Proof of work:** sequential BLAKE3 (`H^N(H(header ‖ nonce))`, N = 1,000,000).
- **Difficulty and time:** ASERT with a 4-hour half-life and a 60-second target.
  Timestamps must beat the median of the last 11 blocks and may be at most 15
  minutes ahead.
- **Fork choice:** cumulative work, tie-broken by the lower midstate.
- **State root:** covers the UTXO set, the kernel set, the chain MMR, the
  running excess sum, the total offset and the supply.

### Emission (`core/types.rs`, `docs/LAUNCH.md`)

- **Supply:** exactly 1,000,000.00000000 coins (8 decimals), reached exactly
  rather than approached, at about block 49.7 million (~95 years).
- **Slow start:** the reward ramps linearly over the first 30 days, so the
  blocks mined while the network is small and least known are worth little.
- **Halvings:** 0.23932616 per block in era 0, halving every 2,100,000 blocks,
  the same wall-clock era as Bitcoin's. ASERT's genesis anchoring keeps the
  halving dates predictable to within a day or two.
- **Checkable anywhere:** the schedule is defined by its running total, so any
  node can verify a supply claim at any height; checkpoint-synced nodes check
  the snapshot they start from.
- **After the cap:** a block pays only its fees, and a block with none carries
  no coinbase.

### Transactions (pluribit, hardened)

- **Commitments:** Pedersen commitments on Ristretto255 with aggregated
  Bulletproofs, padded to a power of two and bound to their outputs' metadata.
- **Stealth outputs:** each carries a one-time owner key
  `Ko = H(t)·G + B`, so only the recipient can spend.
- **Balance rules:**

  ```text
  Pedersen:  Σ C_out − Σ C_in + fee·G = Σ E + o·H
  Owner:     Σ Ko_in              = Σ E' + x·G
  Coinbase:  Σ C_cb − (reward + fees)·G = E_cb
  ```

- **Further rules:**
  - Kernel ids are unique across the chain (replay protection).
  - Coinbase outputs mature after 100 blocks.
  - Blocks list everything in canonical order.
  - A supply audit is available on any node.

### Merged mining with midstate (`core/auxpow.rs`)

- **Commitment:** a miner puts `H(NETWORK_MAGIC, midwimble mining hash)` in the
  salt of the last output of a midstate coinbase. Midstate's own
  `/block_template` computes the state root, so midstate needs no change.
- **Acceptance:** a midwimble block whose work is in such a midstate block is
  valid when the midstate block meets midwimble's target.
- **Proof size:** usually about 220 bytes. Proofs are checked during header
  sync in the same SIMD batches as native blocks.
- **Safety check:** the miner refuses to hash unless its reconstruction of
  midstate's fold reproduces the midstate node's mining hash exactly.

### Pool (`pool.rs`, midstate's provably fair design)

- **Commitment:** every job commits the full score table (a Merkle root in the
  coinbase `extra` field).
- **Payouts:** the fee plus the top 31 scorers, paid directly in the coinbase.
  Paid miners receive **payout receipts** proving, from public data alone, that
  a stealth output pays them a given amount.
- **Miner audit:** before hashing, a miner checks the template hash, its own
  score proof, its receipt (or its legitimate exclusion), and the published
  score list.
- **Kept from midstate:**
  - per-job share replay protection;
  - off-reactor proof-of-work checks;
  - score deduction only after the network accepts the block;
  - orphan reconciliation.

### Anchoring and post-quantum recovery (`docs/ANCHORING.md`)

**Anchoring.** A checkpoint (height, header, state root, work, previous
checkpoint) is anchored in midstate without changing midstate, in one of two
ways:

- as an ordinary **Commit transaction**, with midstate's commit proof of work;
- **for free**, through a merged-mined parent block.

Evidence (the fold proof plus confirmations) is verified SPV-style and stored
on the midwimble side.

**Recovery commitments.** Every output carries

```text
rc = H(R, value, blinding, salt)
```

- `R` is the recipient's midstate-style MSS key, which is part of the v1
  address.
- `salt` comes from the stealth shared secret.
- Because `rc` fixes the commitment's opening while the commitment is still
  binding, a later recovery can pin the value even after a discrete-log break.

**Recovery epoch (dormant).** A future hard fork activates it at an anchored
checkpoint.

- **Claims:** accepted only with an SMT proof of the UTXO leaf, the frozen
  opening, and an MSS signature.
- **Limits:** each MSS leaf is used once, each output is claimed once, and the
  total is capped at the checkpoint's supply.
- **No elliptic curves:** elliptic-curve keys are never consulted.

### Anchored pruning (`docs/PRUNING.md`)

MimbleWimble cut-through cannot coexist with one-sided ownership: removing a
spent output would remove the owner key and signature the rules depend on.
Midstate anchors serve as the horizon instead.

- **Finalized checkpoints.** A checkpoint counts once its Midstate evidence is
  deep enough, it describes this node's chain, the tip is far enough past it,
  and no conflicting anchored checkpoint is known.
- **Floor.** No reorg below it, whatever the competing chain's work.
- **Pruning.** Block bodies below the floor can be deleted. Headers, kernels
  (with signatures), UTXO records and range proofs stay.
- **Grouped proofs keep aggregation.** A spent output shrinks to its
  commitment and metadata hash, which is all its group's Bulletproof needs. A
  group is deleted once all its outputs are spent.
- **UTXO records commit to their whole output,** so a snapshot cannot alter
  scanning data.
- **Wallets** restoring from a pruned node scan the unspent-output set
  (`GET /utxos`) instead of block bodies.

### Networking (midstate)

- **Transports:** TCP and QUIC (WebRTC-direct behind a feature), with Noise and
  Yamux.
- **Discovery and reachability:** Kademlia on a private protocol id, identify,
  relay, DCUtR hole punching, AutoNAT, peer exchange, and the IPFS-DHT
  rendezvous.
- **Limits:** connection caps per /24 subnet and on inbound peers.
- **Light clients:** a light-client protocol with a reputation-based rate
  limiter.
- **Dandelion++:** expired stem transactions are aggregated before fluffing.
- **Sync:**
  - headers first, with SIMD proof-of-work checks;
  - blocks downloaded from several peers at once, with resume from verified
    headers after a restart;
  - reorgs committed atomically;
  - fork states rebuilt from on-disk undo records.
- **Storage:** incremental redb tables, with group and kernel bookkeeping for
  pruning. The state is checked against the tip header on load.
- **Sync modes:** full verification from genesis (default), or checkpoint
  verification from a trusted checkpoint id (`--checkpoint`), which verifies a
  snapshot and its Midstate anchor before validating everything after it in
  full.

## Build and test

```sh
cargo build --release                                  # node, wallet, pool, merged miner, anchoring
cargo build --release --features gpu                   # + midstate's wgpu miner
cargo test --features fast-mining                      # 190 unit, 16 integration, 11 doc tests
cargo test --lib                                       # production constants (165 tests)
cargo test --no-default-features --features fast-mining --lib   # core only (159 tests)
```

`fast-mining` makes proof of work trivial, moves genesis to 2023, sets
coinbase maturity to 3 and skips the slow start. Never ship a binary built with
it. `midwimble params` prints a build's launch parameters, emission calendar and
genesis block id; a build whose launch parameters are still placeholders says
so there and at node startup. Release builds have
not been compiled in this environment.

The integration tests run real nodes on localhost:

| Test | What it shows |
|---|---|
| `network` (8) | gossip sync and a Dandelion++ payment; shallow and deep reorgs; late-joiner sync with restart; resumed sync; multi-peer download; forged-block peers banned |
| `merge_mining` (1) | one search mines both chains against a midstate stand-in built from midstate's own types; merged-mining anchors recorded and verified; a second node syncs the merged-mined chain |
| `pool` (1) | two auditing miners paid in coinbases; fee to the operator; supply audit holds |
| `quantum_recovery` (3) | an attacker holding every elliptic-curve secret cannot claim anchored coins while owners can; a genuinely broken commitment binding still cannot inflate a claim; anchoring round trip with chained checkpoints and tamper detection |
| `pruning` (3) | an anchored checkpoint finalizes, bodies are pruned and a new node bootstraps from the snapshot to the same state root; a heavier chain cannot reorganise below the floor; a wallet restores from a pruned node |

**GPU.** `midwimble gpu-info` runs midstate's shader self-test. It was
verified here on Mesa llvmpipe (software Vulkan), including chains split across
many dispatches, via `MIDWIMBLE_GPU_ALLOW_SOFTWARE=1`. It has not been tested
on real GPU hardware.

## Usage

```sh
export MIDWIMBLE_PASSWORD=...
midwimble wallet --wallet w.mww create            # prints a v1 address + 24 words (recovery key: ~seconds to a minute)
midwimble node --data-dir ./node --mine-to <address> [--backend gpu] [--prune]
midwimble node --data-dir ./node --checkpoint <checkpoint id>   # checkpoint verification
midwimble wallet --wallet w.mww balance
midwimble wallet --wallet w.mww send --to <address> --amount 0.25   # amounts in coins

# merged mining against a midstate node
midwimble merge-mine --midstate-rpc 127.0.0.1:8545 --midstate-address <hex> \
    --midwimble-address <address> --anchor-store anchors.jsonl

# pool and pool miners
midwimble pool --address <operator address> --stratum 0.0.0.0:3333 --api 0.0.0.0:8081
midwimble pool-mine --pool stratum+tcp://host:3333 --address <address>

# anchoring checkpoints in midstate
midwimble anchor --midstate-rpc 127.0.0.1:8545 --depth 6
midwimble anchor-verify --depth 6
```

**RPC.** The node serves these endpoints on loopback, with no authentication:

- `GET /state`
- `GET /blocks/{start}/{count}`
- `GET /headers/{start}/{count}`
- `GET /utxo/{commitment}`
- `GET /mempool`
- `POST /tx`
- `POST /mining`
- `POST /mining/template` (weighted payouts, `extra`, receipts)
- `POST /mining/submit`
- `POST /peers`
- `GET /utxos` (unspent outputs, for wallets on pruned nodes)
- `GET /anchors`, `POST /anchors`
- `GET /finality`

## Upstream bug found in midstate

`mss::keygen` resumes from `mss_h{height}.checkpoint` whatever seed wrote it.
If a generation is interrupted and a different seed later generates a key of
the same height in that directory, the new key loads the old leaves. Its tree
then no longer matches its seed, and signatures from those leaves fail to
verify. The vendored copy keys the file by a seed fingerprint.

## Before any real launch

- [x] Emission schedule, supply cap and decimals (`core/types.rs`).
- [ ] Run `scripts/set_launch_params.py` on launch day: network magic, a
  Bitcoin anchor mined after the code freeze, the genesis time, and a genesis
  target calibrated from midstate's live target (`docs/LAUNCH.md`).
- [ ] Get a cryptographic review of:
  - the ownership scheme (owner sum, kernel AND-proof, transcript binding);
  - the merged-mining proof;
  - the recovery commitments.
- [ ] Set a real minimum work for anchor verification. The CLI defaults to 0.
- [ ] Decide the anchoring cadence and depth, and the social process for
  choosing a recovery checkpoint (`docs/ANCHORING.md` §7).
- [ ] Decide the finality depth and how many archive nodes keep full history,
  since pruned nodes cannot serve it (`docs/PRUNING.md`).
- [ ] Re-evaluate `EXTENSION_ITERATIONS`. A header check costs one full
  attempt.

## Known limitations

- **Not post-quantum in normal operation.** Anchoring plus recovery
  commitments make a *recovery* possible after a curve break, but the recovery
  epoch is a future hard fork and is not wired into the node.
- **Recovery commitments are written by senders.** Wallets flag bad ones
  (`unrecoverable_coins`); consensus cannot check them without heavy
  zero-knowledge proofs.
- **Anchor verification is SPV-level.** Cross-check with a trusted midstate
  node where that matters. Everything midstate-facing has been tested against
  a stand-in built from midstate's source, not a live midstate node.
- **Pruned nodes cannot serve history.** A network needs archive nodes for
  new full-verification peers; checkpoint-synced nodes also cannot serve
  headers below their snapshot.
- **Conflicting anchors stop finalization** rather than resolving by
  "earliest anchored wins".
- **Full verification does not use snapshots yet**; it downloads every block.
- **Wallets restored from a pruned node lose outgoing history** (they see
  only unspent outputs).
- **Staged reorgs are held in memory** (at most 1,000 blocks), and startup
  scans the UTXO set once.
- **Linked outputs:** outputs in one range-proof group are visibly linked (the
  cost of keeping aggregation; one proof per output would remove it).
- **Pool:** at most 31 miners are paid per block; the others carry their score
  forward. The WebRTC browser pool from midstate is not ported.
- **Wallet:** no outgoing history, and the password prompt echoes (use
  `MIDWIMBLE_PASSWORD`).

## Licence

GPL-3.0-or-later (see `LICENSE`), matching midstate and pluribit.
