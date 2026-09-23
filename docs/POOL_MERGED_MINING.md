# Pool merged mining

A midstate pool mines midwimble at the same time, and pays its miners in both
coins. Miners change nothing: no bond, no midwimble software, no second wallet
unless they want the rewards.

This matters more than solo merged mining. Most hashrate mines through pools,
and midwimble's security rests on merged miners showing up. It also spares
miners the fractured wallet that importing mined coinbases produces.

## Who holds what

- **The pool operator** runs a midwimble node with a mining bond
  (`docs/BONDED_POW.md`). One bond covers the whole pool: bond value is a gate,
  never a weight, so a pool's bond buys it no more midwimble than any other
  producer's.
- **Miners** keep mining midstate shares exactly as now. A miner who registers
  a midwimble address with the pool is paid directly in the midwimble
  coinbase, provably, the same way midwimble's own pool pays.
- **Nobody needs a second bond.** The pool produces the blocks, so the pool
  holds the only bond.

## Why it works

Midstate's pool already plants its score-commitment root in the salt of a
coinbase output. Midwimble's merged-mining commitment goes in a coinbase
output's salt too. They simply live in different outputs of the same coinbase,
and neither knows about the other.

A share is a midstate header that met the pool's share target. If that same
header happens to clear midwimble's target, it is a valid midwimble block,
because the midstate coinbase commits to a midwimble block. One search, both
chains: exactly what a solo merged miner does, only the pool builds the
coinbase and so places the commitment.

## The protocol

Two endpoints on the midwimble node, and no new process:

**`POST /merge/job`** — the pool asks what to commit to.

```json
{ "payouts": [ { "address": "mw1…", "weight": 41 }, … ] }
→ { "commitment": "<32 bytes hex>", "target": "<32 bytes hex>",
    "mining_hash": "<32 bytes hex>", "height": 1234 }
```

The node builds a midwimble template paying those addresses in those
proportions, signs it with its bond, caches it, and returns the commitment to
plant plus the target a share must beat to be a midwimble block.

**`POST /merge/found`** — the pool found one.

```json
{ "mining_hash": "…", "batch_template": { … midstate batch JSON … },
  "commit_index": 3, "nonce": 12345, "final_hash": "…" }
→ { "accepted": true, "height": 1234 }
```

The node rebuilds the parent proof from the midstate template, checks that it
really commits to that mining hash, seals the midwimble block with it, and
applies it.

## What the pool changes

1. **Configuration:** the midwimble node's address, and a midwimble payout
   address per miner (optional; miners without one simply aren't paid in
   midwimble).
2. **Building a job:** call `/merge/job` with the same score table the job's
   precommitment root is built from, put the returned commitment in the salt of
   one coinbase output, and remember that output's index. Keep the returned
   target in the job.
3. **Processing a share:** if the share's final hash also clears the job's
   midwimble target, call `/merge/found` with the job's batch template, the
   commitment output's index, and the share's nonce and final hash.

Everything else — share accounting, payouts, the provably-fair score tree —
stays as it is. A pool that doesn't configure a midwimble node behaves exactly
as before.

## Failure behaviour

- **The midwimble node is unreachable:** the pool builds jobs without a
  commitment and mines midstate alone. Merged mining is an extra, never a
  dependency.
- **The bond lapses or the node has none:** `/merge/job` fails, and the same
  thing happens. The pool keeps mining midstate.
- **A midwimble block is rejected:** the midstate block, if the share cleared
  midstate's target too, is unaffected. The two submissions are independent.
- **Refreshing jobs:** a commitment names one midwimble block, so a job's
  commitment goes stale when midwimble's tip moves. The pool should refresh
  jobs on midwimble's tip as well as midstate's. A stale commitment costs
  nothing; those shares simply don't yield midwimble blocks.

## Paying miners in midwimble

The payouts the pool sends with `/merge/job` become the midwimble coinbase's
outputs, so miners are paid directly by the block, with the same receipts and
audit midwimble's own pool provides (`pool::audit_job`). A pool that would
rather pay from its own wallet can send a single payout to itself instead; the
provable path is the default worth keeping.
