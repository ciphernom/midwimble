#!/usr/bin/env python3
"""Fill in midwimble's launch parameters on launch day.

Rewrites only the block between `// @launch-params:begin` and
`// @launch-params:end` in src/core/types.rs, then prints the launch calendar.
See docs/LAUNCH.md for the whole procedure. Typical use:

    scripts/set_launch_params.py \\
        --bitcoin-height 9xxxxx --bitcoin-hash 0000...  --bitcoin-time 2026-11-02T15:04:11Z \\
        --genesis-time 2026-11-02T16:00:00Z \\
        --midstate-rpc 127.0.0.1:8545 --merge-share 0.5

Nothing here is consensus code: it only writes constants that consensus reads,
and refuses values that would make an obviously broken or unfair launch.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import sys
import urllib.request

REPO = pathlib.Path(__file__).resolve().parent.parent
BEGIN, END = "// @launch-params:begin", "// @launch-params:end"

BLOCK_TIME = 60
HALVING_INTERVAL = 2_100_000
SLOW_START_BLOCKS = 43_200
MAX_TARGET = (1 << 256) - 1

# Midstate's own schedule, for keeping the two chains' halvings apart.
MIDSTATE_GENESIS = 1_772_274_770
MIDSTATE_HALVING_SECONDS = 525_600 * 60
MIDSTATE_ANCHOR_HEIGHT = 938_708
# Midstate's genesis target: far too easy for a merge-mined network.
MIDSTATE_GENESIS_TARGET = int("0011" + "ff" * 30, 16)


def die(msg: str) -> None:
    sys.exit(f"error: {msg}")


def warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


def parse_time(s: str) -> int:
    """Unix seconds, or ISO 8601 in UTC (a trailing Z is required)."""
    s = s.strip()
    if s.isdigit():
        return int(s)
    if not s.endswith("Z"):
        die(f"'{s}': write times in UTC with a trailing Z, or as Unix seconds")
    return int(dt.datetime.fromisoformat(s[:-1]).replace(tzinfo=dt.timezone.utc).timestamp())


def utc(ts: int) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def hex32(s: str, what: str) -> str:
    s = s.strip().lower().removeprefix("0x")
    if not re.fullmatch(r"[0-9a-f]{64}", s):
        die(f"{what} must be 64 hex characters")
    return s


def midstate_get(rpc: str, path: str):
    url = rpc if rpc.startswith("http") else f"http://{rpc}"
    try:
        with urllib.request.urlopen(f"{url.rstrip('/')}{path}", timeout=15) as r:
            return json.load(r)
    except Exception as e:  # noqa: BLE001 - any failure here is fatal and explained
        die(f"could not read {path} from the midstate node at {url}: {e}")


def fetch_midstate(rpc: str) -> tuple[str, int, str]:
    """Midstate's live target, and its tip as an anchor: (target, height, hash).

    The tip's height is confirmed against `/headers`, whose `final_hash` is
    the block hash, rather than assumed from `/state`'s height convention."""
    state = midstate_get(rpc, "/state")
    if state.get("is_syncing"):
        die("the midstate node is still syncing; its tip and target are stale")
    tip_hash = hex32(state["header_hash"], "midstate header_hash")
    reported = int(state["height"])
    for h in (reported, reported - 1):
        got = midstate_get(rpc, f"/headers/{h}/1").get("headers", [])
        if got and bytes(got[0]["extension"]["final_hash"]).hex() == tip_hash:
            return hex32(state["target"], "midstate target"), h, tip_hash
    die("could not match the midstate tip hash to a stored header; is the node's /headers endpoint patched in?")


def leading_zero_bits(t: int) -> int:
    return 256 - t.bit_length()


def attempts_per_second(t: int) -> int:
    return (MAX_TARGET // max(t, 1)) // BLOCK_TIME


def render(p: dict) -> str:
    target_note = p["target_note"]
    return f"""{BEGIN}

/// Distinguishes this network from midstate and from other deployments of
/// this code. Feeds the genesis midstate, every signed message, the merged-
/// mining commitment and the DHT rendezvous key.
pub const NETWORK_MAGIC: &[u8] = b"{p['magic']}";

/// Bitcoin block anchoring the genesis. Its hash could not be known before it
/// was mined, so a chain committing to it cannot have been started (or quietly
/// pre-mined) any earlier.
pub const BITCOIN_BLOCK_HASH: &str =
    "{p['btc_hash']}";
pub const BITCOIN_BLOCK_HEIGHT: u64 = {p['btc_height']};
/// The anchor block's own timestamp ({utc(p['btc_time'])}). Genesis may not precede it.
pub const BITCOIN_BLOCK_TIME: u64 = {p['btc_time']:_};

/// Midstate block anchoring the genesis: midstate's tip at launch. Like the
/// Bitcoin anchor it could not be known before it was mined, and it pins the
/// midstate chain that bonded mining is judged against.
pub const MIDSTATE_BLOCK_HASH: &str =
    "{p['ms_hash']}";
pub const MIDSTATE_BLOCK_HEIGHT: u64 = {p['ms_height']};

/// Mainnet genesis time; see [`GENESIS_TIMESTAMP`].
const LAUNCH_GENESIS_TIMESTAMP: u64 = {p['genesis_time']:_}; // {utc(p['genesis_time'])}

/// Mainnet genesis target; see [`GENESIS_TARGET`].
/// {target_note}
const LAUNCH_GENESIS_TARGET: [u8; 32] =
    hex32("{p['target']:064x}");

/// Set by `scripts/set_launch_params.py`: these are real launch parameters.
pub const LAUNCH_PARAMETERS_SET: bool = true;

{END}"""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--magic", default="MIDWIMBLE_MAINNET_V1",
                    help="network magic (use a different one for any public testnet)")
    ap.add_argument("--bitcoin-height", type=int, required=True)
    ap.add_argument("--bitcoin-hash", required=True)
    ap.add_argument("--bitcoin-time", required=True, help="the anchor block's timestamp")
    ap.add_argument("--genesis-time", required=True,
                    help="when mining opens; not before the anchor block")
    tgt = ap.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--midstate-rpc", help="read the live target from a midstate node (host:port)")
    tgt.add_argument("--midstate-target", help="midstate's current target, as reported by its /state")
    tgt.add_argument("--genesis-target", help="use this target as-is (expert use)")
    ap.add_argument("--midstate-block-height", type=int,
                    help="midstate anchor block (read from --midstate-rpc if omitted)")
    ap.add_argument("--midstate-block-hash", help="hash of that midstate block")
    ap.add_argument("--merge-share", type=float, default=0.25,
                    help="share of midstate's hashrate expected to mine midwimble at launch "
                         "(default 0.25: bonded mining from block 1 means only MDS holders mine "
                         "at first)")
    ap.add_argument("--types-rs", type=pathlib.Path, default=REPO / "src/core/types.rs")
    ap.add_argument("--dry-run", action="store_true", help="print the block instead of writing it")
    a = ap.parse_args()

    magic = a.magic
    if not re.fullmatch(r"[A-Z0-9_]{4,32}", magic):
        die("--magic must be 4-32 characters of A-Z, 0-9 and _")

    btc_hash = hex32(a.bitcoin_hash, "--bitcoin-hash")
    if not btc_hash.startswith("0" * 16):
        die("--bitcoin-hash has too few leading zeros to be a Bitcoin block hash (a txid?)")
    if a.bitcoin_height <= MIDSTATE_ANCHOR_HEIGHT:
        die("--bitcoin-height must be newer than midstate's own anchor block")
    btc_time = parse_time(a.bitcoin_time)
    genesis = parse_time(a.genesis_time)
    if genesis < btc_time:
        die("genesis cannot precede the Bitcoin block it commits to")
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    if genesis < now:
        warn(f"genesis ({utc(genesis)}) is already in the past: nodes started now will see the chain "
             f"behind schedule and ASERT will hand out easy blocks until it catches up")
    if genesis - btc_time > 6 * 3600:
        warn("more than six hours between the anchor block and genesis: that is a window in which "
             "anyone holding the release can pre-mine blocks for the first minutes of the chain")

    if not 0.0 < a.merge_share <= 1.0:
        die("--merge-share must be in (0, 1]")
    if a.genesis_target:
        target = int(hex32(a.genesis_target, "--genesis-target"), 16)
        note = "Given explicitly on the command line."
    else:
        if a.midstate_rpc:
            ms_hex, live_height, live_hash = fetch_midstate(a.midstate_rpc)
            source = f"midstate's target at height {live_height}"
        else:
            ms_hex, source = hex32(a.midstate_target, "--midstate-target"), "midstate's target"
        ms = int(ms_hex, 16)
        per_mille = round(a.merge_share * 1000)
        target = min(MAX_TARGET, ms * 1000 // per_mille)
        note = f"{source} ({ms_hex[:16]}…) divided by an expected merged-mining share of {a.merge_share}."
    if target == 0:
        die("target is zero")
    if target >= MIDSTATE_GENESIS_TARGET:
        die("that target is midstate's genesis difficulty or easier: thousands of near-free blocks "
            "would follow launch. Calibrate from midstate's *current* target")
    if leading_zero_bits(target) < 16:
        warn("the genesis target has fewer than 16 leading zero bits; is that really intended?")

    if a.midstate_block_hash or a.midstate_block_height is not None:
        if not (a.midstate_block_hash and a.midstate_block_height is not None):
            die("give both --midstate-block-hash and --midstate-block-height")
        ms_hash, ms_height = hex32(a.midstate_block_hash, "--midstate-block-hash"), a.midstate_block_height
    elif a.midstate_rpc:
        if 'live_hash' not in locals():
            _, live_height, live_hash = fetch_midstate(a.midstate_rpc)
        ms_hash, ms_height = live_hash, live_height
    else:
        die("the genesis also commits to a midstate block: pass --midstate-rpc, or "
            "--midstate-block-hash and --midstate-block-height")
    if ms_hash == "0" * 64:
        die("the midstate anchor hash is all zeros")

    params = dict(magic=magic, btc_hash=btc_hash, btc_height=a.bitcoin_height, btc_time=btc_time,
                  genesis_time=genesis, target=target, target_note=note,
                  ms_hash=ms_hash, ms_height=ms_height)
    block = render(params)

    src = a.types_rs.read_text()
    if src.count(BEGIN) != 1 or src.count(END) != 1:
        die(f"{a.types_rs} does not contain exactly one launch-parameters block")
    head, rest = src.split(BEGIN)
    _, tail = rest.split(END)
    updated = head + block + tail

    if a.dry_run:
        print(block)
    else:
        a.types_rs.write_text(updated)
        print(f"wrote launch parameters to {a.types_rs}")

    # ── The calendar this launch implies ───────────────────────────────────
    print()
    print(f"network magic      {magic}")
    print(f"bitcoin anchor     {a.bitcoin_height}  {btc_hash}  ({utc(btc_time)})")
    print(f"midstate anchor    {ms_height}  {ms_hash}")
    print(f"mining opens       {utc(genesis)}")
    print(f"slow start ends    ~{utc(genesis + SLOW_START_BLOCKS * BLOCK_TIME)}")
    print(f"genesis target     {leading_zero_bits(target)} leading zero bits, "
          f"60 s blocks at ~{attempts_per_second(target):,} attempts/s")
    clashes = []
    for k in range(1, 11):
        when = genesis + k * HALVING_INTERVAL * BLOCK_TIME
        n = round((when - MIDSTATE_GENESIS) / MIDSTATE_HALVING_SECONDS)
        gap_days = abs(when - (MIDSTATE_GENESIS + n * MIDSTATE_HALVING_SECONDS)) / 86400
        if k <= 5:
            print(f"halving {k:<2}         ~{utc(when)}   ({gap_days:.0f} days from a midstate halving)")
        if gap_days < 30:
            clashes.append(k)
    if clashes:
        warn(f"midwimble halving(s) {clashes} fall within 30 days of a midstate halving, so merged "
             f"miners would take two cuts at once. Consider moving the launch date.")
    print()
    print("next: cargo test --lib && cargo run --release -- params")
    print("      then publish the genesis block id it prints alongside the release.")


if __name__ == "__main__":
    main()
