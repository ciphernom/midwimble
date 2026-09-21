#!/usr/bin/env python3
"""Rehearse bonded mining against your real midstate node (docs/REHEARSAL.md).

Builds production midwimble for a private rehearsal network, then does what a
block producer does on launch day, checking every step:

  1. Preflight   the midstate node runs the bonded-mining patch
  2. Build       production midwimble, anchored to real Bitcoin and midstate
  3. Exit drill  lock a small coin in a bond script and spend it back, proving
                 your owner key opens the lock before real money goes behind it
  4. Bond        lock 16 gMDS for the minimum term, on midstate mainnet
  5. Register    prove the bond from your midstate node, then wait for a day of
                 work at the rehearsal difficulty (about 75 midstate blocks)
  6. Mine        a producer and a peer: block 1 registers the bond, every block
                 is signed, and the peer validates all of it

Steps that use your midstate wallet are printed for you to run. Progress is
saved in the work directory, so stop and rerun at will: it resumes.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO = pathlib.Path(__file__).resolve().parent.parent

# Consensus values this plans around (src/core/bond.rs).
MIN_MINING_BOND = 1 << 34  # 16 gMDS
MIN_REMAINING_BOND_LOCK = 43_200  # 30 days of midstate blocks
CLOCK_MARGIN = 10_080  # 7 days
MIDSTATE_GENESIS_TIMESTAMP = 1_772_274_770
MAGIC = "MIDWIMBLE_REHEARSAL_V1"
PORTS = {"a": (19433, 19434), "b": (19533, 19534)}  # (p2p, rpc)

OUTPUT_LINE = re.compile(r"([0-9a-f]{64}):(\d+)\s+salt\s+([0-9a-f]{64})\s+coin\s+([0-9a-f]{64})")


def est_midstate_height(t: int) -> int:
    """The same deliberately high clock estimate consensus uses."""
    return (t - MIDSTATE_GENESIS_TIMESTAMP) // 60 + CLOCK_MARGIN


def section(title: str) -> None:
    print(f"\n── {title} " + "─" * max(4, 70 - len(title)))


def ok(text: str) -> None:
    print(f"  ✓ {text}")


def die(text: str) -> None:
    sys.exit(f"\n  ✗ {text}")


def ask(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        die("no input: this step needs you at the keyboard")
        return ""


def get_json(addr: str, path: str, timeout: int = 20):
    url = (addr if addr.startswith("http") else f"http://{addr}").rstrip("/") + path
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:  # error responses carry JSON bodies
        try:
            return json.loads(e.read())
        except Exception:  # noqa: BLE001
            raise e


def try_get(addr: str, path: str):
    try:
        return get_json(addr, path, timeout=5)
    except Exception:  # noqa: BLE001 - "not up yet" is the expected failure
        return None


def wait_until(what: str, done, interval: int = 15, timeout: int = 7200):
    deadline, last = time.time() + timeout, 0.0
    while True:
        result = done()
        if result:
            return result
        if time.time() > deadline:
            die(f"timed out waiting for {what}")
        if time.time() - last > 60:
            print(f"  … waiting for {what}")
            last = time.time()
        time.sleep(interval)


def run(cmd, cwd=None, env=None, stream=False) -> str:
    cmd = [str(c) for c in cmd]
    print(f"  $ {' '.join(cmd)}")
    if stream:
        subprocess.run(cmd, cwd=cwd, env=env, check=True)
        return ""
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    if p.returncode != 0:
        die(f"command failed:\n{p.stdout}{p.stderr}")
    return p.stdout


def indent(text: str) -> str:
    return "\n".join("    " + line for line in text.strip().splitlines())


def field(out: str, name: str) -> str:
    m = re.search(rf"^{name}\s+([0-9a-f]+)\s*$", out, re.M)
    if not m:
        die(f"could not find '{name}' in:\n{out}")
    return m.group(1)


class Rehearsal:
    def __init__(self, args):
        self.a = args
        self.ms = args.midstate_rpc
        self.dir = pathlib.Path(args.workdir).resolve()
        self.dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.dir / "rehearsal.json"
        self.s = json.loads(self.state_file.read_text()) if self.state_file.exists() else {}
        self.bin = self.dir / "target" / "release" / "midwimble"
        self.procs: list[subprocess.Popen] = []

    def save(self) -> None:
        self.state_file.write_text(json.dumps(self.s, indent=2))

    def midstate_height(self) -> int:
        return int(get_json(self.ms, "/state")["height"])

    # ── 1. Preflight ────────────────────────────────────────────────────────
    def preflight(self) -> None:
        section("1. Preflight: your midstate node")
        st = try_get(self.ms, "/state")
        if not st:
            die(f"no midstate node answering at {self.ms}")
        if st.get("is_syncing"):
            die("the midstate node is still syncing")
        h = int(st["height"])
        ok(f"midstate node at height {h}")
        if not (get_json(self.ms, f"/headers/{h - 1}/1").get("headers")):
            die("GET /headers is missing: apply midstate-bonded-pow.patch and restart the node")
        ok("GET /headers present")
        refusal = str(get_json(self.ms, "/utxo_proof/" + "00" * 32).get("error", ""))
        if "not unspent" not in refusal:
            die(f"GET /utxo_proof is missing or unexpected: {refusal[:120]}")
        ok("GET /utxo_proof present")
        if not shutil.which("cargo"):
            die("cargo is not on PATH")

    # ── 2. Build ────────────────────────────────────────────────────────────
    def bitcoin_anchor(self) -> dict:
        if self.a.bitcoin_hash:
            return {"height": self.a.bitcoin_height, "hash": self.a.bitcoin_hash, "time": self.a.bitcoin_time}
        try:
            with urllib.request.urlopen("https://mempool.space/api/blocks/tip/hash", timeout=20) as r:
                tip = r.read().decode().strip()
            with urllib.request.urlopen(f"https://mempool.space/api/block/{tip}", timeout=20) as r:
                block = json.load(r)
        except Exception as e:  # noqa: BLE001
            die(f"could not fetch Bitcoin's tip from mempool.space ({e}); "
                "pass --bitcoin-height, --bitcoin-hash and --bitcoin-time")
        ok(f"Bitcoin anchor: block {block['height']} (from mempool.space)")
        return {"height": block["height"], "hash": tip, "time": block["timestamp"]}

    def build(self) -> None:
        if self.s.get("built") and self.bin.exists():
            ok("rehearsal build already made")
            return
        section("2. Build production midwimble for a private rehearsal network")
        src = self.dir / "midwimble"
        if not src.exists():
            def skip(dirpath, names):
                here = pathlib.Path(dirpath)
                return [n for n in names if n in ("target", ".git") or (here / n).resolve() == self.dir]
            shutil.copytree(REPO, src, ignore=skip)
            ok(f"copied the source to {src} (your tree is not touched)")
        btc = self.bitcoin_anchor()
        genesis = int(time.time()) + 120
        run([sys.executable, src / "scripts/set_launch_params.py", "--magic", MAGIC,
             "--bitcoin-height", btc["height"], "--bitcoin-hash", btc["hash"], "--bitcoin-time", btc["time"],
             "--genesis-time", genesis, "--midstate-rpc", self.ms, "--merge-share", self.a.merge_share,
             "--types-rs", src / "src/core/types.rs"])
        env = dict(os.environ, CARGO_TARGET_DIR=str(self.dir / "target"))
        run(["cargo", "build", "--release", "--bin", "midwimble"], cwd=src, env=env, stream=True)
        params = run([self.bin, "params"])
        print(indent(params))
        self.s["built"] = {"genesis_time": genesis}
        self.save()

    # ── Shared steps ────────────────────────────────────────────────────────
    def owner_key(self) -> str:
        if "owner_pk" in self.s:
            return self.s["owner_pk"]
        section("Your bond owner key")
        print("  Run:   midstate wallet generate-mss")
        print("  and copy the 'Public key' it prints: 64 hex characters, NOT the address.")
        print("  (A bond locked to an address can never be spent.)")
        while True:
            pk = ask("  Public key: ").strip().lower()
            if re.fullmatch(r"[0-9a-f]{64}", pk):
                break
            if re.fullmatch(r"[0-9a-f]{72}", pk):
                print("  That is an address (72 characters, with a checksum). The bond needs the public key.")
            else:
                print("  Expected 64 hex characters.")
        self.s["owner_pk"] = pk
        self.save()
        return pk

    def fund(self, address: str, value: int) -> dict:
        print(f"\n  In another terminal, run:\n\n    midstate wallet send --to {address}:{value}\n")
        print("  It lists the outputs it pays to others. Paste the line for this address:")
        while True:
            m = OUTPUT_LINE.search(ask("  → ").strip().lower())
            if not m:
                print("  Could not read that. Paste the whole line: <address>:<value>  salt <hex>  coin <hex>")
                continue
            addr, val, salt, coin = m.groups()
            if addr != address or int(val) != value:
                print(f"  That line pays {addr[:16]}…:{val}, not {address[:16]}…:{value}.")
                continue
            return {"salt": salt, "coin": coin}

    def wait_coin(self, coin: str, present: bool, what: str) -> None:
        wait_until(what, lambda: bool(get_json(self.ms, f"/coin/{coin}").get("exists")) == present, 15)

    def bond_address(self, file: pathlib.Path, until: int) -> tuple[str, str]:
        out = run([self.bin, "bond", "address", "--file", file, "--owner-pk", self.owner_key(), "--until", until])
        return field(out, "script"), field(out, "address")

    # ── 3. Exit drill ───────────────────────────────────────────────────────
    def drill(self) -> None:
        d = self.s.setdefault("drill", {})
        if d.get("passed"):
            ok("exit drill already passed")
            return
        section("3. Exit drill: unlock a small bond before locking a real one")
        pk = self.owner_key()
        file = self.dir / "drill-bond.json"
        if not file.exists():
            run([self.bin, "bond", "new", "--file", file])
        if "until" not in d:
            d["until"] = self.midstate_height() + 5
            d["script"], d["address"] = self.bond_address(file, d["until"])
            self.save()
        if "coin" not in d:
            d.update(self.fund(d["address"], self.a.drill_value))
            self.save()
        self.wait_coin(d["coin"], True, "the drill coin to be mined")
        ok("drill coin is on chain")
        wait_until(f"midstate height {d['until']}, when the drill lock opens",
                   lambda: self.midstate_height() >= d["until"], 20)
        print("\n  Unlock it now: half back to you, the rest returns as change minus the fee.\n")
        print(f"    midstate wallet spend-script --coin {d['coin']} --bytecode {d['script']} \\")
        print(f"        --inputs AUTO:{pk} --to <your address from `midstate wallet receive`>:{self.a.drill_value // 2}\n")
        ask("  Press Enter once it has confirmed… ")
        self.wait_coin(d["coin"], False, "the drill coin to be spent")
        ok("exit drill passed: your owner key and wallet open a bond lock")
        d["passed"] = True
        self.save()

    # ── 4. The real bond ────────────────────────────────────────────────────
    def bond(self) -> None:
        b = self.s.setdefault("bond", {})
        section("4. The real bond")
        file = self.dir / "bond.json"
        if not file.exists():
            run([self.bin, "bond", "new", "--file", file])
        if "until" not in b:
            b["until"] = est_midstate_height(int(time.time())) + MIN_REMAINING_BOND_LOCK + 1440
            b["script"], b["address"] = self.bond_address(file, b["until"])
            self.save()
        days = (b["until"] - self.midstate_height()) / 1440
        print(f"  Locks until midstate height {b['until']}, about {days:.0f} days from now:")
        print("  the minimum term plus a day. It can mine while more than 30 days remain.")
        if "coin" not in b:
            if ask(f"  Lock {MIN_MINING_BOND >> 30} gMDS of real MDS until then? [y/N] ").strip().lower() != "y":
                die("stopped before locking the bond")
            b.update(self.fund(b["address"], MIN_MINING_BOND))
            self.save()
        self.wait_coin(b["coin"], True, "the bond coin to be mined")
        ok("bond coin is on chain")

    # ── 5. Registration ─────────────────────────────────────────────────────
    def register(self) -> None:
        b = self.s["bond"]
        if b.get("registered"):
            ok("bond already registered")
            return
        section("5. Register the bond from your midstate node")
        cmd = [self.bin, "bond", "register", "--file", self.dir / "bond.json", "--owner-pk", self.owner_key(),
               "--until", b["until"], "--value", MIN_MINING_BOND, "--salt", b["salt"], "--midstate-rpc", self.ms]
        while True:
            out = run(cmd)
            print(indent(out))
            if "Ready:" in out:
                break
            print("  Checking again in 5 minutes (about 75 midstate blocks in all)…")
            time.sleep(300)
        b["registered"] = True
        self.save()

    # ── 6. Bonded mining ────────────────────────────────────────────────────
    def start_node(self, name: str, extra: list) -> str:
        p2p, rpc = PORTS[name]
        log = open(self.dir / f"node-{name}.log", "a")
        cmd = [str(self.bin), "node", "--data-dir", str(self.dir / f"node-{name}"),
               "--listen", f"/ip4/127.0.0.1/tcp/{p2p}", "--rpc", f"127.0.0.1:{rpc}", *map(str, extra)]
        print(f"  $ {' '.join(cmd)}   (log: {log.name})")
        self.procs.append(subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT))
        return f"127.0.0.1:{rpc}"

    def mine(self) -> None:
        section("6. Bonded mining on the rehearsal network")
        env = dict(os.environ, MIDWIMBLE_PASSWORD="rehearsal")
        wallet = self.dir / "payout.mww"
        if not wallet.exists():
            print("  Creating a payout wallet: its post-quantum recovery key takes a minute or two.")
            run([self.bin, "wallet", "--wallet", wallet, "create"], env=env)
        found = re.findall(r"\bmw1[0-9a-z]{20,}", run([self.bin, "wallet", "--wallet", wallet, "address"], env=env))
        if not found:
            die("could not read the payout address")
        producer = self.start_node("a", ["--mine-to", found[-1], "--mining-bond", self.dir / "bond.json",
                                         "--threads", self.a.threads])
        st = wait_until("the producer's RPC", lambda: try_get(producer, "/state"), 2, 120)
        peer = self.start_node("b", ["--peers", f"/ip4/127.0.0.1/tcp/{PORTS['a'][0]}/p2p/{st['peer_id']}"])
        height = lambda rpc: (try_get(rpc, "/state") or {}).get("height", 0)  # noqa: E731
        wait_until("the producer to mine four blocks", lambda: height(producer) > 4, 10, 3600)
        wait_until("the peer to sync them", lambda: height(peer) > 4, 10, 900)

        blocks = get_json(peer, "/miners/1/4")["blocks"]
        registered = blocks[0]["registrations"]
        if len(registered) != 1:
            die(f"block 1 should register exactly one bond: {blocks[0]}")
        bond_id = registered[0]
        ok(f"block 1 registers bond {bond_id[:16]}…, proven from real midstate data")
        if not all(b["bond_id"] == bond_id for b in blocks):
            die(f"not every block is signed by the bond: {blocks}")
        ok("every block is signed by that bond")
        if any(b["registrations"] for b in blocks[1:]):
            die("a later block registered again")
        ok("later blocks carry only the signature")
        bonds = get_json(peer, "/bonds")["bonds"]
        if not any(x["bond_id"] == bond_id and x["eligible_now"] for x in bonds):
            die(f"the peer does not see the bond as eligible: {bonds}")
        ok("the peer, which mined nothing, validated all of it and holds the same bond set")

        b = self.s["bond"]
        section("Rehearsal complete")
        print(f"  Bond coin {b['coin']} stays locked until midstate height {b['until']}.")
        print("  Once midstate passes it, spend it back exactly as in the exit drill:\n")
        print(f"    midstate wallet spend-script --coin {b['coin']} --bytecode {b['script']} \\")
        print(f"        --inputs AUTO:{self.owner_key()} --to <your address>:{MIN_MINING_BOND // 2}\n")
        print("  This bond has the minimum term, so it could mine only for about a day after it")
        print("  was locked; after that it simply waits out its lock. For the real launch, lock a")
        print("  new bond shortly before launch day, with a term covering as long as you mean to")
        print("  mine: a bond is eligible while more than 30 days of its lock remain.")

    def close(self) -> None:
        if self.procs and not self.a.keep_running:
            for p in self.procs:
                p.terminate()
            print("\n  Rehearsal nodes stopped (--keep-running leaves them up).")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--midstate-rpc", default="127.0.0.1:8545")
    ap.add_argument("--workdir", default=str(REPO.parent / "midwimble-rehearsal"))
    ap.add_argument("--merge-share", type=float, default=0.004,
                    help="sizes the rehearsal difficulty for one machine (default 0.004)")
    ap.add_argument("--drill-value", type=int, default=1 << 24,
                    help="units locked in the exit drill (default 2^24, about 1/64 gMDS)")
    ap.add_argument("--threads", type=int, default=2, help="mining threads for the producer")
    ap.add_argument("--bitcoin-height", type=int)
    ap.add_argument("--bitcoin-hash")
    ap.add_argument("--bitcoin-time")
    ap.add_argument("--keep-running", action="store_true", help="leave the rehearsal nodes up at the end")
    ap.add_argument("--plan", action="store_true", help="print the steps and exit")
    a = ap.parse_args()
    if a.plan:
        print(__doc__)
        return
    r = Rehearsal(a)
    try:
        r.preflight()
        r.build()
        r.drill()
        r.bond()
        r.register()
        r.mine()
    finally:
        r.close()


if __name__ == "__main__":
    main()
