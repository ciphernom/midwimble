#!/usr/bin/env python3
"""Join the midwimble testnet (docs/TESTNET.md).

Builds midwimble from the published testnet parameters, checks that the binary
it produced makes the published genesis block, and starts a node against the
seeds. With --mine it also locks a small bond on midstate mainnet and registers
it, which is what mining a bonded chain takes.

    python3 scripts/join_testnet.py --midstate-rpc 127.0.0.1:8545 [--mine]

Testnet coins are worth nothing and the chain will be thrown away. The bond is
real MDS, but a tiny amount, and it unlocks after the manifest's lock (two days
by default). Everything else is the same code mainnet will run.
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
OUTPUT_LINE = re.compile(r"([0-9a-f]{64}):(\d+)\s+salt\s+([0-9a-f]{64})\s+coin\s+([0-9a-f]{64})")

MIDSTATE_GENESIS_TIMESTAMP = 1_772_274_770
CLOCK_MARGIN = 10_080


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
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read())
        except Exception:  # noqa: BLE001
            raise e


def try_get(addr: str, path: str):
    try:
        return get_json(addr, path, timeout=5)
    except Exception:  # noqa: BLE001
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


def field(out: str, name: str) -> str:
    m = re.search(rf"^\s*{name}\s+([0-9a-f]+)\s*$", out, re.M)
    if not m:
        die(f"could not find '{name}' in:\n{out}")
    return m.group(1)


def est_midstate_height(t: int) -> int:
    return (t - MIDSTATE_GENESIS_TIMESTAMP) // 60 + CLOCK_MARGIN


class Join:
    def __init__(self, a):
        self.a = a
        self.ms = a.midstate_rpc
        self.dir = pathlib.Path(a.workdir).resolve()
        self.dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.dir / "join.json"
        self.s = json.loads(self.state_file.read_text()) if self.state_file.exists() else {}
        self.bin = self.dir / "target" / "release" / "midwimble"
        self.procs: list[subprocess.Popen] = []
        self.net = self.manifest()

    def save(self) -> None:
        self.state_file.write_text(json.dumps(self.s, indent=2))

    # ── The published parameters ────────────────────────────────────────────
    def manifest(self) -> dict:
        source = self.a.manifest
        if source.startswith("http"):
            with urllib.request.urlopen(source, timeout=20) as r:
                net = json.load(r)
        else:
            net = json.loads(pathlib.Path(source).read_text())
        missing = [k for k in ("bitcoin_hash", "genesis_time", "genesis_target", "genesis_block")
                   if not net.get(k)]
        if missing:
            die(f"{source} has no testnet in it yet (missing {', '.join(missing)}). "
                "The testnet has not launched, or you need a newer copy of the repo.")
        if not net.get("seeds"):
            die(f"{source} lists no seed nodes to connect to")
        return net

    # ── 1. Preflight ────────────────────────────────────────────────────────
    def preflight(self) -> None:
        section("1. Preflight")
        print(f"  network      {self.net['network']}")
        print(f"  genesis      {self.net['genesis_block']}")
        print(f"  seeds        {', '.join(self.net['seeds'])}")
        if not shutil.which("cargo"):
            die("cargo is not on PATH")
        if not self.a.mine:
            ok("joining as a plain node (pass --mine to mine, which needs a bond)")
            return
        st = try_get(self.ms, "/state")
        if not st:
            die(f"no midstate node answering at {self.ms}; mining needs one for the bond proof")
        if st.get("is_syncing"):
            die("the midstate node is still syncing")
        ok(f"midstate node at height {st['height']}")
        if not get_json(self.ms, f"/headers/{int(st['height']) - 1}/1").get("headers"):
            die("GET /headers is missing: apply midstate-bonded-pow.patch and restart the node")
        refusal = str(get_json(self.ms, "/utxo_proof/" + "00" * 32).get("error", ""))
        if "not unspent" not in refusal:
            die(f"GET /utxo_proof is missing or unexpected: {refusal[:120]}")
        ok("your midstate node serves bond proofs")

    # ── 2. Build, and check it is the same chain ────────────────────────────
    def build(self) -> None:
        if self.s.get("built") == self.net["genesis_block"] and self.bin.exists():
            ok("testnet build already made, and it makes the published genesis")
            return
        section("2. Build the testnet binary")
        src = self.dir / "midwimble"
        if not src.exists():
            def skip(dirpath, names):
                here = pathlib.Path(dirpath)
                return [n for n in names
                        if n in ("target", ".git") or (here / n).resolve() == self.dir]
            shutil.copytree(REPO, src, ignore=skip)
            ok(f"copied the source to {src} (your tree is not touched)")
        net = self.net
        run([sys.executable, src / "scripts/set_launch_params.py",
             "--magic", net["network"],
             "--bitcoin-height", net["bitcoin_height"], "--bitcoin-hash", net["bitcoin_hash"],
             "--bitcoin-time", net["bitcoin_time"],
             "--midstate-block-height", net["midstate_height"],
             "--midstate-block-hash", net["midstate_hash"],
             "--genesis-time", net["genesis_time"], "--genesis-target", net["genesis_target"],
             "--min-bond", net["min_bond"], "--bond-lock-days", net["bond_lock_days"],
             "--types-rs", src / "src/core/types.rs"])
        print("  (a warning that genesis is in the past is expected: the testnet started already)")
        env = dict(os.environ, CARGO_TARGET_DIR=str(self.dir / "target"))
        run(["cargo", "build", "--release", "--bin", "midwimble"], cwd=src, env=env, stream=True)

        params = run([self.bin, "params"])
        built = field(params, "genesis block")
        if built != self.net["genesis_block"]:
            die(f"this build makes genesis {built}, but the testnet's is "
                f"{self.net['genesis_block']}. Something differs from the published parameters: "
                "do not use this binary.")
        ok(f"this build makes the published genesis block {built[:16]}…")
        self.s["built"] = built
        self.save()

    # ── 3. A bond, if you mean to mine ──────────────────────────────────────
    def bond(self) -> None:
        b = self.s.setdefault("bond", {})
        if b.get("registered"):
            ok("bond already registered")
            return
        section("3. A testnet mining bond")
        value, lock_days = self.net["min_bond"], self.net["bond_lock_days"]
        print(f"  Mining needs a bond of {value} units of real MDS, locked for about")
        print(f"  {lock_days + 1} days. That is {value / (1 << 30):.4f} gMDS: enough to be a bond,")
        print("  little enough to throw at a testnet.")
        file = self.dir / "bond.json"
        if not file.exists():
            run([self.bin, "bond", "new", "--file", file])
        if "owner_pk" not in b:
            print("\n  Run:   midstate wallet generate-mss")
            print("  and copy the 'Public key' it prints: 64 hex characters, NOT the address.")
            while True:
                pk = ask("  Public key: ").strip().lower()
                if re.fullmatch(r"[0-9a-f]{64}", pk):
                    break
                print("  Expected 64 hex characters." if len(pk) != 72 else
                      "  That is an address. The bond needs the public key.")
            b["owner_pk"] = pk
            self.save()
        if "until" not in b:
            b["until"] = est_midstate_height(int(time.time())) + (lock_days + 1) * 1440
            out = run([self.bin, "bond", "address", "--file", file,
                       "--owner-pk", b["owner_pk"], "--until", b["until"]])
            b["script"], b["address"] = field(out, "script"), field(out, "address")
            self.save()
        if "coin" not in b:
            print(f"\n  In another terminal:\n\n    midstate wallet send --to {b['address']}:{value}\n")
            print("  Paste the line it prints for that address:")
            while True:
                m = OUTPUT_LINE.search(ask("  → ").strip().lower())
                if m and m.group(1) == b["address"] and int(m.group(2)) == value:
                    b["salt"], b["coin"] = m.group(3), m.group(4)
                    self.save()
                    break
                print(f"  Expected a line paying {b['address'][:16]}…:{value}.")
        wait_until("the bond coin to be mined",
                   lambda: get_json(self.ms, f"/coin/{b['coin']}").get("exists"))
        ok("bond coin is on chain")

        section("4. Register it")
        print("  A registration needs a day of the testnet's work buried above the proof.")
        cmd = [self.bin, "bond", "register", "--file", file, "--owner-pk", b["owner_pk"],
               "--until", b["until"], "--value", value, "--salt", b["salt"],
               "--midstate-rpc", self.ms]
        while True:
            out = run(cmd)
            print("\n".join("    " + l for l in out.strip().splitlines()))
            if "Ready:" in out:
                break
            print("  Checking again in 5 minutes…")
            time.sleep(300)
        b["registered"] = True
        self.save()

    # ── 5. Run ──────────────────────────────────────────────────────────────
    def node(self) -> None:
        section("5. Join the network")
        env = dict(os.environ, MIDWIMBLE_PASSWORD=self.a.wallet_password)
        wallet = self.dir / "testnet.mww"
        if not wallet.exists():
            print("  Creating a wallet: its post-quantum recovery key takes a minute or two.")
            run([self.bin, "wallet", "--wallet", wallet, "create"], env=env)
        address = re.findall(r"\bmw1[0-9a-z]{20,}",
                             run([self.bin, "wallet", "--wallet", wallet, "address"], env=env))[-1]
        cmd = [str(self.bin), "node", "--data-dir", str(self.dir / "node"),
               "--listen", f"/ip4/0.0.0.0/tcp/{self.a.p2p_port}",
               "--rpc", f"127.0.0.1:{self.a.rpc_port}"]
        for seed in self.net["seeds"]:
            cmd += ["--peer", seed]
        if self.a.mine:
            cmd += ["--mine-to", address, "--mining-bond", str(self.dir / "bond.json"),
                    "--threads", str(self.a.threads)]
        log = open(self.dir / "node.log", "a")
        print(f"  $ {' '.join(cmd)}   (log: {log.name})")
        self.procs.append(subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT))
        rpc = f"127.0.0.1:{self.a.rpc_port}"
        st = wait_until("the node's RPC", lambda: try_get(rpc, "/state"), 2, 120)
        if st["tip"] != self.net["genesis_block"] and st["height"] == 1:
            pass  # still at genesis; sync has not started yet
        wait_until("the first blocks to arrive from the seeds",
                   lambda: (try_get(rpc, "/state") or {}).get("height", 0) > 1, 5, 900)
        st = get_json(rpc, "/state")
        ok(f"synced to height {st['height']}, {len(st['peers'])} peer(s)")
        ok(f"your payout address is {address}")
        print(f"\n  Watch it:   curl -s {rpc}/state")
        print(f"  Who mines:  curl -s {rpc}/miners/{max(1, st['height'] - 10)}/10")
        print(f"  Bonds:      curl -s {rpc}/bonds")
        if self.net.get("faucet"):
            print(f"  Coins to play with: {self.net['faucet']}")
        print("\n  The node keeps running. Ctrl-C here stops it (--keep-running leaves it up).")
        if self.a.keep_running:
            self.procs.clear()
            return
        try:
            self.procs[0].wait()
        except KeyboardInterrupt:
            pass

    def close(self) -> None:
        for p in self.procs:
            p.terminate()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", default=str(REPO / "scripts/testnet.json"),
                    help="the published testnet parameters (path or URL)")
    ap.add_argument("--midstate-rpc", default="127.0.0.1:8545")
    ap.add_argument("--workdir", default=str(REPO.parent / "midwimble-testnet"))
    ap.add_argument("--mine", action="store_true", help="mine, which needs a small bond")
    ap.add_argument("--threads", type=int, default=2)
    ap.add_argument("--p2p-port", type=int, default=9433)
    ap.add_argument("--rpc-port", type=int, default=9434)
    ap.add_argument("--wallet-password", default="testnet")
    ap.add_argument("--keep-running", action="store_true")
    a = ap.parse_args()
    j = Join(a)
    try:
        j.preflight()
        j.build()
        if a.mine:
            j.bond()
        j.node()
    finally:
        j.close()


if __name__ == "__main__":
    main()
