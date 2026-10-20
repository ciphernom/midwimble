#!/usr/bin/env python3
"""Join midwimble (docs/TESTNET.md).

The network opened as the testnet on 16 October 2026 and becomes mainnet when
its early phase ends (`early_bonds_until` in the manifest: 31 October 2026,
00:00 UTC). Nothing restarts: the chain carries on, and so do the coins mined
on it.

Builds midwimble from the published parameters, checks that the binary it
produced makes the published genesis block and carries the published bond
rules, and starts a node against the seeds. With --mine it also locks a bond
on midstate mainnet and registers it, which is what mining a bonded chain
takes.

    python3 scripts/join_testnet.py --midstate-rpc 127.0.0.1:8545 [--mine]

During the early phase the bond is a testnet's: a tiny amount of real MDS
(2^24 units), locked until the phase ends, when it stops counting. From then
on it is mainnet's: 128 gMDS, which mines while more than 30 days of its lock
remain. --full-bond locks a mainnet bond during the early phase too, so that
mining carries on through the switch.

Run it again after every update of the repository: it rebuilds whenever the
code or the published parameters changed. A node left on an old build forks
off the network when the early phase ends.
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import hashlib
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
# The most a bond may be locked for past a block's estimated midstate height.
MAX_BOND_HORIZON_DAYS = 365
# What this script protected wallets with while the network was a testnet.
OLD_DEFAULT_PASSWORD = "testnet"
# The bond rules a build must carry, as the manifest gives them.
RULE_KEYS = ("min_bond", "bond_lock_days", "early_bonds_until", "early_min_bond",
             "early_bond_lock_days")


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


def ask_secret(prompt: str) -> str:
    try:
        return getpass.getpass(prompt)
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


def utc(ts: int) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def bond_text(units: int) -> str:
    """A bond size as `midwimble params` prints it."""
    if units >= 1 << 30:
        return f"{units >> 30} gMDS"
    return f"2^{units.bit_length() - 1} units"


def source_digest() -> str:
    """What a build is made from: the code, and the script that sets its parameters."""
    files = [REPO / "Cargo.toml", REPO / "Cargo.lock", REPO / "scripts/set_launch_params.py"]
    for tree in (REPO / "src", REPO / "docs/assets"):
        files += sorted(p for p in tree.rglob("*") if p.is_file())
    h = hashlib.sha256()
    for f in files:
        if f.is_file():
            h.update(str(f.relative_to(REPO)).encode() + b"\0")
            h.update(f.read_bytes())
            h.update(b"\0")
    return h.hexdigest()


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
        self.early_until = int(self.net.get("early_bonds_until") or 0)
        self.wallet = pathlib.Path(a.wallet).resolve() if a.wallet else self.dir / "testnet.mww"
        self.old_password = False

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
            die(f"{source} has no network in it yet (missing {', '.join(missing)}). "
                "The network has not launched, or you need a newer copy of the repo.")
        if not net.get("seeds"):
            die(f"{source} lists no seed nodes to connect to")
        if net.get("early_bonds_until"):
            missing = [k for k in ("early_min_bond", "early_bond_lock_days") if not net.get(k)]
            if missing:
                die(f"{source} has an early phase but no {', '.join(missing)}")
        return net

    def rules_at(self, t: int) -> tuple[int, int]:
        """The smallest bond, and the lock in midstate blocks, a block stamped t needs."""
        if t < self.early_until:
            return int(self.net["early_min_bond"]), int(self.net["early_bond_lock_days"]) * 1440
        return int(self.net["min_bond"]), int(self.net["bond_lock_days"]) * 1440

    def can_sign(self, value: int, until: int, t: int) -> bool:
        min_bond, lock = self.rules_at(t)
        return value >= min_bond and until >= est_midstate_height(t) + lock

    def midstate_height(self) -> int:
        return int(get_json(self.ms, "/state")["height"])

    # ── 1. Preflight ────────────────────────────────────────────────────────
    def preflight(self) -> None:
        section("1. Preflight")
        print(f"  network      {self.net['network']}")
        print(f"  genesis      {self.net['genesis_block']}")
        print(f"  seeds        {', '.join(self.net['seeds'])}")
        now = int(time.time())
        full = bond_text(int(self.net["min_bond"]))
        if self.early_until and now < self.early_until:
            print(f"  phase        early, until {utc(self.early_until)}: bonds of "
                  f"{bond_text(int(self.net['early_min_bond']))}; mainnet, with bonds of "
                  f"{full}, from then on")
        elif self.early_until:
            print(f"  phase        mainnet since {utc(self.early_until)}: bonds of {full}")
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
        net = self.net
        wanted = {
            "genesis": net["genesis_block"],
            "rules": {k: net.get(k) for k in RULE_KEYS},
            "source": source_digest(),
        }
        if self.s.get("built") == wanted and self.bin.exists():
            ok("build up to date: it makes the published genesis and carries the published bond rules")
            return
        section("2. Build midwimble")
        if self.s.get("built"):
            print("  The code or the published parameters changed since the last build: rebuilding.")
            print("  Restart any node running the old build once this one is made.")
        src = self.dir / "midwimble"
        repo, copy = REPO.resolve(), src.resolve()
        if copy == repo or copy in repo.parents or repo in copy.parents:
            die(f"--workdir {self.dir} puts the build copy at {src}, which overlaps your "
                "repository: choose a workdir outside it")
        # A fresh copy every build, so that what is built is the repository as it is now.
        if src.exists():
            shutil.rmtree(src)

        def skip(dirpath, names):
            here = pathlib.Path(dirpath)
            return [n for n in names
                    if n in ("target", ".git") or (here / n).resolve() == self.dir]
        shutil.copytree(REPO, src, ignore=skip)
        ok(f"copied the source to {src} (your tree is not touched)")
        cmd = [sys.executable, src / "scripts/set_launch_params.py",
               "--magic", net["network"],
               "--bitcoin-height", net["bitcoin_height"], "--bitcoin-hash", net["bitcoin_hash"],
               "--bitcoin-time", net["bitcoin_time"],
               "--midstate-block-height", net["midstate_height"],
               "--midstate-block-hash", net["midstate_hash"],
               "--genesis-time", net["genesis_time"], "--genesis-target", net["genesis_target"],
               "--min-bond", net["min_bond"], "--bond-lock-days", net["bond_lock_days"],
               "--types-rs", src / "src/core/types.rs"]
        if self.early_until:
            cmd += ["--early-bonds-until", self.early_until,
                    "--early-min-bond", net["early_min_bond"],
                    "--early-bond-lock-days", net["early_bond_lock_days"]]
        run(cmd)
        print("  (a warning that genesis is in the past is expected: the network started already)")
        env = dict(os.environ, CARGO_TARGET_DIR=str(self.dir / "target"))
        run(["cargo", "build", "--release", "--bin", "midwimble"], cwd=src, env=env, stream=True)

        params = run([self.bin, "params"])
        built = field(params, "genesis block")
        if built != net["genesis_block"]:
            die(f"this build makes genesis {built}, but the network's is "
                f"{net['genesis_block']}. Something differs from the published parameters: "
                "do not use this binary.")
        ok(f"this build makes the published genesis block {built[:16]}…")
        self.check_rules(params)
        ok("and carries the published bond rules")
        self.s["built"] = wanted
        self.save()

    def check_rules(self, params: str) -> None:
        """The binary's bond rules are the manifest's: `midwimble params` says so.
        The genesis does not commit to them, so a build could differ here alone."""
        net = self.net
        m = re.search(r"^bonded mining\s+.*bonds of at least (.+?), locked (\d+) more days to mine",
                      params, re.M)
        if not m or (m.group(1), int(m.group(2))) != (bond_text(int(net["min_bond"])),
                                                       int(net["bond_lock_days"])):
            die("this build's mining bond is not the published one: do not use this binary")
        e = re.search(r"^early phase\s+blocks stamped before .*?\((\d+)\) take bonds of at "
                      r"least (.+?), locked (\d+) more days", params, re.M)
        if self.early_until:
            want = (self.early_until, bond_text(int(net["early_min_bond"])),
                    int(net["early_bond_lock_days"]))
            if not e or (int(e.group(1)), e.group(2), int(e.group(3))) != want:
                die("this build's early phase is not the published one: do not use this binary")
        elif e:
            die("this build has an early phase the published parameters do not: do not use it")

    # ── 3. A bond, if you mean to mine ──────────────────────────────────────
    def bond(self) -> None:
        b = self.s.setdefault("bond", {})
        now = int(time.time())
        if "until" in b:
            # Bonds from before the early phase was published are its size.
            value = int(b.get("value", self.net.get("early_min_bond", self.net["min_bond"])))
            min_bond = int(self.net["min_bond"])
            replace = self.a.full_bond and value < min_bond
            if not self.can_sign(value, int(b["until"]), now + 3600):
                self.retire(b, value, now)
                b = self.s["bond"] = {}
                self.save()
            elif replace:
                # It still mines: agree the new bond's terms before setting it aside.
                section("3. A mainnet bond, in place of your early-phase one")
                until = self.plan_full_bond(now)
                days = (until - self.midstate_height()) / 1440
                if ask(f"  Lock {bond_text(min_bond)} of real MDS until midstate height {until}, "
                       f"about {days:.0f} days from now, in its place? [y/N] ").strip().lower() != "y":
                    ok("keeping the early-phase bond")
                    self.note_switch(value, int(b["until"]), now)
                    return
                self.retire(b, value, now)
                b = self.s["bond"] = {"value": min_bond, "planned_until": until, "confirmed": True}
                self.save()
            elif b.get("registered"):
                ok("bond already registered")
                self.note_switch(value, int(b["until"]), now)
                return

        section("3. A mining bond")
        full = self.a.full_bond or now >= self.early_until
        if "value" not in b:
            b["value"] = int(self.net["min_bond"] if full else self.net["early_min_bond"])
        value = b["value"]
        full = value >= int(self.net["min_bond"])
        if full:
            kind = "A mainnet bond" if self.early_until else "A bond"
            print(f"  {kind}: {bond_text(value)} of real MDS ({value} units). It mines while")
            print(f"  more than {self.net['bond_lock_days']} days of its lock remain, so it is "
                  "locked for that long")
            print("  plus however long you mean to mine.")
        else:
            print(f"  An early-phase bond: {value} units of real MDS, {value / (1 << 30):.4f} gMDS:")
            print(f"  enough to be a bond, little enough to throw at a testnet. It mines until the")
            print(f"  early phase ends, {utc(self.early_until)}, and is locked a little longer.")
            if self.early_until - now < 86400:
                print("  The early phase ends within a day: registering takes a while, so this bond")
                print("  may never get to mine. --full-bond locks a mainnet bond instead.")
        file = self.dir / "bond.json"
        if not file.exists():
            run([self.bin, "bond", "new", "--file", file])
        if "owner_pk" not in b:
            previous = next((o["owner_pk"] for o in reversed(self.s.get("old_bonds", []))
                             if o.get("owner_pk")), None)
            print("\n  Run:   midstate wallet generate-mss")
            print("  and copy the 'Public key' it prints: 64 hex characters, NOT the address.")
            if previous:
                print(f"  (Or press Enter to use the one your previous bond had, {previous[:16]}…)")
            while True:
                pk = ask("  Public key: ").strip().lower()
                if not pk and previous:
                    pk = previous
                if re.fullmatch(r"[0-9a-f]{64}", pk):
                    break
                print("  Expected 64 hex characters." if len(pk) != 72 else
                      "  That is an address. The bond needs the public key.")
            b["owner_pk"] = pk
            self.save()
        if "until" not in b:
            if full:
                b["until"] = b.pop("planned_until", None) or self.plan_full_bond(now)
            else:
                # Enough to mine until the early phase ends, plus an hour.
                b["until"] = (est_midstate_height(self.early_until)
                              + int(self.net["early_bond_lock_days"]) * 1440 + 60)
            out = run([self.bin, "bond", "address", "--file", file,
                       "--owner-pk", b["owner_pk"], "--until", b["until"]])
            b["script"], b["address"] = field(out, "script"), field(out, "address")
            self.save()
        days = (b["until"] - self.midstate_height()) / 1440
        print(f"  Locked until midstate height {b['until']}, about {days:.0f} days from now.")
        if "coin" not in b:
            if full and not b.get("confirmed"):
                if ask(f"  Lock {bond_text(value)} of real MDS until then? [y/N] ").strip().lower() != "y":
                    die("stopped before locking the bond")
                b["confirmed"] = True
                self.save()
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
        print("  A registration needs a day of the network's work buried above the proof,")
        print("  on the chain's midstate relay. A node syncs first to say where the relay is;")
        print("  the bond file then carries the midstate headers your blocks will relay.")
        rpc = self.start(mine=False)
        cmd = [self.bin, "bond", "register", "--file", file, "--owner-pk", b["owner_pk"],
               "--until", b["until"], "--value", value, "--salt", b["salt"],
               "--midstate-rpc", self.ms, "--midwimble-rpc", rpc]
        while True:
            out = run(cmd)
            print("\n".join("    " + l for l in out.strip().splitlines()))
            if "Ready:" in out:
                break
            print("  Checking again in 5 minutes…")
            time.sleep(300)
        self.close()
        self.procs.clear()
        b["registered"] = True
        self.save()
        self.note_switch(value, int(b["until"]), int(time.time()))

    def plan_full_bond(self, now: int) -> int:
        """Asks how long a mainnet-sized bond should mine; returns its lock height."""
        mine_days = self.a.mine_days
        while mine_days is None:
            answer = ask("  How many days should it mine? [30] ").strip() or "30"
            mine_days = int(answer) if answer.isdigit() and int(answer) > 0 else None
        lock_days = int(self.net["bond_lock_days"]) + mine_days
        if lock_days > MAX_BOND_HORIZON_DAYS - 5:
            die(f"a bond may be locked for at most about {MAX_BOND_HORIZON_DAYS - 5} days")
        return est_midstate_height(now) + lock_days * 1440

    def note_switch(self, value: int, until: int, now: int) -> None:
        """Says so if this bond stops mining when the early phase ends."""
        if not self.early_until or now >= self.early_until or self.can_sign(value, until, self.early_until):
            return
        print(f"\n  This bond mines until the early phase ends, {utc(self.early_until)}. To keep")
        print("  mining after that, run this script again with --full-bond before then: a")
        print(f"  mainnet bond is {bond_text(int(self.net['min_bond']))}, and registering it takes a while.")

    def retire(self, b: dict, value: int, now: int) -> None:
        """Puts aside a bond that cannot mine any more, or is being replaced, and
        says how to get its coin back."""
        section("Your previous bond")
        min_bond, _ = self.rules_at(now)
        if not b.get("registered") and not b.get("coin"):
            print("  It was never funded: starting over with a new one.")
        elif self.can_sign(value, int(b["until"]), now + 3600):
            print("  Replacing it with a mainnet bond (--full-bond).")
        elif value < min_bond:
            print(f"  It holds {value} units, and the network now asks for {bond_text(min_bond)}")
            print("  (the early phase is over): it can no longer mine.")
        else:
            print("  Its lock is too short for it to mine any more.")
        file = self.dir / "bond.json"
        kept = self.dir / f"bond-{b.get('coin', 'unfunded')[:12]}.json"
        if file.exists():
            file.rename(kept)
        self.s.setdefault("old_bonds", []).append(dict(b, value=value, file=str(kept)))
        if b.get("coin") and b.get("script"):
            print(f"  Its coin stays locked until midstate height {b['until']}. Once midstate passes")
            print("  it, spend it back with your midstate wallet:\n")
            print(f"    midstate wallet spend-script --coin {b['coin']} --bytecode {b['script']} \\")
            print(f"        --inputs AUTO:{b['owner_pk']} --to <your address from "
                  f"`midstate wallet receive`>:{value // 2}\n")
        print(f"  (Its bond file is kept as {kept}.)")

    # ── 5. Run ──────────────────────────────────────────────────────────────
    def start(self, mine: bool, address: str = "") -> str:
        """Starts the node, waits for it to sync, and returns its RPC address."""
        cmd = [str(self.bin), "node", "--data-dir", str(self.dir / "node"),
               "--listen", f"/ip4/0.0.0.0/tcp/{self.a.p2p_port}",
               "--rpc", f"127.0.0.1:{self.a.rpc_port}"]
        for seed in self.net["seeds"]:
            cmd += ["--peer", seed]
        if mine:
            cmd += ["--mine-to", address, "--mining-bond", str(self.dir / "bond.json"),
                    "--midstate-rpc", self.ms, "--threads", str(self.a.threads)]
        log = open(self.dir / "node.log", "a")
        print(f"  $ {' '.join(cmd)}   (log: {log.name})")
        self.procs.append(subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT))
        rpc = f"127.0.0.1:{self.a.rpc_port}"
        wait_until("the node's RPC", lambda: try_get(rpc, "/state"), 2, 120)
        wait_until("the first blocks to arrive from the seeds",
                   lambda: (try_get(rpc, "/state") or {}).get("height", 0) > 1, 5, 900)
        wait_until("the node to finish syncing",
                   lambda: not (try_get(rpc, "/state") or {"syncing": True}).get("syncing"), 5, 3600)
        return rpc

    def opens(self, password: str) -> bool:
        env = dict(os.environ, MIDWIMBLE_PASSWORD=password)
        p = subprocess.run([str(self.bin), "wallet", "--wallet", str(self.wallet), "address"],
                           env=env, capture_output=True, text=True)
        return p.returncode == 0

    def wallet_password(self) -> str:
        given = self.a.wallet_password or os.environ.get("MIDWIMBLE_PASSWORD")
        if given:
            return given
        if self.wallet.exists():
            if self.opens(OLD_DEFAULT_PASSWORD):
                self.old_password = True
                return OLD_DEFAULT_PASSWORD
            die(f"give {self.wallet}'s password with --wallet-password or MIDWIMBLE_PASSWORD")
        print("  The wallet holds what you mine, and after the early phase that is real money:")
        print("  choose a password for it (you need it to spend, never to mine).")
        while True:
            first = ask_secret("  New wallet password: ")
            if len(first) < 8:
                print("  At least 8 characters, please.")
                continue
            if ask_secret("  Again: ") == first:
                return first
            print("  The two differ; try again.")

    def node(self) -> None:
        section("5. Join the network")
        password = self.wallet_password()
        env = dict(os.environ, MIDWIMBLE_PASSWORD=password)
        if not self.wallet.exists():
            print("  Creating a wallet: its post-quantum recovery key takes a minute or two.")
            out = run([self.bin, "wallet", "--wallet", self.wallet, "create"], env=env)
            print("\n".join("    " + l for l in out.strip().splitlines()
                            if not l.lower().startswith("address")))
            print("  Write the recovery phrase above down and keep it offline.")
        address = re.findall(r"\bmw1[0-9a-z]{20,}",
                             run([self.bin, "wallet", "--wallet", self.wallet, "address"], env=env))[-1]
        rpc = self.start(self.a.mine, address)
        st = get_json(rpc, "/state")
        ok(f"synced to height {st['height']}, {len(st['peers'])} peer(s)")
        ok(f"your payout address is {address}")
        if self.old_password:
            print(f"\n  ! {self.wallet} still has this script's old default password, "
                  f"\"{OLD_DEFAULT_PASSWORD}\",")
            print("    and its coins are real once the early phase ends. Give it one of your own:\n")
            print(f"      MIDWIMBLE_PASSWORD={OLD_DEFAULT_PASSWORD} {self.bin} wallet --wallet "
                  f"{self.wallet} password\n")
            print("    then pass the new one to this script with MIDWIMBLE_PASSWORD.")
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
                    help="the published network parameters (path or URL)")
    ap.add_argument("--midstate-rpc", default="127.0.0.1:8545")
    ap.add_argument("--workdir", default=str(REPO.parent / "midwimble-testnet"))
    ap.add_argument("--mine", action="store_true", help="mine, which needs a bond")
    ap.add_argument("--full-bond", action="store_true",
                    help="lock a mainnet-sized bond even during the early phase, so mining carries "
                         "on after it (replaces a registered early-phase bond)")
    ap.add_argument("--mine-days", type=int,
                    help="for a mainnet-sized bond: how many days it should mine (asked if not given)")
    ap.add_argument("--threads", type=int, default=2)
    ap.add_argument("--p2p-port", type=int, default=9433)
    ap.add_argument("--rpc-port", type=int, default=9434)
    ap.add_argument("--wallet", help="wallet file (default: testnet.mww in the workdir)")
    ap.add_argument("--wallet-password",
                    help="the wallet's password (or set MIDWIMBLE_PASSWORD); asked for a new wallet")
    ap.add_argument("--keep-running", action="store_true")
    a = ap.parse_args()
    if a.mine_days is not None and a.mine_days < 1:
        ap.error("--mine-days must be at least 1")
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
