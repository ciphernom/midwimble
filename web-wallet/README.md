# midwimble web wallet

A midwimble wallet that runs in the browser. It is the CLI wallet's logic
(`src/wallet`: keys from a BIP39 phrase, view-key scanning, largest-first coin
selection, stealth payments) compiled to WebAssembly, with a simple page
(below). It talks to midwimble nodes over WebRTC-direct, using the
light protocol (`src/network/light_protocol.rs`): no server of its own, no
HTTPS gateway, no certificate authority.

- **Create, restore, or open a wallet file.** The recovery phrase, the address
  and the view key are the CLI's for the same phrase (recovery height 10), and
  the wallet is stored in the CLI's own encrypted file format (`MWWALLET1`:
  Argon2id, XChaCha20-Poly1305), so a `.mww` file moves between
  `midwimble wallet` and the browser in both directions.
- **Receive** to one reusable address (QR included, with an amount if asked
  for); **send** at the relay's minimum fee or a higher rate, from the coins
  the wallet picks or those chosen, to an address typed, pasted, or scanned
  from its QR code with the camera or from a photo; **activity** with change
  folded into the payment that made it; coins, with a warning for any whose
  recovery commitment a sender got wrong.
- **Follows the chain by its scan data**, not its blocks (`get_scan_data`,
  `src/core/scan.rs`): for each block, its id and header hash, each output's
  ephemeral key and view tag, and a prefix of each input's commitment, about
  100 bytes for a block with nothing but its reward. With its view key the
  wallet passes over every block that neither pays it nor spends its coins,
  and fetches the rest whole (below). A full rescan moves a tenth of the data
  it used to. It notices reorganisations, reads the unspent-output set
  instead (`get_utxos`) when a node has pruned the blocks it would need, and
  rebroadcasts payments still waiting for a block.
- **Fetches few blocks, and hides which.** A block it needs whole (one in 256
  foreign outputs shares its view tag, so a few more than its own payments)
  comes with three other blocks from around it, each from a node picked at
  random, and must match the header hash in the scan data, so any node can
  serve it. No node sees which block mattered. Settings → Privacy → Download
  Every Block gives the nodes nothing to go on at all, for ten times the
  data; so does a node from before scan data, which the wallet reads whole.
- **Uses several nodes.** It keeps three connected, picked at random from
  `config.json`'s and from those the nodes it reaches list (`get_nodes`), and
  follows the chain through one of them, picked at random too: wallets spread
  over the nodes there are. Each node must have the configured genesis block;
  one configured node stays in the three while one can be reached; and a
  node it follows whose block a little below the tip the other two
  contradict, or whose height strays from theirs, is dropped for another.
  With a node list of your own in the settings, it uses only those.
- **Shows payments to it before they confirm.** Every five seconds it asks the
  node which transactions wait in its mempool (`get_mempool`), downloads the
  new ones (`get_mempool_txs`) and scans their outputs with the view key, as
  it scans blocks. A payment found there shows as pending ("incoming") and is
  not spendable until a block confirms it; one that leaves the mempool
  unconfirmed disappears again. Its own payments, change included, are not
  income.
- **Mines in the browser** through a pool that merge-mines midwimble with
  midstate (below), paid straight to the wallet's address.
- Keys never leave the page's wallet worker. The nodes learn which coins are
  the wallet's only from the payments sent through them, and from which
  blocks it fetches whole (above).

## The page

Up front it is as simple as a wallet gets: the balance, with what is
arriving, being sent and maturing; Send; Receive; and what happened. The bar
along the top shows how many nodes it has, and holds Lock and Settings. It
locks itself after 15 minutes without use. Everything else is under
Settings, kept in this browser:

| Settings | |
|---|---|
| Backup | the recovery phrase (after the password); the wallet file to download |
| Security | auto-lock after a minute to four hours, or never; the password before each payment; changing the password |
| Network | the nodes connected, each with its height, response time, requests, failures and data; how many at once (1 to 5); finding more through them; cross-checking the one followed; a node to always follow; a node list of your own |
| Privacy | downloading every block whole; how many decoy blocks come with each one fetched (0 to 8) and from how many around it; spreading block requests over the nodes |
| Sending | the fee: the relay minimum, twice it, five times it, or a rate of your own; choosing the coins each payment spends |
| Advanced | block numbers, hashes and commitments, and all eight decimal places; scan data per request and blocks fetched ahead; watching the mempool and how often, and how often payments are sent again; the coins; the view key; rescanning; diagnostics, to copy as JSON; resetting every setting |

### Mining

Mine (`#/mine`) mines midwimble with the device's spare power. Midwimble is
merge-mined: a pool mining midstate commits each job to a midwimble block
too, and a share that beats midwimble's target is that block. Each block the
pool finds pays its miners by the shares each sent since the last
(midstate's `pools.md`, "Merge-Mine Midwimble"). So the wallet mines the
pool's jobs (midstate shares) for its own midwimble address, over HTTPS
(`/api/template`, `/api/submit`), by default at
`https://rpc.cypherpunk.gold/pool`. Payouts arrive as Mined in Activity.

- **One tap.** The welcome card, and any link to `#/mine`, offers "Mine
  midwimble in your browser": the 24 words, a password and one button that
  makes the wallet and starts mining. With a wallet already here, `#/mine`
  opens Mine once it is unlocked.
- **The work.** `miner.js` threads search nonces in the wallet's WebAssembly
  (`search_nonces_pow`): the BLAKE3 chain four at a time with SIMD (about 23
  attempts a second a thread), and Midstate Walk from its activation (about
  270). They follow the proof of work each job names, so they switch when the
  pool does. Before then, a countdown to block 86,400 says what changes.
- **The numbers.** Attempts a second; shares sent, late and refused; the
  wallet's score at the pool out of the total, which is its part of the
  pool's next midwimble block; and an estimate a day at this speed, after the
  pool's fee, from the midwimble target and reward the pool's job carries.
  When merged mining is paused (between midwimble's switch to Walk and
  midstate's, or when the pool's midwimble node is down), the page says why;
  shares still count.
- **Settings.** Threads (phones start on two), effort (Light rests each
  thread as long as it works, Medium half as long, Full not at all; phones
  start on Light), pausing below 20% battery off the charger (resuming once
  charging or above 30%), the pool, and a midstate address for the midstate
  part of each share, which the pool keeps when none is given. It must be a
  reusable (MSS) address.
- It keeps going while the wallet is locked (it needs only the address), and
  stops when the wallet is forgotten or another tab takes it over. "Invite
  someone to mine" shares the `#/mine` link.

On a wide screen the sections are listed down the side, and the balance
and its buttons, or the QR code and the address, sit side by side. Its
pages are addresses (`#/settings/network`, say), so the browser's back
button works and a page can be bookmarked.

It is also an app (a PWA, `manifest.webmanifest`): the browser offers to
install it, and Settings does where the browser lets it. Its service worker
(`sw.js`) keeps a copy of the wallet's files as they load, so it opens,
unlocks and shows what it knew without a network; online, the files always
come fresh from the server, so the page, worker and WebAssembly never come
from different releases.

## Use it

Serve this folder over HTTPS (or `localhost`), e.g. `python3 -m http.server`
here, and open it. `pkg/`, `light_client.bundle.js` and `qr_reader.bundle.js`
are built and committed, so nothing needs building to serve it.
`.github/workflows/pages.yml` publishes it with the website, at `/wallet/`.

It needs a node that serves browsers: one built with `--features webrtc`.
Such a node keeps its WebRTC certificate in `<data-dir>/webrtc_cert.pem`, so
its address survives restarts, and logs it at start:

```text
Browser wallets can connect to /ip4/…/udp/9435/webrtc-direct/certhash/uEi…/p2p/12D3Koo…
```

(UDP port = TCP listen port + 2.) It also lists its public addresses under
`webrtc_addrs` in the RPC's `/state`. Put one or two such addresses in
`config.json`'s `nodes` for everyone: the wallet finds the others through
them, since a node tells browsers the public WebRTC addresses of the nodes
connected to it (and, to a browser on its own machine or network, the
private ones too). A node list pasted into the wallet's settings replaces the
configured one and turns that off.

`config.json` also names the network and its genesis block id: the wallet
checks each node's block 0 against it before using the node. Once the coin
has a ticker, `unit` there names it, and amounts show it.

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.114 --locked
./build.sh                         # the testnet build
FEATURES=fast-mining ./build.sh    # for a local devnet of fast-mining nodes
```

`build.sh` compiles the wallet with WebAssembly SIMD (every current browser
has it) and bundles the libp2p client and the QR reader (jsQR) with rollup
(`npm ci`, `npm run bundle`).

## Test

```sh
cargo test        # real fast-mining chains, and wallet files to and from the CLI
```

## Files

| File | |
|---|---|
| `src/wallet.rs` | the wallet: no JavaScript types, tested natively |
| `src/lib.rs` | its JavaScript bindings |
| `worker.js` | runs the wallet off the page's thread; storage (IndexedDB), syncing, sending |
| `keygen.js` | helper workers that build the recovery key in parallel |
| `mining.js` | browser mining: the pool client, the mining threads, the battery |
| `miner.js` | one mining thread, searching nonces in the wallet's WebAssembly |
| `app.js`, `index.html`, `wallet.css` | the page |
| `light_client.js` | the WebRTC light client and its pool of nodes (bundled into `light_client.bundle.js`) |
| `qr.js` | a QR encoder, so the page loads nothing from anywhere else |
| `qr_scan.js` | reads QR codes for the send form, from the camera or a photo; loaded when someone scans |
| `qr_reader.js` | decodes them on a worker with jsQR (bundled into `qr_reader.bundle.js`); browsers with a `BarcodeDetector` (Chrome on Android and macOS) use that instead |
| `manifest.webmanifest`, `icons/` | what installing it as an app needs |
| `sw.js` | the service worker that lets it open offline |

## Notes

- Creating or restoring builds the address's post-quantum recovery key:
  1,024 one-time keys, about a billion hashes. Helper workers share it; it
  takes a minute or two on a laptop, once.
- One tab at a time: a second tab offers to take the wallet over.
- What a node can still tell: that the wallet fetched some block, among
  four. Near the tip, where the newest block is the one just announced, the
  timing gives it away more than the other three hide it; a wallet that
  would rather not, downloads every block whole.
- Reorganisations: the wallet keeps the hashes of the last 200 blocks it
  scanned, and checks each new block against the one before it. When the
  node's chain no longer holds what it scanned, it steps back ten blocks at a
  time until the hashes match, then scans the new chain. Coins from the lost
  blocks go, and coins they spent come back; a payment of its own that a
  lost block confirmed waits for a block again, with its coins still
  reserved, and is broadcast again until a block takes it (the node puts it
  back in its mempool and relays it, too). A reorganisation deeper than 200
  blocks (nodes accept up to 1,000, never below a finalized checkpoint) makes
  it rescan from its birth height. While its node is syncing or behind it,
  it waits rather than roll back.
- Scanning asks for the camera only when Scan is pressed, and turns it off
  as soon as a code is read, the scanner closes, or the tab is hidden. Where
  there is no camera, or it is refused, Choose Photo reads a photo or a
  screenshot of the code instead. A scanned code may be an address or a
  `midwimble:<address>?amount=<coins>` URI.
- The recovery phrase restores everything that matters. The wallet file also
  keeps the scan position and the payment history.
