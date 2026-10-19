# midwimble web wallet

A midwimble wallet that runs in the browser. It is the CLI wallet's logic
(`src/wallet`: keys from a BIP39 phrase, view-key scanning of whole blocks,
largest-first coin selection, stealth payments) compiled to WebAssembly, with
a page in the explorer's style. It talks to midwimble nodes over
WebRTC-direct, using the light protocol (`src/network/light_protocol.rs`): no
server of its own, no HTTPS gateway, no certificate authority.

- **Create, restore, or open a wallet file.** The recovery phrase, the address
  and the view key are the CLI's for the same phrase (recovery height 10), and
  the wallet is stored in the CLI's own encrypted file format (`MWWALLET1`:
  Argon2id, XChaCha20-Poly1305), so a `.mww` file moves between
  `midwimble wallet` and the browser in both directions.
- **Receive** to one reusable address (QR included); **send** with the relay's
  minimum fee, to an address typed, pasted, or scanned from its QR code with
  the camera or from a photo; **history** with change folded into the payment
  that made it; coins, with a warning for any whose recovery commitment a
  sender got wrong.
- **Follows the chain** by downloading whole blocks (`get_blocks`), notices
  reorganisations, reads the unspent-output set instead (`get_utxos`) when a
  node has pruned the blocks it would need, and rebroadcasts payments still
  waiting for a block.
- Keys never leave the page's wallet worker. The node learns which coins are
  the wallet's only from the payments sent through it.

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
`webrtc_addrs` in the RPC's `/state`. Put such addresses in `config.json`'s
`nodes` for everyone, or paste one into the wallet's node setting.

`config.json` also names the network and its genesis block id: the wallet
checks the node's block 0 against it before scanning anything.

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
| `app.js`, `index.html`, `wallet.css` | the page |
| `light_client.js` | the WebRTC light client (bundled into `light_client.bundle.js`) |
| `qr.js` | a QR encoder, so the page loads nothing from anywhere else |
| `qr_scan.js` | reads QR codes for the send form, from the camera or a photo; loaded when someone scans |
| `qr_reader.js` | decodes them on a worker with jsQR (bundled into `qr_reader.bundle.js`); browsers with a `BarcodeDetector` (Chrome on Android and macOS) use that instead |

## Notes

- Creating or restoring builds the address's post-quantum recovery key:
  1,024 one-time keys, about a billion hashes. Helper workers share it; it
  takes a minute or two on a laptop, once.
- One tab at a time: a second tab offers to take the wallet over.
- Scanning asks for the camera only when "scan" is pressed, and turns it off
  as soon as a code is read, the scanner closes, or the tab is hidden. Where
  there is no camera, or it is refused, "Choose a photo" reads a photo or a
  screenshot of the code instead. A scanned code may be an address or a
  `midwimble:<address>?amount=<coins>` URI.
- The recovery phrase restores everything that matters. The wallet file also
  keeps the scan position and the payment history.
