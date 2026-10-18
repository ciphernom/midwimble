#!/bin/sh
# Builds the browser wallet in place: pkg/ (the wallet, as WebAssembly) and
# light_client.bundle.js (libp2p). Both are committed, so this folder can be
# served as it is; rebuild after changing src/, the core, or light_client.js.
#
# Needs  rustup target add wasm32-unknown-unknown
#        cargo install wasm-bindgen-cli --version 0.2.114 --locked
#        Node.js 18 or later (for the bundle)
#
#   ./build.sh                          the testnet build
#   FEATURES=fast-mining ./build.sh     for a local devnet of fast-mining nodes
#   SKIP_BUNDLE=1 ./build.sh            the wallet only
set -eu
cd "$(dirname "$0")"

# WebAssembly SIMD: the recovery key's billion hashes take a quarter of the time.
export RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+simd128"
cargo build --release --target wasm32-unknown-unknown ${FEATURES:+--features "$FEATURES"} ${CARGO_FLAGS:-}
wasm-bindgen --target web --no-typescript --out-dir pkg \
    target/wasm32-unknown-unknown/release/midwimble_web_wallet.wasm
if command -v wasm-opt >/dev/null 2>&1; then
    wasm-opt -O3 pkg/midwimble_web_wallet_bg.wasm -o pkg/midwimble_web_wallet_bg.wasm \
        || echo "wasm-opt failed; keeping the unoptimised module"
fi

if [ "${SKIP_BUNDLE:-}" != 1 ]; then
    npm ci --no-audit --no-fund
    npm run bundle
fi
