// keygen.js: one of the helpers that build a recovery key's leaves in
// parallel (worker.js hands out ranges). Receives the compiled wasm module,
// the recovery key's seed and a range; answers with the leaves, 32 bytes each.

import init, { recovery_leaves } from './pkg/midwimble_web_wallet.js';

let ready = null;

self.onmessage = async (e) => {
    const { module, seed, start, count } = e.data;
    try {
        if (!ready) ready = init({ module_or_path: module });
        await ready;
        const leaves = recovery_leaves(seed, start, count);
        self.postMessage({ start, leaves }, [leaves.buffer]);
    } catch (err) {
        self.postMessage({ error: (err && err.message) || String(err) });
    }
};
