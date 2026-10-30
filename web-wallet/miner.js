// miner.js: one mining thread. mining.js on the page runs one of these per
// thread and talks to the pool; this only searches. It takes the pool's job
// (which proof of work, the mining hash, the share target) and tries nonces
// in the wallet's WebAssembly, reporting how fast it goes and every nonce that
// beats the target.
//
// A pool job is midstate work: the pool merge-mines, so a share that also
// beats midwimble's target is a midwimble block as well, and the same hash
// counts on both chains.

import init, { search_nonces_pow } from './pkg/midwimble_web_wallet.js';

/** About how long one call into WebAssembly runs, so a new job or a stop
 *  takes effect within a second. A BLAKE3-chain attempt is a million hashes
 *  (a call of four takes about this long); a Midstate Walk attempt is a few
 *  milliseconds, so calls grow to many attempts each. */
const CALL_MS = 800;
const MAX_CHUNK = 4096;

let ready = null;
let job = null;          // { id, pow, midstate, target }, or null when stopped
let running = false;
let rest = 0;            // pause after each call, as a fraction of its length

const post = (m) => self.postMessage(m);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

/** A random place to start in the nonce space, so threads (and every other
 *  miner on the pool) don't search the same nonces. */
const randomStart = () => BigInt(Math.floor(Math.random() * 2 ** 53)) << 8n;

async function loop() {
    running = true;
    let jobId = null;
    let nonce = 0n;
    let chunk = 1;
    let tried = 0;
    let since = performance.now();
    try {
        while (job) {
            const j = job;
            if (j.id !== jobId) {
                jobId = j.id;
                nonce = randomStart();
            }
            const t0 = performance.now();
            const found = search_nonces_pow(j.pow, j.midstate, j.target, nonce, chunk);
            const ms = performance.now() - t0;
            if (found !== undefined && found !== null) {
                // The call stopped at the find: only the nonces up to it were
                // tried, and the search goes on just after it.
                tried += Math.max(1, Math.min(chunk * 4, Number(found - nonce) + 1));
                nonce = found + 1n;
                post({ type: 'found', jobId: j.id, nonce: found.toString() });
            } else {
                tried += chunk * 4;
                nonce += BigInt(chunk * 4);
                // Only a full call says how long `chunk` takes.
                if (ms < CALL_MS / 2 && chunk < MAX_CHUNK) chunk *= 2;
                else if (ms > CALL_MS * 2 && chunk > 1) chunk >>= 1;
            }
            const now = performance.now();
            if (now - since >= 1000) {
                post({ type: 'rate', rate: tried * 1000 / (now - since) });
                tried = 0;
                since = now;
            }
            // Yield every call, so a new job or a stop is read; and rest in
            // proportion to the work done, which is how effort is set.
            await sleep(Math.round(ms * rest));
        }
    } catch (e) {
        post({ type: 'error', error: (e && e.message) || String(e) });
        job = null;
    }
    running = false;
    post({ type: 'rate', rate: 0 });
}

self.onmessage = async (e) => {
    const m = e.data || {};
    if (m.type === 'init') {
        try {
            if (!ready) ready = init(m.module ? { module_or_path: m.module } : undefined);
            await ready;
            post({ type: 'ready' });
        } catch (err) {
            post({ type: 'error', error: `WebAssembly would not start: ${(err && err.message) || err}` });
        }
    } else if (m.type === 'job') {
        await ready;
        job = m.job;
        if (typeof m.rest === 'number') rest = m.rest;
        if (!running && job) loop();
    } else if (m.type === 'rest') {
        rest = m.rest;
    } else if (m.type === 'stop') {
        job = null;
    }
};
