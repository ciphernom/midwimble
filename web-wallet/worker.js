// worker.js: the wallet, off the page's thread.
//
// Holds the WebAssembly wallet (src/wallet.rs), keeps it in IndexedDB as a
// sealed wallet file (the CLI's encrypted format: the password never leaves
// this worker and the plaintext never touches storage), and follows the
// chain through the page, which owns the WebRTC connection (RTCPeerConnection
// does not exist in workers): {type: 'rpc'} out, {type: 'rpc-result'} back.

import init, * as mw from './pkg/midwimble_web_wallet.js';

const WASM_URL = new URL('./pkg/midwimble_web_wallet_bg.wasm', import.meta.url);
/** Blocks asked for per get_blocks (the node caps it, and by size). */
const BLOCKS_PER_REQUEST = 100;
const UTXO_PAGE = 500;
/** Seconds before a payment still waiting for a block is broadcast again. */
const REBROADCAST_SECS = 120;
/** Seconds between looks at the node's mempool for payments to this wallet
 *  (a list of hashes; only new transactions are downloaded). */
const MEMPOOL_SECS = 5;
/** Transactions asked for per get_mempool_txs (the node's limit). */
const MEMPOOL_TXS_PER_REQUEST = 64;
const SAVE_EVERY_MS = 8_000;

let wasmModule = null;
let C = null; // chain constants from the wasm build
let network = 'midwimble';
let genesis = null; // expected genesis block id, from config.json

let wallet = null;
let fileKey = null;
let fileSalt = null;

const chain = {
    connected: false, addr: null, tip: 0, timestamp: 0, prunedBelow: 0,
    nodeSyncing: false, networkOk: null, behind: false,
};
const scan = { active: false, mode: 'blocks', from: 0, to: 0, outputs: 0 };
let supportsGetBlocks = true;
let syncError = null;
let dirty = false;
let lastSave = 0;
const lastBroadcast = new Map();
/** Mempool transactions already scanned (by hash), on this node. */
const mempool = { supported: true, scanned: new Set(), running: false };
/** Set when a rollback changed what the wallet shows: 'changed' or 'deep'. */
let reorged = null;

const post = (msg, transfer) => self.postMessage(msg, transfer || []);
const toast = (text, kind = 'info') => post({ type: 'toast', text, kind });
const errText = e => (e && e.message) || String(e);

// ── storage ─────────────────────────────────────────────────────────────────

const DB_NAME = 'midwimble-wallet';
let dbPromise = null;
function db() {
    if (!dbPromise) {
        dbPromise = new Promise((resolve, reject) => {
            const r = indexedDB.open(DB_NAME, 1);
            r.onupgradeneeded = () => r.result.createObjectStore('kv');
            r.onsuccess = () => resolve(r.result);
            r.onerror = () => reject(r.error);
        });
    }
    return dbPromise;
}
async function kv(mode, fn) {
    const d = await db();
    return new Promise((resolve, reject) => {
        const tx = d.transaction('kv', mode);
        const req = fn(tx.objectStore('kv'));
        tx.oncomplete = () => resolve(req && req.result);
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error || new Error('storage aborted'));
    });
}
const walletKey = () => `wallet:${network}`;
const loadFile = () => kv('readonly', s => s.get(walletKey()));
const storeFile = bytes => kv('readwrite', s => s.put(bytes, walletKey()));
const deleteFile = () => kv('readwrite', s => s.delete(walletKey()));

async function save() {
    if (!wallet || !fileKey) return;
    const bytes = wallet.seal(fileKey, fileSalt);
    await storeFile(bytes);
    dirty = false;
    lastSave = Date.now();
}

function changed() {
    dirty = true;
}

// ── node access through the page ────────────────────────────────────────────

let rpcSeq = 0;
const rpcPending = new Map();
function rpc(method, params) {
    if (!chain.connected) return Promise.reject(new Error('not connected to a node'));
    return new Promise((resolve, reject) => {
        const id = ++rpcSeq;
        rpcPending.set(id, { resolve, reject });
        post({ type: 'rpc', id, method, params });
    });
}
function rpcResult({ id, ok, data, error, unanswered }) {
    const p = rpcPending.get(id);
    if (!p) return;
    rpcPending.delete(id);
    if (ok) p.resolve(data);
    else p.reject(Object.assign(new Error(error || 'request failed'), { unanswered: !!unanswered }));
}

// ── recovery key ────────────────────────────────────────────────────────────
//
// 1,024 WOTS keys at w = 2^16, about a billion hashes: split across helper
// workers (keygen.js), each with its own copy of the wasm module.

let keygenJob = null; // { phrase, promise, cancel }

function recoveryKey(phrase) {
    if (keygenJob && keygenJob.phrase === phrase) return keygenJob.promise;
    if (keygenJob) keygenJob.cancel();
    let cancelled = false;
    let stop;
    const stopped = new Promise((_, reject) => { stop = reject; });
    stopped.catch(() => {});
    const helpers = [];
    const job = {
        phrase,
        cancel() {
            cancelled = true;
            helpers.forEach(w => w.terminate());
            stop(new Error('cancelled'));
        },
    };
    job.promise = (async () => {
        const n = 1 << C.recovery_height;
        const seed = mw.recovery_master_seed(phrase);
        const leaves = new Uint8Array(n * 32);
        let done = 0;
        const progress = () => post({ type: 'keygen', done, total: n });
        const parallel = async (threads) => {
            for (let i = 0; i < threads; i++) {
                helpers.push(new Worker(new URL('./keygen.js', import.meta.url), { type: 'module' }));
            }
            let next = 0;
            const CHUNK = 8;
            await Promise.all(helpers.map(w => (async () => {
                while (next < n && !cancelled) {
                    const start = next;
                    const count = Math.min(CHUNK, n - start);
                    next += count;
                    const out = await Promise.race([stopped, new Promise((resolve, reject) => {
                        w.onmessage = e => (e.data.error ? reject(new Error(e.data.error)) : resolve(e.data.leaves));
                        w.onerror = e => { e.preventDefault(); reject(new Error(e.message || 'a recovery key helper failed')); };
                        w.postMessage({ module: wasmModule, seed, start, count });
                    })]);
                    leaves.set(out, start * 32);
                    done += count;
                    progress();
                }
            })()));
        };
        const here = async () => {
            for (let i = 0; i < n && !cancelled; i += 2) {
                leaves.set(mw.recovery_leaves(seed, i, 2), i * 32);
                done = i + 2;
                progress();
                await new Promise(r => setTimeout(r, 0));
            }
        };
        progress();
        try {
            const threads = typeof Worker === 'undefined' ? 0
                : Math.max(1, Math.min(8, navigator.hardwareConcurrency || 4));
            if (threads) {
                try {
                    await parallel(threads);
                } catch (e) {
                    if (cancelled) throw e;
                    // No helper workers here (an older browser): do it alone.
                    helpers.forEach(w => w.terminate());
                    done = 0;
                    await here();
                }
            } else {
                await here();
            }
            if (cancelled) throw new Error('cancelled');
            // The pieces landed where they belong: spot-check both ends.
            for (const i of [0, n - 1]) {
                const own = mw.recovery_leaves(seed, i, 1);
                if (!own.every((b, j) => b === leaves[i * 32 + j])) throw new Error('the recovery key failed its check; reload and try again');
            }
            return mw.recovery_root(leaves);
        } finally {
            helpers.forEach(w => w.terminate());
            seed.fill(0);
        }
    })();
    keygenJob = job;
    job.promise.catch(() => { if (keygenJob === job) keygenJob = null; });
    return job.promise;
}

/** Done with a phrase: forget the job that holds it. */
function dropKeygen() {
    if (keygenJob) keygenJob.cancel();
    keygenJob = null;
}

// ── state for the page ──────────────────────────────────────────────────────

function snapshot() {
    if (!wallet) return null;
    const tip = chain.tip;
    return {
        address: wallet.address(),
        balance: JSON.parse(wallet.balance(tip)),
        history: JSON.parse(wallet.history(tip)),
        pending: JSON.parse(wallet.pending_txs()).map(p => ({ tx_hash: p.tx_hash, created_at: p.created_at })),
        max: wallet.max_sendable(tip),
        scanned: wallet.scanned_height(),
        birth: wallet.birth_height(),
        recoveryHeight: wallet.recovery_height(),
        tip,
        chain: { ...chain },
        scan: { ...scan },
        syncError,
    };
}
let lastPost = 0;
function postState(force) {
    if (!wallet) return;
    const now = Date.now();
    if (!force && now - lastPost < 350) return;
    let state;
    try {
        state = snapshot();
    } catch (e) {
        console.error('wallet state', e); // the next post carries it
        return;
    }
    lastPost = now;
    post({ type: 'state', state });
}

// ── following the chain ─────────────────────────────────────────────────────

let syncRunning = false;
let syncAgain = false;
function requestSync() {
    if (!wallet || !chain.connected) return;
    if (syncRunning) { syncAgain = true; return; }
    syncRunning = true;
    runSync().finally(() => {
        syncRunning = false;
        if (syncAgain) { syncAgain = false; requestSync(); }
    });
}

async function refreshState() {
    const st = await rpc('get_state');
    if (!Number.isSafeInteger(st.height) || st.height < 0) throw new Error('The node answered get_state without a height.');
    chain.tip = st.height;
    chain.timestamp = st.timestamp || chain.timestamp;
    chain.prunedBelow = st.pruned_below || 0;
    chain.nodeSyncing = !!st.syncing;
    return st;
}

async function checkNetwork() {
    if (!genesis) { chain.networkOk = true; return; }
    const d = await rpc('get_headers', { start_height: 0, count: 1 });
    const ids = JSON.parse(mw.header_ids(d.headers_hex));
    chain.networkOk = ids[0] === genesis;
    if (!chain.networkOk) {
        syncError = `This node is on another network (genesis ${String(ids[0]).slice(0, 12)}…, expected ${genesis.slice(0, 12)}…). Pick another node in settings.`;
    }
}

/** A block this wallet scanned is no longer the node's: forget the last ten
 *  blocks, and the caller looks again from there. Past the oldest block hash
 *  it keeps (200 blocks), it cannot tell where the chains part, so it
 *  rescans from its birth height instead. */
function rollBack() {
    const birth = wallet.birth_height();
    let to = Math.max(birth, wallet.scanned_height() - 1 - 10);
    let deep = false;
    if (to > birth && !wallet.recorded_hash(to - 1)) {
        to = birth;
        deep = true;
    }
    if (wallet.rollback_to(to) || deep) reorged = deep ? 'deep' : (reorged || 'changed');
    changed();
}

/** Rolls back while the last block scanned is no longer the node's. */
async function checkLastBlock() {
    for (let guard = 0; guard < 64; guard++) {
        const h = wallet.scanned_height();
        if (h === 0) return;
        const recorded = wallet.recorded_hash(h - 1);
        if (!recorded) return;
        if (h - 1 >= chain.tip) return; // the node is behind us: wait for it
        let id;
        try {
            id = mw.block_id((await rpc('get_block', { height: h - 1 })).block_hex);
        } catch (e) {
            if (/no block/.test(errText(e))) return; // pruned: final anyway
            throw e;
        }
        if (id === recorded) return;
        rollBack();
    }
}

async function scanUnspent() {
    scan.active = true; scan.mode = 'utxos'; scan.outputs = 0;
    postState(true);
    const tip = chain.tip;
    const all = [];
    let after = null;
    for (;;) {
        let page;
        try {
            page = await rpc('get_utxos', { after, limit: UTXO_PAGE });
        } catch (e) {
            if (e.unanswered) throw new Error(`This node has pruned the blocks below ${chain.prunedBelow} and is too old to list unspent outputs to browsers. Use another node, or one that keeps every block.`);
            throw e;
        }
        all.push(...page.outputs);
        scan.outputs = all.length;
        postState();
        if (!page.next || page.outputs.length < UTXO_PAGE) break;
        after = page.next;
    }
    // A restore's worth of coins at once: history, not news.
    wallet.scan_unspent(JSON.stringify(all), tip);
    changed();
    await save();
}

async function scanBlocks() {
    scan.active = true; scan.mode = 'blocks';
    scan.from = wallet.scanned_height(); scan.to = chain.tip;
    while (wallet && chain.connected && wallet.scanned_height() < chain.tip) {
        const start = wallet.scanned_height();
        const count = Math.min(chain.tip - start, BLOCKS_PER_REQUEST);
        let r;
        if (supportsGetBlocks) {
            try {
                const d = await rpc('get_blocks', { start_height: start, count });
                if (!d.count) break;
                r = JSON.parse(wallet.scan_blocks(start, d.blocks_hex));
            } catch (e) {
                if (e.unanswered) { supportsGetBlocks = false; continue; } // an older node
                throw e;
            }
        } else {
            const d = await rpc('get_block', { height: start });
            try {
                r = JSON.parse(wallet.scan_block(start, d.block_hex));
                r.scanned = 1;
            } catch (e) {
                if (!/^reorg/.test(errText(e))) throw e;
                r = { reorg: true, scanned: 0, received: [], spent: [], confirmed: [], failed: [] };
            }
        }
        if (r.reorg) {
            rollBack();
            continue;
        }
        changed();
        announce(r);
        scan.to = chain.tip;
        postState();
        if (Date.now() - lastSave > SAVE_EVERY_MS) await save();
    }
    if (dirty) await save();
}

function announce(r) {
    const value = r.received.reduce((s, [, v, coinbase]) => s + (coinbase ? 0 : v), 0);
    const mined = r.received.filter(([, , coinbase]) => coinbase).length;
    if (r.confirmed && r.confirmed.length) toast(r.confirmed.length === 1 ? 'Payment confirmed.' : `${r.confirmed.length} payments confirmed.`, 'ok');
    if (r.failed && r.failed.length) toast('A payment failed: its coins were spent by another copy of this wallet.', 'bad');
    // During a long rescan, receipts are part of the history, not news.
    if (scan.to - scan.from > 20) return;
    if (value > 0) toast(`Received ${mw.format_amount(value)}.`, 'ok');
    if (mined) toast(mined === 1 ? 'Mined a block.' : `Mined ${mined} blocks.`, 'ok');
}

async function rebroadcast() {
    const now = Date.now() / 1000;
    for (const p of JSON.parse(wallet.pending_txs())) {
        const last = lastBroadcast.get(p.tx_hash) || p.created_at;
        if (now - last < REBROADCAST_SECS) continue;
        lastBroadcast.set(p.tx_hash, now);
        // A duplicate or a conflict is expected here; scanning settles it.
        try { await rpc('submit_transaction', { tx_hex: p.tx_hex }); } catch (_) {}
    }
}

async function runSync() {
    try {
        await refreshState();
        if (chain.networkOk === null) await checkNetwork();
        if (chain.networkOk === false) return;
        syncError = null;
        chain.behind = chain.tip < wallet.scanned_height();
        if (chain.nodeSyncing || chain.behind) return; // never roll back to a node that is catching up
        await checkLastBlock();
        if (wallet.scanned_height() < chain.prunedBelow) await scanUnspent();
        await scanBlocks();
        await rebroadcast();
        await scanMempool();
    } catch (e) {
        syncError = errText(e);
    } finally {
        scan.active = false;
        if (reorged) {
            toast(reorged === 'deep'
                ? `The chain reorganised further back than this wallet keeps track of; it rescanned from block ${wallet ? wallet.birth_height() : 0}.`
                : 'The chain reorganised; this wallet now follows the new chain, and payments its old blocks held are waiting for a block again.');
            reorged = null;
        }
        postState(true);
    }
}

/** Looks in the node's mempool for payments to this wallet, so that they
 *  show (as pending, not spendable) before a block confirms them. Only new
 *  transactions are downloaded; the wallet scans their outputs with its
 *  view key, as it scans blocks, so the node learns nothing from it. */
async function scanMempool() {
    if (!wallet || !chain.connected || !mempool.supported || mempool.running) return;
    if (chain.networkOk !== true || chain.nodeSyncing || chain.behind) return;
    if (wallet.scanned_height() < chain.tip) return; // catch up first: unscanned coins would look like income
    mempool.running = true;
    try {
        const d = await rpc('get_mempool');
        if (!Array.isArray(d.hashes)) {
            if (typeof d.count === 'number') mempool.supported = false; // a node from before this
            return;
        }
        const live = new Set(d.hashes);
        for (const h of mempool.scanned) if (!live.has(h)) mempool.scanned.delete(h);
        const wanted = d.hashes.filter(h => !mempool.scanned.has(h)).slice(0, MEMPOOL_TXS_PER_REQUEST);
        let txsHex = '';
        if (wanted.length) {
            const r = await rpc('get_mempool_txs', { hashes: wanted });
            txsHex = r.txs_hex || '';
            for (const h of (Array.isArray(r.hashes) ? r.hashes : wanted)) mempool.scanned.add(h);
        }
        if (!wallet) return;
        const incoming = () => JSON.parse(wallet.balance(chain.tip)).incoming;
        const before = incoming();
        const fresh = JSON.parse(wallet.scan_mempool(txsHex, JSON.stringify(d.hashes), Math.floor(Date.now() / 1000)));
        for (const p of fresh) toast(`Incoming ${mw.format_amount(p.value)}; waiting for a block.`, 'ok');
        postState(incoming() !== before);
    } catch (e) {
        if (e.unanswered) mempool.supported = false;
    } finally {
        mempool.running = false;
    }
}

function forgetMempool() {
    mempool.supported = true;
    mempool.scanned.clear();
}

/** Waits (a while) for the wallet to have scanned up to `height`. */
async function scannedTo(height, ms) {
    const until = Date.now() + ms;
    while (wallet && wallet.scanned_height() < height) {
        if (Date.now() > until) return false;
        requestSync();
        await new Promise(r => setTimeout(r, 250));
    }
    return !!wallet;
}

// Poll in case a push notification is lost.
setInterval(() => { if (wallet && chain.connected) requestSync(); }, 30_000);
// New payments arrive without a block; nothing announces them.
setInterval(() => { if (wallet && chain.connected) scanMempool(); }, MEMPOOL_SECS * 1000);

// ── unlocking ───────────────────────────────────────────────────────────────

function sameBytes(a, b) {
    if (!a || !b || a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
}

function checkPassword(password) {
    return sameBytes(mw.derive_file_key(password, fileSalt), fileKey);
}

async function becomeUnlocked(w, key, salt) {
    if (wallet) wallet.free();
    wallet = w;
    fileKey = key;
    fileSalt = salt;
    syncError = null;
    forgetMempool(); // a new wallet object knows no incoming payments yet
    await save();
    post({ type: 'unlocked' });
    postState(true);
    requestSync();
}

function lock() {
    dropKeygen();
    if (wallet) { wallet.free(); wallet = null; }
    if (fileKey) fileKey.fill(0);
    fileKey = null;
    fileSalt = null;
    post({ type: 'locked' });
}

function newPasswordOk(p) {
    if (typeof p !== 'string' || p.length < 8) throw new Error('Use a password of at least 8 characters.');
}

// ── messages from the page ──────────────────────────────────────────────────

const handlers = {
    async init({ config }) {
        wasmModule = await WebAssembly.compileStreaming(fetch(WASM_URL)).catch(async () =>
            WebAssembly.compile(await (await fetch(WASM_URL)).arrayBuffer()));
        await init({ module_or_path: wasmModule });
        C = JSON.parse(mw.chain_constants());
        network = (config && config.network) || C.network;
        genesis = (config && config.genesis) || null;
        const file = await loadFile().catch(() => null);
        post({ type: 'boot', hasWallet: !!file, constants: C, network });
        return {};
    },

    net({ status, addr }) {
        const was = chain.connected;
        chain.connected = status === 'connected';
        chain.addr = addr || null;
        if (chain.connected && !was) {
            chain.networkOk = null;
            supportsGetBlocks = true;
            forgetMempool();
            requestSync();
        }
        if (!chain.connected) {
            for (const [, p] of rpcPending) p.reject(new Error('lost the node'));
            rpcPending.clear();
        }
        postState(true);
    },

    push({ msg }) {
        if (msg && msg.type === 'NewBlockTip') {
            if (msg.payload && typeof msg.payload.height === 'number') {
                chain.tip = Math.max(chain.tip, msg.payload.height + 1);
            }
            requestSync();
        }
    },

    'rpc-result': rpcResult,

    async unlock({ password }) {
        const file = await loadFile();
        if (!file) throw new Error('No wallet is stored in this browser.');
        const salt = mw.file_salt(file);
        const key = mw.derive_file_key(password, salt);
        let w;
        try { w = mw.Wallet.open(file, key); } catch (e) { throw new Error('Wrong password.'); }
        await becomeUnlocked(w, key, salt);
    },

    'new-phrase'() {
        const phrase = mw.generate_mnemonic();
        // Start the slow part now, while the phrase is being written down.
        recoveryKey(phrase).catch(() => {});
        return { phrase };
    },

    'check-address'({ to }) {
        mw.check_address(to);
        return {};
    },

    'cancel-keygen'() {
        dropKeygen();
    },

    async create({ phrase, password }) {
        newPasswordOk(password);
        const rk = await recoveryKey(phrase);
        // Nothing can have paid a wallet before it existed: start at the tip.
        let birth = 0;
        if (chain.connected) {
            try { await refreshState(); birth = chain.tip; } catch (_) {}
        }
        const w = new mw.Wallet(phrase, rk, C.recovery_height, birth);
        dropKeygen();
        const salt = mw.new_salt();
        await becomeUnlocked(w, mw.derive_file_key(password, salt), salt);
    },

    async restore({ phrase, password, birth }) {
        newPasswordOk(password);
        const canonical = mw.normalize_mnemonic(phrase);
        const from = Math.max(0, Math.floor(Number(birth) || 0));
        const rk = await recoveryKey(canonical);
        const w = new mw.Wallet(canonical, rk, C.recovery_height, from);
        dropKeygen();
        const salt = mw.new_salt();
        await becomeUnlocked(w, mw.derive_file_key(password, salt), salt);
    },

    async import({ bytes, password }) {
        const file = new Uint8Array(bytes);
        const salt = mw.file_salt(file);
        const key = mw.derive_file_key(password, salt);
        let w;
        try { w = mw.Wallet.open(file, key); } catch (e) {
            throw new Error(/password/.test(errText(e)) ? 'Wrong password for this file.' : errText(e));
        }
        await becomeUnlocked(w, key, salt);
    },

    lock() { lock(); },

    async forget() {
        lock();
        await deleteFile();
        post({ type: 'boot', hasWallet: false, constants: C, network });
    },

    quote({ amount }) {
        const units = mw.parse_amount(amount);
        return JSON.parse(wallet.quote(units, chain.tip));
    },

    async send({ to, amount }) {
        if (!chain.connected) throw new Error('Not connected to a node.');
        mw.check_address(to);
        const units = mw.parse_amount(amount);
        await refreshState();
        // Pick coins knowing everything up to the tip.
        if (!(await scannedTo(chain.tip, 20_000))) throw new Error('Still catching up with the chain; try again when the scan is done.');
        const built = JSON.parse(wallet.build_send(to.trim(), units, chain.tip, Date.now() / 1000));
        await save();
        postState(true);
        try {
            await rpc('submit_transaction', { tx_hex: built.tx_hex });
        } catch (e) {
            // A repeat of a submission whose answer was lost: it is in.
            if (/already in pool|already being validated/.test(errText(e))) {
                lastBroadcast.set(built.tx_hash, Date.now() / 1000);
                return { tx_hash: built.tx_hash, amount: built.amount, fee: built.fee };
            }
            wallet.discard_send(built.tx_hash);
            await save();
            postState(true);
            throw new Error(`The node refused the payment: ${errText(e)}`);
        }
        lastBroadcast.set(built.tx_hash, Date.now() / 1000);
        return { tx_hash: built.tx_hash, amount: built.amount, fee: built.fee };
    },

    async cancel({ tx_hash }) {
        wallet.cancel_pending(tx_hash);
        await save();
        postState(true);
    },

    async rescan({ from }) {
        wallet.rescan_from(Math.max(0, Math.floor(Number(from) || 0)));
        await save();
        postState(true);
        requestSync();
    },

    coins() {
        return JSON.parse(wallet.coins(chain.tip));
    },

    reveal({ password }) {
        if (!checkPassword(password)) throw new Error('Wrong password.');
        return { phrase: wallet.mnemonic() };
    },

    'view-key'() {
        return { key: wallet.view_key() };
    },

    exportFile({ password }) {
        if (!checkPassword(password)) throw new Error('Wrong password.');
        const bytes = wallet.seal(fileKey, fileSalt);
        return { bytes };
    },

    async 'change-password'({ old, password }) {
        if (!checkPassword(old)) throw new Error('The current password is wrong.');
        newPasswordOk(password);
        const salt = mw.new_salt();
        fileKey.fill(0);
        fileKey = mw.derive_file_key(password, salt);
        fileSalt = salt;
        await save();
    },
};

self.onmessage = async (e) => {
    const msg = e.data || {};
    const fn = handlers[msg.type];
    if (!fn) return;
    try {
        const result = await fn(msg);
        if (msg.reqId !== undefined) {
            const transfer = result && result.bytes ? [result.bytes.buffer] : [];
            post({ type: 'reply', reqId: msg.reqId, ok: true, result }, transfer);
        }
    } catch (err) {
        if (msg.reqId !== undefined) post({ type: 'reply', reqId: msg.reqId, ok: false, error: errText(err) });
        else toast(errText(err), 'bad');
    }
};
