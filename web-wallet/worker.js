// worker.js: the wallet, off the page's thread.
//
// Holds the WebAssembly wallet (src/wallet.rs), keeps it in IndexedDB as a
// sealed wallet file (the CLI's encrypted format: the password never leaves
// this worker and the plaintext never touches storage), and follows the
// chain through the page, which owns the WebRTC connections (RTCPeerConnection
// does not exist in workers): {type: 'rpc'} out, {type: 'rpc-result'} back.
//
// It reads the chain as scan data (core/scan.rs), not whole blocks: enough to
// pass over every block that neither pays this wallet nor spends its coins.
// The few others it fetches whole, each together with a few other blocks
// (three, unless set otherwise), and each of those from a node picked at
// random, so that no node learns which blocks are this wallet's. A user who
// would rather give nothing away downloads every block whole instead. The
// page's settings tune all of it (`settings`, below).

import init, * as mw from './pkg/midwimble_web_wallet.js';

const WASM_URL = new URL('./pkg/midwimble_web_wallet_bg.wasm', import.meta.url);
/** Blocks asked for per get_blocks (the node caps it, and by size). */
const BLOCKS_PER_REQUEST = 100;
/** When more than this share of the blocks in a request's scan data are the
 *  wallet's business, they are downloaded in bulk instead (get_blocks): as
 *  cheap, and it gives nothing away. */
const BULK_SHARE = 1 / 8;
/** Blocks in a row that do not match their scan data, from the node that
 *  sent it, after which the wallet stops trusting that node. */
const MISMATCHES_TO_DROP = 3;
const UTXO_PAGE = 500;

/** What the page's settings can change (app.js keeps them, per browser). */
const settings = {
    /** Every block whole, as before scan data. */
    wholeBlocks: false,
    /** Other blocks fetched with each block the wallet needs whole. */
    decoys: 3,
    /** Decoys come from the blocks around the one needed, this many. */
    decoyWindow: 1000,
    /** Blocks' scan data asked for per get_scan_data (the node caps it). */
    scanPerRequest: 2000,
    /** Blocks fetched ahead of the scan, at most. */
    fetchAhead: 8,
    /** Look in the node's mempool for payments to this wallet. */
    watchMempool: true,
    /** Seconds between those looks (a list of hashes; only new
     *  transactions are downloaded). */
    mempoolSecs: 5,
    /** Seconds before a payment still waiting for a block is broadcast
     *  again. */
    rebroadcastSecs: 120,
    /** Fee rate for payments, in base units per weight (0: the minimum). */
    feeRate: 0,
};
const clampInt = (v, lo, hi, dflt) => (Number.isInteger(v) ? Math.min(hi, Math.max(lo, v)) : dflt);
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
    connected: false, addr: null, nodes: 0, tip: 0, timestamp: 0, prunedBelow: 0,
    nodeSyncing: false, networkOk: null, behind: false,
};
const scan = { active: false, mode: 'blocks', from: 0, to: 0, outputs: 0, fetched: 0 };
let supportsGetBlocks = true;
let supportsScanData = true;
let mismatches = 0;
let lastSync = 0; // when a sync last ended without an error
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
function shuffle(list) {
    const a = list.slice();
    for (let i = a.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
}

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
/** A light request, to the node the wallet follows, or with `spread` to
 *  any of the nodes connected, picked at random. */
function rpc(method, params, { spread = false } = {}) {
    if (!chain.connected) return Promise.reject(new Error('not connected to a node'));
    return new Promise((resolve, reject) => {
        const id = ++rpcSeq;
        rpcPending.set(id, { resolve, reject });
        post({ type: 'rpc', id, method, params, spread });
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

/** The chain's height as far as is known: what a node said, or, before any
 *  has (offline, say), how far this wallet has scanned. Without it, every
 *  mined coin would look immature until a node answered. */
const knownTip = () => Math.max(chain.tip, wallet ? wallet.scanned_height() : 0);

function snapshot() {
    if (!wallet) return null;
    const tip = knownTip();
    return {
        address: wallet.address(),
        // Tolerate a wallet module built before watch-only existed, so this
        // doesn't break state updates until pkg/ is rebuilt (see build.sh).
        watchOnly: typeof wallet.is_watch_only === 'function' && wallet.is_watch_only(),
        balance: JSON.parse(wallet.balance(tip)),
        history: JSON.parse(wallet.history(tip)),
        pending: JSON.parse(wallet.pending_txs()).map(p => ({ tx_hash: p.tx_hash, created_at: p.created_at })),
        max: wallet.max_sendable_with(sendOptions(), tip),
        scanned: wallet.scanned_height(),
        birth: wallet.birth_height(),
        recoveryHeight: wallet.recovery_height(),
        tip,
        chain: { ...chain },
        scan: { ...scan, whole: settings.wholeBlocks, scanData: supportsScanData },
        diag: { supportsGetBlocks, supportsScanData, mismatches, lastSync, settings: { ...settings } },
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

/** The id of the node's block at `height`, from its scan data (or the block,
 *  from a node without scan data); null if the node has pruned it. */
async function blockId(height) {
    if (supportsScanData && !settings.wholeBlocks) {
        try {
            const d = await rpc('get_scan_data', { start_height: height, count: 1 });
            if (!d.count) return null;
            const data = new mw.ScanData(height, d.scan_hex);
            try { return data.id(height); } finally { data.free(); }
        } catch (e) {
            if (!e.unanswered) throw e;
            supportsScanData = false; // an older node
        }
    }
    try {
        return mw.block_id((await rpc('get_block', { height })).block_hex);
    } catch (e) {
        if (/no block/.test(errText(e))) return null;
        throw e;
    }
}

/** Rolls back while the last block scanned is no longer the node's. */
async function checkLastBlock() {
    for (let guard = 0; guard < 64; guard++) {
        const h = wallet.scanned_height();
        if (h === 0) return;
        const recorded = wallet.recorded_hash(h - 1);
        if (!recorded) return;
        if (h - 1 >= chain.tip) return; // the node is behind us: wait for it
        const id = await blockId(h - 1);
        if (id === null || id === recorded) return; // pruned: final anyway
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
        let more = null;
        if (supportsScanData && !settings.wholeBlocks) more = await scanByScanData();
        if (more === null) more = await scanWhole(chain.tip);
        if (!more) break;
        scan.to = chain.tip;
        postState();
        if (Date.now() - lastSave > SAVE_EVERY_MS) await save();
    }
    if (dirty) await save();
}

/** One request's worth of blocks, whole, up to `end`. False if the node had
 *  none to give. */
async function scanWhole(end) {
    const start = wallet.scanned_height();
    const count = Math.min(end - start, BLOCKS_PER_REQUEST);
    let r;
    if (supportsGetBlocks) {
        try {
            const d = await rpc('get_blocks', { start_height: start, count });
            if (!d.count) return false;
            r = JSON.parse(wallet.scan_blocks(start, d.blocks_hex));
        } catch (e) {
            if (e.unanswered) { supportsGetBlocks = false; return true; } // an older node
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
        return true;
    }
    changed();
    announce(r);
    return true;
}

/**
 * One request's worth of scan data: the blocks that are not this wallet's
 * business are applied by it, the others fetched whole (fetchWhole). False
 * if the node had none to give; null if it serves no scan data.
 */
async function scanByScanData() {
    const start = wallet.scanned_height();
    let d;
    try {
        d = await rpc('get_scan_data', { start_height: start, count: Math.min(chain.tip - start, settings.scanPerRequest) });
    } catch (e) {
        if (e.unanswered) { supportsScanData = false; return null; } // an older node
        throw e;
    }
    if (!d.count) return false;
    if (d.start_height !== start) throw new Error('The node sent scan data for other blocks than asked.');
    const data = new mw.ScanData(start, d.scan_hex);
    try {
        const ahead = JSON.parse(wallet.wanted(data));
        if (ahead.length > Math.max(settings.decoys + 1, (data.end() - start) * BULK_SHARE)) {
            // Most of these blocks are this wallet's: all of them, in bulk.
            while (wallet.scanned_height() < data.end()) {
                if (!(await scanWhole(data.end()))) break;
            }
            return true;
        }
        const fetches = new Map();
        const fetch = (h) => {
            let p = fetches.get(h);
            if (!p) {
                p = fetchWhole(h, data);
                p.catch(() => {});
                fetches.set(h, p);
            }
            return p;
        };
        const topUp = () => {
            for (const h of fetches.keys()) if (h < wallet.scanned_height()) fetches.delete(h);
            while (ahead.length && fetches.size < settings.fetchAhead) {
                const h = ahead.shift();
                if (h >= wallet.scanned_height()) fetch(h);
            }
        };
        for (;;) {
            topUp();
            const r = JSON.parse(wallet.scan_compact(data));
            if (r.scanned) changed();
            if (r.reorg) { rollBack(); return true; }
            if (r.need == null) return true;
            const report = await scanFetched(data, r.need, await fetch(r.need));
            if (!report) return true; // the node's chain moved: fresh scan data
            changed();
            announce(report);
            scan.to = chain.tip;
            postState();
        }
    } finally {
        data.free();
    }
}

/**
 * Block `height`, whole, from a node picked at random, with
 * `settings.decoys` other blocks from around it, each from a node picked at
 * random too: no node can tell which block the wallet needed. Resolves with
 * the block's hex.
 */
function fetchWhole(height, data) {
    // From the blocks around it that a wallet at this point could need:
    // none past its scan data, none below where it started, or the decoys
    // would give themselves away.
    const birth = wallet.birth_height();
    const window = settings.decoyWindow;
    const hi = Math.min(data.end(), Math.max(birth, height - window / 2) + window);
    const lo = Math.max(birth, Math.min(height - window / 2, hi - window));
    const heights = new Set([height]);
    for (let tries = 0; heights.size < Math.min(settings.decoys + 1, hi - lo) && tries < 64; tries++) {
        heights.add(lo + Math.floor(Math.random() * (hi - lo)));
    }
    let wanted;
    for (const h of shuffle([...heights])) {
        const p = rpc('get_block', { height: h }, { spread: true });
        if (h === height) wanted = p;
        else p.catch(() => {}); // a decoy: its answer does not matter
    }
    scan.fetched++;
    return wanted.then(d => d.block_hex);
}

/**
 * Applies block `height`, fetched whole, once it is checked against the scan
 * data. A block from another node that does not match is asked of the node
 * that sent the scan data; if its own does not match either, its chain has
 * moved since (or it lies): resolves null, and the caller starts over.
 */
async function scanFetched(data, height, hex) {
    const apply = (blockHex) => {
        try {
            return JSON.parse(wallet.scan_full(data, height, blockHex));
        } catch (e) {
            if (/does not match its scan data/.test(errText(e))) return null;
            throw e;
        }
    };
    let report = apply(hex);
    if (!report) report = apply((await rpc('get_block', { height })).block_hex);
    if (report) {
        mismatches = 0;
        return report;
    }
    if (++mismatches >= MISMATCHES_TO_DROP) {
        mismatches = 0;
        post({ type: 'bad-node', addr: chain.addr });
        throw new Error('The node\'s scan data does not match its own blocks; trying another node.');
    }
    return null;
}

function announce(r) {
    const value = r.received.reduce((s, [, v, coinbase]) => s + (coinbase ? 0 : v), 0);
    if (r.confirmed && r.confirmed.length) toast(r.confirmed.length === 1 ? 'Payment confirmed.' : `${r.confirmed.length} payments confirmed.`, 'ok');
    if (r.failed && r.failed.length) toast('A payment failed: its coins were spent by another copy of this wallet.', 'bad');
    // During a long rescan, receipts are part of the history, not news.
    if (scan.to - scan.from > 20) return;
    if (value > 0) toast(`Received ${mw.format_amount(value)}.`, 'ok');
    // Blocks mined show in the activity; a miner's would be a stream of news.
}

async function rebroadcast() {
    const now = Date.now() / 1000;
    for (const p of JSON.parse(wallet.pending_txs())) {
        const last = lastBroadcast.get(p.tx_hash) || p.created_at;
        if (now - last < settings.rebroadcastSecs) continue;
        lastBroadcast.set(p.tx_hash, now);
        // A duplicate or a conflict is expected here; scanning settles it.
        // Each time to a node picked at random, in case one dropped it.
        try { await rpc('submit_transaction', { tx_hex: p.tx_hex }, { spread: true }); } catch (_) {}
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
        lastSync = Date.now();
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
    if (!wallet || !chain.connected || !mempool.supported || mempool.running || !settings.watchMempool) return;
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
let mempoolTimer = null;
function watchMempool() {
    clearInterval(mempoolTimer);
    mempoolTimer = setInterval(() => { if (wallet && chain.connected) scanMempool(); }, settings.mempoolSecs * 1000);
}
watchMempool();

/** The page's choices for a payment, as the wallet takes them: its fee
 *  rate, and the coins it spends if the user chose them. */
function sendOptions(coins) {
    const o = {};
    if (settings.feeRate > 0) o.fee_rate = settings.feeRate;
    if (Array.isArray(coins) && coins.length) o.coins = coins;
    return JSON.stringify(o);
}

function applySettings(next) {
    if (!next) return;
    const before = { ...settings };
    if (typeof next.wholeBlocks === 'boolean') settings.wholeBlocks = next.wholeBlocks;
    if (typeof next.watchMempool === 'boolean') settings.watchMempool = next.watchMempool;
    settings.decoys = clampInt(next.decoys, 0, 16, settings.decoys);
    settings.decoyWindow = clampInt(next.decoyWindow, 10, 100_000, settings.decoyWindow);
    settings.scanPerRequest = clampInt(next.scanPerRequest, 50, 2000, settings.scanPerRequest);
    settings.fetchAhead = clampInt(next.fetchAhead, 1, 64, settings.fetchAhead);
    settings.mempoolSecs = clampInt(next.mempoolSecs, 2, 3600, settings.mempoolSecs);
    settings.rebroadcastSecs = clampInt(next.rebroadcastSecs, 30, 86_400, settings.rebroadcastSecs);
    settings.feeRate = clampInt(next.feeRate, 0, 1e12, settings.feeRate);
    if (settings.mempoolSecs !== before.mempoolSecs) watchMempool();
    if (settings.wholeBlocks !== before.wholeBlocks) requestSync();
}

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
    async init({ config, settings: chosen }) {
        wasmModule = await WebAssembly.compileStreaming(fetch(WASM_URL)).catch(async () =>
            WebAssembly.compile(await (await fetch(WASM_URL)).arrayBuffer()));
        await init({ module_or_path: wasmModule });
        C = JSON.parse(mw.chain_constants());
        network = (config && config.network) || C.network;
        genesis = (config && config.genesis) || null;
        applySettings(chosen);
        const file = await loadFile().catch(() => null);
        post({ type: 'boot', hasWallet: !!file, constants: C, network });
        return {};
    },

    net({ status, addr, nodes }) {
        const was = chain.connected ? chain.addr : false;
        // 'gateway' is the HTTPS fallback: no WebRTC node, but requests still
        // reach one, so the wallet scans and sends as if connected.
        chain.connected = status === 'connected' || status === 'gateway';
        chain.addr = chain.connected ? (addr || null) : null;
        chain.nodes = chain.connected ? (nodes || 1) : 0;
        if (chain.connected && was !== chain.addr) {
            // Another node to follow: what was learned of the last one's
            // support and mempool does not carry over.
            chain.networkOk = null;
            supportsGetBlocks = true;
            supportsScanData = true;
            mismatches = 0;
            forgetMempool();
            requestSync();
        }
        if (!chain.connected) {
            for (const [, p] of rpcPending) p.reject(new Error('lost the node'));
            rpcPending.clear();
        }
        postState(true);
    },

    settings({ settings: chosen }) {
        applySettings(chosen);
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

    /** What block `height` mints under the schedule, for the miner's
     *  estimate when the pool doesn't say. */
    'block-reward'({ height }) {
        return { units: typeof mw.block_reward === 'function' ? mw.block_reward(Math.max(0, Math.floor(Number(height) || 0))) : 0 };
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

    async watch({ viewKey, password, birth }) {
        newPasswordOk(password);
        const from = Math.max(0, Math.floor(Number(birth) || 0));
        // No recovery key: a watch-only wallet holds no secrets to recover.
        const w = mw.Wallet.watch(String(viewKey).trim(), from);
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

    quote({ amount, coins }) {
        const units = mw.parse_amount(amount);
        return JSON.parse(wallet.quote_with(units, sendOptions(coins), knownTip()));
    },

    /** The most one payment can send from `coins` (all of them when none
     *  are named), at the fee rate set. */
    max({ coins }) {
        return { max: wallet.max_sendable_with(sendOptions(coins), knownTip()) };
    },

    'verify-password'({ password }) {
        if (!checkPassword(password)) throw new Error('Wrong password.');
        return {};
    },

    async send({ to, amount, coins }) {
        if (!chain.connected) throw new Error('Not connected to a node.');
        mw.check_address(to);
        const units = mw.parse_amount(amount);
        await refreshState();
        // Pick coins knowing everything up to the tip.
        if (!(await scannedTo(chain.tip, 20_000))) throw new Error('Still catching up with the chain; try again when the scan is done.');
        const built = JSON.parse(wallet.build_send_with(to.trim(), units, sendOptions(coins), chain.tip, Date.now() / 1000));
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
        return JSON.parse(wallet.coins(knownTip()));
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
