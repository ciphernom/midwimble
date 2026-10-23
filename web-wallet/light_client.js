// light_client.js: the browser's line to midwimble nodes.
//
// js-libp2p over WebRTC-direct: no domain, no certificate authority, no
// HTTPS gateway. The browser authenticates a node by the certificate hash
// in its address (/certhash/…) and its libp2p identity (/p2p/…). Ported from
// midstate's wasm-wallet/light_client.js, with its fixes kept: streams are
// released as soon as a response is read (else a scan exhausts the
// 64-streams-per-protocol cap), and the write side is half-closed right
// after the request.
//
// It keeps connections to a few nodes at once (POOL_SIZE), picked at random
// from the configured ones and from those the nodes it reaches know of
// (`get_nodes`), and uses a node only once it has checked that the node
// follows the wallet's genesis block. One of them, picked at random, is the
// wallet's primary: the wallet follows the chain through it (its state, its
// scan data, its new-tip pushes). A request that may go anywhere
// (`{spread: true}`, the whole blocks a wallet fetches) goes to a node
// picked at random, so that no one node sees all a wallet asks for, and
// wallets spread their load over the nodes there are rather than all using
// the first one in the configuration.
//
// The nodes it learns of are anyone's, and a light wallet believes the node
// it follows, so the pool keeps watch on its primary: one configured node
// stays in the pool while one can be reached; the primary is picked among
// the nodes near the pool's median height, which one node claiming a great
// height cannot move; and the nodes vote on a block a little below the tip,
// and a primary the others contradict is dropped.
//
// Wire format (src/network/light_protocol.rs): a JSON request
// {"method", "params"} and a JSON response {ok, data?, error?}, each behind
// a 4-byte little-endian length, one request per stream. The node pushes
// {"type": "NewBlockTip", "payload": {…}} on a second protocol.
//
// `npm run bundle` turns this file into light_client.bundle.js, which the
// page loads. RTCPeerConnection does not exist in workers, so this runs on
// the page's main thread and the wallet worker reaches the nodes through it.

import { createLibp2p } from 'libp2p';
import { webRTCDirect } from '@libp2p/webrtc';
import { multiaddr } from '@multiformats/multiaddr';

const LIGHT_PROTOCOL = '/midwimble/light/2.0.0';
const PUSH_PROTOCOL = '/midwimble/light-push/2.0.0';
const REQUEST_TIMEOUT_MS = 30_000;
const DIAL_TIMEOUT_MS = 8_000;
/** Nodes connected at once, unless the wallet asks for another number. */
const POOL_SIZE = 3;
/** Addresses learned from nodes, kept at most (configured ones aside). */
const MAX_FOUND = 64;
/** Addresses learned from any one node's answer, at most. */
const MAX_FOUND_PER_ANSWER = 8;
/** Failed dials in a row after which a learned address is forgotten. */
const FORGET_AFTER_FAILURES = 4;
/** Blocks a node's height may be from the pool's median for it to become
 *  the primary. */
const PRIMARY_SLACK = 2;
/** Blocks the primary may fall behind the pool's median before another
 *  node takes over. */
const PRIMARY_LAG = 6;
/** How far below the primary's tip the pool votes on a block. */
const VOTE_DEPTH = 6;
/** The node's own limit on a light message (light_protocol.rs). */
const MAX_MESSAGE = 4_000_000;
/** Requests in flight at once on each connection: well under the node's 50
 *  streams per peer. */
const MAX_IN_FLIGHT = 4;
/**
 * Largest piece of a request written at once. Each becomes one framed
 * message on its data channel, and the node (libp2p-webrtc) cannot decode a
 * frame over 8 KiB: a payment spending many coins is written in pieces.
 */
const WRITE_CHUNK = 8000;
/**
 * A field every successful answer to a method carries. An answer without it
 * belongs to another request: WebRTC reuses a closed data channel's id
 * quickly, and the late answer to an abandoned request can land on the next
 * stream. Nodes echo each request's number, which settles it; for nodes
 * from before that, this check catches answers to a different method. Either
 * way the request is sent again rather than the answer handed on.
 */
const ANSWER_FIELD = {
    get_state: 'height',
    get_headers: 'headers_hex',
    get_block: 'block_hex',
    get_blocks: 'blocks_hex',
    get_scan_data: 'scan_hex',
    get_nodes: 'nodes',
    get_utxos: 'outputs',
    get_mempool: 'count',
    get_mempool_txs: 'txs_hex',
    get_utxo_proof: 'proof',
};
/** What a browser can dial: WebRTC-direct, with the certificate hash and the
 *  node's identity. */
const DIALABLE = /^\/(ip4|ip6|dns4|dns6|dns)\/[^/]+\/udp\/\d+\/webrtc-direct\/certhash\/[^/]+\/p2p\/[^/]+$/;

function shuffle(list) {
    const a = list.slice();
    for (let i = a.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
}
const pick = list => list[Math.floor(Math.random() * list.length)];
const sleep = ms => new Promise(r => setTimeout(r, ms));
const peerOf = addr => addr.slice(addr.lastIndexOf('/p2p/') + 5);

function concat(chunks, total) {
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { out.set(c, off); off += c.length; }
    return out;
}

const asBytes = d => (d instanceof Uint8Array ? d : d.subarray());

/**
 * The id of the first header in `get_headers`' answer (hex bincode
 * `Vec<BatchHeader>`): its extension's final hash, which follows the list's
 * length (8 bytes), the height (8), two midstates (32 each) and the
 * extension's nonce (8).
 */
function firstHeaderId(hex) {
    return typeof hex === 'string' && hex.length >= 240 ? hex.slice(176, 240).toLowerCase() : null;
}

export class LightClient {
    constructor() {
        this.node = null;
        /** addr → {addr, found, failures, retryAt, bad}: where nodes may be. */
        this.known = new Map();
        /** peer id → {peer, id, addr, found, height, ready, inFlight, queue}. */
        this.conns = new Map();
        this.primary = null;     // peer id of the node the wallet follows
        this.genesis = null;     // expected genesis block id, if configured
        this.discover = true;    // learn nodes from the nodes reached
        this.poolSize = POOL_SIZE;
        this.spread = true;      // `spread` requests may go to any node
        this.vote = true;        // check the primary against the others
        this.follow = '';        // an address to follow when it is connected
        this.closed = false;
        this.seq = 0;            // numbers requests; the node echoes the number
        this.errors = [];        // the latest dial failures, for the page
        this.onStatus = () => {};
        this.onPush = () => {};
        this.onPool = () => {};
        this._timer = null;
        this._maintaining = null;
    }

    /**
     * Starts libp2p and connects to nodes from `addrs` (the configured ones)
     * and `found` (ones learned before). With `discover`, nodes reached are
     * asked where other nodes are. With `genesis`, a node must follow that
     * genesis block to be used.
     */
    async start(addrs, { genesis = null, found = [], discover = true, ...options } = {}) {
        this.genesis = genesis ? String(genesis).toLowerCase() : null;
        this.discover = discover;
        this.setOptions(options);
        this._learn(addrs, false);
        if (discover) this._learn(found, true);
        if (!this.known.size) throw new Error('no node addresses to dial');
        this.node = await createLibp2p({
            transports: [webRTCDirect()],
            // Allow private and loopback addresses: a wallet may well be
            // pointed at the node on its own machine or LAN.
            connectionGater: { denyDialMultiaddr: async () => false },
        });
        await this.node.handle(PUSH_PROTOCOL, (stream, connection) => this._readPush(stream, connection));
        await this.node.start();
        this.node.addEventListener('peer:disconnect', (evt) => this._lost(evt.detail.toString()));
        this.onStatus('connecting', null);
        await this._maintain();
    }

    get connected() {
        return !!this.primary;
    }

    /**
     * What can change while connected: `poolSize` (nodes at once), `spread`
     * (whether a `spread` request may go to any node, or only the primary),
     * `vote` (whether the pool checks its primary) and `follow` (an address
     * to follow whenever it is connected; '' for none).
     */
    setOptions({ poolSize, spread, vote, follow } = {}) {
        if (Number.isInteger(poolSize) && poolSize >= 1 && poolSize <= 8) this.poolSize = poolSize;
        if (typeof spread === 'boolean') this.spread = spread;
        if (typeof vote === 'boolean') this.vote = vote;
        if (typeof follow === 'string') {
            this.follow = follow.trim();
            if (this.follow) this._learn([this.follow], false);
        }
        if (!this.node) return;
        // Too many nodes: the newest that are not followed go.
        const extra = [...this.conns.values()].filter(c => c.id !== this.primary).reverse()
            .slice(0, Math.max(0, this.conns.size - this.poolSize));
        for (const c of extra) {
            this.node.hangUp(c.peer).catch(() => {});
            this._lost(c.id);
        }
        const wanted = this.follow && [...this.conns.values()].find(c => c.ready && c.addr === this.follow);
        if (wanted && wanted.id !== this.primary) {
            this.primary = wanted.id;
            this.onStatus('connected', wanted.addr);
        }
        this._report();
        this._maintain();
    }

    /** The nodes connected (that passed their checks), primary first, with
     *  what the wallet has asked of each. */
    nodes() {
        return [...this.conns.values()].filter(c => c.ready)
            .map(c => ({
                addr: c.addr,
                height: c.height,
                primary: c.id === this.primary,
                followed: !!this.follow && c.addr === this.follow,
                found: c.found,
                requests: c.requests,
                failures: c.failures,
                bytes: c.bytes,
                ms: c.ms,
            }))
            .sort((a, b) => b.primary - a.primary);
    }

    /** The learned addresses worth keeping for next time. */
    found() {
        return [...this.known.values()].filter(k => k.found && !k.bad).map(k => k.addr);
    }

    /** Stops using the primary for ten minutes (its answers did not hold
     *  up), and follows another node. */
    dropPrimary(why = 'its scan data did not match its blocks') {
        const c = this.conns.get(this.primary);
        if (!c) return;
        const k = this.known.get(c.addr);
        if (k) {
            k.failures++;
            k.retryAt = Date.now() + 600_000;
        }
        this.errors.push(`${c.addr.slice(0, 40)}…: ${why}`);
        this.node.hangUp(c.peer).catch(() => {});
        this._lost(c.id);
    }

    async stop() {
        this.closed = true;
        clearTimeout(this._timer);
        if (this.node) { try { await this.node.stop(); } catch (_) {} }
        this.node = null;
        this.conns.clear();
        this.primary = null;
    }

    // ── the pool ───────────────────────────────────────────────────────────

    /** Adds addresses to the known ones; returns those that are new. */
    _learn(addrs, found) {
        const fresh = [];
        for (const raw of addrs || []) {
            const addr = String(raw).trim();
            if (!DIALABLE.test(addr) || this.known.has(addr)) continue;
            this.known.set(addr, { addr, found, failures: 0, retryAt: 0, bad: false });
            fresh.push(addr);
        }
        const learned = [...this.known.values()].filter(k => k.found);
        for (const k of learned.slice(0, Math.max(0, learned.length - MAX_FOUND))) this.known.delete(k.addr);
        return fresh;
    }

    /** Fills the pool, then comes back when an address may be tried again. */
    _maintain() {
        if (this.closed || this._maintaining) return this._maintaining;
        clearTimeout(this._timer);
        this._maintaining = (async () => {
            try {
                for (;;) {
                    const want = this.poolSize - this.conns.size;
                    if (this.closed || want <= 0) break;
                    const picks = this._candidates(want);
                    if (!picks.length) break;
                    await Promise.all(picks.map(k => this._open(k)));
                }
            } finally {
                this._maintaining = null;
            }
            if (this.closed) return;
            if (!this.primary) {
                this.onStatus('failed', this.errors.slice(-3).join('; ') || 'no node reachable');
            } else {
                await this._watchPrimary();
            }
            this._report();
            // Again once an address is due, and every half minute regardless
            // (to replace a node that has quietly gone).
            const connected = new Set(this.conns.keys());
            const due = [...this.known.values()]
                .filter(k => !k.bad && !connected.has(peerOf(k.addr)))
                .map(k => k.retryAt);
            const next = this.conns.size < this.poolSize && due.length ? Math.min(...due) - Date.now() : 30_000;
            this._timer = setTimeout(() => this._maintain(), Math.min(30_000, Math.max(2_000, next)));
        })();
        return this._maintaining;
    }

    /** Up to `n` addresses to dial: due, of nodes not connected, one each;
     *  the followed node first, then a configured one if the pool has none. */
    _candidates(n) {
        const now = Date.now();
        const peers = new Set(this.conns.keys());
        const anchored = [...this.conns.values()].some(c => !c.found);
        const due = shuffle([...this.known.values()]).filter(k => !k.bad && k.retryAt <= now);
        if (!anchored) due.sort((a, b) => a.found - b.found);
        due.sort((a, b) => (b.addr === this.follow) - (a.addr === this.follow));
        const out = [];
        for (const k of due) {
            if (out.length >= n) break;
            const peer = peerOf(k.addr);
            if (peers.has(peer)) continue;
            peers.add(peer);
            out.push(k);
        }
        return out;
    }

    async _open(k) {
        let conn;
        try {
            conn = await this.node.dial(multiaddr(k.addr), { signal: AbortSignal.timeout(DIAL_TIMEOUT_MS) });
        } catch (e) {
            this._failed(k, e);
            return;
        }
        const id = conn.remotePeer.toString();
        if (this.conns.has(id)) return;
        const c = {
            peer: conn.remotePeer, id, addr: k.addr, found: k.found, height: 0, ready: false, inFlight: 0, queue: [],
            requests: 0, failures: 0, bytes: 0, ms: null,
        };
        this.conns.set(id, c);
        try {
            const st = await this._call(c, 'get_state');
            c.height = Number(st.height) || 0;
            if (this.genesis) {
                const d = await this._call(c, 'get_headers', { start_height: 0, count: 1 });
                const id0 = firstHeaderId(d.headers_hex);
                if (id0 !== this.genesis) {
                    throw Object.assign(new Error(`on another network (genesis ${String(id0).slice(0, 12)}…)`), { bad: true });
                }
            }
        } catch (e) {
            this.conns.delete(id);
            try { await this.node.hangUp(conn.remotePeer); } catch (_) {}
            this._failed(k, e);
            return;
        }
        if (!this.conns.has(id) || this.closed) return; // gone while checked
        k.failures = 0;
        k.retryAt = 0;
        c.ready = true;
        if (!this.primary || (this.follow && c.addr === this.follow)) this._choosePrimary();
        if (this.discover) this._discover(c);
        this._report();
    }

    _failed(k, e) {
        k.failures++;
        // 5 s, 10 s, 20 s, … up to five minutes; a node on another network
        // is not tried again.
        k.retryAt = Date.now() + Math.min(300_000, 5_000 * 2 ** (k.failures - 1));
        if (e && e.bad) k.bad = true;
        if (k.found && (k.bad || k.failures >= FORGET_AFTER_FAILURES)) this.known.delete(k.addr);
        this.errors.push(`${k.addr.slice(0, 40)}…: ${(e && e.message) || e}`);
        this.errors = this.errors.slice(-10);
    }

    /** Asks a node where other nodes are (an older node does not know), and
     *  keeps a few of its answers: no one node fills the list. */
    async _discover(c) {
        let d;
        try { d = await this._call(c, 'get_nodes'); } catch (_) { return; }
        const listed = shuffle(Array.isArray(d.nodes) ? d.nodes : []).slice(0, MAX_FOUND_PER_ANSWER);
        const fresh = this._learn(listed, true);
        if (fresh.length) {
            this._report();
            this._maintain();
        }
    }

    _lost(id) {
        const c = this.conns.get(id);
        if (!c) return;
        this.conns.delete(id);
        c.queue.splice(0).forEach(wake => wake()); // they find it gone
        if (this.primary === id) {
            this.primary = null;
            this._choosePrimary();
            if (!this.primary) this.onStatus('disconnected', c.addr);
        }
        this._report();
        this._maintain();
    }

    /** The median of the ready nodes' heights (the lower middle one). */
    _median() {
        const heights = [...this.conns.values()].filter(c => c.ready).map(c => c.height).sort((a, b) => a - b);
        return heights.length ? heights[Math.floor((heights.length - 1) / 2)] : 0;
    }

    /** The followed node if connected, else a random node among those near
     *  the pool's median height. */
    _choosePrimary(except) {
        const ready = [...this.conns.values()].filter(c => c.ready && c.id !== except);
        if (!ready.length) return;
        const followed = this.follow && ready.find(c => c.addr === this.follow);
        if (followed) {
            this.primary = followed.id;
            this.onStatus('connected', followed.addr);
            return;
        }
        const median = this._median();
        const near = ready.filter(r => Math.abs(r.height - median) <= PRIMARY_SLACK);
        const c = pick(near.length ? near : ready);
        this.primary = c.id;
        this.onStatus('connected', c.addr);
    }

    /**
     * Another node takes over from a primary whose height has drifted from
     * the pool's (fallen behind, or claimed past it), or whose block a
     * little below the pool's tip most of the others contradict. With fewer
     * than three nodes there is no majority, and the primary stays.
     */
    async _watchPrimary() {
        const p = this.conns.get(this.primary);
        // A node the user chose is followed as it is.
        if (!p || !this.vote || (this.follow && p.addr === this.follow)) return;
        // Heights fresh from each node, not only from the pushes it sent.
        await Promise.all([...this.conns.values()].filter(c => c.ready)
            .map(c => this._call(c, 'get_state').catch(() => {})));
        if (this.primary !== p.id) return;
        const median = this._median();
        if (Math.abs(p.height - median) > PRIMARY_LAG) {
            this._choosePrimary(p.id);
            return;
        }
        const ready = [...this.conns.values()].filter(c => c.ready);
        const height = Math.min(p.height, median) - 1 - VOTE_DEPTH;
        if (ready.length < 3 || height < 1) return;
        const ids = await Promise.all(ready.map(c => this._call(c, 'get_headers', { start_height: height, count: 1 })
            .then(d => firstHeaderId(d.headers_hex), () => null)));
        const mine = ids[ready.indexOf(p)];
        const others = ids.filter((id, i) => id && ready[i] !== p);
        const against = others.filter(id => id !== mine).length;
        if (this.primary === p.id && others.length >= 2 && against * 2 > others.length) {
            this.dropPrimary(`its block ${height} is not the other nodes'`);
        }
    }

    _report() {
        try { this.onPool({ nodes: this.nodes(), found: this.found() }); } catch (_) {}
    }

    // ── requests ───────────────────────────────────────────────────────────

    /**
     * One light request: resolves with `data`, rejects with the node's
     * error. It goes to the primary, or with `spread` to a node picked at
     * random, and on to another if that one fails or cannot answer (a node
     * that is behind, or has pruned the block).
     */
    async call(method, params, { spread = false } = {}) {
        const tried = new Set();
        let last;
        for (let attempt = 0; attempt < 4; attempt++) {
            let c;
            if (spread && this.spread) {
                const ready = [...this.conns.values()].filter(r => r.ready && !tried.has(r.id));
                c = ready.length ? pick(ready) : null;
            } else {
                if (attempt) await sleep(250 * attempt);
                c = this.conns.get(this.primary);
            }
            if (!c) break;
            try {
                return await this._call(c, method, params);
            } catch (e) {
                last = e;
                tried.add(c.id);
                // The primary's answer stands, unless it was too busy to give one.
                if (!spread && e.nodeError && !/busy|rate limit/.test(e.message)) throw e;
            }
        }
        throw last || new Error('not connected to a node');
    }

    /**
     * A request to one node. A stream that fails without an answer is tried
     * again twice: WebRTC data channels are reused quickly, and a new stream
     * occasionally collides with the reset of the one before it. An error
     * from the node itself is final. Repeating a submit_transaction is
     * harmless: the node answers a duplicate with "already in pool".
     */
    async _call(c, method, params) {
        const req = params === undefined ? { method } : { method, params };
        let last;
        for (let attempt = 0; attempt < 3; attempt++) {
            if (attempt) await sleep(150 * attempt);
            let resp;
            const t0 = Date.now();
            try {
                c.requests++;
                resp = await this._queued(c, () => this._request(c, req));
                c.ms = c.ms == null ? Date.now() - t0 : Math.round(c.ms * 0.8 + (Date.now() - t0) * 0.2);
            } catch (e) {
                c.failures++;
                last = e;
                if (!this.conns.has(c.id)) break;
                continue;
            }
            if (!resp || resp.ok !== true) {
                const e = new Error((resp && resp.error) || `${method} failed`);
                e.nodeError = true;
                throw e;
            }
            const field = ANSWER_FIELD[method];
            if (field && !(resp.data && typeof resp.data === 'object' && field in resp.data)) {
                console.warn(`${method}: got an answer to another request; asking again`);
                last = new Error(`${method}: the node's answer did not match the request`);
                continue;
            }
            if (method === 'get_state' && Number.isSafeInteger(resp.data.height)) c.height = resp.data.height;
            return resp.data;
        }
        throw last;
    }

    async _queued(c, fn) {
        while (c.inFlight >= MAX_IN_FLIGHT && this.conns.has(c.id)) {
            await new Promise(r => c.queue.push(r));
        }
        c.inFlight++;
        try {
            return await fn();
        } finally {
            c.inFlight--;
            const next = c.queue.shift();
            if (next) next();
        }
    }

    async _request(c, req) {
        const conns = this.conns.has(c.id) ? this.node.getConnections(c.peer) : [];
        if (!conns.length) throw new Error('not connected to the node');
        const stream = await conns[0].newStream([LIGHT_PROTOCOL], { signal: AbortSignal.timeout(DIAL_TIMEOUT_MS) });
        const id = ++this.seq;
        try {
            const body = new TextEncoder().encode(JSON.stringify({ id, ...req }));
            const msg = new Uint8Array(4 + body.length);
            new DataView(msg.buffer).setUint32(0, body.length, true);
            msg.set(body, 4);

            const response = new Promise((resolve, reject) => {
                const chunks = [];
                let total = 0;
                let expected = null;
                const onMessage = (evt) => {
                    const bytes = asBytes(evt.data);
                    chunks.push(bytes);
                    total += bytes.length;
                    if (expected === null && total >= 4) {
                        const head = concat(chunks, total);
                        expected = new DataView(head.buffer, head.byteOffset).getUint32(0, true);
                        if (expected > MAX_MESSAGE) { done(); reject(new Error('response too large')); return; }
                    }
                    if (expected !== null && total >= 4 + expected) {
                        done();
                        c.bytes += total;
                        resolve(concat(chunks, total).subarray(4, 4 + expected));
                    }
                };
                const onClose = (evt) => {
                    done();
                    // A node closes (or resets) a request it cannot parse
                    // without a word: an older node that lacks the method.
                    const why = evt && evt.error ? (evt.error.message || String(evt.error)) : 'closed';
                    const e = new Error(`${req.method}: the node ended the stream without answering (${why})`);
                    e.unanswered = total === 0;
                    reject(e);
                };
                const timer = setTimeout(() => { done(); reject(new Error(`${req.method}: the node did not answer in time`)); }, REQUEST_TIMEOUT_MS);
                const done = () => {
                    clearTimeout(timer);
                    stream.removeEventListener('message', onMessage);
                    stream.removeEventListener('close', onClose);
                };
                stream.addEventListener('message', onMessage);
                stream.addEventListener('close', onClose);
            });
            response.catch(() => {});

            for (let at = 0; at < msg.length; at += WRITE_CHUNK) {
                if (stream.send(msg.subarray(at, at + WRITE_CHUNK))) continue;
                await new Promise((resolve, reject) => {
                    const onDrain = () => { off(); resolve(); };
                    const onClose = () => { off(); reject(new Error('stream closed while sending')); };
                    const off = () => {
                        stream.removeEventListener('drain', onDrain);
                        stream.removeEventListener('close', onClose);
                    };
                    stream.addEventListener('drain', onDrain);
                    stream.addEventListener('close', onClose);
                });
            }
            stream.close().catch(() => {});
            const answer = JSON.parse(new TextDecoder().decode(await response));
            // An answer numbered for another request reached this stream (see
            // ANSWER_FIELD); nodes from before numbering send none.
            if (answer && answer.id !== undefined && answer.id !== id) {
                console.warn(`${req.method}: got the answer to another request; asking again`);
                throw new Error(`${req.method}: the answer was for another request`);
            }
            return answer;
        } finally {
            // Frees the stream slot now rather than after the FIN handshake.
            try { stream.abort(new Error('done')); } catch (_) {}
        }
    }

    // ── pushes ─────────────────────────────────────────────────────────────

    /** A new tip, pushed by a node: the primary's is passed on; the others'
     *  keep their heights current, for choosing a primary. */
    async _readPush(stream, connection) {
        // Handler signature differs across libp2p versions: ({stream,
        // connection}) or (stream, connection).
        const s = stream && stream.stream ? stream.stream : stream;
        const conn = (stream && stream.connection) || connection;
        const from = conn && conn.remotePeer ? conn.remotePeer.toString() : null;
        try {
            const chunks = [];
            let total = 0;
            for await (const chunk of (s.source || s)) {
                const bytes = asBytes(chunk);
                chunks.push(bytes);
                total += bytes.length;
                if (total > MAX_MESSAGE) throw new Error('push too large');
                if (total >= 4) {
                    const buf = concat(chunks, total);
                    const len = new DataView(buf.buffer, buf.byteOffset).getUint32(0, true);
                    if (len > MAX_MESSAGE) throw new Error('push too large');
                    if (total >= 4 + len) {
                        const msg = JSON.parse(new TextDecoder().decode(buf.subarray(4, 4 + len)));
                        const c = from && this.conns.get(from);
                        const height = msg && msg.payload && msg.payload.height;
                        if (c && Number.isSafeInteger(height)) c.height = Math.max(c.height, height + 1);
                        if (!from || from === this.primary) this.onPush(msg);
                        break;
                    }
                }
            }
        } catch (_) {
            // A malformed push is dropped; the wallet also polls.
        } finally {
            try { s.close ? await s.close() : null; } catch (_) {}
        }
    }
}
