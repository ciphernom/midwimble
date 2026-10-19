// light_client.js: the browser's line to a midwimble node.
//
// js-libp2p over WebRTC-direct: no domain, no certificate authority, no
// HTTPS gateway. The browser authenticates the node by the certificate hash
// in its address (/certhash/…) and its libp2p identity (/p2p/…). Ported from
// midstate's wasm-wallet/light_client.js, with its fixes kept: streams are
// released as soon as a response is read (else a scan exhausts the
// 64-streams-per-protocol cap), and the write side is half-closed right
// after the request.
//
// Wire format (src/network/light_protocol.rs): a JSON request
// {"method", "params"} and a JSON response {ok, data?, error?}, each behind
// a 4-byte little-endian length, one request per stream. The node pushes
// {"type": "NewBlockTip", "payload": {…}} on a second protocol.
//
// `npm run bundle` turns this file into light_client.bundle.js, which the
// page loads. RTCPeerConnection does not exist in workers, so this runs on
// the page's main thread and the wallet worker reaches the node through it.

import { createLibp2p } from 'libp2p';
import { webRTCDirect } from '@libp2p/webrtc';
import { multiaddr } from '@multiformats/multiaddr';

const LIGHT_PROTOCOL = '/midwimble/light/2.0.0';
const PUSH_PROTOCOL = '/midwimble/light-push/2.0.0';
const REQUEST_TIMEOUT_MS = 30_000;
const DIAL_TIMEOUT_MS = 8_000;
/** The node's own limit on a light message (light_protocol.rs). */
const MAX_MESSAGE = 4_000_000;
/** Requests in flight at once: well under the node's 50 streams per peer. */
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
    get_utxos: 'outputs',
    get_mempool: 'count',
    get_mempool_txs: 'txs_hex',
    get_utxo_proof: 'proof',
};

function shuffle(list) {
    const a = list.slice();
    for (let i = a.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
}

function concat(chunks, total) {
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { out.set(c, off); off += c.length; }
    return out;
}

const asBytes = d => (d instanceof Uint8Array ? d : d.subarray());

export class LightClient {
    constructor() {
        this.node = null;
        this.peer = null;        // PeerId of the node we use
        this.addr = null;        // the address we reached it at
        this.addrs = [];         // candidates, in the user's order
        this.closed = false;
        this.inFlight = 0;
        this.queue = [];
        this.seq = 0;            // numbers requests; the node echoes the number
        this.onStatus = () => {};
        this.onPush = () => {};
        this._retry = null;
        this._attempt = 0;
    }

    /** Starts libp2p and connects to one of `addrs` (tried in random order). */
    async start(addrs) {
        this.addrs = [...new Set(addrs.map(a => String(a).trim()).filter(Boolean))];
        if (!this.addrs.length) throw new Error('no node addresses to dial');
        this.node = await createLibp2p({
            transports: [webRTCDirect()],
            // Allow private and loopback addresses: a wallet may well be
            // pointed at the node on its own machine or LAN.
            connectionGater: { denyDialMultiaddr: async () => false },
        });
        await this.node.handle(PUSH_PROTOCOL, (stream) => this._readPush(stream));
        await this.node.start();
        this.node.addEventListener('peer:disconnect', (evt) => {
            if (this.peer && evt.detail.toString() === this.peer.toString()) {
                this.peer = null;
                this.onStatus('disconnected', this.addr);
                this._scheduleReconnect();
            }
        });
        await this._connectAny();
    }

    async _connectAny() {
        this.onStatus('connecting', null);
        const errors = [];
        for (const a of shuffle(this.addrs)) {
            if (this.closed) return;
            try {
                const ma = multiaddr(a);
                const conn = await this.node.dial(ma, { signal: AbortSignal.timeout(DIAL_TIMEOUT_MS) });
                this.peer = conn.remotePeer;
                this.addr = a;
                this._attempt = 0;
                this.onStatus('connected', a);
                return;
            } catch (e) {
                errors.push(`${a.slice(0, 48)}…: ${e.message || e}`);
            }
        }
        this.onStatus('failed', errors.join('; '));
        this._scheduleReconnect();
    }

    _scheduleReconnect() {
        if (this.closed || this._retry) return;
        // 3 s, 6 s, … capped at 30 s; a wallet left open keeps trying.
        const delay = Math.min(30_000, 3_000 * ++this._attempt);
        this._retry = setTimeout(async () => {
            this._retry = null;
            if (!this.closed && !this.peer) await this._connectAny();
        }, delay);
    }

    get connected() {
        return !!this.peer;
    }

    /** Replaces the candidate list and reconnects. */
    async reconnect(addrs) {
        this.addrs = [...new Set(addrs.map(a => String(a).trim()).filter(Boolean))];
        const old = this.peer;
        this.peer = null;
        if (old) { try { await this.node.hangUp(old); } catch (_) {} }
        await this._connectAny();
    }

    async stop() {
        this.closed = true;
        clearTimeout(this._retry);
        if (this.node) { try { await this.node.stop(); } catch (_) {} }
        this.node = null;
        this.peer = null;
    }

    async _readPush(stream) {
        // Handler signature differs across libp2p versions: ({stream}) or (stream).
        const s = stream && stream.stream ? stream.stream : stream;
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
                        this.onPush(msg);
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

    /**
     * One light request: resolves with `data`, rejects with the node's error.
     * A stream that fails without an answer is tried again twice: WebRTC
     * data channels are reused quickly, and a new stream occasionally
     * collides with the reset of the one before it. An error from the node
     * itself is final. Repeating a submit_transaction is harmless: the node
     * answers a duplicate with "already in pool".
     */
    async call(method, params) {
        const req = params === undefined ? { method } : { method, params };
        let last;
        for (let attempt = 0; attempt < 3; attempt++) {
            if (attempt) await new Promise(r => setTimeout(r, 150 * attempt));
            let resp;
            try {
                resp = await this._queued(() => this._request(req));
            } catch (e) {
                last = e;
                if (!this.peer) break;
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
            return resp.data;
        }
        throw last;
    }

    async _queued(fn) {
        while (this.inFlight >= MAX_IN_FLIGHT) {
            await new Promise(r => this.queue.push(r));
        }
        this.inFlight++;
        try {
            return await fn();
        } finally {
            this.inFlight--;
            const next = this.queue.shift();
            if (next) next();
        }
    }

    async _request(req) {
        if (!this.peer) throw new Error('not connected to a node');
        const conns = this.node.getConnections(this.peer);
        if (!conns.length) throw new Error('not connected to a node');
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
}
