// mining.js: mining in the browser, for the page. It runs miner.js threads
// on a merge-mining pool's job, sends the pool every share they find, and
// keeps the numbers the Mine screen shows.
//
// Midwimble is merge-mined: a pool mining midstate commits each job to a
// midwimble block too, and a share that beats midwimble's target is that
// block. The pool pays every midwimble block it finds to its miners, by the
// shares each one sent since the last. So the wallet mines midstate shares
// for its own midwimble address. Each share is midstate work as well: a
// midstate address given here is paid that part, and without one the pool
// keeps it (midstate's pools.md, "Merge-Mine Midwimble").
//
// The pool speaks plain HTTPS (`/api/template`, `/api/submit`), as it does to
// midstate's web wallet.

/** The public pool new miners start on. */
export const DEFAULT_POOL = 'https://rpc.cypherpunk.gold/pool';

/** How often to ask the pool for a fresh job. A stale share also asks. */
const POLL_MS = 10_000;

const CORES = Math.max(1, navigator.hardwareConcurrency || 2);
/** Phones and tablets heat up and slow down under every core, and a casual
 *  miner whose phone gets hot stops for good: they start on two threads.
 *  Elsewhere two cores stay free for the page, the wallet and the system. */
export const IS_MOBILE = !!((navigator.userAgentData && navigator.userAgentData.mobile)
    || /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent || ''));
export const MAX_THREADS = CORES;
export const DEFAULT_THREADS = IS_MOBILE ? Math.max(1, Math.min(2, CORES - 1)) : Math.max(1, CORES - 2);

/** How hard each thread works: its rest after each stretch of work, as a
 *  fraction of that stretch. */
export const EFFORTS = [[1, 'Light', 1], [2, 'Medium', 0.5], [3, 'Full', 0]];
export const DEFAULT_EFFORT = IS_MOBILE ? 1 : 2;
export const restOf = effort => (EFFORTS.find(([v]) => v === effort) || EFFORTS[1])[2];

/** A pool's base URL as typed: trimmed, without trailing slashes or `/api`. */
export function poolBase(url) {
    return String(url || '').trim().replace(/\/+$/, '').replace(/\/api$/, '');
}

/** Attempts a target takes on average: 2^256 / target. */
export function expectedAttempts(targetHex) {
    const hex = String(targetHex || '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(hex)) return 0;
    const lead = hex.replace(/^0+/, '');
    if (!lead) return 0;
    const zeros = hex.length - lead.length;
    // 13 hex digits (52 bits) is all a double holds exactly.
    const top = parseInt(lead.slice(0, 13).padEnd(13, '0'), 16) / 16 ** 13;
    const fraction = top * 16 ** -zeros;
    return fraction > 0 ? 1 / fraction : 0;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
const errOf = e => (e && e.message) || String(e);

/** An error from the pool that retrying won't fix: a bad address, or a pool
 *  that doesn't merge-mine. */
class Refused extends Error {}

export class Miner {
    constructor({ onChange } = {}) {
        this.onChange = onChange || (() => {});
        this.workers = [];
        this.module = null;
        this.job = null;            // { id, pow, midstate, target }
        this.lastPoll = 0;
        this.polling = false;
        this.timer = null;
        this.backoff = POLL_MS;
        this.battery = null;
        this.pauseOnBattery = true;
        this.state = {
            on: false,           // asked to mine
            phase: 'off',        // off | starting | mining | waiting | paused | error
            note: '',            // why it is waiting, paused or stopped
            rate: 0,             // attempts a second, every thread together
            threads: DEFAULT_THREADS,
            rest: restOf(DEFAULT_EFFORT),
            pool: DEFAULT_POOL,
            address: '',
            midstate: '',
            accepted: 0,
            rejected: 0,
            stale: 0,
            blocks: 0,
            lastShare: 0,
            since: 0,
            template: null,      // the pool's last template
            score: null,         // this address's midwimble score at the pool
            midstateScore: null,
        };
        this.watchBattery();
    }

    changed() {
        try { this.onChange(this.state); } catch (_) {}
    }

    /** Starts mining for `address` (mw1…), at `pool`. `midstate` is a
     *  midstate address to be paid the midstate part of each share, or ''. */
    async start({ address, midstate = '', pool = DEFAULT_POOL, threads, rest, pauseOnBattery = true }) {
        const s = this.state;
        const again = s.on && s.address === address && s.midstate === midstate && s.pool === poolBase(pool);
        Object.assign(s, {
            on: true,
            address,
            midstate: String(midstate || '').trim(),
            pool: poolBase(pool) || DEFAULT_POOL,
            threads: Math.max(1, Math.min(MAX_THREADS, threads || DEFAULT_THREADS)),
            rest: typeof rest === 'number' ? rest : s.rest,
            note: '',
        });
        this.pauseOnBattery = pauseOnBattery;
        if (!again) {
            // Another pool or other addresses: the old job's shares would be
            // sent to the wrong place, so its threads go now.
            Object.assign(s, { accepted: 0, rejected: 0, stale: 0, blocks: 0, lastShare: 0, since: Date.now(), template: null, score: null, midstateScore: null, rate: 0 });
            for (const w of this.workers) w.terminate();
            this.workers = [];
            this.job = null;
            this.backoff = POLL_MS;
            s.phase = 'starting';
        }
        this.changed();
        if (this.batteryLow()) { this.pause('Paused: the battery is low. Mining resumes when you plug in.'); return; }
        if (!again) await this.poll(true);
        this.schedule();
        this.fit();
    }

    /** Stops every thread. */
    stop() {
        const s = this.state;
        s.on = false;
        s.phase = 'off';
        s.note = '';
        s.rate = 0;
        clearTimeout(this.timer);
        this.timer = null;
        this.job = null;
        for (const w of this.workers) w.terminate();
        this.workers = [];
        this.changed();
    }

    setThreads(n) {
        this.state.threads = Math.max(1, Math.min(MAX_THREADS, n));
        if (this.state.on) this.fit();
        this.changed();
    }

    setRest(rest) {
        this.state.rest = rest;
        for (const w of this.workers) w.worker.postMessage({ type: 'rest', rest });
        this.changed();
    }

    setPauseOnBattery(on) {
        this.pauseOnBattery = on;
        this.checkBattery();
    }

    // ── threads ─────────────────────────────────────────────────────────

    async wasm() {
        if (!this.module) {
            const url = new URL('./pkg/midwimble_web_wallet_bg.wasm', import.meta.url);
            this.module = WebAssembly.compileStreaming(fetch(url)).catch(async () =>
                WebAssembly.compile(await (await fetch(url)).arrayBuffer()));
            this.module.catch(() => { this.module = null; });
        }
        return this.module;
    }

    /** As many threads as asked, each on the current job; none without one. */
    async fit() {
        const s = this.state;
        const want = s.on && this.job && s.phase !== 'paused' ? s.threads : 0;
        while (this.workers.length > want) this.workers.pop().terminate();
        if (this.workers.length < want) {
            let module;
            try { module = await this.wasm(); } catch (e) { return this.fail(`The miner could not start: ${errOf(e)}`); }
            while (this.workers.length < (s.on && this.job && s.phase !== 'paused' ? s.threads : 0)) this.spawn(module);
        }
        for (const w of this.workers) this.give(w);
        this.sumRate();
    }

    spawn(module) {
        const worker = new Worker(new URL('./miner.js', import.meta.url), { type: 'module' });
        const w = { worker, rate: 0, jobId: null, terminate: () => worker.terminate() };
        worker.onmessage = (e) => this.fromThread(w, e.data || {});
        worker.onerror = (e) => { e.preventDefault(); this.fail(`A mining thread failed: ${e.message || 'unknown error'}`); };
        worker.postMessage({ type: 'init', module });
        this.workers.push(w);
    }

    give(w) {
        if (!this.job || w.jobId === this.job.id) return;
        w.jobId = this.job.id;
        w.worker.postMessage({ type: 'job', job: this.job, rest: this.state.rest });
    }

    fromThread(w, m) {
        if (m.type === 'rate') {
            w.rate = m.rate;
            this.sumRate();
            // Threads report every second, and their timers keep time in a
            // background tab where the page's are slowed to once a minute:
            // so their reports drive the pool polling.
            if (Date.now() - this.lastPoll >= this.backoff) this.poll();
            this.changed();
        } else if (m.type === 'found') {
            this.submit(m.jobId, m.nonce);
        } else if (m.type === 'error') {
            this.fail(`Mining stopped: ${m.error}`);
        }
    }

    sumRate() {
        this.state.rate = this.workers.reduce((sum, w) => sum + (w.rate || 0), 0);
    }

    // ── the pool ────────────────────────────────────────────────────────

    query() {
        const s = this.state;
        const q = new URLSearchParams({ address: s.midstate || '', midwimble_address: s.address });
        return `${s.pool}/api/template?${q}`;
    }

    async fetchJson(url, init) {
        const res = await fetch(url, { cache: 'no-store', ...init, signal: AbortSignal.timeout(20_000) });
        let body = null;
        try { body = await res.json(); } catch (_) {}
        if (res.status === 400) throw new Refused((body && body.error) || 'The pool refused the request.');
        return { res, body };
    }

    /** Asks the pool for its job; hands a new one to the threads. */
    async poll(first = false) {
        const s = this.state;
        if (!s.on || this.polling) return;
        this.polling = true;
        this.lastPoll = Date.now();
        try {
            const { res, body } = await this.fetchJson(this.query());
            if (!res.ok || !body) throw new Error((body && body.error) || `the pool answered HTTP ${res.status}`);
            if (body.job_id === undefined || !body.mining_midstate || !body.target) throw new Error('the pool sent an incomplete job');
            if (!s.on) return;
            s.template = body;
            this.backoff = POLL_MS;
            if (body.midwimble === null) {
                // A pool that doesn't merge-mine pays nothing in midwimble.
                throw new Refused('This pool doesn’t merge-mine midwimble, so its shares would earn no midwimble. Choose a pool that does.');
            }
            if (body.midwimble && body.midwimble.score != null) s.score = body.midwimble.score;
            if (body.shares_recorded != null) s.midstateScore = body.shares_recorded;
            const job = { id: body.job_id, pow: body.pow || 'blake3-chain', midstate: body.mining_midstate, target: body.target };
            const fresh = !this.job || this.job.id !== job.id || this.job.midstate !== job.midstate;
            if (fresh) this.job = job;
            if (s.phase === 'starting' || s.phase === 'waiting' || s.phase === 'error') {
                s.phase = 'mining';
                s.note = '';
            }
            if (fresh || first) await this.fit();
        } catch (e) {
            if (e instanceof Refused) {
                // A pool from before midstate v6.0.1 wants a midstate address
                // from every miner, and says so as an invalid one.
                const old = !s.midstate && /^Invalid address/i.test(errOf(e));
                this.fail(old
                    ? 'This pool doesn’t take miners paid only in midwimble yet (it needs midstate v6.0.1). Give it a midstate address under Midstate payouts, or try again later.'
                    : errOf(e));
            } else if (s.on) {
                // The pool or the network is down: keep on the last job, which
                // may well still be good, and try again less often.
                this.backoff = Math.min(60_000, this.backoff * 2);
                if (!this.job) { s.phase = 'waiting'; s.note = `Can’t reach the pool (${errOf(e)}). Trying again.`; }
            }
        } finally {
            this.polling = false;
            this.changed();
        }
    }

    /** Keeps polling while the threads are idle (no job, or paused). */
    schedule() {
        clearTimeout(this.timer);
        if (!this.state.on) return;
        this.timer = setTimeout(async () => {
            if (Date.now() - this.lastPoll >= this.backoff && this.state.phase !== 'paused') await this.poll();
            this.schedule();
        }, 2_000);
    }

    /** Sends a share; retries what the pool asks to have retried. */
    async submit(jobId, nonce) {
        const s = this.state;
        const body = JSON.stringify({
            job_id: jobId,
            nonce: String(nonce),
            address: s.midstate || '',
            midwimble_address: s.address,
            worker: 'midwimble-web',
        });
        for (let tries = 0; tries < 4 && s.on; tries++) {
            let answer;
            try {
                const { res, body: b } = await this.fetchJson(`${s.pool}/api/submit`, {
                    method: 'POST', headers: { 'content-type': 'application/json' }, body,
                });
                answer = b || {};
                if (res.status === 429 || answer.reason === 'throttled') { await sleep(150 + 200 * tries); continue; }
                if (res.status === 503 || answer.reason === 'busy') { await sleep(1000 * (tries + 1)); continue; }
            } catch (e) {
                if (e instanceof Refused) { s.rejected++; s.note = errOf(e); this.changed(); return; }
                await sleep(1000 * (tries + 1));
                continue;
            }
            if (answer.midwimble_score != null) s.score = answer.midwimble_score;
            if (answer.score != null) s.midstateScore = answer.score;
            if (answer.accepted) {
                s.accepted++;
                s.lastShare = Date.now();
                if (answer.is_block) s.blocks++;
            } else if (answer.reason === 'stale' || answer.reason === 'duplicate') {
                // Routine: a new block made the job old. Fetch the new one now.
                s.stale++;
                if (answer.reason === 'stale') { this.lastPoll = 0; this.poll(); }
            } else {
                s.rejected++;
            }
            this.changed();
            return;
        }
        s.rejected++;
        this.changed();
    }

    /** Stops the threads with a reason, staying asked to mine so the next
     *  poll can bring them back (unless the pool refused outright). */
    fail(note) {
        const s = this.state;
        s.phase = 'error';
        s.note = note;
        s.rate = 0;
        for (const w of this.workers) w.terminate();
        this.workers = [];
        this.job = null;
        this.backoff = 60_000;
        this.changed();
    }

    // ── the battery ─────────────────────────────────────────────────────
    //
    // Mining a battery flat is the quickest way to lose a miner: below 20%
    // and off the charger it pauses, and it carries on once the device is
    // charging or back above 30%. Only Chromium has the Battery Status API;
    // elsewhere this does nothing.

    async watchBattery() {
        if (!navigator.getBattery) return;
        try {
            const b = await navigator.getBattery();
            this.battery = b;
            b.addEventListener('levelchange', () => this.checkBattery());
            b.addEventListener('chargingchange', () => this.checkBattery());
            this.checkBattery();
            this.changed();
        } catch (_) {}
    }

    hasBattery() {
        return !!this.battery;
    }

    batteryLow() {
        const b = this.battery;
        return !!(this.pauseOnBattery && b && !b.charging && b.level < 0.20);
    }

    pause(note) {
        const s = this.state;
        s.phase = 'paused';
        s.note = note;
        s.rate = 0;
        for (const w of this.workers) w.terminate();
        this.workers = [];
        this.schedule();
        this.changed();
    }

    checkBattery() {
        const s = this.state;
        const b = this.battery;
        if (!s.on || !b) return;
        if (s.phase !== 'paused' && this.batteryLow()) {
            this.pause('Paused: the battery is below 20%. Mining resumes when you plug in.');
        } else if (s.phase === 'paused' && (!this.pauseOnBattery || b.charging || b.level >= 0.30)) {
            s.phase = this.job ? 'mining' : 'starting';
            s.note = '';
            this.lastPoll = 0;
            this.poll(true).then(() => this.fit());
        }
    }
}
