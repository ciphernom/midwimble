// app.js: the page. Draws the wallet in the explorer's style, owns the
// WebRTC connection to a node (light_client.bundle.js), and relays the
// wallet worker's requests to it. Everything from the chain or the user is
// rendered as text, never as HTML.

import { qrSvg } from './qr.js';

const COIN = 100_000_000;
const NODES_KEY = 'midwimble.nodes';
const $view = document.getElementById('view');
const $nav = document.getElementById('nav');
const $net = document.getElementById('net');
const $toasts = document.getElementById('toasts');

const app = {
    phase: 'loading', // loading | welcome | unlock | wallet | elsewhere | broken
    hasWallet: false,
    constants: null,
    config: { network: null, genesis: null, nodes: [] },
    network: '',
    state: null,
    net: { status: 'idle', addr: null, detail: '' },
    keygen: { done: 0, total: 0 },
    flow: null,
    fatal: null,
};

// ── small helpers (as in the explorer) ──────────────────────────────────────

function h(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
        if (v == null || v === false) continue;
        if (k === 'class') n.className = v;
        else if (k === 'value') n.value = v;
        else if (k === 'hidden' || k === 'checked' || k === 'disabled') n[k] = !!v;
        else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
        else n.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat(Infinity)) {
        if (kid == null || kid === false) continue;
        n.appendChild(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return n;
}
const short = (x, n = 10) => (x ? (x.length > 2 * n ? x.slice(0, n) + '…' + x.slice(-6) : x) : '—');
const num = x => Number(x).toLocaleString();
function coins(units) {
    const whole = Math.floor(units / COIN), frac = String(units % COIN).padStart(8, '0');
    return whole.toLocaleString() + '.' + frac;
}
const plain = units => Math.floor(units / COIN) + '.' + String(units % COIN).padStart(8, '0');
/** An amount with its fraction dimmed past the last significant digit. */
function amount(units, cls) {
    const s = coins(units);
    const [w, f] = s.split('.');
    const sig = f.replace(/0+$/, '');
    return h('span', { class: cls || null }, w, '.', sig, h('span', { class: 'dim' }, f.slice(sig.length)));
}
function dur(s) {
    if (s == null) return '—';
    const a = Math.abs(s), sign = s < 0 ? '-' : '';
    if (a < 120) return sign + a + 's';
    if (a < 7200) return sign + Math.round(a / 60) + 'm';
    if (a < 172800) return sign + (a / 3600).toFixed(1) + 'h';
    return sign + (a / 86400).toFixed(1) + 'd';
}
const ago = ts => dur(Math.max(0, Math.floor(Date.now() / 1000) - ts)) + ' ago';
const tag = (cls, text) => h('span', { class: 'tag ' + cls }, text);
const section = (title, aside, ...body) =>
    h('section', null, h('h2', null, title, aside ? h('span', { class: 'aside' }, aside) : null), ...body);
const cell = (k, v, small) => h('div', { class: 'cell' }, h('div', { class: 'k' }, k), h('div', { class: 'v' + (small ? ' small' : '') }, v));
function meter(fraction) {
    const span = h('span');
    span.style.width = Math.min(100, Math.max(0, fraction * 100)) + '%';
    return h('div', { class: 'meter' }, span);
}
const dl = rows => h('dl', null, rows.filter(Boolean).map(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
const table = (heads, rows, numeric = []) => h('div', { class: 'scroll' }, h('table', null,
    h('thead', null, h('tr', null, heads.map((x, i) => h('th', { class: numeric.includes(i) ? 'num' : null }, x)))),
    h('tbody', null, rows.map(r => h('tr', null, r.map((c, i) => h('td', { class: numeric.includes(i) ? 'num' : null }, c)))))));
const errOf = e => (e && e.message) || String(e);

function toast(text, kind = 'info') {
    const t = h('div', { class: 'toast ' + kind }, text);
    $toasts.appendChild(t);
    setTimeout(() => t.remove(), kind === 'bad' ? 9000 : 5000);
}

async function copy(text, what) {
    try {
        await navigator.clipboard.writeText(text);
        toast(`Copied ${what}.`);
    } catch (_) {
        toast('Copying is blocked here; select the text and copy it.', 'bad');
    }
}
const copyButton = (text, what) => h('button', { class: 'btn small', type: 'button', onclick: () => copy(text, what) }, 'copy');

function download(bytes, name) {
    const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
    const a = h('a', { href: url, download: name });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** Shows `content` (a section) over the page; resolves when closed. */
function overlay(build) {
    return new Promise(resolve => {
        const box = h('div', { class: 'overlay' });
        const close = (v) => { box.remove(); document.removeEventListener('keydown', onKey); resolve(v); };
        const onKey = (e) => { if (e.key === 'Escape') close(null); };
        box.addEventListener('mousedown', (e) => { if (e.target === box) close(null); });
        document.addEventListener('keydown', onKey);
        box.appendChild(build(close));
        document.body.appendChild(box);
        const first = box.querySelector('input, textarea, button.primary');
        if (first) first.focus();
    });
}

function askPassword(title, why) {
    return overlay(close => {
        const pw = h('input', { type: 'password', autocomplete: 'current-password' });
        const err = h('div', { class: 'err' });
        return section(title, null, h('form', {
            class: 'pad stack', onsubmit: (e) => { e.preventDefault(); if (pw.value) close(pw.value); else err.textContent = 'Enter the password.'; },
        }, why ? h('p', { class: 'dim', style: null }, why) : null,
        h('label', null, h('span', null, 'password'), pw), err,
        h('div', { class: 'row' }, h('button', { class: 'btn primary', type: 'submit' }, 'Continue'),
            h('button', { class: 'btn', type: 'button', onclick: () => close(null) }, 'Cancel'))));
    });
}

// ── the wallet worker ───────────────────────────────────────────────────────

const worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
let seq = 0;
const waiting = new Map();
function ask(type, payload = {}, transfer = []) {
    return new Promise((resolve, reject) => {
        const reqId = ++seq;
        waiting.set(reqId, { resolve, reject });
        worker.postMessage({ type, reqId, ...payload }, transfer);
    });
}

worker.onerror = (e) => fatal(`The wallet could not start: ${e.message || 'worker error'}. This browser may lack WebAssembly SIMD or module workers.`);

worker.onmessage = (e) => {
    const m = e.data || {};
    switch (m.type) {
        case 'reply': {
            const w = waiting.get(m.reqId);
            if (!w) return;
            waiting.delete(m.reqId);
            m.ok ? w.resolve(m.result) : w.reject(new Error(m.error));
            return;
        }
        case 'boot':
            app.hasWallet = m.hasWallet;
            app.constants = m.constants;
            app.network = m.network;
            app.phase = m.hasWallet ? 'unlock' : 'welcome';
            app.flow = null;
            app.state = null;
            render();
            return;
        case 'unlocked':
            app.phase = 'wallet';
            app.hasWallet = true;
            app.flow = null;
            if (!/^#\/(send|receive|history|settings)?$/.test(location.hash)) location.hash = '#/';
            render();
            return;
        case 'locked':
            app.phase = app.hasWallet ? 'unlock' : 'welcome';
            app.state = null;
            render();
            return;
        case 'state':
            app.state = m.state;
            update();
            return;
        case 'keygen':
            app.keygen = { done: m.done, total: m.total };
            document.querySelectorAll('[data-keygen]').forEach(drawKeygen);
            return;
        case 'toast':
            toast(m.text, m.kind);
            return;
        case 'rpc':
            relay(m);
            return;
    }
};

// ── the node ────────────────────────────────────────────────────────────────

let lc = null;
let lcModule = null;
let chainTip = null; // known before unlocking too, for the header

function nodeList() {
    try {
        const v = JSON.parse(localStorage.getItem(NODES_KEY) || 'null');
        if (Array.isArray(v) && v.length) return v;
    } catch (_) {}
    return app.config.nodes || [];
}
const customNodes = () => { try { return !!localStorage.getItem(NODES_KEY); } catch (_) { return false; } };

async function connect() {
    const addrs = nodeList();
    if (lc) { const old = lc; lc = null; old.stop(); }
    if (!addrs.length) { setNet('none', ''); return; }
    try {
        if (!lcModule) lcModule = import('./light_client.bundle.js');
        const { LightClient } = await lcModule;
        const c = new LightClient();
        lc = c;
        c.onStatus = (status, info) => { if (lc === c) setNet(status, info); };
        c.onPush = (msg) => {
            if (lc !== c) return;
            if (msg && msg.payload && typeof msg.payload.height === 'number') chainTip = msg.payload.height + 1;
            worker.postMessage({ type: 'push', msg });
            drawNet();
        };
        await c.start(addrs);
    } catch (e) {
        setNet('failed', errOf(e));
    }
}

function setNet(status, info) {
    app.net = { status, addr: status === 'connected' ? info : null, detail: status === 'failed' ? info : '' };
    worker.postMessage({ type: 'net', status, addr: app.net.addr });
    if (status === 'connected' && lc) {
        lc.call('get_state').then(s => { chainTip = s.height; update(); }).catch(() => {});
    }
    update();
}

function relay(m) {
    const c = lc;
    const reply = (r) => worker.postMessage({ type: 'rpc-result', id: m.id, ...r });
    if (!c || !c.connected) return reply({ ok: false, error: 'not connected to a node' });
    c.call(m.method, m.params).then(
        data => reply({ ok: true, data }),
        e => reply({ ok: false, error: errOf(e), unanswered: !!e.unanswered }));
}

// Keep the header's height fresh while locked (the worker reports it after).
setInterval(() => {
    if (lc && lc.connected && app.phase !== 'wallet') lc.call('get_state').then(s => { chainTip = s.height; update(); }).catch(() => {});
}, 60_000);

// ── header ──────────────────────────────────────────────────────────────────

function drawNet() {
    const s = app.net.status;
    const tip = app.state ? app.state.tip : chainTip;
    let dot = '', text;
    if (s === 'connected') {
        const st = app.state && app.state.chain;
        if (st && st.networkOk === false) { dot = 'bad'; text = 'wrong network'; }
        else { dot = 'ok'; text = tip ? `block ${num(tip - 1)}` : 'connected'; }
    } else if (s === 'connecting') { dot = 'busy'; text = 'connecting…'; }
    else if (s === 'disconnected') { dot = 'busy'; text = 'reconnecting…'; }
    else if (s === 'failed') { dot = 'bad'; text = 'no node reachable'; }
    else if (s === 'none') { dot = 'bad'; text = 'no node set'; }
    else text = 'starting…';
    $net.replaceChildren(h('span', { class: 'dot ' + dot }), h('span', null, text));
    $net.title = app.net.addr || app.net.detail || '';
}

function drawNav() {
    const on = app.phase === 'wallet';
    $nav.hidden = !on;
    const r = routeName();
    $nav.querySelectorAll('a').forEach(a => a.classList.toggle('on', a.dataset.route === r));
}

// ── routing ─────────────────────────────────────────────────────────────────

let current = null;
const routeName = () => (location.hash.match(/^#\/(send|receive|history|settings)$/) || [])[1] || '';
const ROUTES = { '': walletView, send: sendView, receive: receiveView, history: historyView, settings: settingsView };

function render() {
    drawNav();
    drawNet();
    let view;
    if (app.phase === 'broken') view = brokenView();
    else if (app.phase === 'elsewhere') view = elsewhereView();
    else if (app.phase === 'loading') view = { els: [h('div', { class: 'empty' }, 'loading…')] };
    else if (app.phase === 'welcome') view = onboardingView();
    else if (app.phase === 'unlock') view = unlockView();
    else view = ROUTES[routeName()]();
    current = view;
    $view.replaceChildren(...view.els);
    window.scrollTo(0, 0);
    update();
}

function update() {
    drawNet();
    if (current && current.update) current.update();
}

window.addEventListener('hashchange', () => { if (app.phase === 'wallet') render(); });

// ── shared pieces ───────────────────────────────────────────────────────────

function drawKeygen(el) {
    const { done, total } = app.keygen;
    if (!total) { el.replaceChildren(); return; }
    const pct = Math.floor((done / total) * 100);
    el.replaceChildren(
        h('div', { class: 'k' }, done < total ? `building the recovery key · ${pct}%` : 'recovery key ready'),
        meter(done / total),
        h('div', { class: 'dim' }, done < total
            ? `${num(done)} of ${num(total)} one-time keys. Your address carries a hash-based recovery key that could still claim your coins if elliptic curves are ever broken; it is built once, here.`
            : 'Your address includes it.'));
}
const keygenBox = () => { const el = h('div', { class: 'stack', 'data-keygen': '' }); drawKeygen(el); return el; };

function syncSummary(s) {
    const c = s.chain;
    if (app.net.status !== 'connected') return 'offline · showing the last scan';
    if (c.networkOk === false) return 'node on another network';
    if (!s.tip) return 'asking the node…';
    if (s.scan.active && s.scan.mode === 'utxos') return `reading unspent outputs · ${num(s.scan.outputs)}`;
    if (c.behind) return `node is behind this wallet`;
    if (c.nodeSyncing) return 'node is catching up';
    if (s.scanned < s.tip) return `scanning ${num(s.scanned)} / ${num(s.tip)}`;
    return `synced · block ${num(s.tip - 1)}` + (c.timestamp ? ` · ${ago(c.timestamp)}` : '');
}

function historyRows(entries, withActions) {
    return entries.map(e => {
        const kindTag = e.kind === 'mined' ? tag('lilac', 'mined') : e.kind === 'received' ? tag('ok', 'received') : tag('plain', 'sent');
        const value = e.kind === 'sent' ? h('span', null, '−', amount(e.value)) : h('span', { class: 'plus' }, '+', amount(e.value));
        let status;
        if (e.status === 'confirmed') status = tag('ok', 'confirmed');
        else if (e.status === 'immature') status = tag('warn', 'immature');
        else if (e.status === 'pending') status = tag('warn', 'pending');
        else if (e.status === 'failed') status = tag('bad', 'failed');
        else status = tag('plain', e.status);
        let detail;
        if (e.kind === 'sent' && e.to) detail = h('span', { title: e.to }, 'to ', short(e.to, 12));
        else if (e.kind === 'sent') detail = h('span', { class: 'dim' }, 'made elsewhere or before a restore (fee included)');
        else if (e.commitment) detail = h('span', { class: 'dim', title: e.commitment }, 'coin ', short(e.commitment, 8));
        else detail = h('span', { class: 'dim' }, 'net of change');
        const block = e.height != null ? num(e.height) : h('span', { class: 'dim' }, e.created_at ? ago(e.created_at) : '—');
        const row = [block, kindTag, value, e.fee != null ? coins(e.fee) : h('span', { class: 'dim' }, '—'), status, detail];
        if (withActions) {
            row.push(e.status === 'pending' && e.tx_hash
                ? h('button', { class: 'btn small', type: 'button', onclick: () => release(e.tx_hash) }, 'release')
                : '');
        }
        return row;
    });
}

async function release(txHash) {
    const ok = await overlay(close => section('Release this payment?', null, h('div', { class: 'pad stack' },
        h('p', { class: 'lede' }, 'Its coins become spendable again. Do this only if the payment will never confirm, for instance because the node dropped it. If it confirms anyway, the wallet still records it.'),
        h('div', { class: 'row' },
            h('button', { class: 'btn primary', type: 'button', onclick: () => close(true) }, 'Release coins'),
            h('button', { class: 'btn', type: 'button', onclick: () => close(false) }, 'Keep waiting')))));
    if (ok) ask('cancel', { tx_hash: txHash }).catch(e => toast(errOf(e), 'bad'));
}

function nodeSection(onboarding) {
    const box = h('section');
    const ta = h('textarea', { rows: 3, spellcheck: 'false', placeholder: '/ip4/…/udp/9435/webrtc-direct/certhash/…/p2p/…' });
    ta.value = nodeList().join('\n');
    const save = async () => {
        const list = ta.value.split(/\s+/).map(s => s.trim()).filter(Boolean);
        const bad = list.find(a => !/^\/(ip4|ip6|dns4|dns6|dns)\/.+\/webrtc-direct\/certhash\/.+\/p2p\/.+/.test(a));
        if (bad) { toast(`Not a WebRTC address: ${short(bad, 24)}`, 'bad'); return; }
        try { list.length ? localStorage.setItem(NODES_KEY, JSON.stringify(list)) : localStorage.removeItem(NODES_KEY); } catch (_) {}
        toast(list.length ? 'Connecting…' : 'Using the default nodes.');
        await connect();
    };
    const reset = async () => {
        try { localStorage.removeItem(NODES_KEY); } catch (_) {}
        ta.value = (app.config.nodes || []).join('\n');
        await connect();
    };
    const status = h('div');
    const draw = () => {
        const n = app.net;
        const st = app.state && app.state.chain;
        status.replaceChildren(dl([
            ['status', n.status === 'connected' ? tag('ok', 'connected') : n.status === 'failed' ? tag('bad', 'unreachable') : n.status === 'none' ? tag('bad', 'none set') : tag('warn', n.status)],
            n.addr && ['node', h('span', { class: 'hash' }, n.addr)],
            n.detail && ['last error', h('span', { class: 'dim' }, n.detail)],
            ['chain', (app.state ? app.state.tip : chainTip) ? `${num((app.state ? app.state.tip : chainTip) - 1)} blocks` : '—'],
            st && ['network', st.networkOk === true ? (app.config.genesis ? tag('ok', 'genesis checked') : tag('plain', 'not checked')) : st.networkOk === false ? tag('bad', 'different network') : '—'],
        ]));
    };
    box.append(
        h('h2', null, 'Node', h('span', { class: 'aside' }, customNodes() ? 'your list' : 'default list')),
        status,
        h('div', { class: 'pad stack' },
            h('label', null, h('span', null, 'WebRTC addresses, one per line'), ta),
            h('div', { class: 'row' },
                h('button', { class: 'btn primary', type: 'button', onclick: save }, 'Save and connect'),
                h('button', { class: 'btn', type: 'button', onclick: reset }, 'Use defaults'))),
        h('div', { class: 'note' }, 'A node serves browsers when built with ', h('code', null, '--features webrtc'),
            '; it logs “Browser wallets can connect to …” at start and lists the address under ', h('code', null, 'webrtc_addrs'),
            ' in its /state. The node never sees your keys; it learns which coins are yours only from payments you send through it.'));
    draw();
    return { el: box, update: draw, onboarding };
}

// ── onboarding ──────────────────────────────────────────────────────────────

function onboardingView() {
    if (app.flow && app.flow.kind === 'create') return createView();
    if (app.flow && app.flow.kind === 'restore') return restoreView();
    if (app.flow && app.flow.kind === 'open') return openView();
    const node = nodeSection(true);
    const start = (kind) => () => { app.flow = { kind, step: 'phrase' }; render(); };
    return {
        els: [
            h('section', null,
                h('div', { class: 'hero' },
                    h('div', null,
                        h('div', { class: 'eyebrow' }, (app.network || 'midwimble').replace(/_/g, ' ').toLowerCase()),
                        h('h1', null, 'A MimbleWimble wallet ', h('span', null, 'in your browser.')),
                        h('p', { class: 'lede' }, 'Amounts hidden by Pedersen commitments, payments to one-time keys, and a post-quantum recovery key in every address. The wallet runs here: your phrase and keys never leave this browser.')),
                    h('img', { src: 'logo.svg', alt: '' })),
                h('div', { class: 'choices' },
                    h('div', { class: 'choice' }, h('div', { class: 'k' }, 'new'), h('h3', null, 'Create a wallet'),
                        h('p', null, 'A fresh 24-word recovery phrase, the same kind ', h('code', null, 'midwimble wallet create'), ' makes.'),
                        h('button', { class: 'btn primary', type: 'button', onclick: start('create') }, 'Create')),
                    h('div', { class: 'choice' }, h('div', { class: 'k' }, 'existing'), h('h3', null, 'Restore from a phrase'),
                        h('p', null, 'Rebuilds the wallet from its 24 words and scans the chain for its coins.'),
                        h('button', { class: 'btn', type: 'button', onclick: start('restore') }, 'Restore')),
                    h('div', { class: 'choice' }, h('div', { class: 'k' }, 'file'), h('h3', null, 'Open a wallet file'),
                        h('p', null, 'A .mww file from the CLI or from this wallet, with its password. No rescan needed.'),
                        h('button', { class: 'btn', type: 'button', onclick: start('open') }, 'Open file')))),
            node.el,
        ],
        update: node.update,
    };
}

function backButton(label = '← back') {
    return h('button', { class: 'btn', type: 'button', onclick: () => { ask('cancel-keygen').catch(() => {}); app.flow = null; app.keygen = { done: 0, total: 0 }; render(); } }, label);
}

function steps(names, on) {
    return h('div', { class: 'steps' }, names.map((n, i) => [i ? h('span', null, '›') : null, h('span', { class: i === on ? 'on' : null }, n)]));
}

function passwordFields() {
    const pw = h('input', { type: 'password', autocomplete: 'new-password' });
    const pw2 = h('input', { type: 'password', autocomplete: 'new-password' });
    return {
        els: [h('div', { class: 'two' },
            h('label', null, h('span', null, 'password'), pw),
            h('label', null, h('span', null, 'again'), pw2))],
        value() {
            if (pw.value.length < 8) throw new Error('Use a password of at least 8 characters.');
            if (pw.value !== pw2.value) throw new Error('The passwords differ.');
            return pw.value;
        },
    };
}

function createView() {
    const f = app.flow;
    if (!f.phrase) {
        ask('new-phrase').then(r => { if (app.flow === f) { f.phrase = r.phrase; render(); } }, e => toast(errOf(e), 'bad'));
        return { els: [section('Create a wallet', null, h('div', { class: 'empty' }, 'making a phrase…'))] };
    }
    const words = f.phrase.split(' ');
    const names = ['phrase', 'check', 'password'];
    if (f.step === 'phrase') {
        const grid = h('div', { class: 'words blur' }, words.map(w => h('div', null, w)));
        const reveal = h('button', { class: 'btn', type: 'button', onclick: () => { grid.classList.remove('blur'); reveal.remove(); } }, 'Show the words');
        const box = h('input', { type: 'checkbox' });
        const next = h('button', { class: 'btn primary', type: 'button', disabled: true, onclick: () => {
            const picks = new Set();
            while (picks.size < 3) picks.add(Math.floor(Math.random() * words.length));
            f.check = [...picks].sort((a, b) => a - b);
            f.step = 'check';
            render();
        } }, 'Next');
        box.addEventListener('change', () => { next.disabled = !box.checked; });
        return { els: [section('Your recovery phrase', steps(names, 0),
            h('div', { class: 'pad' }, h('p', { class: 'lede' }, 'Write these 24 words down, in order, and keep them offline. They are the wallet: anyone who has them can spend it, and nothing else can restore it.')),
            grid,
            h('div', { class: 'pad stack' }, h('div', { class: 'row' }, reveal, h('span', { class: 'dim' }, 'Paper, not a screenshot or the clipboard.')),
                h('label', { class: 'check' }, box, h('span', null, 'I have written the words down.')),
                h('div', { class: 'row' }, next, backButton('Cancel'))),
            h('div', { class: 'note' }, keygenBox()))] };
    }
    if (f.step === 'check') {
        const inputs = f.check.map(i => h('input', { autocomplete: 'off', spellcheck: 'false', 'aria-label': `word ${i + 1}` }));
        const err = h('div', { class: 'err' });
        const form = h('form', { class: 'pad stack', onsubmit: (e) => {
            e.preventDefault();
            const wrong = f.check.find((i, k) => inputs[k].value.trim().toLowerCase() !== words[i]);
            if (wrong !== undefined) { err.textContent = `That is not word ${wrong + 1}.`; return; }
            f.step = 'password';
            render();
        } },
        h('p', { class: 'lede' }, 'To be sure the words are written down right, type three of them.'),
        h('div', { class: 'two' }, f.check.map((i, k) => h('label', null, h('span', null, `word ${i + 1}`), inputs[k]))),
        err,
        h('div', { class: 'row' }, h('button', { class: 'btn primary', type: 'submit' }, 'Next'),
            h('button', { class: 'btn', type: 'button', onclick: () => { f.step = 'phrase'; render(); } }, '← show the words')));
        return { els: [section('Check the phrase', steps(names, 1), form, h('div', { class: 'note' }, keygenBox()))] };
    }
    const pw = passwordFields();
    const err = h('div', { class: 'err' });
    const go = h('button', { class: 'btn primary', type: 'submit' }, 'Create wallet');
    const form = h('form', { class: 'pad stack', onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = '';
        let password;
        try { password = pw.value(); } catch (x) { err.textContent = errOf(x); return; }
        go.disabled = true;
        go.replaceChildren(h('span', { class: 'spin' }), 'creating…');
        try { await ask('create', { phrase: f.phrase, password }); }
        catch (x) { err.textContent = errOf(x); go.disabled = false; go.replaceChildren('Create wallet'); }
    } },
    h('p', { class: 'lede' }, 'The password encrypts the wallet in this browser (Argon2id and XChaCha20-Poly1305, the CLI’s wallet file format). You need it to unlock the wallet here; restoring from the phrase does not.'),
    ...pw.els, err,
    h('div', { class: 'row' }, go, backButton('Cancel')));
    return { els: [section('Set a password', steps(names, 2), form, h('div', { class: 'note' }, keygenBox()))] };
}

function restoreView() {
    const f = app.flow;
    const phrase = h('textarea', { rows: 4, spellcheck: 'false', autocomplete: 'off', placeholder: 'twenty-four words, separated by spaces' });
    const birth = h('input', { inputmode: 'numeric', placeholder: '0', value: f.birth || '' });
    const pw = passwordFields();
    const err = h('div', { class: 'err' });
    const go = h('button', { class: 'btn primary', type: 'submit' }, 'Restore');
    const form = h('form', { class: 'pad stack', onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = '';
        let password;
        try { password = pw.value(); } catch (x) { err.textContent = errOf(x); return; }
        const from = birth.value.trim() ? Number(birth.value.trim()) : 0;
        if (!Number.isInteger(from) || from < 0) { err.textContent = 'The block to scan from is a whole number.'; return; }
        go.disabled = true;
        go.replaceChildren(h('span', { class: 'spin' }), 'restoring…');
        try { await ask('restore', { phrase: phrase.value, password, birth: from }); }
        catch (x) { err.textContent = errOf(x); go.disabled = false; go.replaceChildren('Restore'); }
    } },
    h('label', null, h('span', null, 'recovery phrase'), phrase),
    h('label', null, h('span', null, 'scan from block (optional)'), birth),
    h('div', { class: 'dim' }, 'The earliest block that could hold a payment to this wallet. Leave it empty to scan the whole chain.'),
    ...pw.els, err,
    h('div', { class: 'row' }, go, backButton('Cancel')));
    return { els: [section('Restore from a phrase', null, form, h('div', { class: 'note' }, keygenBox()))] };
}

function openView() {
    const file = h('input', { type: 'file', accept: '.mww,application/octet-stream' });
    const pw = h('input', { type: 'password', autocomplete: 'current-password' });
    const err = h('div', { class: 'err' });
    const go = h('button', { class: 'btn primary', type: 'submit' }, 'Open');
    const form = h('form', { class: 'pad stack', onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = '';
        const f = file.files && file.files[0];
        if (!f) { err.textContent = 'Choose a wallet file.'; return; }
        if (f.size > 64 * 1024 * 1024) { err.textContent = 'That file is too large to be a wallet.'; return; }
        go.disabled = true;
        go.replaceChildren(h('span', { class: 'spin' }), 'opening…');
        try {
            const bytes = await f.arrayBuffer();
            await ask('import', { bytes, password: pw.value }, [bytes]);
        } catch (x) { err.textContent = errOf(x); go.disabled = false; go.replaceChildren('Open'); }
    } },
    h('label', null, h('span', null, 'wallet file'), file),
    h('label', null, h('span', null, 'its password'), pw), err,
    h('div', { class: 'row' }, go, backButton('Cancel')));
    return { els: [section('Open a wallet file', null, form,
        h('div', { class: 'note' }, 'From ', h('code', null, 'midwimble wallet --wallet <file>'), ' or this wallet’s settings. The wallet keeps the file’s password and carries on scanning where the file left off.'))] };
}

function unlockView() {
    const pw = h('input', { type: 'password', autocomplete: 'current-password' });
    const err = h('div', { class: 'err' });
    const go = h('button', { class: 'btn primary', type: 'submit' }, 'Unlock');
    const form = h('form', { class: 'pad stack', onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = '';
        go.disabled = true;
        go.replaceChildren(h('span', { class: 'spin' }), 'unlocking…');
        try { await ask('unlock', { password: pw.value }); }
        catch (x) { err.textContent = errOf(x); go.disabled = false; go.replaceChildren('Unlock'); pw.select(); }
    } },
    h('label', null, h('span', null, 'password'), pw), err,
    h('div', { class: 'row' }, go, h('button', { class: 'btn danger', type: 'button', onclick: forget }, 'Forget this wallet')));
    const node = nodeSection(true);
    return { els: [section('Unlock your wallet', app.network ? app.network.replace(/_/g, ' ').toLowerCase() : null, form), node.el], update: node.update };
}

async function forget() {
    const ok = await overlay(close => {
        const word = h('input', { autocomplete: 'off', spellcheck: 'false' });
        const err = h('div', { class: 'err' });
        return section('Forget this wallet?', null, h('form', { class: 'pad stack', onsubmit: (e) => {
            e.preventDefault();
            if (word.value.trim().toLowerCase() !== 'forget') { err.textContent = 'Type forget to confirm.'; return; }
            close(true);
        } },
        h('p', { class: 'lede' }, 'This deletes the wallet from this browser. Its coins stay on the chain, but only its recovery phrase or a wallet file can bring them back.'),
        h('label', null, h('span', null, 'type “forget”'), word), err,
        h('div', { class: 'row' }, h('button', { class: 'btn danger', type: 'submit' }, 'Delete from this browser'),
            h('button', { class: 'btn', type: 'button', onclick: () => close(false) }, 'Keep it'))));
    });
    if (ok) ask('forget').catch(e => toast(errOf(e), 'bad'));
}

// ── wallet pages ────────────────────────────────────────────────────────────

function balanceSection() {
    const box = h('section');
    const draw = () => {
        const s = app.state;
        if (!s) return;
        const b = s.balance;
        const span = Math.max(1, s.tip - s.birth);
        const done = s.tip ? Math.min(1, Math.max(0, (s.scanned - s.birth) / span)) : 0;
        const mature = app.constants ? app.constants.coinbase_maturity : 100;
        const notes = [];
        if (s.syncError) notes.push(h('div', { class: 'note warn-text' }, s.syncError));
        else if (s.chain && s.chain.behind) notes.push(h('div', { class: 'note' }, `The node is at block ${num(s.tip - 1)}, behind what this wallet has scanned (${num(s.scanned - 1)}). Waiting for it to catch up.`));
        box.replaceChildren(
            h('h2', null, 'Balance', h('span', { class: 'aside' }, syncSummary(s))),
            h('div', { class: 'balance' },
                h('div', { class: 'cell' }, h('div', { class: 'k' }, 'spendable'), h('div', { class: 'big' }, amount(b.spendable)), meter(done)),
                cell('immature', amount(b.immature), false),
                cell('pending', amount(b.pending), false)),
            h('div', { class: 'note top' }, `Mined coins mature ${mature} blocks after their block; pending coins are in payments waiting for a block.`),
            ...notes);
    };
    return { el: box, update: draw };
}

function addressBlock(s, large) {
    return h('div', { class: 'pad address' },
        h('div', { class: 'stack' },
            h('div', { class: 'mono-block' }, s.address),
            h('div', { class: 'row' }, copyButton(s.address, 'the address'),
                h('span', { class: 'dim' }, 'v1 address · ', s.address.length, ' characters'))),
        h('div', { class: 'qr' + (large ? ' large' : '') }, qrSvg(s.address.toUpperCase(), 'M')));
}

function walletView() {
    const bal = balanceSection();
    const addr = h('section');
    const recent = h('section');
    let drawnAddress = null;
    return {
        els: [bal.el, addr, recent],
        update() {
            const s = app.state;
            if (!s) return;
            bal.update();
            if (drawnAddress !== s.address) {
                drawnAddress = s.address;
                addr.replaceChildren(h('h2', null, 'Your address', h('a', { class: 'aside', href: '#/receive' }, 'receive →')), addressBlock(s, false));
            }
            const items = s.history.slice(0, 8);
            recent.replaceChildren(
                h('h2', null, 'Recent activity', h('a', { class: 'aside', href: '#/history' }, 'history →')),
                items.length ? table(['block', 'kind', 'amount', 'fee', 'status', ''], historyRows(items), [2, 3])
                    : h('div', { class: 'empty' }, s.scanned < s.tip ? 'nothing yet; still scanning' : 'nothing yet: share your address to get paid'));
        },
    };
}

// ── scanning a payment's QR code ────────────────────────────────────────────

/** A QR-code glyph for the scan button (DOM calls, so CSP needs no exceptions). */
function scanIcon() {
    const NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS(NS, 'path');
    path.setAttribute('d', 'M4 9V4h5M15 4h5v5M20 15v5h-5M9 20H4v-5M8 12h8');
    svg.appendChild(path);
    return svg;
}

/** What a scanned code asks to pay: an address in either case (this
 *  wallet's codes hold it in capitals), or a `midwimble:` URI with an
 *  optional amount in coins. */
function paymentCode(text) {
    let address = String(text).trim();
    let amount = null;
    const uri = /^midwimble:([^?#]*)(?:\?([^#]*))?/i.exec(address);
    if (uri) {
        address = uri[1];
        const a = new URLSearchParams(uri[2] || '').get('amount');
        if (a && /^\d+(\.\d{1,8})?$/.test(a)) amount = a;
    }
    return { address: address.toLowerCase(), amount };
}

function cameraTrouble(e) {
    switch (e && e.name) {
        case 'NotAllowedError':
        case 'SecurityError':
            return 'Camera access is blocked. Allow it for this site in the browser’s settings, or choose a photo of the code.';
        case 'NotFoundError':
        case 'OverconstrainedError':
            return 'No camera found. Choose a photo of the code instead.';
        case 'NotReadableError':
        case 'AbortError':
            return 'The camera is in use by another app. Close that app, or choose a photo of the code.';
        default:
            return `The camera did not start (${errOf(e)}). Choose a photo of the code instead.`;
    }
}

/** Reads a payment's QR code with the camera, or from a photo or screenshot.
 *  Resolves with { address, amount } once a code holds a midwimble address,
 *  or null if closed. The camera is off again by the time it resolves. */
let scanning = false;
async function scanPayment() {
    if (scanning) return null; // a second tap while the first opens
    scanning = true;
    try {
        return await scanner();
    } finally {
        scanning = false;
    }
}

async function scanner() {
    let qr;
    try {
        qr = await import('./qr_scan.js');
    } catch (e) {
        toast(`The QR reader did not load: ${errOf(e)}`, 'bad');
        return null;
    }
    const canCamera = qr.cameraSupported();
    const video = h('video', { playsinline: true, autoplay: true, muted: true });
    video.muted = true;
    video.playsInline = true;
    const view = h('div', { class: 'scanner', hidden: !canCamera }, video);
    const status = h('div', { 'aria-live': 'polite' });
    const say = (text, cls = 'dim') => { status.className = cls; status.textContent = text; };
    const file = h('input', { type: 'file', accept: 'image/*', hidden: true });
    const flip = h('button', { class: 'btn', type: 'button', hidden: true }, 'Switch camera');
    const camera = new qr.Camera(video);
    let done = false;
    let finish = null;
    let rejected = null; // the last text that was not an address: said once
    let active = false; // the camera is on, or on its way
    let paused = false; // turned off because the tab was hidden
    let wanted = null; // which camera to turn back on
    let run = 0; // bumped to stop a watching loop, or a start in progress
    camera.onended = () => {
        if (done) return;
        run++;
        active = false;
        view.hidden = true;
        say('The camera stopped. Close this and scan again, or choose a photo of the code.', 'warn-text');
    };

    // A code's text: closes the scanner if it pays a midwimble address, or
    // says why not while the camera keeps looking.
    const consider = async (text) => {
        if (text == null || done || text === rejected) return;
        const code = paymentCode(text);
        try {
            await ask('check-address', { to: code.address });
        } catch (_) {
            if (done) return;
            rejected = text;
            say(`That QR code is not a midwimble address. It reads “${short(String(text), 16)}”.`, 'warn-text');
            return;
        }
        if (done) return;
        done = true;
        view.classList.add('found');
        setTimeout(() => finish(code), 200);
    };

    const watch = async (me) => {
        while (!done && me === run && camera.live) {
            let text = null;
            try {
                text = await camera.read();
            } catch (e) {
                if (me === run) say(`The QR reader failed (${errOf(e)}). Choose a photo of the code instead.`, 'bad-text');
                return;
            }
            await consider(text);
            await new Promise(r => setTimeout(r, 100));
        }
    };

    const startCamera = async (deviceId) => {
        const me = ++run;
        if (!canCamera) {
            say('This browser cannot use a camera here. Choose a photo of the code instead.');
            return;
        }
        active = true;
        say('Starting the camera…');
        try {
            await camera.start(deviceId);
        } catch (e) {
            if (done || me !== run) return;
            active = false;
            view.hidden = true;
            say(cameraTrouble(e), 'warn-text');
            return;
        }
        if (done) return;
        if (me !== run) {
            // Overtaken: by the tab hiding (turn it off), or by another start.
            if (paused) camera.stop();
            return;
        }
        wanted = camera.deviceId();
        view.hidden = false;
        rejected = null; // the status line no longer says why, so say it again
        say('Hold the recipient’s QR code up to the camera.');
        watch(me);
        flip.hidden = (await qr.cameraList()).length < 2;
    };

    flip.addEventListener('click', async () => {
        const cams = await qr.cameraList();
        const at = cams.findIndex(c => c.deviceId === camera.deviceId());
        if (cams.length > 1) startCamera(cams[(at + 1) % cams.length].deviceId);
    });

    file.addEventListener('change', async () => {
        const f = file.files && file.files[0];
        file.value = '';
        if (!f || done) return;
        say('Reading the picture…');
        let text;
        try {
            text = await qr.readImageFile(f);
        } catch (e) {
            say(`That file could not be read as a picture (${errOf(e)}).`, 'bad-text');
            return;
        }
        if (text == null) {
            say('No QR code found in that picture. Try a sharper or closer one.', 'warn-text');
            return;
        }
        rejected = null; // a picture always gets an answer
        await consider(text);
    });

    // No camera runs in a hidden tab; coming back turns it on again.
    const onVisibility = () => {
        if (done) return;
        if (document.hidden) {
            if (!active) return;
            paused = true;
            run++;
            camera.stop();
        } else if (paused) {
            paused = false;
            startCamera(wanted);
        }
    };
    document.addEventListener('visibilitychange', onVisibility);

    const closed = overlay(close => {
        finish = close;
        const box = section('Scan a QR code', 'the recipient’s address', h('div', { class: 'pad stack' },
            view, status, file,
            h('div', { class: 'row' },
                h('button', { class: 'btn', type: 'button', onclick: () => file.click() }, 'Choose a photo'),
                flip,
                h('button', { class: 'btn', type: 'button', onclick: () => close(null) }, 'Cancel'))));
        box.classList.add('scan');
        return box;
    });
    startCamera(null);
    const result = await closed;
    done = true;
    run++;
    document.removeEventListener('visibilitychange', onVisibility);
    camera.close();
    return result;
}

function sendView() {
    const to = h('textarea', { rows: 2, spellcheck: 'false', autocomplete: 'off', placeholder: 'mw1…' });
    const amt = h('input', { inputmode: 'decimal', autocomplete: 'off', placeholder: '0.00000000' });
    const quoteLine = h('div', { class: 'dim' }, ' ');
    const err = h('div', { class: 'err' });
    const available = h('div', { class: 'dim' });
    const pending = h('section');
    let quoted = null;
    let qtimer = null;
    const requote = () => {
        clearTimeout(qtimer);
        quoted = null;
        const v = amt.value.trim();
        if (!v) { quoteLine.textContent = ' '; amt.classList.remove('bad'); return; }
        qtimer = setTimeout(async () => {
            try {
                const q = await ask('quote', { amount: v });
                quoted = q;
                amt.classList.remove('bad');
                quoteLine.textContent = `fee ${coins(q.fee)} · ${q.inputs} coin${q.inputs === 1 ? '' : 's'} spent · ${coins(q.change)} back as change`;
            } catch (e) {
                amt.classList.add('bad');
                quoteLine.textContent = errOf(e);
            }
        }, 200);
    };
    amt.addEventListener('input', requote);
    const max = h('button', { class: 'btn small', type: 'button', onclick: () => { if (app.state) { amt.value = plain(app.state.max); requote(); } } }, 'max');
    const review = h('button', { class: 'btn primary', type: 'submit' }, 'Review payment');
    const scan = h('button', { class: 'btn small', type: 'button', title: 'Scan the recipient’s QR code', onclick: async () => {
        const got = await scanPayment();
        if (!got) return;
        to.value = got.address;
        to.classList.remove('bad');
        err.textContent = '';
        if (got.amount) {
            amt.value = got.amount;
            requote();
        }
        toast(got.amount ? `Scanned the address and an amount of ${got.amount} coins.` : 'Scanned the address.');
        (got.amount ? review : amt).focus();
    } }, scanIcon(), 'scan');
    const form = h('form', { class: 'pad stack', onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = '';
        const dest = to.value.trim();
        try { await ask('check-address', { to: dest }); to.classList.remove('bad'); }
        catch (x) { to.classList.add('bad'); err.textContent = errOf(x); return; }
        let q;
        try { q = await ask('quote', { amount: amt.value.trim() }); } catch (x) { err.textContent = errOf(x); return; }
        const s = app.state;
        if (s && dest === s.address) toast('That is this wallet’s own address.', 'info');
        const go = await overlay(close => section('Send this payment?', null,
            dl([
                ['to', h('span', { class: 'hash' }, dest)],
                ['amount', amount(q.amount)],
                ['fee', coins(q.fee)],
                ['total', amount(q.amount + q.fee)],
                ['change', `${coins(q.change)} back to this wallet`],
            ]),
            h('div', { class: 'pad row' },
                h('button', { class: 'btn primary', type: 'button', onclick: () => close(true) }, 'Send'),
                h('button', { class: 'btn', type: 'button', onclick: () => close(false) }, 'Back')),
            h('div', { class: 'note' }, 'Only the recipient can see the amount. A payment cannot be recalled once a block includes it.')));
        if (!go) return;
        review.disabled = true;
        review.replaceChildren(h('span', { class: 'spin' }), 'sending…');
        try {
            const r = await ask('send', { to: dest, amount: amt.value.trim() });
            toast(`Sent ${coins(r.amount)}; waiting for a block.`, 'ok');
            to.value = '';
            amt.value = '';
            quoteLine.textContent = ' ';
        } catch (x) {
            err.textContent = errOf(x);
        } finally {
            review.disabled = false;
            review.replaceChildren('Review payment');
        }
    } },
    h('label', null, h('span', null, 'to'), h('div', { class: 'input-row top' }, to, scan)),
    h('label', null, h('span', null, 'amount (coins)'), h('div', { class: 'input-row' }, amt, max)),
    quoteLine, err,
    h('div', { class: 'row' }, review, available));
    return {
        els: [section('Send', 'one recipient · fee: the relay minimum', form,
            h('div', { class: 'note' }, 'Payments go to a one-time key derived from the recipient’s address, so nobody else can tell who was paid. They are passed on through Dandelion++, which hides where they started.')), pending],
        update() {
            const s = app.state;
            if (!s) return;
            available.textContent = `spendable ${coins(s.balance.spendable)} · at most ${coins(s.max)} in one payment`;
            const rows = s.history.filter(e => e.kind === 'sent' && e.status === 'pending');
            pending.hidden = !rows.length;
            if (rows.length) {
                pending.replaceChildren(h('h2', null, 'Waiting for a block', h('span', { class: 'aside' }, 'rebroadcast every 2 minutes')),
                    table(['sent', 'kind', 'amount', 'fee', 'status', '', ''], historyRows(rows, true), [2, 3]));
            }
        },
    };
}

function receiveView() {
    const addr = h('section');
    const vk = h('section');
    let drawn = null;
    const viewKeyBody = h('div', { class: 'pad stack' },
        h('p', { class: 'lede' }, 'A view key sees every payment to this address and its amount, and can spend none of them. Give it to someone who should audit what you receive (a pool, an accountant); never give out the recovery phrase for that.'),
        h('div', { class: 'row' }, h('button', { class: 'btn', type: 'button', onclick: async () => {
            try {
                const { key } = await ask('view-key');
                viewKeyBody.replaceChildren(h('div', { class: 'mono-block' }, key), h('div', { class: 'row' }, copyButton(key, 'the view key'),
                    h('span', { class: 'dim' }, 'Also: ', h('code', null, 'midwimble wallet view-key'))));
            } catch (e) { toast(errOf(e), 'bad'); }
        } }, 'Show view key')));
    vk.append(h('h2', null, 'View key', h('span', { class: 'aside' }, 'watch-only')), viewKeyBody);
    return {
        els: [addr, vk],
        update() {
            const s = app.state;
            if (!s || drawn === s.address) return;
            drawn = s.address;
            addr.replaceChildren(h('h2', null, 'Receive', h('span', { class: 'aside' }, 'one address, reused safely')),
                addressBlock(s, true),
                h('div', { class: 'note' }, 'Share this address as often as you like: every payment to it lands on a fresh one-time key, so payers cannot see each other, your balance, or your other payments. It also carries your post-quantum recovery key.'));
        },
    };
}

function historyView() {
    const hist = h('section');
    const coinsBox = h('section');
    let coinsOpen = false;
    const drawCoins = async () => {
        if (!coinsOpen) {
            coinsBox.replaceChildren(h('h2', null, 'Coins', h('span', { class: 'aside' }, 'the outputs this wallet owns')),
                h('div', { class: 'pad' }, h('button', { class: 'btn', type: 'button', onclick: () => { coinsOpen = true; drawCoins(); } }, 'Show coins')));
            return;
        }
        try {
            const list = await ask('coins');
            const live = list.filter(c => c.status !== 'spent');
            const statusTag = c => c.status === 'spendable' ? tag('ok', 'spendable') : c.status === 'immature' ? tag('warn', 'matures at ' + num(c.matures_at)) : c.status === 'pending' ? tag('warn', 'pending') : tag('plain', 'spent in ' + num(c.spent_height));
            const unclaimable = live.filter(c => !c.recovery_ok).length;
            coinsBox.replaceChildren(h('h2', null, 'Coins', h('span', { class: 'aside' }, `${live.length} unspent · ${list.length - live.length} spent`)),
                ...[list.length ? table(['commitment', 'value', 'block', 'status', 'recovery'], list.map(c => [
                    h('span', { title: c.commitment }, short(c.commitment, 12)), amount(c.value), num(c.height), statusTag(c),
                    c.recovery_ok ? tag('ok', 'ok') : tag('warn', 'not claimable'),
                ]), [1]) : h('div', { class: 'empty' }, 'none yet'),
                unclaimable ? h('div', { class: 'note warn-text' }, `${unclaimable} coin${unclaimable === 1 ? '' : 's'} came with a wrong recovery commitment (the sender’s doing): spendable as usual, but not claimable in a post-quantum recovery. Sending them to your own address repairs that.`) : null].filter(Boolean));
        } catch (e) { toast(errOf(e), 'bad'); }
    };
    drawCoins();
    let lastKey = null;
    return {
        els: [hist, coinsBox],
        update() {
            const s = app.state;
            if (!s) return;
            const key = JSON.stringify([s.history, s.tip]);
            if (key === lastKey) return;
            lastKey = key;
            hist.replaceChildren(h('h2', null, 'History', h('span', { class: 'aside' }, syncSummary(s))),
                s.history.length ? table(['block', 'kind', 'amount', 'fee', 'status', '', ''], historyRows(s.history, true), [2, 3])
                    : h('div', { class: 'empty' }, 'nothing yet'),
                h('div', { class: 'note' }, 'Change is folded into the payment that made it. Payments made before a restore, or by another copy of this wallet, show as one entry per block, net of their change.'));
            if (coinsOpen) drawCoins();
        },
    };
}

function settingsView() {
    const node = nodeSection(false);
    const backup = section('Backup', null, h('div', { class: 'pad stack' },
        h('p', { class: 'lede' }, 'The recovery phrase restores everything that matters. The wallet file also keeps the scan position and your payment history, and opens in the CLI: ', h('code', null, 'midwimble wallet --wallet midwimble-wallet.mww balance'), '.'),
        h('div', { class: 'row' },
            h('button', { class: 'btn', type: 'button', onclick: async () => {
                const password = await askPassword('Show the recovery phrase', 'Anyone who sees the words can spend this wallet.');
                if (!password) return;
                try {
                    const { phrase } = await ask('reveal', { password });
                    await overlay(close => section('Recovery phrase', null, h('div', { class: 'words' }, phrase.split(' ').map(w => h('div', null, w))),
                        h('div', { class: 'pad row' }, h('button', { class: 'btn primary', type: 'button', onclick: () => close() }, 'Done'))));
                } catch (e) { toast(errOf(e), 'bad'); }
            } }, 'Show recovery phrase'),
            h('button', { class: 'btn', type: 'button', onclick: async () => {
                const password = await askPassword('Download the wallet file', 'The file is encrypted with this same password.');
                if (!password) return;
                try {
                    const { bytes } = await ask('exportFile', { password });
                    download(bytes, 'midwimble-wallet.mww');
                } catch (e) { toast(errOf(e), 'bad'); }
            } }, 'Download wallet file'))));

    const from = h('input', { inputmode: 'numeric' });
    const rescan = section('Rescan', null, h('form', { class: 'pad stack', onsubmit: async (e) => {
        e.preventDefault();
        const v = Number(from.value.trim() || 0);
        if (!Number.isInteger(v) || v < 0) { toast('The block to scan from is a whole number.', 'bad'); return; }
        try { await ask('rescan', { from: v }); toast(`Rescanning from block ${num(v)}.`); } catch (x) { toast(errOf(x), 'bad'); }
    } },
    h('p', { class: 'lede' }, 'Forgets what was learned from blocks after the one given and scans them again. Payment details made here are kept.'),
    h('label', null, h('span', null, 'from block'), from),
    h('div', { class: 'row' }, h('button', { class: 'btn', type: 'submit' }, 'Rescan'))));

    const old = h('input', { type: 'password', autocomplete: 'current-password' });
    const pw = passwordFields();
    const perr = h('div', { class: 'err' });
    const password = section('Password', null, h('form', { class: 'pad stack', onsubmit: async (e) => {
        e.preventDefault();
        perr.textContent = '';
        let next;
        try { next = pw.value(); } catch (x) { perr.textContent = errOf(x); return; }
        try { await ask('change-password', { old: old.value, password: next }); toast('Password changed.', 'ok'); e.target.reset(); }
        catch (x) { perr.textContent = errOf(x); }
    } },
    h('label', null, h('span', null, 'current password'), old), ...pw.els, perr,
    h('div', { class: 'row' }, h('button', { class: 'btn', type: 'submit' }, 'Change password'))));

    const browser = section('This browser', null, h('div', { class: 'pad stack' },
        h('p', { class: 'lede' }, 'The wallet is stored here encrypted. Locking clears it from memory until the password is entered again.'),
        h('div', { class: 'row' },
            h('button', { class: 'btn', type: 'button', onclick: () => ask('lock').catch(() => {}) }, 'Lock'),
            h('button', { class: 'btn danger', type: 'button', onclick: forget }, 'Forget this wallet'))));

    let filled = false;
    return {
        els: [node.el, backup, rescan, password, browser],
        update() {
            node.update();
            if (!filled && app.state) { from.value = String(app.state.birth); filled = true; }
        },
    };
}

function brokenView() {
    return { els: [section('The wallet cannot run here', null, h('div', { class: 'pad' }, h('p', { class: 'lede' }, app.fatal)))] };
}

function elsewhereView() {
    return { els: [section('Open in another tab', null, h('div', { class: 'pad stack' },
        h('p', { class: 'lede' }, 'This wallet is already open in another tab of this browser. One tab at a time keeps the two from spending the same coins.'),
        h('div', { class: 'row' }, h('button', { class: 'btn primary', type: 'button', onclick: () => holdTab(true) }, 'Use it here instead'))))] };
}

function fatal(text) {
    app.phase = 'broken';
    app.fatal = text;
    render();
}

// ── start ───────────────────────────────────────────────────────────────────

async function loadConfig() {
    try {
        const r = await fetch('config.json', { cache: 'no-cache' });
        if (r.ok) return { network: null, genesis: null, nodes: [], ...(await r.json()) };
    } catch (_) {}
    return app.config;
}

let started = false;
async function start() {
    if (started) return;
    started = true;
    app.config = await loadConfig();
    try {
        await ask('init', { config: app.config });
    } catch (e) {
        fatal(`The wallet could not start: ${errOf(e)}`);
        return;
    }
    connect();
}

/** One tab at a time: two tabs syncing one wallet would overwrite each other. */
function holdTab(steal) {
    if (!navigator.locks) { start(); return; }
    navigator.locks.request('midwimble-wallet-tab', steal ? { steal: true } : { ifAvailable: true }, async (lock) => {
        if (!lock) { app.phase = 'elsewhere'; render(); return; }
        if (app.phase === 'elsewhere') app.phase = 'loading';
        render();
        start();
        await new Promise(() => {}); // held until another tab takes it
    }).catch(() => {
        // Another tab took the wallet over.
        worker.terminate();
        if (lc) lc.stop();
        app.phase = 'elsewhere';
        app.state = null;
        started = true;
        current = { els: [section('Opened in another tab', null, h('div', { class: 'pad' }, h('p', { class: 'lede' }, 'The wallet moved to another tab. Reload this one to use it here.')))] };
        $view.replaceChildren(...current.els);
        $nav.hidden = true;
    });
}

render();
holdTab(false);
