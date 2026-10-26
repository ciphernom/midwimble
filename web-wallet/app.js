// app.js: the page. On top it is as simple as a wallet gets: a balance,
// Send, Receive, and what happened. Under Settings is every knob a technical
// user could want: which nodes and how many, how private the scanning is,
// what fee, which coins. It owns the WebRTC
// connections to nodes (light_client.bundle.js) and relays the wallet
// worker's requests to them. Everything from the chain or the user is
// rendered as text, never as HTML.

import { qrSvg } from './qr.js';

const COIN = 100_000_000;
const KEY = {
    nodes: 'midwimble.nodes',
    found: 'midwimble.found',
    settings: 'midwimble.settings',
    wholeBlocks: 'midwimble.wholeBlocks', // from before the settings were kept together
};

/** What the settings change, as they start. Kept per browser. */
const DEFAULTS = Object.freeze({
    autoLock: 15,          // minutes without use before the wallet locks; 0: never
    passwordToSend: false, // ask for the password before each payment
    technical: false,      // show block numbers, hashes and commitments
    fullDecimals: false,   // amounts to all eight decimal places
    poolSize: 3,           // nodes connected at once
    discover: true,        // also use the nodes those nodes know of
    spread: true,          // block fetches go to any node, not only the one followed
    vote: true,            // the nodes check the one followed
    follow: '',            // a node to follow whenever it is connected
    wholeBlocks: false,    // download every block whole
    decoys: 3,             // blocks fetched with each one needed
    decoyWindow: 1000,     // ...from among this many around it
    scanPerRequest: 2000,  // blocks' scan data per request
    fetchAhead: 8,         // blocks fetched ahead of the scan
    watchMempool: true,    // show payments before a block confirms them
    mempoolSecs: 5,
    rebroadcastSecs: 120,
    feeLevel: 1,           // times the relay minimum; 0: the custom rate
    feeRate: 0,            // the custom rate, base units per weight
    coinControl: false,    // choose the coins each payment spends
});
const WORKER_KEYS = new Set(['wholeBlocks', 'decoys', 'decoyWindow', 'scanPerRequest', 'fetchAhead',
    'watchMempool', 'mempoolSecs', 'rebroadcastSecs', 'feeLevel', 'feeRate']);
const NET_KEYS = new Set(['poolSize', 'spread', 'vote', 'follow']);

const settings = loadSettings();

const app = {
    phase: 'loading', // loading | welcome | unlock | wallet | elsewhere | broken
    hasWallet: false,
    constants: null,
    config: { network: null, genesis: null, nodes: [] },
    network: '',
    state: null,
    net: { status: 'idle', addr: null, detail: '' },
    pool: [],          // the nodes connected, from the light client
    keygen: { done: 0, total: 0 },
    flow: null,        // a wallet being created or restored
    fatal: null,
    draft: { to: '', amount: '', coins: [] }, // the payment being written
    sent: null,        // the payment just sent, for its receipt
    phrase: null,      // the recovery phrase while it is shown
};

function loadSettings() {
    let stored = {};
    try { stored = JSON.parse(localStorage.getItem(KEY.settings) || '{}') || {}; } catch (_) {}
    const s = { ...DEFAULTS };
    for (const k of Object.keys(DEFAULTS)) if (typeof stored[k] === typeof DEFAULTS[k]) s[k] = stored[k];
    try { if (!('wholeBlocks' in stored) && localStorage.getItem(KEY.wholeBlocks) === '1') s.wholeBlocks = true; } catch (_) {}
    return s;
}

function set(key, value) {
    settings[key] = value;
    try { localStorage.setItem(KEY.settings, JSON.stringify(settings)); } catch (_) {}
    if (WORKER_KEYS.has(key)) worker.postMessage({ type: 'settings', settings: workerSettings() });
    if (NET_KEYS.has(key) && lc) lc.setOptions(netOptions());
    if (key === 'discover') connect();
    update();
}

function resetSettings() {
    for (const [k, v] of Object.entries(DEFAULTS)) settings[k] = v;
    try { localStorage.removeItem(KEY.settings); localStorage.removeItem(KEY.wholeBlocks); } catch (_) {}
    worker.postMessage({ type: 'settings', settings: workerSettings() });
    connect();
}

const minRate = () => (app.constants && app.constants.min_fee_rate) || 100;
/** The fee rate payments use, in base units per weight; 0 for the minimum. */
function feeRate() {
    if (settings.feeLevel === 0) return Math.max(minRate(), settings.feeRate || 0);
    return settings.feeLevel > 1 ? settings.feeLevel * minRate() : 0;
}
const workerSettings = () => ({
    wholeBlocks: settings.wholeBlocks, decoys: settings.decoys, decoyWindow: settings.decoyWindow,
    scanPerRequest: settings.scanPerRequest, fetchAhead: settings.fetchAhead,
    watchMempool: settings.watchMempool, mempoolSecs: settings.mempoolSecs,
    rebroadcastSecs: settings.rebroadcastSecs, feeRate: feeRate(),
});
const netOptions = () => ({ poolSize: settings.poolSize, spread: settings.spread, vote: settings.vote, follow: settings.follow });

// ── small helpers ───────────────────────────────────────────────────────────

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
/** Replaces an element's children, taking them as h() does: arrays
 *  flattened, null and false left out. */
function fill(el, ...kids) {
    el.replaceChildren(...kids.flat(Infinity).filter(k => k != null && k !== false));
    return el;
}
const errOf = e => (e && e.message) || String(e);
const num = x => Number(x).toLocaleString();
const sleep = ms => new Promise(r => setTimeout(r, ms));

/** An amount: at least two decimal places, all eight with the setting. */
function coins(units) {
    const neg = units < 0;
    const u = Math.abs(units);
    const whole = Math.floor(u / COIN).toLocaleString();
    let frac = String(u % COIN).padStart(8, '0');
    if (!settings.fullDecimals) frac = frac.replace(/0+$/, '').padEnd(2, '0');
    return (neg ? '−' : '') + whole + '.' + frac;
}
/** An amount as the send form takes it: digits and one point. */
const plain = units => Math.floor(units / COIN) + '.' + String(units % COIN).padStart(8, '0');
const unit = () => (app.config.unit ? String(app.config.unit) : '');
const withUnit = units => coins(units) + (unit() ? ' ' + unit() : '');

function shortAddr(a) {
    return a && a.length > 22 ? a.slice(0, 11) + '…' + a.slice(-6) : a || '';
}

function when(ts) {
    const d = new Date(ts * 1000);
    const now = new Date();
    const day = 86_400_000;
    const start = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
    const t = d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
    if (d.getTime() >= start) return `Today ${t}`;
    if (d.getTime() >= start - day) return `Yesterday ${t}`;
    if (d.getTime() >= start - 6 * day) return `${d.toLocaleDateString([], { weekday: 'long' })} ${t}`;
    return d.toLocaleDateString([], { day: 'numeric', month: 'short', year: d.getFullYear() === now.getFullYear() ? undefined : 'numeric' });
}
function ago(secs) {
    const s = Math.max(0, Math.round(secs));
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86_400) { const n = Math.round(s / 3600); return `${n} hour${n === 1 ? '' : 's'} ago`; }
    const n = Math.round(s / 86_400);
    return `${n} day${n === 1 ? '' : 's'} ago`;
}
/** How long ago block `height` was, from the target block time. */
function blockAgo(height) {
    const s = app.state;
    if (!s || height == null) return '';
    const secs = (s.tip - 1 - height) * ((app.constants && app.constants.target_block_time) || 60);
    return secs < 60 ? 'just now' : 'about ' + ago(secs);
}
function hostOf(addr) {
    const m = /^\/(?:ip4|ip6|dns4|dns6|dns)\/([^/]+)\/udp\/(\d+)/.exec(addr || '');
    return m ? (m[1].includes(':') ? `[${m[1]}]` : m[1]) + ':' + m[2] : shortAddr(addr);
}
const networkName = () => (app.network || 'midwimble').replace(/_/g, ' ').replace(/\b(\w)(\w*)/g, (_, a, b) => a + b.toLowerCase());

// ── icons: inline SVG, drawn here ───────────────────────────────────────────

const NS = 'http://www.w3.org/2000/svg';
function svgEl(tag, attrs) {
    const el = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    return el;
}
const ICONS = {
    backup: ['c12,12,9', 'c12,12,4', 'M5.6 5.6l3.6 3.6', 'M18.4 5.6l-3.6 3.6', 'M5.6 18.4l3.6-3.6', 'M18.4 18.4l-3.6-3.6'],
    lock: ['r5,11,14,10,2', 'M8 11V8a4 4 0 0 1 8 0v3'],
    globe: ['c12,12,9', 'e12,12,4,9', 'M3 12h18'],
    eye: ['M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z', 'c12,12,3'],
    plane: ['M3 11l18-8-7 18-3-7z', 'M11 13l10-10'],
    sliders: ['M4 7h9', 'M17 7h3', 'M4 17h3', 'M11 17h9', 'c15,7,2', 'c9,17,2'],
    info: ['c12,12,9', 'M12 11v6', 'M12 7.6v.4'],
    down: ['M12 4v15', 'M6 13l6 6 6-6'],
    up: ['M12 20V5', 'M6 11l6-6 6 6'],
    star: ['M12 3l2.6 6 6.4.5-4.9 4.2 1.5 6.3L12 16.6 6.4 20l1.5-6.3L3 9.5l6.4-.5z'],
    clock: ['c12,12,9', 'M12 7v5l3 3'],
    check: ['M5 13l4 4L19 7'],
    warn: ['M12 3l10 18H2z', 'M12 10v5', 'M12 18v.4'],
    copy: ['r8,8,12,12,2', 'M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3'],
    scan: ['M4 9V4h5', 'M15 4h5v5', 'M20 15v5h-5', 'M9 20H4v-5', 'M8 12h8'],
    paste: ['r6,4,12,17,2', 'M9 4V3h6v1', 'M9 10h6', 'M9 14h6'],
    share: ['M12 15V3', 'M7 8l5-5 5 5', 'M5 12v8h14v-8'],
    coins: ['e12,7,7,3', 'M5 7v5c0 1.7 3.1 3 7 3s7-1.3 7-3V7', 'M5 12v5c0 1.7 3.1 3 7 3s7-1.3 7-3v-5'],
    key: ['c8,15,4', 'M11 12l9-9', 'M17 6l3 3', 'M15 8l2 2'],
    pulse: ['M3 12h4l3-7 4 14 3-7h4'],
    rescan: ['M20 12a8 8 0 1 1-2.3-5.7', 'M20 4v4h-4'],
    file: ['M6 3h8l4 4v14H6z', 'M14 3v4h4'],
    download: ['M12 4v11', 'M7 10l5 5 5-5', 'M5 20h14'],
    left: ['M15 5l-7 7 7 7'],
    wallet: ['r3,6,18,14,3', 'M3 10h18', 'M16 15h2'],
    install: ['M12 3v12', 'M7 10l5 5 5-5', 'M4 15v4a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-4'],
};
function icon(name) {
    const s = svgEl('svg', { viewBox: '0 0 24 24', 'aria-hidden': 'true', class: 'icon' });
    for (const part of ICONS[name] || []) {
        const n = part.slice(1).split(',').map(Number);
        if (part[0] === 'c') s.appendChild(svgEl('circle', { cx: n[0], cy: n[1], r: n[2] }));
        else if (part[0] === 'e') s.appendChild(svgEl('ellipse', { cx: n[0], cy: n[1], rx: n[2], ry: n[3] }));
        else if (part[0] === 'r') s.appendChild(svgEl('rect', { x: n[0], y: n[1], width: n[2], height: n[3], rx: n[4] }));
        else s.appendChild(svgEl('path', { d: part }));
    }
    return s;
}
function gearPath(cx, cy, outer, root, teeth, hole) {
    const step = Math.PI * 2 / teeth;
    const pts = [];
    for (let i = 0; i < teeth; i++) {
        const a = i * step;
        pts.push([a - step * 0.3, root], [a - step * 0.2, outer], [a + step * 0.2, outer], [a + step * 0.3, root]);
    }
    const p = ([a, r]) => `${(cx + r * Math.cos(a)).toFixed(2)} ${(cy + r * Math.sin(a)).toFixed(2)}`;
    return 'M' + pts.map(p).join('L') + 'Z' +
        `M${cx + hole} ${cy}a${hole} ${hole} 0 1 0 ${-2 * hole} 0a${hole} ${hole} 0 1 0 ${2 * hole} 0Z`;
}
function gearIcon() {
    const s = svgEl('svg', { viewBox: '0 0 24 24', 'aria-hidden': 'true', class: 'icon' });
    s.appendChild(svgEl('path', { d: gearPath(12, 12, 9.5, 7.3, 8, 3) }));
    return s;
}
const tile = (color, name) => h('span', { class: 'tile ' + color }, icon(name));
const spinner = () => h('span', { class: 'spinner', 'aria-hidden': 'true' });
const logo = small => h('img', { class: 'logo' + (small ? ' small' : ''), src: 'logo.svg', alt: '' });

// ── table pieces ────────────────────────────────────────────────────────────

const title = text => h('div', { class: 'group-title' }, text);
const note = (...kids) => h('div', { class: 'group-note' }, ...kids);
const group = (...rows) => h('div', { class: 'group' }, ...rows);
function linkRow(label, href, { value, sub, tile: t } = {}) {
    return h('a', { class: 'row link', href }, t,
        h('span', { class: 'grow' }, label, sub ? h('span', { class: 'sub' }, sub) : null),
        value != null && value !== '' ? h('span', { class: 'value' }, value) : null);
}
function actionRow(label, onclick, { bad } = {}) {
    return h('button', { class: 'row action' + (bad ? ' bad' : ''), type: 'button', onclick }, label);
}
function infoRow(label, value, { wrap, mono, sub } = {}) {
    return h('div', { class: 'row' }, h('span', { class: wrap ? '' : 'grow' }, label, sub ? h('span', { class: 'sub' }, sub) : null),
        h('span', { class: 'value' + (wrap ? ' wrap' : '') + (mono ? ' mono' : '') }, value));
}
const textRow = (...kids) => h('div', { class: 'row text' }, ...kids);
function rowWith(label, control, sub) {
    return h('div', { class: 'row' }, h('span', { class: 'grow' }, label, sub ? h('span', { class: 'sub' }, sub) : null), control);
}
function switchEl(checked, onchange, label) {
    const input = h('input', { type: 'checkbox', role: 'switch', 'aria-label': label });
    input.checked = checked;
    input.addEventListener('change', () => onchange(input.checked));
    return h('span', { class: 'switch' }, input, h('span', { class: 'track' }));
}
/** A switch for one of the settings. */
const switchRow = (label, key, sub) => rowWith(label, switchEl(settings[key], v => set(key, v), label), sub);
function segmented(options, current, onpick, inRow = true) {
    const el = h('div', { class: 'segmented' + (inRow ? ' in-row' : ''), role: 'group' });
    const draw = cur => fill(el, ...options.map(([v, label]) =>
        h('button', { type: 'button', 'aria-pressed': String(v === cur), onclick: () => { draw(v); onpick(v); } }, label)));
    draw(current);
    return el;
}
/** A segmented control for one of the settings. */
const segRow = (label, key, options) => rowWith(label, segmented(options, settings[key], v => set(key, v)));
function checkRow(label, on, onclick, sub) {
    return h('button', { class: 'row check' + (on ? ' on' : ''), type: 'button', 'aria-pressed': String(on), onclick },
        h('span', { class: 'grow' }, label, sub ? h('span', { class: 'sub' }, sub) : null));
}
function mini(label, iconName, onclick) {
    return h('button', { class: 'mini', type: 'button', onclick }, iconName ? icon(iconName) : null, label);
}
function bar(fraction, cls = 'progress') {
    const fill = h('span');
    fill.style.width = Math.min(100, Math.max(0, fraction * 100)) + '%';
    return h('div', { class: cls }, fill);
}

// ── dialogs and notices ────────────────────────────────────────────────────

/** A dialog. Buttons are [{label, value, cls}]; resolves with
 *  {value, text} (the text field's, if it has one). Escape is the first
 *  button, Enter the last. */
function alertBox({ title: t, message, input, buttons, error }) {
    return new Promise(resolve => {
        const field = input ? h('input', { type: input.type || 'text', placeholder: input.placeholder || '', autocomplete: input.autocomplete || 'off', 'aria-label': input.label || t }) : null;
        const err = h('div', { class: 'err', role: 'alert' }, error || '');
        const layer = h('div', { class: 'dim-layer' });
        const close = (b) => { layer.remove(); document.removeEventListener('keydown', onKey, true); resolve({ value: b.value, text: field ? field.value : null }); };
        const onKey = (e) => {
            if (e.key === 'Escape') { e.preventDefault(); close(buttons[0]); }
            else if (e.key === 'Enter') { e.preventDefault(); close(buttons[buttons.length - 1]); }
        };
        const box = h('div', { class: 'alert', role: 'alertdialog', 'aria-modal': 'true', 'aria-label': t },
            h('h2', null, t), message ? h('p', null, message) : null, field, err,
            h('div', { class: 'choices' + (buttons.length > 2 ? ' stacked' : '') },
                buttons.map((b, i) => h('button', { type: 'button', class: (b.cls || '') + (i === buttons.length - 1 ? ' default' : ''), onclick: () => close(b) }, b.label))));
        layer.appendChild(box);
        document.body.appendChild(layer);
        document.addEventListener('keydown', onKey, true);
        (field || box.querySelector('button.default') || box.querySelector('button')).focus();
    });
}
const ok = (t, message) => alertBox({ title: t, message, buttons: [{ label: 'OK', value: true }] });

/** The password, asked for in an alert; null if cancelled. */
async function askPassword(t, message) {
    const r = await alertBox({ title: t, message, input: { type: 'password', autocomplete: 'current-password', placeholder: 'Password' },
        buttons: [{ label: 'Cancel', value: null }, { label: 'OK', value: true }] });
    return r.value && r.text ? r.text : null;
}

/** A dialog whose body `build(close)` gives; resolves with what `close` is
 *  called with (null for Escape or a click outside). */
function openSheet(build) {
    return new Promise(resolve => {
        const layer = h('div', { class: 'sheet-layer' });
        const close = (v) => { layer.remove(); document.removeEventListener('keydown', onKey, true); resolve(v); };
        const onKey = (e) => { if (e.key === 'Escape') { e.preventDefault(); close(null); } };
        const sheet = h('div', { class: 'sheet', role: 'dialog', 'aria-modal': 'true' }, build(close));
        layer.addEventListener('mousedown', (e) => { if (e.target === layer) close(null); });
        layer.appendChild(sheet);
        document.body.appendChild(layer);
        document.addEventListener('keydown', onKey, true);
        const first = sheet.querySelector('button');
        if (first) first.focus();
    });
}
/** A confirmation: a message and buttons [{label, value, cls}]. */
function actionSheet(message, buttons) {
    return openSheet(close => [message ? h('p', null, message) : null,
        buttons.map(b => h('button', { class: 'btn ' + (b.cls || 'secondary'), type: 'button', onclick: () => close(b.value) }, b.label))]);
}

let hudEl = null;
let hudTimer = null;
function hud(text, iconName = 'check', ms = 1400) {
    if (hudEl) hudEl.remove();
    clearTimeout(hudTimer);
    hudEl = h('div', { class: 'toast', role: 'status' }, iconName ? icon(iconName) : spinner(), text);
    document.body.appendChild(hudEl);
    const el = hudEl;
    hudTimer = setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 450); }, ms);
}
function hudBusy(text) {
    if (hudEl) hudEl.remove();
    clearTimeout(hudTimer);
    hudEl = h('div', { class: 'toast', role: 'status' }, spinner(), text);
    document.body.appendChild(hudEl);
    const el = hudEl;
    return () => { if (hudEl === el) { el.remove(); hudEl = null; } };
}

async function copyText(text, what) {
    try {
        await navigator.clipboard.writeText(text);
        hud(`${what} copied`);
    } catch (_) {
        ok('Can’t copy', 'This browser blocks copying here. Select the text and copy it yourself.');
    }
}

function download(bytes, name) {
    const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
    const a = h('a', { href: url, download: name });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

const shake = el => { el.classList.remove('shake'); void el.offsetWidth; el.classList.add('shake'); };

/** A text area that grows to fit what it holds. */
function textArea(attrs, value = '') {
    const ta = h('textarea', { rows: 1, spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off', ...attrs });
    ta.value = value;
    const fit = () => {
        ta.style.height = 'auto';
        if (ta.scrollHeight) ta.style.height = ta.scrollHeight + 'px';
    };
    ta.addEventListener('input', fit);
    ta.fit = fit;
    requestAnimationFrame(fit);
    return ta;
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
            worker.postMessage({ type: 'settings', settings: workerSettings() });
            goHome();
            return;
        case 'unlocked':
            app.phase = 'wallet';
            app.hasWallet = true;
            app.flow = null;
            app.keygen = { done: 0, total: 0 };
            lastUse = Date.now();
            goHome();
            return;
        case 'locked':
            app.phase = app.hasWallet ? 'unlock' : 'welcome';
            app.state = null;
            app.phrase = null;
            app.draft = { to: '', amount: '', coins: [] };
            goHome();
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
            if (app.phase === 'wallet') hud(m.text.replace(/\.$/, ''), m.kind === 'bad' ? 'warn' : m.kind === 'ok' ? 'check' : 'info', m.kind === 'bad' ? 4000 : 2200);
            return;
        case 'rpc':
            relay(m);
            return;
        case 'bad-node':
            if (lc && lc.connected) lc.dropPrimary();
            return;
    }
};

// ── the nodes ───────────────────────────────────────────────────────────────

let lc = null;
let lcModule = null;

function nodeList() {
    try {
        const v = JSON.parse(localStorage.getItem(KEY.nodes) || 'null');
        if (Array.isArray(v) && v.length) return v;
    } catch (_) {}
    return app.config.nodes || [];
}
const customNodes = () => { try { return !!localStorage.getItem(KEY.nodes); } catch (_) { return false; } };
const foundKey = () => `${KEY.found}.${app.config.network || app.network || 'default'}`;
function loadFound() {
    try {
        const v = JSON.parse(localStorage.getItem(foundKey()) || '[]');
        return Array.isArray(v) ? v : [];
    } catch (_) { return []; }
}
function saveFound(list) {
    try { list.length ? localStorage.setItem(foundKey(), JSON.stringify(list)) : localStorage.removeItem(foundKey()); } catch (_) {}
}

async function connect() {
    const addrs = nodeList();
    if (lc) { const old = lc; lc = null; old.stop(); }
    app.pool = [];
    if (!addrs.length) { setNet('none', ''); return; }
    try {
        if (!lcModule) lcModule = import('./light_client.bundle.js');
        const { LightClient } = await lcModule;
        const c = new LightClient();
        lc = c;
        c.onStatus = (status, info) => { if (lc === c) setNet(status, info); };
        c.onPool = ({ nodes, found }) => {
            if (lc !== c) return;
            app.pool = nodes;
            if (!customNodes() && settings.discover) saveFound(found);
            tellWorker();
            update();
        };
        c.onPush = (msg) => {
            if (lc === c) worker.postMessage({ type: 'push', msg });
        };
        // A list of the user's own is used as it is; the default one grows
        // by the nodes its nodes know of, unless that is turned off.
        const discover = !customNodes() && settings.discover;
        await c.start(addrs, { genesis: app.config.genesis, found: discover ? loadFound() : [], discover, ...netOptions() });
    } catch (e) {
        setNet('failed', errOf(e));
    }
}

function tellWorker() {
    worker.postMessage({ type: 'net', status: app.net.status, addr: app.net.addr, nodes: app.pool.length });
}

function setNet(status, info) {
    app.net = { status, addr: status === 'connected' ? info : null, detail: status === 'failed' ? info : '' };
    tellWorker();
    update();
}

function relay(m) {
    const c = lc;
    const reply = (r) => worker.postMessage({ type: 'rpc-result', id: m.id, ...r });
    if (!c || !c.connected) return reply({ ok: false, error: 'not connected to a node' });
    c.call(m.method, m.params, { spread: !!m.spread }).then(
        data => reply({ ok: true, data }),
        e => reply({ ok: false, error: errOf(e), unanswered: !!e.unanswered }));
}

// ── auto-lock ───────────────────────────────────────────────────────────────

let lastUse = Date.now();
for (const ev of ['pointerdown', 'keydown', 'wheel', 'touchstart']) {
    addEventListener(ev, () => { lastUse = Date.now(); }, { passive: true, capture: true });
}
setInterval(() => {
    const minutes = settings.autoLock;
    if (app.phase === 'wallet' && minutes > 0 && Date.now() - lastUse > minutes * 60_000) ask('lock').catch(() => {});
}, 10_000);

// ── the page: a bar along the top, then the screen ──────────────────────────

const $app = document.getElementById('app');
const $top = h('header', { class: 'topbar' });
const $side = h('nav', { class: 'sidebar', 'aria-label': 'Sections' });
const $content = h('main', { class: 'content' });
$app.append($top, h('div', { class: 'shell' }, $side, $content));

/** The sections a wide screen lists down the side. */
const SECTIONS = [['', 'Wallet', 'wallet'], ['activity', 'Activity', 'clock'], ['send', 'Send', 'up'], ['receive', 'Receive', 'down'], ['settings', 'Settings', null]];
function drawSide(path) {
    const top = path.split('/')[0];
    const watchOnly = app.state && app.state.watchOnly;
    fill($side, ...SECTIONS.filter(([p]) => !(p === 'send' && watchOnly)).map(([p, label, ic]) =>
        h('a', { class: 'side-link', href: '#/' + p, 'aria-current': top === p ? 'page' : null }, ic ? icon(ic) : gearIcon(), label)));
}

const routePath = () => decodeURI((location.hash.match(/^#\/?(.*)$/) || [])[1] || '').replace(/\/+$/, '');
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');

let current = null; // { path, sc, el }

function goHome() {
    if (location.hash && location.hash !== '#/') location.hash = '#/';
    else render(false);
}

/** How the wallet is connected, in two words and a colour. */
function netSummary() {
    if (!navigator.onLine) return { cls: 'bad', text: 'Offline' };
    const n = app.pool.length;
    if (n) return { cls: 'ok', text: n === 1 ? '1 node' : `${n} nodes` };
    if (app.net.status === 'failed' || app.net.status === 'none') return { cls: 'bad', text: 'Offline' };
    return { cls: 'busy', text: 'Connecting' };
}

/** The top bar: the name and, with a wallet open, its connection, Lock and
 *  Settings. */
let topKey = null;
function drawTop() {
    const open = app.phase === 'wallet';
    const net = open ? netSummary() : null;
    const key = JSON.stringify([open, net]);
    if (key === topKey) return;
    topKey = key;
    fill($top,
        h('a', { class: 'brand', href: '#/' }, h('img', { src: 'logo.svg', alt: '' }), h('b', null, 'Midwimble')),
        open ? h('div', { class: 'top-actions' },
            h('a', { class: 'status-pill', href: '#/settings/network', title: 'Network' }, h('span', { class: 'dot ' + net.cls }), net.text),
            h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Lock', title: 'Lock', onclick: () => ask('lock').catch(() => {}) }, icon('lock')),
            h('a', { class: 'icon-btn top-settings', href: '#/settings', 'aria-label': 'Settings', title: 'Settings' }, gearIcon())) : null);
}

function render(animate) {
    const path = routePath();
    const sc = screenFor(path);
    if (current && current.sc.leave) current.sc.leave();
    $app.classList.toggle('bare', !!sc.bare);
    $top.hidden = !!sc.bare;
    $side.hidden = !!sc.bare || app.phase !== 'wallet';
    $app.classList.toggle('with-side', !$side.hidden);
    $app.classList.toggle('wide', !!sc.wide);
    if (!$side.hidden) drawSide(path);
    const nav = sc.back || sc.left || sc.right
        ? h('div', { class: 'page-nav' },
            h('div', { class: 'side' }, sc.back ? h('a', { class: 'back' + (sc.back[1] === '#/' ? ' to-home' : ''), href: sc.back[1] }, icon('left'), sc.back[0]) : null, sc.left),
            h('div', { class: 'side right' }, sc.right))
        : null;
    const head = nav || sc.title ? h('div', { class: 'page-head' }, nav, sc.title ? h('h1', null, sc.title) : null) : null;
    const el = h('div', { class: 'screen' + (sc.bare ? ' bare' : '') + (sc.wide ? ' wide' : '') }, head, ...sc.els);
    fill($content, el);
    current = { path, sc, el };
    if (animate) {
        window.scrollTo(0, 0);
        if (!reducedMotion.matches) el.animate([{ opacity: 0, transform: 'translateY(6px)' }, { opacity: 1, transform: 'none' }], { duration: 180, easing: 'ease-out' });
    }
    update();
    if (sc.focus) setTimeout(() => sc.focus(), 0);
}

function update() {
    drawTop();
    if (current && current.sc.update) current.sc.update();
}

window.addEventListener('hashchange', () => render(true));

function screenFor(path) {
    if (app.phase === 'loading') return loadingScreen();
    if (app.phase === 'broken') return fatalScreen();
    if (app.phase === 'elsewhere') return elsewhereScreen();
    if (app.phase !== 'wallet') {
        const net = /^network(?:\/(.*))?$/.exec(path);
        if (net) return networkRoute(net[1] || '', '#/network', ['Back', '#/']);
        if (app.phase === 'welcome') {
            if (path === 'create' || path.startsWith('create/')) return createScreen(path);
            if (path === 'restore') return restoreScreen();
            if (path === 'watch') return watchScreen();
            if (path === 'open') return openScreen();
            return welcomeScreen();
        }
        return lockScreen();
    }
    let m;
    if (path === 'activity') return activityScreen();
    if ((m = /^activity\/(.+)$/.exec(path))) return activityItemScreen(decodeURIComponent(m[1]));
    if (path === 'send') return sendScreen();
    if (path === 'send/coins') return coinPickerScreen();
    if (path === 'send/done') return sentScreen();
    if (path === 'receive') return receiveScreen();
    if (path === 'settings') return settingsScreen();
    if (path === 'settings/backup') return backupScreen();
    if (path === 'settings/backup/phrase') return phraseScreen();
    if (path === 'settings/security') return securityScreen();
    if (path === 'settings/security/autolock') return autoLockScreen();
    if (path === 'settings/security/password') return passwordScreen();
    if ((m = /^settings\/network(?:\/(.*))?$/.exec(path))) return networkRoute(m[1] || '', '#/settings/network', ['Settings', '#/settings']);
    if (path === 'settings/privacy') return privacyScreen();
    if (path === 'settings/sending') return sendingScreen();
    if (path === 'settings/advanced') return advancedScreen();
    if (path === 'settings/advanced/coins') return coinsScreen();
    if (path === 'settings/advanced/viewkey') return viewKeyScreen();
    if (path === 'settings/advanced/rescan') return rescanScreen();
    if (path === 'settings/advanced/diagnostics') return diagnosticsScreen();
    if (path === 'settings/about') return aboutScreen();
    return homeScreen();
}

// ── screens with no wallet open ─────────────────────────────────────────────

function loadingScreen() {
    return { bare: true, els: [h('div', { class: 'center-card' }, spinner())] };
}

function fatalScreen() {
    return { bare: true, els: [h('div', { class: 'center-card' }, logo(), h('h1', null, 'Can’t start'), h('p', null, app.fatal))] };
}

function elsewhereScreen() {
    return {
        bare: true,
        els: [h('div', { class: 'center-card' }, logo(), h('h1', null, 'Open in another tab'),
            h('p', null, 'The wallet is open in another tab of this browser. One tab at a time keeps them from spending the same coins.'),
            h('div', { class: 'stack-buttons' }, h('button', { class: 'btn primary', type: 'button', onclick: () => holdTab(true) }, 'Use it here')))],
    };
}

function welcomeScreen() {
    return {
        bare: true,
        els: [h('div', { class: 'center-card' },
            logo(),
            h('h1', null, 'Midwimble'),
            h('p', null, 'A private wallet that lives in this browser. Your keys never leave it.'),
            h('div', { class: 'stack-buttons' },
                h('a', { class: 'btn primary', href: '#/create' }, 'Create new wallet'),
                h('a', { class: 'btn secondary', href: '#/restore' }, 'Restore with recovery phrase'),
                h('a', { class: 'btn secondary', href: '#/open' }, 'Open wallet file'),
                h('a', { class: 'btn secondary', href: '#/watch' }, 'Watch an address (view key)')),
            h('div', { class: 'quiet-links' }, h('a', { class: 'quiet', href: '#/network' }, `Network: ${networkName()}`)))],
    };
}

function lockScreen() {
    const pw = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Password', 'aria-label': 'Password' });
    const err = h('div', { class: 'err', role: 'alert' });
    const go = h('button', { class: 'btn primary', type: 'submit' }, 'Unlock');
    let card = null;
    const unlock = async (e) => {
        e.preventDefault();
        if (!pw.value) { err.textContent = 'Type your password.'; shake(card); pw.focus(); return; }
        err.textContent = '';
        go.disabled = true;
        fill(go, spinner(), 'Unlocking…');
        try {
            await ask('unlock', { password: pw.value });
        } catch (x) {
            err.textContent = errOf(x);
            shake(card);
            pw.select();
        } finally {
            go.disabled = false;
            fill(go, 'Unlock');
        }
    };
    pw.addEventListener('input', () => { err.textContent = ''; });
    card = h('form', { class: 'center-card', onsubmit: unlock },
        logo(),
        h('h1', null, 'Welcome back'),
        h('p', null, 'Your wallet is locked.'),
        h('div', { class: 'stack-buttons' }, pw, err, go),
        h('div', { class: 'quiet-links' },
            h('button', { class: 'quiet', type: 'button', onclick: forgotPassword }, 'Forgot your password?'),
            h('a', { class: 'quiet', href: '#/network' }, networkName())));
    return { bare: true, els: [card], focus() { pw.focus(); } };
}

async function forgotPassword() {
    const r = await alertBox({
        title: 'Forgot your password?',
        message: 'It can’t be recovered. Forget the wallet here, then restore it with your 24-word recovery phrase and choose a new password.',
        buttons: [{ label: 'Cancel', value: null }, { label: 'Forget wallet', value: true, cls: 'bad' }],
    });
    if (r.value) forget();
}

async function forget() {
    const sure = await actionSheet('This removes the wallet from this browser. Only its recovery phrase or a wallet file can bring it back.',
        [{ label: 'Forget this wallet', value: true, cls: 'danger' }, { label: 'Cancel', value: null, cls: 'plain' }]);
    if (!sure) return;
    const again = await alertBox({
        title: 'Forget the wallet?',
        message: 'Have you written down the recovery phrase, or saved a wallet file?',
        buttons: [{ label: 'Cancel', value: null }, { label: 'Forget', value: true, cls: 'bad' }],
    });
    if (again.value) ask('forget').catch(e => ok('Not forgotten', errOf(e)));
}

// ── creating, restoring, opening ────────────────────────────────────────────

function drawKeygen(el) {
    const { done, total } = app.keygen;
    if (!total) { fill(el); return; }
    fill(el, bar(done / total), h('div', null, done < total
        ? `Preparing your wallet’s recovery key: ${Math.floor((done / total) * 100)}%`
        : 'Recovery key ready.'));
}
const keygenBox = () => { const el = h('div', { class: 'keygen', 'data-keygen': '' }); drawKeygen(el); return el; };

function cancelFlow() {
    ask('cancel-keygen').catch(() => {});
    app.flow = null;
    app.keygen = { done: 0, total: 0 };
    goHome();
}
const cancelButton = () => h('button', { class: 'btn plain small', type: 'button', onclick: cancelFlow }, 'Cancel');

function passwordRows() {
    const pw = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'At least 8 characters', 'aria-label': 'Password' });
    const pw2 = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'Once more', 'aria-label': 'Confirm password' });
    return {
        rows: [h('label', { class: 'row field' }, h('span', { class: 'label' }, 'Password'), pw),
            h('label', { class: 'row field' }, h('span', { class: 'label' }, 'Confirm'), pw2)],
        first: pw,
        value() {
            if (pw.value.length < 8) throw new Error('Use a password of at least 8 characters.');
            if (pw.value !== pw2.value) throw new Error('The two passwords don’t match.');
            return pw.value;
        },
    };
}

function createScreen(path) {
    if (!app.flow || app.flow.kind !== 'create') app.flow = { kind: 'create', phrase: null };
    const f = app.flow;
    if (!f.phrase) {
        ask('new-phrase').then(r => { if (app.flow === f) { f.phrase = r.phrase; render(false); } }, e => ok('Can’t create', errOf(e)));
        return { title: 'New wallet', left: cancelButton(), els: [h('div', { class: 'empty-note' }, spinner())] };
    }
    const words = f.phrase.split(' ');
    if (path === 'create/check' && f.wrote) {
        if (!f.check) {
            const picks = new Set();
            while (picks.size < 3) picks.add(Math.floor(Math.random() * words.length));
            f.check = [...picks].sort((a, b) => a - b);
        }
        const inputs = f.check.map(i => h('input', { autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', 'aria-label': `Word ${i + 1}` }));
        const err = note();
        err.classList.add('bad');
        const form = h('form', { onsubmit: (e) => {
            e.preventDefault();
            const wrong = f.check.find((i, k) => inputs[k].value.trim().toLowerCase() !== words[i]);
            if (wrong !== undefined) { err.textContent = `That isn’t word ${wrong + 1}. Check your paper.`; return; }
            f.checked = true;
            location.hash = '#/create/password';
        } },
        note('Type these three words from your paper, so you know it’s right.'),
        group(...f.check.map((i, k) => h('label', { class: 'row field' }, h('span', { class: 'label' }, `Word ${i + 1}`), inputs[k]))),
        err,
        h('div', { class: 'stack-buttons' }, h('button', { class: 'btn primary', type: 'submit' }, 'Next')),
        keygenBox());
        return { title: 'Check', back: ['Words', '#/create'], right: cancelButton(), els: [form], focus: () => inputs[0].focus() };
    }
    if (path === 'create/password' && f.checked) {
        const pw = passwordRows();
        const err = note();
        err.classList.add('bad');
        const go = h('button', { class: 'btn primary', type: 'submit' }, 'Create wallet');
        const form = h('form', { onsubmit: async (e) => {
            e.preventDefault();
            err.textContent = '';
            let password;
            try { password = pw.value(); } catch (x) { err.textContent = errOf(x); return; }
            go.disabled = true;
            fill(go, spinner(), 'Creating…');
            try { await ask('create', { phrase: f.phrase, password }); }
            catch (x) { err.textContent = errOf(x); go.disabled = false; fill(go, 'Create wallet'); }
        } },
        note('The password unlocks the wallet in this browser. If you forget it, your recovery phrase still works.'),
        group(...pw.rows), err,
        h('div', { class: 'stack-buttons' }, go),
        keygenBox());
        return { title: 'Password', back: ['Check', '#/create/check'], right: cancelButton(), els: [form], focus: () => pw.first.focus() };
    }
    const paper = h('div', { class: 'paper hidden-words', 'aria-label': 'Recovery phrase' },
        words.map((w, i) => h('span', null, h('i', null, i + 1), w)));
    const show = h('button', { class: 'btn secondary small', type: 'button', onclick: () => { paper.classList.remove('hidden-words'); show.remove(); } }, 'Show words');
    const next = h('button', { class: 'btn primary', type: 'button', disabled: !f.wrote, onclick: () => { location.hash = '#/create/check'; } }, 'Next');
    const drawNext = () => { next.disabled = !f.wrote; };
    return {
        title: 'New wallet',
        left: cancelButton(),
        els: [note('These 24 words are your wallet. Write them on paper, in order, and keep it safe. Anyone who has them can spend your money.'),
            paper,
            h('div', { class: 'buttons' }, show),
            group(rowWith('I wrote them down', switchEl(!!f.wrote, (v) => { f.wrote = v; drawNext(); }, 'I wrote them down'))),
            note('On paper: not a screenshot, not a note on this computer.'),
            h('div', { class: 'stack-buttons' }, next),
            keygenBox()],
    };
}

function restoreScreen() {
    const phrase = textArea({ rows: 4, placeholder: 'Your 24 words, separated by spaces', 'aria-label': 'Recovery phrase' });
    const birth = h('input', { inputmode: 'numeric', placeholder: 'Optional', 'aria-label': 'Start scanning at block' });
    const pw = passwordRows();
    const err = note();
    err.classList.add('bad');
    const go = h('button', { class: 'btn primary', type: 'submit' }, 'Restore wallet');
    const form = h('form', { onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = '';
        let password;
        try { password = pw.value(); } catch (x) { err.textContent = errOf(x); return; }
        const from = birth.value.trim() ? Number(birth.value.trim().replace(/,/g, '')) : 0;
        if (!Number.isInteger(from) || from < 0) { err.textContent = 'The block to start at is a whole number.'; return; }
        go.disabled = true;
        fill(go, spinner(), 'Restoring…');
        try { await ask('restore', { phrase: phrase.value, password, birth: from }); }
        catch (x) { err.textContent = errOf(x); go.disabled = false; fill(go, 'Restore wallet'); }
    } },
    group(h('label', { class: 'row stacked' }, h('span', { class: 'label' }, 'Recovery phrase'), phrase)),
    title('New password'),
    group(...pw.rows),
    note('It unlocks the wallet in this browser.'),
    title('Start scanning at'),
    group(h('label', { class: 'row field' }, h('span', { class: 'label' }, 'Block'), birth)),
    note('Leave it empty to look through the whole chain. If you know about when the wallet was made, starting there is faster.'),
    err,
    h('div', { class: 'stack-buttons' }, go),
    keygenBox());
    return { title: 'Restore', left: cancelButton(), els: [form], focus: () => phrase.focus() };
}

function watchScreen() {
    const view = textArea({ rows: 3, placeholder: 'mwview1…  (or scan the QR)', 'aria-label': 'View key' });
    const birth = h('input', { inputmode: 'numeric', placeholder: 'Optional', 'aria-label': 'Start scanning at block' });
    const pw = passwordRows();
    const err = note();
    err.classList.add('bad');
    let node = null; // a node address, if a scanned link carried one
    const go = h('button', { class: 'btn primary', type: 'submit' }, 'Watch address');
    const scan = h('button', { class: 'btn secondary', type: 'button', onclick: async () => {
        const link = await scanWatchLink();
        if (!link) return;
        view.value = link.viewKey;
        if (view.fit) view.fit();
        node = link.node;
    } }, 'Scan QR');
    const form = h('form', { onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = '';
        let password;
        try { password = pw.value(); } catch (x) { err.textContent = errOf(x); return; }
        const from = birth.value.trim() ? Number(birth.value.trim().replace(/,/g, '')) : 0;
        if (!Number.isInteger(from) || from < 0) { err.textContent = 'The block to start at is a whole number.'; return; }
        const key = view.value.trim();
        if (!/^mwview1[0-9a-z]+$/i.test(key)) { err.textContent = 'That doesn’t look like a view key (mwview1…).'; return; }
        go.disabled = true;
        fill(go, spinner(), 'Setting up…');
        try {
            if (node) { try { localStorage.setItem(KEY.nodes, JSON.stringify([node])); } catch (_) {} }
            await ask('watch', { viewKey: key, password, birth: from });
        } catch (x) { err.textContent = errOf(x); go.disabled = false; fill(go, 'Watch address'); }
    } },
    group(h('label', { class: 'row stacked' }, h('span', { class: 'label' }, 'View key'), view)),
    h('div', { class: 'stack-buttons' }, scan),
    note('A view key (mwview1…) sees payments to its address and their amounts, but cannot spend. Make one in a full wallet under Settings → Advanced → View key.'),
    title('New password'),
    group(...pw.rows),
    note('It unlocks this watch-only wallet in this browser.'),
    title('Start scanning at'),
    group(h('label', { class: 'row field' }, h('span', { class: 'label' }, 'Block'), birth)),
    note('Leave it empty to look through the whole chain.'),
    err,
    h('div', { class: 'stack-buttons' }, go));
    return { title: 'Watch an address', left: cancelButton(), els: [form], focus: () => view.focus() };
}

function openScreen() {
    const file = h('input', { type: 'file', accept: '.mww,application/octet-stream', hidden: true });
    const name = h('span', { class: 'value' }, 'None');
    const pw = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'The file’s password', 'aria-label': 'Password' });
    const err = note();
    err.classList.add('bad');
    file.addEventListener('change', () => { name.textContent = file.files && file.files[0] ? file.files[0].name : 'None'; });
    const go = h('button', { class: 'btn primary', type: 'submit' }, 'Open wallet');
    const form = h('form', { onsubmit: async (e) => {
        e.preventDefault();
        err.textContent = '';
        const f = file.files && file.files[0];
        if (!f) { err.textContent = 'Choose a wallet file first.'; return; }
        if (f.size > 64 * 1024 * 1024) { err.textContent = 'That file is too large to be a wallet.'; return; }
        go.disabled = true;
        fill(go, spinner(), 'Opening…');
        try {
            const bytes = await f.arrayBuffer();
            await ask('import', { bytes, password: pw.value }, [bytes]);
        } catch (x) { err.textContent = errOf(x); go.disabled = false; fill(go, 'Open wallet'); }
    } },
    group(h('button', { class: 'row link', type: 'button', onclick: () => file.click() }, h('span', { class: 'grow' }, 'Wallet file'), name),
        h('label', { class: 'row field' }, h('span', { class: 'label' }, 'Password'), pw)),
    file,
    note('A .mww file, from this wallet or from midwimble wallet on the command line. Scanning carries on where the file left off.'),
    err,
    h('div', { class: 'stack-buttons' }, go));
    return { title: 'Open file', left: cancelButton(), els: [form] };
}

// ── the wallet ──────────────────────────────────────────────────────────────

/** What the status line says, and whether it is busy or wrong. */
function syncStatus(s) {
    if (!navigator.onLine) return { text: 'Offline. This is what the wallet last saw.' };
    const n = app.net.status;
    if (n === 'none') return { text: 'No nodes set. Add one in Settings.', bad: true };
    if (n === 'failed') return { text: 'Can’t reach a node right now.', bad: true, detail: app.net.detail };
    if (n !== 'connected') return { text: 'Connecting…', busy: true };
    if (!s) return { text: 'Connecting…', busy: true };
    const c = s.chain;
    if (c.networkOk === false) return { text: 'The node is on another network.', bad: true, detail: s.syncError };
    if (!s.tip) return { text: 'Connecting…', busy: true };
    if (s.syncError) return { text: 'Can’t update. Trying again.', bad: true, detail: s.syncError };
    if (c.behind || c.nodeSyncing) return { text: 'Waiting for the network to catch up…', busy: true };
    if (s.scanned < s.tip) {
        const done = (s.scanned - s.birth) / Math.max(1, s.tip - s.birth);
        return { text: `Updating… ${Math.floor(done * 100)}%`, busy: true, progress: done };
    }
    const last = c.timestamp ? ` Last block ${ago(Date.now() / 1000 - c.timestamp)}.` : '';
    return { text: 'Up to date.' + last };
}

/** The balance. Built once and updated in place, so its spinner keeps
 *  turning between updates. */
function balanceView() {
    const amount = h('span');
    const extra = h('div', { class: 'extra' });
    const spin = spinner();
    const statusText = h('span', { role: 'status' });
    const status = h('button', { class: 'status', type: 'button' }, spin, statusText);
    const meter = bar(0, 'meter');
    let detail = null;
    status.addEventListener('click', () => { if (detail) ok(detail.title, detail.text); });
    const el = h('div', { class: 'balance' }, h('div', { class: 'caption' }, 'Balance'),
        h('div', { class: 'amount' }, amount, unit() ? h('span', { class: 'unit' }, unit()) : null),
        extra, status, meter);
    let lastKey = null;
    /** Smaller type for a balance too long for its line. */
    function fitAmount() {
        const line = amount.parentNode;
        for (let size = 52; size >= 24; size -= 2) {
            line.style.fontSize = size + 'px';
            if (line.scrollWidth <= line.clientWidth) break;
        }
    }
    addEventListener('resize', () => { if (el.isConnected) fitAmount(); });
    function draw() {
        const s = app.state;
        const st = syncStatus(s);
        const b = s ? s.balance : null;
        const key = JSON.stringify([st, b, settings.fullDecimals]);
        if (key === lastKey) return;
        lastKey = key;
        amount.textContent = b ? coins(b.spendable) : '—';
        fitAmount();
        const lines = [];
        if (b && b.incoming) lines.push(h('span', null, 'Arriving ', h('b', null, '+' + coins(b.incoming))));
        if (b && b.pending) lines.push(h('span', null, 'Pending ', h('b', null, coins(b.pending))));
        if (b && b.immature) lines.push(h('span', null, 'Maturing ', h('b', null, coins(b.immature))));
        fill(extra, ...lines);
        extra.hidden = !lines.length;
        spin.hidden = !st.busy;
        statusText.textContent = st.text;
        status.classList.toggle('bad', !!st.bad);
        detail = st.detail ? { title: st.text.replace(/[.…]+$/, ''), text: st.detail } : null;
        status.tabIndex = detail ? 0 : -1;
        status.style.cursor = detail ? 'pointer' : 'default';
        meter.hidden = st.progress == null;
        meter.firstChild.style.width = Math.min(100, Math.max(0, (st.progress || 0) * 100)) + '%';
    }
    return { el, draw };
}

const entryKey = e => e.tx_hash || (e.commitment ? 'c' + e.commitment : `${e.kind}-${e.height}-${e.value}`);
const KIND = { received: 'Received', mined: 'Mined', sent: 'Sent' };

function activitySub(e) {
    const state = {
        pending: e.kind === 'sent' ? 'Waiting for a block' : 'On its way',
        failed: 'Didn’t go through', cancelled: 'Released', immature: 'Maturing',
    }[e.status];
    const block = settings.technical && e.height != null ? `Block ${num(e.height)}` : null;
    const parts = [];
    if (e.kind === 'sent' && e.to) parts.push(`To ${shortAddr(e.to)}`);
    if (state) parts.push(state);
    if (block) parts.push(block);
    else if (!state) parts.push(e.created_at ? when(e.created_at) : blockAgo(e.height));
    return parts.join(', ');
}

function activityRow(e) {
    const t = e.kind === 'mined' ? tile('orange', 'star') : e.kind === 'received' ? tile('green', 'down') : tile('blue', 'up');
    const out = e.kind === 'sent';
    return h('a', { class: 'row link', href: '#/activity/' + encodeURIComponent(entryKey(e)) }, t,
        h('span', { class: 'grow' }, KIND[e.kind] || e.kind, h('span', { class: 'sub' }, activitySub(e))),
        h('span', { class: 'amt ' + (out ? 'amount-out' : 'amount-in') }, (out ? '−' : '+') + coins(e.value)));
}

function homeScreen() {
    const balance = balanceView();
    const recent = h('div');
    let lastKey = null;
    return {
        wide: true,
        els: [h('div', { class: 'home-top' }, balance.el,
            h('div', { class: 'buttons' },
                app.state && app.state.watchOnly
                    ? h('span', { class: 'pill' }, 'Watch-only')
                    : h('a', { class: 'btn primary', href: '#/send' }, icon('up'), 'Send'),
                h('a', { class: 'btn secondary', href: '#/receive' }, icon('down'), 'Receive'))),
            recent],
        update() {
            balance.draw();
            const s = app.state;
            if (!s) return;
            const items = s.history.slice(0, 5);
            const key = JSON.stringify([items, s.history.length, s.tip, settings.technical, settings.fullDecimals]);
            if (key === lastKey) return;
            lastKey = key;
            fill(recent, title('Recent activity'),
                group(...(items.length ? items.map(activityRow)
                    : [textRow(s.scanned < s.tip ? 'Nothing yet. Still looking through the chain.' : 'Nothing yet. To get paid, choose Receive and share your address.')]),
                s.history.length > items.length ? linkRow('All activity', '#/activity', { value: num(s.history.length) }) : null));
        },
    };
}

function activityScreen() {
    const body = h('div');
    let lastKey = null;
    return {
        title: 'Activity',
        back: ['Wallet', '#/'],
        els: [body],
        update() {
            const s = app.state;
            if (!s) return;
            const key = JSON.stringify([s.history, s.tip, settings.technical, settings.fullDecimals]);
            if (key === lastKey) return;
            lastKey = key;
            const waiting = s.history.filter(e => e.status === 'pending');
            const rest = s.history.filter(e => e.status !== 'pending');
            fill(body,
                waiting.length ? [title('Waiting for a block'), group(...waiting.map(activityRow))] : null,
                rest.length ? [title(waiting.length ? 'Earlier' : 'All activity'), group(...rest.map(activityRow))] : null,
                s.history.length ? note('Change is folded into the payment that made it.') : group(textRow('Nothing yet.')));
        },
    };
}

function activityItemScreen(key) {
    const body = h('div');
    let lastKey = null;
    const first = app.state && app.state.history.find(x => entryKey(x) === key);
    const screen = {
        title: first ? KIND[first.kind] || 'Payment' : 'Payment',
        back: ['Activity', '#/activity'],
        els: [body],
        update() {
            const s = app.state;
            if (!s) return;
            const e = s.history.find(x => entryKey(x) === key);
            const k = JSON.stringify([e, s.tip, settings.technical, settings.fullDecimals]);
            if (k === lastKey) return;
            lastKey = k;
            if (!e) { fill(body, group(textRow('This payment is no longer in the list.'))); return; }
            const out = e.kind === 'sent';
            const status = {
                confirmed: 'Confirmed', pending: out ? 'Waiting for a block' : 'On its way', failed: 'Didn’t go through',
                cancelled: 'Released', immature: 'Maturing',
            }[e.status] || e.status;
            const mature = app.constants ? app.constants.coinbase_maturity : 100;
            const rows = [
                infoRow('Status', status),
                out && e.to ? h('div', { class: 'row stacked' }, h('span', { class: 'label' }, 'To'), h('span', { class: 'mono' }, e.to),
                    h('div', { class: 'inline-buttons' }, mini('Copy', 'copy', () => copyText(e.to, 'Address')))) : null,
                e.fee != null ? infoRow('Fee', coins(e.fee)) : null,
                e.created_at || e.height != null ? infoRow('When', e.created_at ? when(e.created_at) : blockAgo(e.height)) : null,
            ];
            const technical = settings.technical ? [
                e.tx_hash ? h('div', { class: 'row stacked' }, h('span', { class: 'label' }, 'Transaction'), h('span', { class: 'mono' }, e.tx_hash),
                    h('div', { class: 'inline-buttons' }, mini('Copy', 'copy', () => copyText(e.tx_hash, 'Hash')))) : null,
                e.commitment ? h('div', { class: 'row stacked' }, h('span', { class: 'label' }, 'Coin'), h('span', { class: 'mono' }, e.commitment)) : null,
                e.height != null ? infoRow('Block', num(e.height)) : null,
            ].filter(Boolean) : [];
            const notes = [];
            if (!e.detailed) notes.push(note('Made from another copy of this wallet, or before it was restored. The amount includes the fee.'));
            if (e.status === 'failed') notes.push(note('Another copy of this wallet spent the same coins first.'));
            if (e.status === 'pending' && !out) notes.push(note('It becomes spendable once a block includes it.'));
            if (e.status === 'immature') notes.push(note(`Mined coins can be spent ${mature} blocks after their block.`));
            fill(body,
                h('div', { class: 'detail-head' },
                    h('div', { class: 'big ' + (out ? 'amount-out' : 'amount-in') }, (out ? '−' : '+') + withUnit(e.value)),
                    h('div', { class: 'what' }, KIND[e.kind] || e.kind)),
                group(...rows.filter(Boolean)),
                ...notes,
                technical.length ? [title('Technical'), group(...technical)] : null,
                out && e.status === 'pending' && e.tx_hash ? [
                    h('div', { class: 'stack-buttons' }, h('button', { class: 'btn danger', type: 'button', onclick: () => release(e.tx_hash) }, 'Release coins')),
                    note('If this payment will never go through, release its coins to spend them again. If it goes through anyway, the wallet still records it.')] : null);
        },
    };
    return screen;
}

async function release(txHash) {
    const go = await actionSheet('Release this payment’s coins? Do this only if it will never go through.',
        [{ label: 'Release coins', value: true, cls: 'danger' }, { label: 'Cancel', value: null, cls: 'plain' }]);
    if (!go) return;
    try { await ask('cancel', { tx_hash: txHash }); hud('Released'); } catch (e) { ok('Not released', errOf(e)); }
}

// ── sending ─────────────────────────────────────────────────────────────────

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

/** A node-link QR (`midwimble:node?a=<multiaddr>&follow=1`), the kind
 *  `midwimble link` shows. Returns { addrs, follow } with the dialable
 *  WebRTC addresses, or null if the text isn't a node link. */
function nodeLink(text) {
    const m = /^midwimble:node(?:\?([^#]*))?$/i.exec(String(text).trim());
    if (!m) return null;
    const q = new URLSearchParams(m[1] || '');
    const re = /^\/(ip4|ip6|dns4|dns6|dns)\/.+\/webrtc-direct\/certhash\/.+\/p2p\/.+/;
    const addrs = q.getAll('a').map(s => s.trim()).filter(a => re.test(a));
    if (!addrs.length) return null;
    return { addrs, follow: q.get('follow') === '1' };
}

/** A watch-only link: a bare `mwview1…` view key, or
 *  `midwimble:watch?view=<view key>&a=<node addr>` which also names a node
 *  to use. Returns { viewKey, node } or null. */
function watchLink(text) {
    const t = String(text).trim();
    const viewRe = /^mwview1[0-9a-z]+$/i;
    const nodeRe = /^\/(ip4|ip6|dns4|dns6|dns)\/.+\/webrtc-direct\/certhash\/.+\/p2p\/.+/;
    if (viewRe.test(t)) return { viewKey: t, node: null };
    const m = /^midwimble:watch(?:\?([^#]*))?$/i.exec(t);
    if (!m) return null;
    const q = new URLSearchParams(m[1] || '');
    const viewKey = (q.get('view') || '').trim();
    if (!viewRe.test(viewKey)) return null;
    const node = (q.get('a') || '').trim();
    return { viewKey, node: nodeRe.test(node) ? node : null };
}

function sendScreen() {
    if (app.state && app.state.watchOnly) {
        return { title: 'Send', els: [group(textRow('This is a watch-only wallet: it can see payments to its address but holds no keys to spend them.'))] };
    }
    const d = app.draft;
    const to = textArea({ placeholder: 'mw1…', 'aria-label': 'Send to' }, d.to);
    const amt = h('input', { inputmode: 'decimal', autocomplete: 'off', placeholder: '0.00', 'aria-label': 'Amount' });
    amt.value = d.amount;
    const quoteNote = note();
    const coinsBox = h('div');
    const waitingBox = h('div');
    let qtimer = null;
    let quoteText = '';
    const drawQuote = () => {
        const s = app.state;
        quoteNote.classList.toggle('bad', /^!/.test(quoteText));
        quoteNote.textContent = quoteText.replace(/^!/, '') || (s ? `You can send up to ${withUnit(s.max)}.` : '');
    };
    const requote = () => {
        clearTimeout(qtimer);
        const v = amt.value.trim();
        if (!v) { quoteText = ''; drawQuote(); return; }
        qtimer = setTimeout(async () => {
            try {
                const q = await ask('quote', { amount: v, coins: d.coins });
                quoteText = `Network fee ${coins(q.fee)}${q.change ? `, and ${coins(q.change)} comes back as change` : ''}.`;
            } catch (e) {
                quoteText = '!' + capital(errOf(e));
            }
            drawQuote();
        }, 250);
    };
    to.addEventListener('input', () => { d.to = to.value; toRow.classList.remove('bad'); });
    amt.addEventListener('input', () => { d.amount = amt.value; requote(); });
    const paste = navigator.clipboard && navigator.clipboard.readText ? mini('Paste', 'paste', async () => {
        try {
            const code = paymentCode(await navigator.clipboard.readText());
            to.value = d.to = code.address;
            to.fit();
            if (code.amount) { amt.value = d.amount = code.amount; requote(); }
        } catch (_) { ok('Can’t paste', 'This browser blocks reading the clipboard here. Paste into the field instead.'); }
    }) : null;
    const scan = mini('Scan', 'scan', async () => {
        const got = await scanPayment();
        if (!got) return;
        to.value = d.to = got.address;
        to.fit();
        toRow.classList.remove('bad');
        if (got.amount) { amt.value = d.amount = got.amount; requote(); }
        hud(got.amount ? 'Address and amount scanned' : 'Address scanned');
    });
    const max = mini('Max', null, async () => {
        try {
            const r = await ask('max', { coins: d.coins });
            amt.value = d.amount = plain(r.max);
            requote();
        } catch (e) { ok('Can’t tell', errOf(e)); }
    });
    const toRow = h('div', { class: 'row stacked' }, h('span', { class: 'label' }, 'To'), to, h('div', { class: 'inline-buttons' }, paste, scan));
    const amtRow = h('label', { class: 'row field' }, h('span', { class: 'label' }, 'Amount'), amt, max);
    const review = h('button', { class: 'btn primary', type: 'submit' }, 'Review payment');
    const form = h('form', { onsubmit: async (e) => {
        e.preventDefault();
        const dest = to.value.trim();
        try { await ask('check-address', { to: dest }); toRow.classList.remove('bad'); }
        catch (x) { toRow.classList.add('bad'); quoteText = '!That isn’t a midwimble address. It starts with mw1.'; drawQuote(); return; }
        let q;
        try { q = await ask('quote', { amount: amt.value.trim(), coins: d.coins }); }
        catch (x) { quoteText = '!' + capital(errOf(x)); drawQuote(); return; }
        const own = app.state && dest === app.state.address;
        const go = await actionSheet([`Send `, h('b', null, withUnit(q.amount)), ` to ${shortAddr(dest)}${own ? ' (this wallet)' : ''}? The network fee is ${coins(q.fee)}, for ${withUnit(q.amount + q.fee)} in all.`],
            [{ label: 'Send payment', value: true, cls: 'primary' }, { label: 'Cancel', value: null, cls: 'plain' }]);
        if (!go) return;
        if (settings.passwordToSend) {
            const password = await askPassword('Password', 'Type your password to send this payment.');
            if (!password) return;
            try { await ask('verify-password', { password }); } catch (x) { ok('Not sent', errOf(x)); return; }
        }
        const done = hudBusy('Sending…');
        try {
            const r = await ask('send', { to: dest, amount: amt.value.trim(), coins: d.coins });
            done();
            app.sent = { amount: r.amount, fee: r.fee, to: dest };
            app.draft = { to: '', amount: '', coins: [] };
            location.hash = '#/send/done';
        } catch (x) {
            done();
            ok('Payment not sent', capital(errOf(x)));
        }
    } },
    group(toRow, amtRow), quoteNote, coinsBox,
    h('div', { class: 'stack-buttons' }, review));
    let lastKey = null;
    drawQuote();
    if (d.amount) requote();
    return {
        title: 'Send',
        back: ['Wallet', '#/'],
        els: [form, waitingBox],
        update() {
            const s = app.state;
            if (!s) return;
            if (!quoteText) drawQuote();
            const waiting = s.history.filter(e => e.kind === 'sent' && e.status === 'pending');
            const key = JSON.stringify([waiting, d.coins, settings.coinControl, settings.feeLevel, settings.feeRate, settings.fullDecimals]);
            if (key === lastKey) return;
            lastKey = key;
            fill(coinsBox,
                settings.coinControl ? group(linkRow('Coins', '#/send/coins', { value: d.coins.length ? `${d.coins.length} chosen` : 'Automatic' })) : null,
                settings.feeLevel !== 1 ? note(`Paying ${feeLabel().toLowerCase()} fees (Settings, Sending).`) : null);
            fill(waitingBox, waiting.length ? [title('Waiting for a block'), group(...waiting.map(activityRow)),
                note(`Sent again every ${Math.round(settings.rebroadcastSecs / 60)} minute${settings.rebroadcastSecs >= 120 ? 's' : ''} until a block takes it.`)] : null);
        },
    };
}
const capital = t => t.charAt(0).toUpperCase() + t.slice(1).replace(/([^.!?])$/, '$1.');

function coinPickerScreen() {
    const d = app.draft;
    const body = h('div');
    let list = null;
    const draw = () => {
        if (!list) { fill(body, h('div', { class: 'empty-note' }, spinner())); return; }
        const usable = list.filter(c => c.status === 'spendable');
        const chosen = new Set(d.coins);
        const total = usable.filter(c => chosen.has(c.commitment)).reduce((a, c) => a + c.value, 0);
        fill(body,
            group(checkRow('Automatic', !d.coins.length, () => { d.coins = []; draw(); }, 'Largest coins first')),
            usable.length ? [title('Spendable coins'), group(...usable.map(c => checkRow(coins(c.value), chosen.has(c.commitment), () => {
                if (chosen.has(c.commitment)) d.coins = d.coins.filter(x => x !== c.commitment);
                else d.coins = [...d.coins, c.commitment];
                draw();
            }, (c.coinbase ? 'Mined, ' : 'Received, ') + (settings.technical ? `block ${num(c.height)}, ${c.commitment.slice(0, 12)}…` : blockAgo(c.height)))))]
                : group(textRow('No coins can be spent right now.')),
            note(d.coins.length ? `${d.coins.length} chosen, holding ${coins(total)}. The payment spends all of them; the rest comes back as change.` : 'The wallet picks the coins.'));
    };
    ask('coins').then(l => { list = l; draw(); }, e => ok('Can’t list coins', errOf(e)));
    draw();
    return { title: 'Coins', back: ['Send', '#/send'], els: [body] };
}

function sentScreen() {
    const s = app.sent;
    if (!s) return homeScreen();
    return {
        title: 'Sent',
        right: h('a', { class: 'btn primary small', href: '#/' }, 'Done'),
        els: [h('div', { class: 'done-mark' }, icon('check')),
            h('div', { class: 'detail-head' }, h('div', { class: 'big' }, withUnit(s.amount)), h('div', { class: 'what' }, `On its way to ${shortAddr(s.to)}`)),
            note(`It confirms with the next block, usually within a few minutes. The network fee was ${coins(s.fee)}.`),
            h('div', { class: 'stack-buttons' }, h('a', { class: 'btn secondary', href: '#/' }, 'Done'))],
    };
}

// ── scanning a payment's QR code ────────────────────────────────────────────

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
            return 'Another app is using the camera. Close it, or choose a photo of the code.';
        default:
            return `The camera didn’t start (${errOf(e)}). Choose a photo of the code instead.`;
    }
}

/** Reads a payment's QR code with the camera, or from a photo or
 *  screenshot. Resolves with { address, amount } once a code holds a
 *  midwimble address, or null if closed. The camera is off again by then. */
let scanning = false;
async function runScanner(opts) {
    if (scanning) return null;
    scanning = true;
    try { return await scanner(opts); } finally { scanning = false; }
}

/** Scans a payment QR: resolves { address, amount } once a code holds a
 *  midwimble address, or null if closed. */
function scanPayment() {
    return runScanner({
        prompt: 'Point the camera at the recipient’s QR code.',
        reject: 'That QR code isn’t a midwimble address.',
        recognize: async (text) => {
            const code = paymentCode(text);
            try { await ask('check-address', { to: code.address }); } catch (_) { return null; }
            return code;
        },
    });
}

/** Scans a node-link QR (from `midwimble link`): resolves { addrs, follow },
 *  or null if closed. */
function scanNodeLink() {
    return runScanner({
        prompt: 'Point the camera at your node’s QR code.',
        reject: 'That QR code isn’t a node link.',
        recognize: async (text) => nodeLink(text),
    });
}

/** Scans a watch-only QR (a view key): resolves { viewKey, node }, or null. */
function scanWatchLink() {
    return runScanner({
        prompt: 'Point the camera at the view-key QR code.',
        reject: 'That QR code isn’t a view key.',
        recognize: async (text) => watchLink(text),
    });
}

async function scanner({ recognize, prompt, reject }) {
    let qr;
    try { qr = await import('./qr_scan.js'); }
    catch (e) { ok('Can’t scan', `The QR reader didn’t load: ${errOf(e)}`); return null; }
    const canCamera = qr.cameraSupported();
    const video = h('video', { playsinline: true, autoplay: true, muted: true });
    video.muted = true;
    video.playsInline = true;
    const view = h('div', { class: 'scanner-view', hidden: !canCamera }, video);
    const status = h('p', { 'aria-live': 'polite' });
    const say = (text) => { status.textContent = text; };
    const file = h('input', { type: 'file', accept: 'image/*', hidden: true });
    const flip = h('button', { class: 'btn secondary', type: 'button', hidden: true }, 'Switch camera');
    const camera = new qr.Camera(video);
    let done = false;
    let finish = null;
    let rejected = null;
    let active = false;
    let paused = false;
    let wanted = null;
    let run = 0;
    camera.onended = () => {
        if (done) return;
        run++;
        active = false;
        view.hidden = true;
        say('The camera stopped. Choose a photo of the code, or cancel and scan again.');
    };
    const consider = async (text) => {
        if (text == null || done || text === rejected) return;
        const result = await recognize(text);
        if (!result) {
            if (done) return;
            rejected = text;
            say(reject);
            return;
        }
        if (done) return;
        done = true;
        view.classList.add('found');
        setTimeout(() => finish(result), 200);
    };
    const watch = async (me) => {
        while (!done && me === run && camera.live) {
            let text = null;
            try { text = await camera.read(); } catch (e) {
                if (me === run) say(`The QR reader failed (${errOf(e)}). Choose a photo of the code instead.`);
                return;
            }
            await consider(text);
            await sleep(100);
        }
    };
    const startCamera = async (deviceId) => {
        const me = ++run;
        if (!canCamera) { say('This browser can’t use a camera here. Choose a photo of the code instead.'); return; }
        active = true;
        say('Starting the camera…');
        try { await camera.start(deviceId); } catch (e) {
            if (done || me !== run) return;
            active = false;
            view.hidden = true;
            say(cameraTrouble(e));
            return;
        }
        if (done) return;
        if (me !== run) { if (paused) camera.stop(); return; }
        wanted = camera.deviceId();
        view.hidden = false;
        rejected = null;
        say(prompt);
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
        try { text = await qr.readImageFile(f); } catch (e) { say(`That file can’t be read as a picture (${errOf(e)}).`); return; }
        if (text == null) { say('No QR code in that picture. Try a sharper or closer one.'); return; }
        rejected = null;
        await consider(text);
    });
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
    const closed = openSheet(close => {
        finish = close;
        return [view, status, file,
            h('button', { class: 'btn secondary', type: 'button', onclick: () => file.click() }, 'Choose photo'),
            flip,
            h('button', { class: 'btn plain', type: 'button', onclick: () => close(null) }, 'Cancel')];
    });
    startCamera(null);
    const result = await closed;
    done = true;
    run++;
    document.removeEventListener('visibilitychange', onVisibility);
    camera.close();
    return result;
}

// ── receiving ───────────────────────────────────────────────────────────────

function receiveScreen() {
    const card = h('div', { class: 'qr-card' });
    const addrText = h('span', { class: 'mono' });
    const request = h('input', { inputmode: 'decimal', autocomplete: 'off', placeholder: 'Any', 'aria-label': 'Amount to ask for' });
    let drawn = null;
    const draw = () => {
        const s = app.state;
        if (!s) return;
        const amount = request.value.trim();
        const valid = /^\d+(\.\d{1,8})?$/.test(amount) && Number(amount) > 0;
        const code = valid ? `midwimble:${s.address}?amount=${amount}` : s.address.toUpperCase();
        if (code === drawn) return;
        drawn = code;
        fill(card, qrSvg(code, 'M'));
        addrText.textContent = s.address;
    };
    request.addEventListener('input', draw);
    const shareable = typeof navigator.share === 'function';
    return {
        title: 'Receive',
        back: ['Wallet', '#/'],
        wide: true,
        els: [h('div', { class: 'receive-grid' },
            h('div', { class: 'qr-col' }, card, note('Anyone can pay you with this code or the address.')),
            h('div', { class: 'info-col' },
                group(h('div', { class: 'row stacked' }, h('span', { class: 'label' }, 'Your address'), addrText)),
                h('div', { class: 'actions' },
                    h('button', { class: 'btn secondary', type: 'button', onclick: () => app.state && copyText(app.state.address, 'Address') }, icon('copy'), 'Copy address'),
                    shareable ? h('button', { class: 'btn secondary', type: 'button', onclick: () => app.state && navigator.share({ text: app.state.address }).catch(() => {}) }, icon('share'), 'Share') : null),
                title('Ask for an amount'),
                group(h('label', { class: 'row field' }, h('span', { class: 'label' }, 'Amount'), request)),
                note('The code then carries the amount too. Use the address as often as you like: payers can’t see each other, your balance, or your other payments.')))],
        update: draw,
    };
}

// ── settings ────────────────────────────────────────────────────────────────

const AUTOLOCK = [[0, 'Never'], [1, '1 minute'], [5, '5 minutes'], [15, '15 minutes'], [60, '1 hour'], [240, '4 hours']];
const autoLockLabel = () => (AUTOLOCK.find(([v]) => v === settings.autoLock) || [0, `${settings.autoLock} minutes`])[1];
function feeLabel() {
    if (settings.feeLevel === 0) return 'Custom';
    return { 1: 'Standard', 2: 'Faster', 5: 'Fastest' }[settings.feeLevel] || `${settings.feeLevel}×`;
}

function settingsScreen() {
    const netValue = h('span');
    const install = h('div', { hidden: !installPrompt }, group(h('button', { class: 'row link', type: 'button', onclick: installApp },
        tile('blue', 'install'), h('span', { class: 'grow' }, 'Install as an app', h('span', { class: 'sub' }, 'Open the wallet from your home screen or dock, in its own window')))));
    return {
        title: 'Settings',
        back: ['Wallet', '#/'],
        els: [install, group(
            linkRow('Backup', '#/settings/backup', { tile: tile('green', 'backup') }),
            linkRow('Security', '#/settings/security', { tile: tile('gray', 'lock'), value: autoLockLabel() })),
        group(
            h('a', { class: 'row link', href: '#/settings/network' }, tile('blue', 'globe'), h('span', { class: 'grow' }, 'Network'), h('span', { class: 'value' }, netValue)),
            linkRow('Privacy', '#/settings/privacy', { tile: tile('purple', 'eye'), value: settings.wholeBlocks ? 'Every block' : 'Standard' }),
            linkRow('Sending', '#/settings/sending', { tile: tile('orange', 'plane'), value: feeLabel() }),
            linkRow('Advanced', '#/settings/advanced', { tile: tile('steel', 'sliders') })),
        group(linkRow('About', '#/settings/about', { tile: tile('sky', 'info') })),
        group(actionRow('Lock wallet', () => ask('lock').catch(() => {}))),
        h('div', { class: 'stack-buttons' }, h('button', { class: 'btn danger', type: 'button', onclick: forget }, 'Forget this wallet')),
        note('Removes the wallet from this browser. Its recovery phrase or a wallet file brings it back.')],
        update() {
            netValue.textContent = app.pool.length === 1 ? '1 node' : `${app.pool.length} nodes`;
            install.hidden = !installPrompt;
        },
    };
}

function backupScreen() {
    const watchOnly = app.state && app.state.watchOnly;
    const els = [];
    if (!watchOnly) {
        els.push(group(h('button', { class: 'row link', type: 'button', onclick: async () => {
            const password = await askPassword('Recovery phrase', 'Type your password to see the 24 words.');
            if (!password) return;
            try {
                const { phrase } = await ask('reveal', { password });
                app.phrase = phrase;
                location.hash = '#/settings/backup/phrase';
            } catch (e) { ok('Can’t show', errOf(e)); }
        } }, tile('green', 'file'), h('span', { class: 'grow' }, 'Show recovery phrase'))));
        els.push(note('The 24 words restore everything that matters, on any device.'));
    } else {
        els.push(note('This is a watch-only wallet: it has no recovery phrase. The view key that set it up sees payments but cannot spend.'));
    }
    els.push(group(h('button', { class: 'row link', type: 'button', onclick: async () => {
        const password = await askPassword('Wallet file', 'Type your password. The file is locked with it too.');
        if (!password) return;
        try {
            const { bytes } = await ask('exportFile', { password });
            download(bytes, 'midwimble-wallet.mww');
            hud('Downloaded');
        } catch (e) { ok('Can’t save', errOf(e)); }
    } }, tile('blue', 'download'), h('span', { class: 'grow' }, 'Download wallet file'))));
    els.push(note('The file also keeps your history and where scanning got to. midwimble wallet on the command line opens it too.'));
    return { title: 'Backup', back: ['Settings', '#/settings'], els };
}

function phraseScreen() {
    const words = app.phrase ? app.phrase.split(' ') : null;
    if (!words) return backupScreen();
    return {
        title: 'Recovery phrase',
        back: ['Backup', '#/settings/backup'],
        els: [h('div', { class: 'paper' }, words.map((w, i) => h('span', null, h('i', null, i + 1), w))),
            note('Write these down, in order. Anyone who sees them can spend this wallet.'),
            h('div', { class: 'stack-buttons' }, h('a', { class: 'btn secondary', href: '#/settings/backup' }, 'Done'))],
        leave() { app.phrase = null; },
    };
}

function securityScreen() {
    return {
        title: 'Security',
        back: ['Settings', '#/settings'],
        els: [group(linkRow('Auto-Lock', '#/settings/security/autolock', { value: autoLockLabel() })),
            group(switchRow('Password to send', 'passwordToSend')),
            note('Ask for the password before each payment.'),
            group(linkRow('Change password', '#/settings/security/password')),
            group(actionRow('Lock now', () => ask('lock').catch(() => {})))],
    };
}

function autoLockScreen() {
    const body = h('div');
    const draw = () => fill(body, group(...AUTOLOCK.map(([v, label]) => checkRow(label, settings.autoLock === v, () => { set('autoLock', v); draw(); }))),
        note('Lock the wallet after this long without use. Unlocking it takes the password.'));
    draw();
    return { title: 'Auto-Lock', back: ['Security', '#/settings/security'], els: [body] };
}

function passwordScreen() {
    const old = h('input', { type: 'password', autocomplete: 'current-password', 'aria-label': 'Current password' });
    const pw = passwordRows();
    const err = note();
    err.classList.add('bad');
    const save = async () => {
        err.textContent = '';
        let next;
        try { next = pw.value(); } catch (x) { err.textContent = errOf(x); return; }
        try {
            await ask('change-password', { old: old.value, password: next });
            hud('Password changed');
            location.hash = '#/settings/security';
        } catch (x) { err.textContent = errOf(x); }
    };
    return {
        title: 'Password',
        back: ['Security', '#/settings/security'],
        right: h('button', { class: 'btn primary small', type: 'button', onclick: save }, 'Save'),
        els: [h('form', { onsubmit: (e) => { e.preventDefault(); save(); } },
            group(h('label', { class: 'row field' }, h('span', { class: 'label' }, 'Current'), old)),
            group(...pw.rows), err,
            note('The wallet stays locked with the new password in this browser. Wallet files saved before keep the old one.'),
            h('button', { type: 'submit', hidden: true }))],
        focus: () => old.focus(),
    };
}

/** The network's screens: `sub` is what follows `base` in the address. */
function networkRoute(sub, base, back) {
    if (sub === 'list') return nodeListScreen(base);
    const m = /^node\/(.+)$/.exec(sub);
    if (m) return nodeScreen(decodeURIComponent(m[1]), base);
    return networkScreen(base, back);
}

function nodeSub(p) {
    const parts = [];
    if (p.height) parts.push(`Block ${num(p.height - 1)}`);
    if (p.ms != null) parts.push(`${p.ms} ms`);
    return parts.join(', ');
}

function networkScreen(base, back) {
    const nodesBox = h('div');
    let lastKey = null;
    const list = customNodes() ? `Yours (${nodeList().length})` : 'Default';
    return {
        title: 'Network',
        back,
        els: [nodesBox,
            title('Connections'),
            group(segRow('Nodes at once', 'poolSize', [[1, '1'], [2, '2'], [3, '3'], [4, '4'], [5, '5']])),
            note('The wallet follows the chain through one of them, picked at random, and fetches blocks from all of them.'),
            group(switchRow('Find more nodes', 'discover')),
            note('Ask the nodes you reach where other nodes are. Off, or with a node list of your own, the wallet uses only its list.'),
            group(switchRow('Cross-Check', 'vote')),
            note('With three nodes or more, the node you follow is replaced if the others disagree with it about the chain.'),
            group(linkRow('Node list', base + '/list', { value: list }),
                actionRow('Forget found nodes', () => { saveFound([]); connect(); hud('Forgotten'); })),
            note('A node serves browser wallets when it is built with --features webrtc and its UDP port (TCP + 2) is open.')],
        update() {
            const key = JSON.stringify([app.pool, app.net, settings.follow]);
            if (key === lastKey) return;
            lastKey = key;
            const rows = app.pool.map(p => linkRow(hostOf(p.addr), base + '/node/' + encodeURIComponent(p.addr),
                { sub: nodeSub(p), value: p.followed ? 'Chosen' : p.primary ? 'Following' : '' }));
            const status = app.net.status === 'failed' ? `No node reachable. ${app.net.detail || ''}`
                : app.net.status === 'none' ? 'No nodes in the list.' : 'Connecting…';
            fill(nodesBox, title('Nodes'), group(...(rows.length ? rows : [textRow(status)])));
        },
    };
}

function nodeScreen(addr, base) {
    const body = h('div');
    let lastKey = null;
    return {
        title: hostOf(addr),
        back: ['Network', base],
        els: [body],
        update() {
            const p = app.pool.find(x => x.addr === addr);
            const key = JSON.stringify([p, settings.follow]);
            if (key === lastKey) return;
            lastKey = key;
            const chosen = settings.follow === addr;
            fill(body,
                group(h('div', { class: 'row stacked' }, h('span', { class: 'label' }, 'Address'), h('span', { class: 'mono' }, addr),
                    h('div', { class: 'inline-buttons' }, mini('Copy', 'copy', () => copyText(addr, 'Address'))))),
                p ? group(
                    infoRow('Status', p.primary ? 'Following' : 'Connected'),
                    infoRow('Chain height', num(Math.max(0, p.height - 1))),
                    infoRow('Response time', p.ms != null ? `${p.ms} ms` : '—'),
                    infoRow('Requests', num(p.requests)),
                    infoRow('Failed', num(p.failures)),
                    infoRow('Received', `${(p.bytes / 1024).toFixed(p.bytes > 1024 * 1024 ? 0 : 1)} KB`),
                    infoRow('Source', p.found ? 'Found by a node' : 'Node list')) : group(textRow('Not connected now.')),
                h('div', { class: 'stack-buttons' }, chosen
                    ? h('button', { class: 'btn secondary', type: 'button', onclick: () => { set('follow', ''); hud('Any node'); } }, 'Stop choosing this node')
                    : h('button', { class: 'btn primary', type: 'button', onclick: () => { set('follow', addr); hud('Chosen'); } }, 'Always follow this node')),
                note(chosen ? 'The wallet follows this node whenever it is connected, and doesn’t check it against the others.'
                    : 'Follow this node whenever it is connected, as when it is your own.'));
        },
    };
}

function nodeListScreen(base) {
    const ta = textArea({ rows: 4, placeholder: '/ip4/…/udp/9435/webrtc-direct/certhash/…/p2p/…', 'aria-label': 'Node addresses' }, nodeList().join('\n'));
    const err = note();
    err.classList.add('bad');
    const save = async () => {
        const list = ta.value.split(/\s+/).map(s => s.trim()).filter(Boolean);
        const bad = list.find(a => !/^\/(ip4|ip6|dns4|dns6|dns)\/.+\/webrtc-direct\/certhash\/.+\/p2p\/.+/.test(a));
        if (bad) { err.textContent = `Not a WebRTC address: ${shortAddr(bad)}`; return; }
        try { list.length ? localStorage.setItem(KEY.nodes, JSON.stringify(list)) : localStorage.removeItem(KEY.nodes); } catch (_) {}
        hud(list.length ? 'Saved' : 'Using defaults');
        location.hash = base;
        await connect();
    };
    return {
        title: 'Node list',
        back: ['Network', base],
        right: h('button', { class: 'btn primary small', type: 'button', onclick: save }, 'Save'),
        els: [group(h('label', { class: 'row stacked' }, h('span', { class: 'label' }, 'WebRTC addresses, one per line'), ta)), err,
            note('A node logs its address at start (“Browser wallets can connect to …”) and lists it under webrtc_addrs in /state.'),
            group(actionRow('Scan node QR', async () => {
                const link = await scanNodeLink();
                if (!link) return;
                try { localStorage.setItem(KEY.nodes, JSON.stringify(link.addrs)); } catch (_) {}
                if (link.follow) set('follow', link.addrs[0]); else update();
                hud('Linked to your node');
                await connect();
            })),
            note('Run “midwimble link” on your node to show a QR, then scan it to use your own node.'),
            group(actionRow('Use default nodes', async () => {
                try { localStorage.removeItem(KEY.nodes); } catch (_) {}
                ta.value = (app.config.nodes || []).join('\n');
                ta.fit();
                hud('Using defaults');
                await connect();
            }))],
    };
}

function privacyScreen() {
    return {
        title: 'Privacy',
        back: ['Settings', '#/settings'],
        els: [group(switchRow('Download every block', 'wholeBlocks')),
            note('Normally the wallet reads a few dozen bytes of each block and fetches only the blocks that may be yours. Downloading every block tells the nodes nothing, for about ten times the data.'),
            title('Decoys'),
            group(segRow('Blocks added', 'decoys', [[0, 'None'], [1, '1'], [3, '3'], [5, '5'], [8, '8']]),
                segRow('Drawn from', 'decoyWindow', [[100, '100'], [1000, '1,000'], [10000, '10,000']])),
            note('Each block the wallet needs comes with this many others from the blocks around it, so no node can tell which one mattered.'),
            group(switchRow('Spread requests', 'spread')),
            note('Send each block request to a node picked at random, so that no one node sees them all.')],
    };
}

function sendingScreen() {
    const body = h('div');
    const draw = () => {
        const rate = h('input', { inputmode: 'numeric', autocomplete: 'off', placeholder: String(minRate()), value: settings.feeRate ? String(settings.feeRate) : '', 'aria-label': 'Fee rate' });
        rate.addEventListener('change', () => {
            const v = Number(rate.value.trim());
            if (Number.isInteger(v) && v >= minRate()) set('feeRate', v);
            else { rate.value = settings.feeRate ? String(settings.feeRate) : ''; ok('Fee rate', `Use a whole number of at least ${minRate()}.`); }
        });
        const level = (v, label, sub) => checkRow(label, settings.feeLevel === v, () => { set('feeLevel', v); draw(); }, sub);
        fill(body,
            title('Network fee'),
            group(level(1, 'Standard', 'The relay minimum'), level(2, 'Faster', 'Twice the minimum'), level(5, 'Fastest', 'Five times the minimum'), level(0, 'Custom')),
            settings.feeLevel === 0 ? group(h('label', { class: 'row field' }, h('span', { class: 'label' }, 'Rate'), rate, h('span', { class: 'value' }, 'per weight'))) : null,
            note(`The minimum is ${minRate()} base units per unit of weight. A higher fee can help a payment into a full block.`),
            group(switchRow('Choose coins myself', 'coinControl')),
            note('Pick the coins each payment spends, under Send.'));
    };
    draw();
    return { title: 'Sending', back: ['Settings', '#/settings'], els: [body] };
}

function advancedScreen() {
    return {
        title: 'Advanced',
        back: ['Settings', '#/settings'],
        els: [group(switchRow('Technical details', 'technical'), switchRow('All decimal places', 'fullDecimals')),
            note('Show block numbers, transaction hashes and coin commitments, and amounts to all eight decimal places.'),
            title('Scanning'),
            group(segRow('Per request', 'scanPerRequest', [[500, '500'], [1000, '1,000'], [2000, '2,000']]),
                segRow('Fetch ahead', 'fetchAhead', [[2, '2'], [8, '8'], [16, '16']])),
            note('Blocks of scan data each request asks for, and blocks fetched ahead of the scan.'),
            title('Waiting payments'),
            group(switchRow('Watch for incoming', 'watchMempool'),
                segRow('Look every', 'mempoolSecs', [[5, '5 s'], [15, '15 s'], [60, '1 min']]),
                segRow('Resend every', 'rebroadcastSecs', [[60, '1 min'], [120, '2 min'], [600, '10 min']])),
            note('Payments to you show as soon as they reach a node. Your own are sent again until a block takes them.'),
            group(linkRow('Coins', '#/settings/advanced/coins', { tile: tile('orange', 'coins') }),
                linkRow('View key', '#/settings/advanced/viewkey', { tile: tile('purple', 'key') }),
                linkRow('Rescan', '#/settings/advanced/rescan', { tile: tile('green', 'rescan') }),
                linkRow('Diagnostics', '#/settings/advanced/diagnostics', { tile: tile('red', 'pulse') })),
            group(actionRow('Reset all settings', async () => {
                const go = await actionSheet('Put every setting back as it started? The wallet and its node list stay.',
                    [{ label: 'Reset settings', value: true, cls: 'danger' }, { label: 'Cancel', value: null, cls: 'plain' }]);
                if (go) { resetSettings(); render(false); hud('Reset'); }
            }, { bad: true }))],
    };
}

function coinsScreen() {
    const body = h('div', null, h('div', { class: 'empty-note' }, spinner()));
    const load = () => ask('coins').then(list => {
        const groups = [['spendable', 'Spendable'], ['immature', 'Maturing'], ['pending', 'In payments waiting'], ['spent', 'Spent']];
        const bad = list.filter(c => c.status !== 'spent' && !c.recovery_ok).length;
        const row = c => h('div', { class: 'row' }, h('span', { class: 'grow' }, coins(c.value),
            h('span', { class: 'sub mono' }, `${c.commitment.slice(0, 20)}… ${c.coinbase ? 'mined' : 'received'} in block ${num(c.height)}${c.status === 'immature' ? `, spendable at ${num(c.matures_at)}` : ''}${c.spent_height != null ? `, spent in ${num(c.spent_height)}` : ''}`)),
            c.recovery_ok ? null : h('span', { class: 'badge warn' }, 'No recovery'));
        fill(body,
            ...groups.map(([k, label]) => {
                const cs = list.filter(c => c.status === k);
                return cs.length ? [title(`${label} (${cs.length})`), group(...cs.map(row))] : null;
            }),
            list.length ? null : group(textRow('No coins yet.')),
            bad ? note(`${bad} coin${bad === 1 ? '' : 's'} came with a wrong recovery commitment (the sender’s doing): spendable as usual, but not claimable in a post-quantum recovery. Sending them to your own address repairs that.`) : null);
    }, e => fill(body, group(textRow(errOf(e)))));
    load();
    return { title: 'Coins', back: ['Advanced', '#/settings/advanced'], els: [body] };
}

function viewKeyScreen() {
    const body = h('div');
    body.append(group(textRow('A view key sees every payment to your address and its amount, and can spend none of them. Give it to someone who should check what you receive, such as a pool or an accountant. Never give out the recovery phrase for that.')),
        h('div', { class: 'stack-buttons' }, h('button', { class: 'btn secondary', type: 'button', onclick: async (e) => {
            try {
                const { key } = await ask('view-key');
                const node = (app.net && app.net.addr) || nodeList()[0] || null;
                const uri = 'midwimble:watch?view=' + key + (node ? '&a=' + node : '');
                const card = h('div', { class: 'qr-card' });
                fill(card, qrSvg(uri, 'M'));
                e.target.closest('.stack-buttons').replaceWith(
                    group(h('div', { class: 'qr-col' }, card,
                        note('Scan this in a new wallet (“Watch an address”) to set up a watch-only wallet' + (node ? ', pointed at the node you use.' : '.')))),
                    group(h('div', { class: 'row stacked' }, h('span', { class: 'label' }, 'View key'), h('span', { class: 'mono' }, key),
                        h('div', { class: 'inline-buttons' }, mini('Copy', 'copy', () => copyText(key, 'View key'))))));
            } catch (x) { ok('Can’t show', errOf(x)); }
        } }, 'Show view key')));
    return { title: 'View key', back: ['Advanced', '#/settings/advanced'], els: [body] };
}

function rescanScreen() {
    const from = h('input', { inputmode: 'numeric', autocomplete: 'off', 'aria-label': 'Rescan from block' });
    let filled = false;
    return {
        title: 'Rescan',
        back: ['Advanced', '#/settings/advanced'],
        els: [group(h('label', { class: 'row field' }, h('span', { class: 'label' }, 'From block'), from)),
            note('Forgets what was learned from the blocks after this one and looks through them again. Details of payments made here are kept.'),
            h('div', { class: 'stack-buttons' }, h('button', { class: 'btn primary', type: 'button', onclick: async () => {
                const v = Number(from.value.trim().replace(/,/g, '') || 0);
                if (!Number.isInteger(v) || v < 0) { ok('Rescan', 'The block to start at is a whole number.'); return; }
                try { await ask('rescan', { from: v }); hud('Rescanning'); location.hash = '#/'; }
                catch (x) { ok('Can’t rescan', errOf(x)); }
            } }, 'Rescan'))],
        update() { if (!filled && app.state) { from.value = String(app.state.birth); filled = true; } },
    };
}

function diagnostics() {
    const s = app.state;
    return {
        at: new Date().toISOString(),
        network: app.network,
        config: app.config,
        constants: app.constants,
        net: app.net,
        nodes: app.pool,
        lightClientErrors: lc ? lc.errors.slice() : [],
        wallet: s ? { scanned: s.scanned, tip: s.tip, birth: s.birth, recoveryHeight: s.recoveryHeight, chain: s.chain, scan: s.scan, diag: s.diag, syncError: s.syncError } : null,
        settings: { ...settings },
    };
}

function diagnosticsScreen() {
    const body = h('div');
    let lastKey = null;
    return {
        title: 'Diagnostics',
        back: ['Advanced', '#/settings/advanced'],
        els: [body, h('div', { class: 'stack-buttons' }, h('button', { class: 'btn secondary', type: 'button', onclick: () => copyText(JSON.stringify(diagnostics(), null, 2), 'Diagnostics') }, icon('copy'), 'Copy diagnostics'))],
        update() {
            const s = app.state;
            const key = JSON.stringify([s && [s.scanned, s.tip, s.scan, s.diag, s.syncError, s.chain], app.pool, app.net]);
            if (key === lastKey) return;
            lastKey = key;
            const errors = lc ? lc.errors.slice(-5).reverse() : [];
            fill(body,
                title('Wallet'),
                group(
                    infoRow('Scanned to', s ? num(Math.max(0, s.scanned - 1)) : '—'),
                    infoRow('Chain tip', s && s.tip ? num(s.tip - 1) : '—'),
                    infoRow('Starts at', s ? num(s.birth) : '—'),
                    infoRow('Reading', s ? (s.scan.whole ? 'Every block' : s.scan.scanData ? 'Scan data' : 'Every block (old node)') : '—'),
                    infoRow('Fetched whole', s ? num(s.scan.fetched) : '—', { sub: 'Blocks this session, each with its decoys' }),
                    infoRow('Last update', s && s.diag && s.diag.lastSync ? when(s.diag.lastSync / 1000) : '—'),
                    s && s.syncError ? h('div', { class: 'row stacked' }, h('span', { class: 'label' }, 'Last error'), h('span', { class: 'mono' }, s.syncError)) : null),
                title('Nodes'),
                group(...(app.pool.length ? app.pool.map(p => infoRow(hostOf(p.addr), `${num(p.requests)} req, ${(p.bytes / 1024).toFixed(0)} KB`,
                    { sub: `${p.primary ? 'Following. ' : ''}${nodeSub(p)}${p.failures ? `, ${p.failures} failed` : ''}` }))
                    : [textRow(app.net.detail || 'Not connected.')])),
                errors.length ? [title('Recent node errors'), group(...errors.map(e => textRow(h('span', { class: 'mono' }, e))))] : null);
        },
    };
}

function aboutScreen() {
    const C = app.constants || {};
    return {
        title: 'About',
        back: ['Settings', '#/settings'],
        els: [h('div', { class: 'detail-head' }, logo(true), h('div', { class: 'big' }, 'Midwimble'), h('div', { class: 'what' }, 'Wallet')),
            group(
                infoRow('Network', networkName()),
                app.config.genesis ? infoRow('Genesis block', app.config.genesis.slice(0, 16) + '…', { mono: true }) : null,
                C.target_block_time ? infoRow('Block time', `${C.target_block_time} seconds`) : null,
                C.coinbase_maturity ? infoRow('Mined coins mature', `After ${C.coinbase_maturity} blocks`) : null,
                C.recovery_height ? infoRow('Recovery key', `${num(2 ** C.recovery_height)} one-time keys`) : null,
                infoRow('Build', C.fast_mining ? 'Fast-mining test build' : 'Standard')),
            group(h('a', { class: 'row link', href: 'https://github.com/ciphernom/midwimble', target: '_blank', rel: 'noopener noreferrer' }, h('span', { class: 'grow' }, 'Source code'))),
            note('Free software under the GPL. Your keys stay in this browser: the nodes never see them.')],
    };
}

function fatal(text) {
    app.phase = 'broken';
    app.fatal = text;
    render(false);
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
        await ask('init', { config: app.config, settings: workerSettings() });
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
        if (!lock) { app.phase = 'elsewhere'; render(false); return; }
        if (app.phase === 'elsewhere') app.phase = 'loading';
        render(false);
        start();
        await new Promise(() => {}); // held until another tab takes it
    }).catch(() => {
        // Another tab took the wallet over.
        worker.terminate();
        if (lc) lc.stop();
        app.phase = 'elsewhere';
        app.state = null;
        started = true;
        $app.classList.add('bare');
        $top.hidden = true;
        fill($content, h('div', { class: 'screen bare' }, h('div', { class: 'center-card' }, logo(), h('h1', null, 'Moved to another tab'),
            h('p', null, 'The wallet is open in another tab now. Reload this one to use it here.'))));
    });
}

// Offline and back: say so, and look for nodes again once the network is back.
addEventListener('offline', update);
addEventListener('online', () => {
    if (app.net.status === 'failed' || app.net.status === 'none') connect();
    update();
});

// ── installing as an app ────────────────────────────────────────────────────

let installPrompt = null;
addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault(); // offered under Settings instead
    installPrompt = e;
    update();
});
addEventListener('appinstalled', () => { installPrompt = null; update(); });
async function installApp() {
    const p = installPrompt;
    if (!p) return;
    installPrompt = null;
    await p.prompt();
    update();
}
if ('serviceWorker' in navigator) {
    const sw = navigator.serviceWorker;
    // Whether a worker was already in control when the page loaded: true on an
    // update (an old worker is running), false on a first-ever visit. Only an
    // update should trigger the reload below.
    const hadController = !!sw.controller;
    let reloading = false;
    sw.addEventListener('controllerchange', () => {
        if (reloading || !hadController) return;
        reloading = true;
        location.reload();
    });
    sw.addEventListener('message', (e) => {
        const m = e.data;
        if (!m || m.type !== 'sw-version' || !m.version) return;
        try {
            const seen = localStorage.getItem('mw.swVersion');
            // A genuine version change (not the first install): celebrate after
            // the reload that controllerchange triggers.
            if (seen && seen !== m.version) sessionStorage.setItem('mw.celebrate', m.version);
            localStorage.setItem('mw.swVersion', m.version);
        } catch (_) {}
    });
    sw.register('sw.js').catch(() => {});
    try {
        const v = sessionStorage.getItem('mw.celebrate');
        if (v) {
            sessionStorage.removeItem('mw.celebrate');
            setTimeout(() => hud('Updated to the latest version', 'check', 2600), 600);
        }
    } catch (_) {}
}

render(false);
holdTab(false);
