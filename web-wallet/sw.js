// sw.js: makes the wallet an app that installs and opens offline.
//
// Online, every file comes from the network as it is now, so the page, the
// wallet worker and the WebAssembly always come from the same release; each
// answer is kept here as it passes. Offline, or when the network has not
// answered in four seconds, the kept copy is used instead: the wallet opens,
// unlocks and shows what it knew, and catches up once a node answers.
// Nothing but the wallet's own files passes through here; nodes are reached
// over WebRTC, which a service worker never sees.

// Bump VERSION on every release: the service worker then reinstalls,
// refetches every file (new WebAssembly included, with `cache: 'reload'` so
// the browser's HTTP cache is bypassed), drops the old cache and tells the
// page a new version is live.
const VERSION = '2';
const CACHE = 'midwimble-wallet-' + VERSION;
const FILES = [
    './', 'index.html', 'app.js', 'worker.js', 'keygen.js', 'qr.js', 'qr_scan.js', 'wallet.css', 'logo.svg',
    'config.json', 'light_client.bundle.js', 'qr_reader.bundle.js', 'manifest.webmanifest',
    'pkg/midwimble_web_wallet.js', 'pkg/midwimble_web_wallet_bg.wasm',
    'icons/icon-192.png', 'icons/icon-512.png', 'icons/maskable-512.png', 'icons/apple-touch-icon.png',
];

self.addEventListener('install', (e) => {
    // Keep a copy of everything up front, so the first offline start works.
    // A file that fails to load is fetched again when it is next used.
    e.waitUntil(caches.open(CACHE)
        .then(c => Promise.all(FILES.map(f => c.add(new Request(f, { cache: 'reload' })).catch(() => {}))))
        .then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
    e.waitUntil(caches.keys()
        .then(keys => Promise.all(keys.filter(k => k.startsWith('midwimble-wallet-') && k !== CACHE).map(k => caches.delete(k))))
        .then(() => self.clients.claim())
        .then(() => self.clients.matchAll())
        .then(cs => cs.forEach(c => c.postMessage({ type: 'sw-version', version: VERSION }))));
});

self.addEventListener('fetch', (e) => {
    const req = e.request;
    if (req.method !== 'GET' || new URL(req.url).origin !== self.location.origin) return;
    e.respondWith(networkFirst(req));
});

async function networkFirst(req) {
    const cache = await caches.open(CACHE);
    const network = fetch(req).then((res) => {
        if (res.ok && res.type === 'basic' && !res.redirected) cache.put(req, res.clone()).catch(() => {});
        return res;
    });
    const kept = await cache.match(req, { ignoreSearch: true })
        || (req.mode === 'navigate' ? await cache.match('index.html') : undefined);
    if (!kept) return network;
    const late = new Promise(resolve => setTimeout(resolve, 4000, null));
    try {
        return (await Promise.race([network, late])) || kept;
    } catch (_) {
        return kept;
    }
}
