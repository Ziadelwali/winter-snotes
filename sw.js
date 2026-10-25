/* Offline shell cache. Holds only encrypted files and public code. Rebuilt on every publish.
   Other pages share this github.io origin (and its caches), so this page's caches
   carry a pp- prefix and only those are ever cleaned up. */
const VERSION = 'v-afc4821f92';
const CACHE = 'pp-' + VERSION;
const SHELL = ['./', './index.html', './unlock.js', './sync.js', './fbconfig.js', './manifest.webmanifest', './icon-192.png', './icon-180.png'];
const FONT_HOSTS = ['fonts.googleapis.com', 'fonts.gstatic.com'];

self.addEventListener('install', function (e) {
  e.waitUntil((async function () {
    const c = await caches.open(CACHE);
    // cache: 'reload' skips the HTTP cache, so a new version never precaches old files
    await Promise.all(SHELL.map(function (u) { return c.add(new Request(u, { cache: 'reload' })).catch(function () {}); }));
    await self.skipWaiting();
  })());
});

/* An old unprefixed 'v-' cache is this page's only if everything in it is under this scope (or a font). */
async function legacyMine(name) {
  const scope = self.registration.scope;
  const reqs = await (await caches.open(name)).keys();
  let mine = 0;
  for (const r of reqs) {
    if (r.url.startsWith(scope)) mine++;
    else if (FONT_HOSTS.indexOf(new URL(r.url).hostname) < 0) return false;
  }
  return mine > 0;
}

self.addEventListener('activate', function (e) {
  e.waitUntil((async function () {
    const keys = await caches.keys();
    await Promise.all(keys.map(async function (k) {
      if (k === CACHE) return;
      if (k.startsWith('pp-') || (k.startsWith('v-') && await legacyMine(k))) await caches.delete(k);
    }));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', function (e) {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  const same = url.origin === self.location.origin;
  const font = FONT_HOSTS.indexOf(url.hostname) >= 0;
  if (!(same && url.href.startsWith(self.registration.scope)) && !font) return;

  // keeps the worker alive until the background refresh has been stored
  let settle; e.waitUntil(new Promise(function (r) { settle = r; }));
  let net = null, stored = null;
  e.respondWith((async function () {
    try {
      const cache = await caches.open(CACHE);
      const hit = await cache.match(req, { ignoreSearch: same });
      net = fetch(req).then(function (res) {
        if (res && (res.ok || res.type === 'opaque')) stored = cache.put(req, res.clone()).catch(function () {});
        return res;
      }).catch(function () { return null; });
      if (hit) return hit;
      const fresh = await net;
      if (fresh) return fresh;
      if (req.mode === 'navigate') {
        const shell = await cache.match('./index.html', { ignoreSearch: true });
        if (shell) return shell;
      }
      return new Response('Offline, and this page has not been saved on this device yet.',
        { status: 503, headers: { 'Content-Type': 'text/plain' } });
    } finally { settle(net && net.then(function () { return stored; })); }
  })());
});
