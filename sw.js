/* Offline shell cache. Holds only the encrypted file; nothing decrypted
   is ever written to storage. Rebuilt on every publish. */
const VERSION = 'v-19ecf1dd58';
const SHELL = ['./', './index.html', './manifest.webmanifest', './icon-192.png', './icon-180.png'];

self.addEventListener('install', function (e) {
  e.waitUntil((async function () {
    const c = await caches.open(VERSION);
    await Promise.all(SHELL.map(function (u) { return c.add(u).catch(function () {}); }));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', function (e) {
  e.waitUntil((async function () {
    const keys = await caches.keys();
    await Promise.all(keys.map(function (k) { return k === VERSION ? null : caches.delete(k); }));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', function (e) {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  const same = url.origin === self.location.origin;
  const font = url.hostname === 'fonts.googleapis.com' || url.hostname === 'fonts.gstatic.com';
  const sdk = url.hostname === 'www.gstatic.com';
  if (!same && !font && !sdk) return;

  e.respondWith((async function () {
    const cache = await caches.open(VERSION);
    const hit = await cache.match(req, { ignoreSearch: same });
    const net = fetch(req).then(function (res) {
      if (res && (res.ok || res.type === 'opaque')) cache.put(req, res.clone()).catch(function () {});
      return res;
    }).catch(function () { return null; });
    if (hit) { net; return hit; }
    const fresh = await net;
    if (fresh) return fresh;
    if (req.mode === 'navigate') {
      const shell = await cache.match('./index.html', { ignoreSearch: true });
      if (shell) return shell;
    }
    return new Response('Offline, and this page has not been saved on this device yet.',
      { status: 503, headers: { 'Content-Type': 'text/plain' } });
  })());
});
