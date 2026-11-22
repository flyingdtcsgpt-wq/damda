const CACHE = 'damda-v4';
const SHELL = ['./', 'index.html', 'styles.css', 'app.js', 'vendor/argon2.js', 'manifest.webmanifest', 'icons/icon.svg', 'icons/icon-192.png', 'icons/icon-512.png'];
self.addEventListener('install', e => e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())));
self.addEventListener('activate', e => e.waitUntil(
  caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== location.origin || u.pathname.includes('/v/')) return;
  // 앱 파일: 캐시 먼저 보여주고 뒤에서 새 버전 받아두기 (오프라인에서도 열림)
  e.respondWith(caches.open(CACHE).then(async c => {
    const req = e.request.mode === 'navigate' ? './' : e.request;
    const hit = await c.match(req, { ignoreSearch: true });
    const net = fetch(e.request).then(r => { if (r.ok) c.put(req, r.clone()); return r; }).catch(() => hit);
    return hit || net;
  }));
});
