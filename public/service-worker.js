/* eslint-env serviceworker */
/* eslint-disable no-restricted-globals */
const CACHE_NAME = 'secure-chat-cache-v1';
const ASSETS = [
  '/',
  '/index.html',
  '/styles.css',
  '/bundle.js',
  '/version.json',
  '/bundle.js.sig',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(
      keys.filter((key) => key !== CACHE_NAME)
        .map((key) => caches.delete(key)),
    )),
  );
});

self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((cached) => cached || fetch(event.request)),
  );
});
