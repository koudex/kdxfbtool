const CACHE_VERSION = 'kdxfb-v1';
const STATIC_CACHE = `static-${CACHE_VERSION}`;
const DYNAMIC_CACHE = `dynamic-${CACHE_VERSION}`;

const APP_SHELL = [
  '/',
  '/index.html',
  '/manifest.json',
  '/favicon-32x32.png',
  '/apple-touch-icon.png'
];

// INSTALL
self.addEventListener('install', (event) => {
  self.skipWaiting();

  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((cache) => cache.addAll(APP_SHELL))
  );
});

// ACTIVATE
self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      // cleanup old caches
      const keys = await caches.keys();

      await Promise.all(
        keys.map((key) => {
          if (
            key !== STATIC_CACHE &&
            key !== DYNAMIC_CACHE
          ) {
            return caches.delete(key);
          }
        })
      );

      // take control immediately
      await self.clients.claim();
    })()
  );
});

// FETCH
self.addEventListener('fetch', (event) => {
  const request = event.request;

  // ignore non-GET
  if (request.method !== 'GET') return;

  // network-first for HTML
  if (request.headers.get('accept')?.includes('text/html')) {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const clone = response.clone();

          caches.open(DYNAMIC_CACHE)
            .then((cache) => cache.put(request, clone));

          return response;
        })
        .catch(async () => {
          const cached = await caches.match(request);
          return cached || caches.match('/index.html');
        })
    );

    return;
  }

  // stale-while-revalidate for assets
  event.respondWith(
    caches.match(request).then((cached) => {
      const fetchPromise = fetch(request)
        .then((networkResponse) => {
          if (
            networkResponse &&
            networkResponse.status === 200
          ) {
            const clone = networkResponse.clone();

            caches.open(DYNAMIC_CACHE)
              .then((cache) => cache.put(request, clone));
          }

          return networkResponse;
        })
        .catch(() => cached);

      return cached || fetchPromise;
    })
  );
});

// AUTO UPDATE
self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});