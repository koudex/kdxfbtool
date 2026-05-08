const CACHE_VERSION = 'kdxfb-v2';
const STATIC_CACHE = `static-${CACHE_VERSION}`;
const DYNAMIC_CACHE = `dynamic-${CACHE_VERSION}`;

// Only cache local files that actually exist
const APP_SHELL = [
  '/',
  '/index.html',
  '/manifest.json',
  '/favicon-32x32.png',
  '/apple-touch-icon.png'
];

// INSTALL
self.addEventListener('install', (event) => {
  console.log('[SW] Installing...');
  self.skipWaiting();

  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((cache) => {
        console.log('[SW] Caching app shell');
        return cache.addAll(APP_SHELL);
      })
      .catch((err) => {
        console.error('[SW] Cache addAll failed:', err);
      })
  );
});

// ACTIVATE
self.addEventListener('activate', (event) => {
  console.log('[SW] Activating...');
  
  event.waitUntil(
    (async () => {
      // Cleanup old caches
      const keys = await caches.keys();
      
      await Promise.all(
        keys.map((key) => {
          if (key !== STATIC_CACHE && key !== DYNAMIC_CACHE) {
            console.log('[SW] Deleting old cache:', key);
            return caches.delete(key);
          }
        })
      );
      
      // Take control immediately
      await self.clients.claim();
      console.log('[SW] Now controlling all clients');
    })()
  );
});

// FETCH
self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);
  
  // Ignore non-GET requests
  if (request.method !== 'GET') return;
  
  // SKIP all external/CDN requests - let browser handle them directly
  // This is critical for Vue, Axios, and other external libraries
  if (url.origin !== self.location.origin) {
    // console.log('[SW] Skipping external request:', url.href);
    return; // Don't intercept - browser handles normally
  }
  
  // For local requests (same origin)
  
  // Network-first for HTML pages
  if (request.headers.get('accept')?.includes('text/html')) {
    event.respondWith(
      fetch(request)
        .then((response) => {
          // Cache successful response
          const clone = response.clone();
          caches.open(DYNAMIC_CACHE)
            .then((cache) => cache.put(request, clone))
            .catch((err) => console.error('[SW] Cache put failed:', err));
          return response;
        })
        .catch(async () => {
          // Fallback to cache
          const cached = await caches.match(request);
          if (cached) {
            console.log('[SW] Serving HTML from cache:', request.url);
            return cached;
          }
          // Ultimate fallback - serve index.html
          return caches.match('/index.html');
        })
    );
    return;
  }
  
  // Stale-while-revalidate for local assets (JS, CSS, images)
  event.respondWith(
    caches.match(request).then((cached) => {
      const fetchPromise = fetch(request)
        .then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            const clone = networkResponse.clone();
            caches.open(DYNAMIC_CACHE)
              .then((cache) => cache.put(request, clone))
              .catch((err) => console.error('[SW] Cache put failed:', err));
          }
          return networkResponse;
        })
        .catch((err) => {
          console.log('[SW] Network failed, using cache for:', request.url);
          return cached;
        });
      
      return cached || fetchPromise;
    })
  );
});

// AUTO UPDATE - listen for skip waiting messages
self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') {
    console.log('[SW] Skipping waiting...');
    self.skipWaiting();
  }
});

// Handle offline analytics or logging (optional)
self.addEventListener('sync', (event) => {
  console.log('[SW] Sync event:', event.tag);
});
