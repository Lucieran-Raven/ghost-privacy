// Ghost PWA Service Worker v5 - Offline-First Architecture
// Caches critical assets for instant offline loading

const CACHE_NAME = 'ghost-pwa-v5';
const STATIC_ASSETS = [
  '/icon-192.png',
  '/icon-512.png',
  '/manifest.json'
];

// Critical app shell assets - cached on install
const APP_SHELL = [
  '/',
  '/index.html'
];

// Install - cache static assets + app shell
self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    try {
      const cache = await caches.open(CACHE_NAME);
      await cache.addAll(STATIC_ASSETS.map((p) => new Request(p, { cache: 'reload' })));
    } catch {
      
    }
    await self.skipWaiting();
  })());
});

// Activate - clean old caches, take control
self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    try {
      const cacheNames = await caches.keys();
      await Promise.all(
        cacheNames
          .filter((name) => name.startsWith('ghost-pwa-') && name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      );
    } catch {
      
    }

    try {
      try {
        await self.registration.update();
      } catch {
        
      }

      await self.clients.claim();
    } catch {
      
    }
  })());
});

// Fetch strategy: Network-first for API/realtime, Cache-first for assets
self.addEventListener('fetch', (event) => {
  if (!event.request) return;

  const req = event.request;

  if (req.method !== 'GET') {
    event.respondWith(fetch(req));
    return;
  }

  const url = new URL(req.url);
  const hasAuth = Boolean(req.headers.get('authorization'));
  const isSupabase = url.hostname.endsWith('.supabase.co');
  const isSameOrigin = url.origin === self.location.origin;
  const isStaticAllowlist = isSameOrigin && STATIC_ASSETS.includes(url.pathname);
  const isHashedAsset = isSameOrigin && url.pathname.startsWith('/assets/');

  const isSessionRoute = url.origin === self.location.origin && url.pathname.startsWith('/session');
  const isBundleAsset = url.origin === self.location.origin && url.pathname.startsWith('/assets/') && (url.pathname.endsWith('.js') || url.pathname.endsWith('.css') || url.pathname.endsWith('.map'));

  if (hasAuth || isSupabase) {
    event.respondWith(fetch(new Request(req, { cache: 'no-store' })));
    return;
  }

  if (!isSameOrigin) {
    return;
  }

  if (req.mode === 'navigate' || isSessionRoute || isBundleAsset) {
    event.respondWith(fetch(new Request(req, { cache: 'no-store' })));
    return;
  }

  if (isStaticAllowlist || isHashedAsset) {
    event.respondWith((async () => {
      try {
        const cache = await caches.open(CACHE_NAME);
        const cached = await cache.match(req);
        if (cached) return cached;

        const res = await fetch(new Request(req, { cache: 'no-store' }));
        try {
          if (res && res.ok && res.type === 'basic') {
            await cache.put(req, res.clone());
          }
        } catch {
          
        }
        return res;
      } catch {
        return fetch(new Request(req, { cache: 'no-store' }));
      }
    })());
    return;
  }

  event.respondWith(fetch(new Request(req, { cache: 'no-store' })));
});

// Handle skip waiting message
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
