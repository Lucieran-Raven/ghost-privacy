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
  console.log('[SW v5] Installing - Offline-First Mode');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('[SW v5] Caching app shell and static assets');
        // Cache static assets first
        return cache.addAll(STATIC_ASSETS)
          .then(() => {
            // Try to cache app shell, but don't fail if network is unavailable
            return Promise.allSettled(
              APP_SHELL.map(url => 
                fetch(url).then(response => {
                  if (response.ok) {
                    return cache.put(url, response);
                  }
                }).catch(() => {
                  console.log('[SW v5] Could not cache:', url);
                })
              )
            );
          });
      })
      .then(() => self.skipWaiting())
  );
});

// Activate - clean old caches, take control
self.addEventListener('activate', (event) => {
  console.log('[SW v5] Activating - Claiming clients');
  event.waitUntil(
    Promise.all([
      // Delete all old caches
      caches.keys().then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((name) => name !== CACHE_NAME)
            .map((name) => {
              console.log('[SW v5] Deleting old cache:', name);
              return caches.delete(name);
            })
        );
      }),
      // Take control immediately
      self.clients.claim()
    ])
  );
});

// Fetch strategy: Network-first for API/realtime, Cache-first for assets
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  
  // Skip non-GET requests
  if (event.request.method !== 'GET') {
    return;
  }
  
  // Skip cross-origin requests (Supabase, external APIs)
  if (url.origin !== self.location.origin) {
    return;
  }
  
  // Session pages and API calls - always network first, no cache
  const neverCache = [
    '/session',
    '/api/',
    'supabase',
    'realtime'
  ];
  
  if (neverCache.some(pattern => url.href.includes(pattern))) {
    event.respondWith(
      fetch(event.request).catch(() => {
        return new Response(JSON.stringify({ error: 'Offline' }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' }
        });
      })
    );
    return;
  }
  
  // Navigation requests - network first, cache fallback for offline
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          // Cache successful navigation responses
          if (response.ok) {
            const responseClone = response.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(event.request, responseClone);
            });
          }
          return response;
        })
        .catch(() => {
          // Offline - serve from cache
          return caches.match(event.request)
            .then((cached) => {
              if (cached) return cached;
              // Fallback to index.html for SPA routing
              return caches.match('/index.html');
            });
        })
    );
    return;
  }
  
  // Static assets (icons, manifest) - cache first
  if (STATIC_ASSETS.some(asset => url.pathname === asset || url.pathname.endsWith(asset))) {
    event.respondWith(
      caches.match(event.request)
        .then((cached) => cached || fetch(event.request))
    );
    return;
  }
  
  // JS/CSS assets - stale-while-revalidate for fast loads + updates
  if (url.pathname.match(/\.(js|css|woff2?)$/)) {
    event.respondWith(
      caches.open(CACHE_NAME).then((cache) => {
        return cache.match(event.request).then((cached) => {
          const fetchPromise = fetch(event.request).then((networkResponse) => {
            if (networkResponse.ok) {
              cache.put(event.request, networkResponse.clone());
            }
            return networkResponse;
          }).catch(() => cached);
          
          // Return cached immediately, update in background
          return cached || fetchPromise;
        });
      })
    );
    return;
  }
  
  // Everything else - network first with cache fallback
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (response.ok) {
          const responseClone = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseClone);
          });
        }
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});

// Handle skip waiting message
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
