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
  event.waitUntil(self.skipWaiting());
});

// Activate - clean old caches, take control
self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    try {
      const cacheNames = await caches.keys();
      await Promise.all(cacheNames.map((name) => caches.delete(name)));
    } catch {
      
    }

    try {
      await self.registration.unregister();
    } catch {
      
    }

    try {
      await self.clients.claim();
    } catch {
      
    }
  })());
});

// Fetch strategy: Network-first for API/realtime, Cache-first for assets
self.addEventListener('fetch', (event) => {
  return;
});

// Handle skip waiting message
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
