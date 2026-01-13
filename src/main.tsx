import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import "./index.css";
import { isTauriRuntime, tauriInvoke } from "@/utils/runtime";

const enableServiceWorker = import.meta.env.VITE_ENABLE_SERVICE_WORKER === 'true';

// Offline detection for native apps
const setupOfflineDetection = () => {
  // Only run in native apps (Tauri/Android), not web PWA
  if (isTauriRuntime() || window.Capacitor) {
    const isOffline = !window.navigator.onLine;
    
    // Add offline class to body for CSS styling
    if (isOffline) {
      document.body.classList.add('offline-mode');
    }
    
    // Listen for online/offline events
    const updateOnlineStatus = () => {
      if (window.navigator.onLine) {
        document.body.classList.remove('offline-mode');
        // Remove offline badge if it exists
        const badge = document.getElementById('offline-badge');
        if (badge) badge.remove();
      } else {
        document.body.classList.add('offline-mode');
        // Create offline badge
        const existingBadge = document.getElementById('offline-badge');
        if (!existingBadge) {
          const badge = document.createElement('div');
          badge.id = 'offline-badge';
          badge.textContent = 'Offline Mode';
          badge.style.cssText = `
            position: fixed;
            top: 10px;
            right: 10px;
            background: #f59e0b;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            z-index: 9999;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
          `;
          document.body.appendChild(badge);
        }
      }
    };
    
    window.addEventListener('online', updateOnlineStatus);
    window.addEventListener('offline', updateOnlineStatus);
  }
};

// PWA Update Banner - shows when new version is available (XSS-safe DOM construction)
const showUpdateBanner = () => {
  return;
};

// Detect stale PWA state (MIME type error prevention)
const detectStalePWA = () => {
  return;
};

const disableServiceWorkersAndCaches = () => {
  try {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.getRegistrations().then((regs) => {
        regs.forEach((r) => r.unregister());
      }).catch(() => {});
    }
  } catch {
    
  }

  try {
    if ('caches' in window) {
      caches.keys().then((names) => {
        return Promise.all(names.map((name) => caches.delete(name)));
      }).catch(() => {});
    }
  } catch {
    
  }
};

// Run stale detection immediately for web PWA only
if (!isTauriRuntime() && !window.Capacitor) {
  setTimeout(() => {
    detectStalePWA();
    disableServiceWorkersAndCaches();
  }, 0);
}

// Setup offline detection for native apps
setupOfflineDetection();

if (isTauriRuntime()) {
  try {
    window.addEventListener('beforeunload', () => {
      void tauriInvoke('secure_panic_wipe');
    });
  } catch {
  }
}

// Register service worker for PWA functionality only
if (enableServiceWorker && 'serviceWorker' in navigator && !isTauriRuntime() && !window.Capacitor) {
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}

createRoot(document.getElementById("root")!).render(<App />);
