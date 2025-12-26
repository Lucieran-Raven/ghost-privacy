import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import "./index.css";

// PWA Update Banner - shows when new version is available (XSS-safe DOM construction)
const showUpdateBanner = () => {
  // Don't show if already showing
  if (document.getElementById('ghost-update-banner')) return;
  
  // Add animation styles
  const style = document.createElement('style');
  style.textContent = `
    @keyframes ghostSlideUp {
      from { transform: translateY(100%); }
      to { transform: translateY(0); }
    }
  `;
  document.head.appendChild(style);
  
  // Create banner using safe DOM methods (no innerHTML)
  const banner = document.createElement('div');
  banner.id = 'ghost-update-banner';
  
  const container = document.createElement('div');
  container.style.cssText = `
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    background: hsl(222 47% 11%);
    border-top: 1px solid hsl(160 100% 50% / 0.5);
    padding: 12px 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 12px;
    z-index: 9999;
    font-family: system-ui, sans-serif;
    animation: ghostSlideUp 0.3s ease-out;
  `;
  
  const text = document.createElement('span');
  text.style.cssText = 'color: hsl(187 100% 50%); font-size: 14px;';
  text.textContent = '🆕 New version available!';
  
  const button = document.createElement('button');
  button.style.cssText = `
    background: hsl(160 100% 50%);
    color: hsl(222 47% 11%);
    border: none;
    padding: 8px 16px;
    border-radius: 6px;
    font-weight: 600;
    cursor: pointer;
    font-size: 14px;
  `;
  button.textContent = 'Update Now';
  button.addEventListener('click', () => {
    window.location.reload();
  });
  
  container.appendChild(text);
  container.appendChild(button);
  banner.appendChild(container);
  document.body.appendChild(banner);
};

// Detect stale PWA state (MIME type error prevention)
const detectStalePWA = () => {
  const isPWA = window.matchMedia('(display-mode: standalone)').matches ||
                (window.navigator as unknown as { standalone?: boolean }).standalone === true;
  
  if (isPWA) {
    window.addEventListener('error', (event) => {
      if (event.message?.includes('module') || 
          event.message?.includes('MIME') ||
          event.message?.includes('text/html')) {
        if ('caches' in window) {
          caches.keys().then((names) => {
            Promise.all(names.map((name) => caches.delete(name))).then(() => {
              location.reload();
            });
          });
        } else {
          location.reload();
        }
      }
    }, true);
  }
};

// Run stale detection immediately
detectStalePWA();

// Register service worker for PWA functionality
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js')
      .then((registration) => {
        // Force update check on page load
        registration.update();
        
        // Check for updates and show banner (not auto-reload)
        registration.addEventListener('updatefound', () => {
          const newWorker = registration.installing;
          if (newWorker) {
            newWorker.addEventListener('statechange', () => {
              if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                showUpdateBanner();
              }
            });
          }
        });
      })
      .catch(() => {
        // Silent fail for service worker
      });
  });
  
  // Handle controller change (new SW took over)
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    // Silent - new service worker activated
  });
}

createRoot(document.getElementById("root")!).render(<App />);
