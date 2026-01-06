import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import "./index.css";
import { isTauriRuntime, tauriInvoke } from "@/utils/runtime";

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

// Run stale detection immediately
detectStalePWA();
disableServiceWorkersAndCaches();

if (isTauriRuntime()) {
  try {
    window.addEventListener('beforeunload', () => {
      void tauriInvoke('secure_panic_wipe');
    });
  } catch {
  }
}

// Register service worker for PWA functionality
if (false && 'serviceWorker' in navigator) {
}

createRoot(document.getElementById("root")!).render(<App />);
