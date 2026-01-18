import trapState from '@/utils/trapState';
import { destroyMessageQueue } from '@/utils/clientMessageQueue';
import { destroySessionKeyManager } from '@/utils/sessionKeyManager';
import { nuclearPurgeSessionValidationCache } from '@/lib/sessionService';
import { SecurityManager } from '@/utils/security';

let installed = false;

export function nuclearPurgeAll(): void {
  try {
    SecurityManager.clearAllCapabilityTokens();
  } catch {
  }

  try {
    nuclearPurgeSessionValidationCache();
  } catch {
  }

  try {
    destroySessionKeyManager();
  } catch {
  }

  try {
    destroyMessageQueue();
  } catch {
  }

  try {
    trapState.clear();
  } catch {
  }
}

export function installMemoryLifecycleHandlers(): void {
  if (installed) return;
  installed = true;

  if (typeof window === 'undefined') return;

  const handler = (event?: Event) => {
    nuclearPurgeAll();
    try {
      event?.preventDefault();
    } catch {
    }
    try {
      event?.stopImmediatePropagation();
    } catch {
    }
  };

  window.addEventListener('pagehide', handler);
  window.addEventListener('unload', handler);
  window.addEventListener('error', (e) => handler(e));
  window.addEventListener('unhandledrejection', (e) => handler(e));

  window.addEventListener('beforeunload', (e) => {
    try {
      const hasPrompt = typeof e.returnValue === 'string' && e.returnValue.length > 0;
      if (hasPrompt) {
        return;
      }
    } catch {
    }
    handler();
  });
}
