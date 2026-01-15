import trapState from '@/utils/trapState';
import { destroyMessageQueue } from '@/utils/clientMessageQueue';
import { destroySessionKeyManager } from '@/utils/sessionKeyManager';

let installed = false;

export function nuclearPurgeAll(): void {
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

  const handler = () => {
    nuclearPurgeAll();
  };

  window.addEventListener('pagehide', handler);
  window.addEventListener('unload', handler);

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
