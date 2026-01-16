let listenersInstalled = false;
let lastWritten: string | null = null;
let clearTimer: ReturnType<typeof setTimeout> | null = null;

async function clearIfStillOurs(): Promise<void> {
  if (!lastWritten) return;
  if (typeof navigator === 'undefined' || !navigator.clipboard) return;

  try {
    const current = await navigator.clipboard.readText();
    if (current !== lastWritten) {
      return;
    }
  } catch {
    return;
  }

  try {
    await navigator.clipboard.writeText('');
    lastWritten = null;
  } catch {
  }
}

function installListeners(): void {
  if (listenersInstalled) return;
  listenersInstalled = true;

  if (typeof window !== 'undefined') {
    window.addEventListener('blur', () => {
      void clearIfStillOurs();
    });
  }

  if (typeof document !== 'undefined') {
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        void clearIfStillOurs();
      }
    });
  }
}

export async function writeEphemeralClipboard(text: string, ttlMs: number = 30_000): Promise<boolean> {
  if (typeof navigator === 'undefined' || !navigator.clipboard) return false;

  installListeners();

  try {
    await navigator.clipboard.writeText(text);
  } catch {
    return false;
  }

  lastWritten = text;

  if (clearTimer) {
    try {
      clearTimeout(clearTimer);
    } catch {
    }
    clearTimer = null;
  }

  clearTimer = setTimeout(() => {
    void clearIfStillOurs();
  }, ttlMs);

  return true;
}
