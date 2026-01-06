export function isTauriRuntime(): boolean {
  try {
    const w = window as any;
    return Boolean(
      w &&
        (typeof w.__TAURI__ !== 'undefined' ||
          typeof w.__TAURI_INTERNALS__ !== 'undefined' ||
          typeof w.__TAURI_IPC__ !== 'undefined')
    );
  } catch {
    return false;
  }
}

export async function tauriInvoke<T = unknown>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauriRuntime()) {
    throw new Error('Tauri runtime not available');
  }

  const mod = await import('@tauri-apps/api/core');
  return mod.invoke<T>(cmd, args);
}
