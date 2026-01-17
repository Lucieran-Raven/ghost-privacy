import { isTauriRuntime, tauriInvoke } from '@/utils/runtime';

export type VersionGuardStatus = 'ok' | 'downgraded' | 'error' | 'skipped';

export type VersionGuardResult =
  | {
      platform: 'tauri';
      status: VersionGuardStatus;
      currentVersion?: string;
      maxSeenVersion?: string;
    }
  | {
      platform: 'android';
      status: VersionGuardStatus;
      currentVersionCode?: number;
      maxSeenVersionCode?: number;
    }
  | {
      platform: 'web';
      status: 'skipped';
    };

export async function checkVersionGuard(): Promise<VersionGuardResult> {
  if (isTauriRuntime()) {
    try {
      const res = await tauriInvoke<{
        status: VersionGuardStatus;
        currentVersion?: string;
        maxSeenVersion?: string;
      }>('get_version_guard');
      return {
        platform: 'tauri',
        status: res.status,
        currentVersion: res.currentVersion,
        maxSeenVersion: res.maxSeenVersion,
      };
    } catch {
      return { platform: 'tauri', status: 'error' };
    }
  }

  try {
    const mod = await import('@capacitor/core');
    if (mod.Capacitor?.isNativePlatform?.()) {
      const VersionGuard = mod.registerPlugin('VersionGuard') as {
        getVersionGuardStatus: () => Promise<{
          status: VersionGuardStatus;
          currentVersionCode?: number;
          maxSeenVersionCode?: number;
        }>;
      };
      const res = await VersionGuard.getVersionGuardStatus();
      return {
        platform: 'android',
        status: res.status,
        currentVersionCode: res.currentVersionCode,
        maxSeenVersionCode: res.maxSeenVersionCode,
      };
    }
  } catch {
  }

  return { platform: 'web', status: 'skipped' };
}
