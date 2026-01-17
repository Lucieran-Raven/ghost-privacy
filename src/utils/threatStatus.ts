import { isTauriRuntime, tauriInvoke } from '@/utils/runtime';

export type ThreatStatusLevel = 'ok' | 'warn' | 'error' | 'skipped';

export type ThreatStatusResult =
  | {
      platform: 'tauri';
      status: ThreatStatusLevel;
      debugBuild?: boolean;
    }
  | {
      platform: 'android';
      status: ThreatStatusLevel;
      debuggable?: boolean;
      debuggerAttached?: boolean;
      emulatorLikely?: boolean;
      rootLikely?: boolean;
    }
  | {
      platform: 'web';
      status: 'skipped';
    };

export async function checkThreatStatus(): Promise<ThreatStatusResult> {
  if (isTauriRuntime()) {
    try {
      const res = await tauriInvoke<{ status: ThreatStatusLevel; debugBuild?: boolean }>('get_threat_status');
      return {
        platform: 'tauri',
        status: res.status,
        debugBuild: res.debugBuild
      };
    } catch {
      return { platform: 'tauri', status: 'error' };
    }
  }

  try {
    const mod = await import('@capacitor/core');
    if (mod.Capacitor?.isNativePlatform?.()) {
      const ThreatStatus = mod.registerPlugin('ThreatStatus') as {
        getThreatStatus: () => Promise<{
          status: ThreatStatusLevel;
          debuggable?: boolean;
          debuggerAttached?: boolean;
          emulatorLikely?: boolean;
          rootLikely?: boolean;
        }>;
      };
      const res = await ThreatStatus.getThreatStatus();
      return {
        platform: 'android',
        status: res.status,
        debuggable: res.debuggable,
        debuggerAttached: res.debuggerAttached,
        emulatorLikely: res.emulatorLikely,
        rootLikely: res.rootLikely
      };
    }
  } catch {
  }

  return { platform: 'web', status: 'skipped' };
}
