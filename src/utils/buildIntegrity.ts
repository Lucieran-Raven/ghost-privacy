import { isTauriRuntime, tauriInvoke } from '@/utils/runtime';

export type BuildIntegrityStatus = 'verified' | 'unverified' | 'skipped' | 'error';

export type BuildIntegrityResult = {
  status: BuildIntegrityStatus;
  platform: 'tauri' | 'android' | 'web';
  observed?: string;
  expected?: string;
};

export async function checkBuildIntegrity(): Promise<BuildIntegrityResult> {
  if (isTauriRuntime()) {
    try {
      const res = await tauriInvoke<{ status: BuildIntegrityStatus; observed?: string; expected?: string }>(
        'verify_build_integrity'
      );
      return {
        status: res.status,
        platform: 'tauri',
        observed: res.observed,
        expected: res.expected,
      };
    } catch {
      return { status: 'error', platform: 'tauri' };
    }
  }

  try {
    const mod = await import('@capacitor/core');
    if (mod.Capacitor?.isNativePlatform?.()) {
      const BuildIntegrity = mod.registerPlugin('BuildIntegrity') as {
        verifyBuildIntegrity: () => Promise<{ status: BuildIntegrityStatus; observed?: string; expected?: string }>;
      };
      const res = await BuildIntegrity.verifyBuildIntegrity();
      return {
        status: res.status,
        platform: 'android',
        observed: res.observed,
        expected: res.expected,
      };
    }
  } catch {
  }

  return { status: 'skipped', platform: 'web' };
}
