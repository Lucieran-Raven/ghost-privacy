import { isTauriRuntime, tauriInvoke } from '@/utils/runtime';
import { destroyMessageQueue } from '@/utils/clientMessageQueue';
import { destroySessionKeyManager } from '@/utils/sessionKeyManager';
import { trapState } from '@/utils/trapState';

export type BuildIntegrityStatus = 'verified' | 'unverified' | 'skipped' | 'error';

export type BuildIntegrityResult = {
  status: BuildIntegrityStatus;
  platform: 'tauri' | 'android' | 'web';
  observed?: string;
  expected?: string;
};

export async function enforceBuildIntegrityOrExit(): Promise<BuildIntegrityResult> {
  const res = await checkBuildIntegrity();
  const isNative = res.platform === 'tauri' || res.platform === 'android';
  const shouldExit =
    res.status === 'unverified' ||
    (import.meta.env.PROD && isNative && res.status !== 'verified');

  if (!shouldExit) return res;

  try {
    destroyMessageQueue();
  } catch {
  }
  try {
    destroySessionKeyManager();
  } catch {
  }
  try {
    trapState.nuclearPurge();
  } catch {
  }

  if (res.platform === 'tauri') {
    try {
      await tauriInvoke('secure_panic_exit');
    } catch {
      try {
        await tauriInvoke('secure_panic_wipe');
      } catch {
      }
    }
  }

  if (res.platform === 'android') {
    try {
      const mod = await import('@capacitor/core');
      const BuildIntegrity = mod.registerPlugin('BuildIntegrity') as {
        panicExit: () => Promise<void>;
      };
      await BuildIntegrity.panicExit();
    } catch {
    }
  }

  try {
    window.location.replace('about:blank');
  } catch {
  }

  throw new Error('Build integrity failure');
}

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
