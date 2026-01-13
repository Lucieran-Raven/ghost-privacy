import { toast } from 'sonner';
import { isTauriRuntime, tauriInvoke } from '@/utils/runtime';

type PinsConfig = {
  expires: string;
  domains: Record<string, { pins: string[]; backupPins?: string[] }>;
};

type PinCheckResult = {
  host: string;
  observedPin?: string;
  status: 'ok' | 'mismatch' | 'skipped' | 'error';
};

async function loadPinsConfig(): Promise<PinsConfig | null> {
  try {
    const res = await fetch('/cert_pins.json', { cache: 'no-store' });
    if (!res.ok) return null;
    return (await res.json()) as PinsConfig;
  } catch {
    return null;
  }
}

export async function runCertificatePinningCheck(): Promise<void> {
  const cfg = await loadPinsConfig();
  if (!cfg) return;

  const targets = Object.entries(cfg.domains).map(([host, data]) => ({
    host,
    pins: [...(data.pins || []), ...(data.backupPins || [])].filter(Boolean),
  }));

  if (targets.every((t) => t.pins.length === 0)) {
    return;
  }

  // Tauri path
  if (isTauriRuntime()) {
    try {
      const res = await tauriInvoke<{ results: PinCheckResult[] }>('verify_cert_pinning', {
        targets,
      });
      const hasMismatch = (res.results || []).some((r) => r.status === 'mismatch');
      if (hasMismatch) {
        toast('⚠️ Security Warning: Server certificate changed. Verify you’re not under attack.', {
          id: 'cert-pinning-warning',
          duration: 1000000,
        });
      }
    } catch {
      // Best-effort: never block.
    }
    return;
  }

  // Capacitor Android path
  try {
    const mod = await import('@capacitor/core');
    if (!mod.Capacitor?.isNativePlatform?.()) return;

    const CertPinning = mod.registerPlugin('CertPinning') as {
      verifyCertPinning: (args: { targets: { host: string; pins: string[] }[] }) => Promise<{ results: PinCheckResult[] }>;
    };

    const res = await CertPinning.verifyCertPinning({ targets });
    const hasMismatch = (res.results || []).some((r) => r.status === 'mismatch');
    if (hasMismatch) {
      toast('⚠️ Security Warning: Server certificate changed. Verify you’re not under attack.', {
        id: 'cert-pinning-warning',
        duration: 1000000,
      });
    }
  } catch {
    // Best-effort: never block.
  }
}
