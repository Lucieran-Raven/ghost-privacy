import { useEffect, useState } from 'react';
import { checkBuildIntegrity, type BuildIntegrityResult } from '@/utils/buildIntegrity';

export default function SecurityStatusBar() {
  const [buildIntegrity, setBuildIntegrity] = useState<BuildIntegrityResult | null>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      const res = await checkBuildIntegrity();
      if (!alive) return;
      setBuildIntegrity(res);
    })().catch(() => {
      if (!alive) return;
      setBuildIntegrity({ status: 'error', platform: 'web' });
    });
    return () => {
      alive = false;
    };
  }, []);

  return (
    <div className="hidden md:block fixed top-0 left-0 right-0 z-[60] bg-black/95 border-b border-[rgba(255,10,42,0.18)] backdrop-blur-md safe-area-inset-top">
      <div className="mx-auto max-w-[1400px] px-4">
        <div className="h-9 flex items-center justify-between gap-4 text-[11px] leading-none font-mono tracking-wide text-white/90">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
            <span className="inline-flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#ff0a2a] shadow-[0_0_12px_rgba(255,10,42,0.55)]" />
              <span className="text-white/85">ENCRYPTION: AES-256-GCM</span>
            </span>
            <span className="inline-flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#ff0a2a] shadow-[0_0_12px_rgba(255,10,42,0.55)]" />
              <span className="text-white/85">KEY EXCHANGE: ECDH P-256</span>
            </span>
            <span className="inline-flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#ff0a2a] shadow-[0_0_12px_rgba(255,10,42,0.55)]" />
              <span className="text-white/85">STORAGE: RAM-ONLY</span>
            </span>

            <span className="inline-flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-white/40" />
              <span className="text-white/70">ANONYMITY: COMING SOON</span>
            </span>
          </div>
          <div className="hidden md:flex items-center gap-3 text-white/60">
            {buildIntegrity?.status === 'verified' ? (
              <span className="text-white/85">SECURITY SEAL</span>
            ) : buildIntegrity?.status === 'unverified' ? (
              <span className="text-[#ff0a2a]">UNVERIFIED BUILD</span>
            ) : null}
            {buildIntegrity?.status === 'verified' || buildIntegrity?.status === 'unverified' ? (
              <span className="text-white/20">|</span>
            ) : null}
            <span>OPERATIONAL INTERFACE</span>
            <span className="text-white/20">|</span>
            <span>v2.0.0</span>
          </div>
        </div>
      </div>
    </div>
  );
}
