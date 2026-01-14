import { useEffect, useMemo, useState } from 'react';
import { checkBuildIntegrity, type BuildIntegrityResult } from '@/utils/buildIntegrity';

type TorStatus = 'unknown' | 'tor' | 'clearnet';

function detectTorLikely(): boolean {
  try {
    if (typeof window === 'undefined' || !window.screen) return false;
    const screenWidth = window.screen.width;
    const screenHeight = window.screen.height;
    return screenWidth === 1000 && screenHeight === 1000;
  } catch {
    return false;
  }
}

export default function SecurityStatusBar() {
  const [torStatus, setTorStatus] = useState<TorStatus>('unknown');
  const [buildIntegrity, setBuildIntegrity] = useState<BuildIntegrityResult | null>(null);

  useEffect(() => {
    const isTorLikely = detectTorLikely();
    setTorStatus(isTorLikely ? 'tor' : 'unknown');
  }, []);

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

  const anonymityLine = useMemo(() => {
    if (torStatus === 'tor') {
      return {
        tone: 'ok',
        text: "[✓] ANONYMITY: ACTIVE — IP MASKED",
      } as const;
    }

    return {
      tone: 'neutral',
      text: "[?] ANONYMITY: UNKNOWN (USE TOR)",
    } as const;
  }, [torStatus]);

  const anonymityStatusText = useMemo(() => {
    if (torStatus === 'tor') return '[●] ANONYMITY: TOR';
    if (torStatus === 'clearnet') return '[●] ANONYMITY: CLEARNET';
    return '[●] ANONYMITY: UNKNOWN';
  }, [torStatus]);

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
              <span
                className={
                  torStatus === 'tor'
                    ? 'w-1.5 h-1.5 rounded-full bg-[#ff0a2a] shadow-[0_0_22px_rgba(255,10,42,0.95)] opsec-pulse'
                    : anonymityLine.tone === 'warn'
                      ? 'w-1.5 h-1.5 rounded-full bg-[#ff0a2a] shadow-[0_0_14px_rgba(255,10,42,0.7)] opsec-pulse'
                      : anonymityLine.tone === 'ok'
                        ? 'w-1.5 h-1.5 rounded-full bg-[#ff0a2a] shadow-[0_0_18px_rgba(255,10,42,0.9)]'
                        : 'w-1.5 h-1.5 rounded-full bg-white/40'
                }
              />
              <span
                className={
                  anonymityLine.tone === 'warn'
                    ? 'text-[#ff0a2a] opsec-pulse'
                    : anonymityLine.tone === 'ok'
                      ? 'text-white/90'
                      : 'text-white/70'
                }
              >
                {anonymityStatusText}
              </span>
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
