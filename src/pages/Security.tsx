import Navbar from '@/components/Ghost/Navbar';
import Footer from '@/components/Ghost/Footer';
import PageTransition from '@/components/Ghost/PageTransition';
import { useEffect, useState } from 'react';
import { isTauriRuntime } from '@/utils/runtime';
import { checkBuildIntegrity, type BuildIntegrityResult } from '@/utils/buildIntegrity';
import { checkVersionGuard, type VersionGuardResult } from '@/utils/versionGuard';
import { checkThreatStatus, type ThreatStatusResult } from '@/utils/threatStatus';

const repoUrl = 'https://github.com/Lucieran-Raven/ghost-privacy';
const bugReportUrl = 'https://t.me/ghostdeveloperadmin';

const Security = () => {
  const secureRuntime = isTauriRuntime();
  const [buildIntegrity, setBuildIntegrity] = useState<BuildIntegrityResult | null>(null);
  const [versionGuard, setVersionGuard] = useState<VersionGuardResult | null>(null);
  const [threatStatus, setThreatStatus] = useState<ThreatStatusResult | null>(null);

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

  useEffect(() => {
    let alive = true;
    (async () => {
      const res = await checkVersionGuard();
      if (!alive) return;
      setVersionGuard(res);
    })().catch(() => {
      if (!alive) return;
      setVersionGuard({ platform: 'web', status: 'skipped' });
    });
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    let alive = true;
    (async () => {
      const res = await checkThreatStatus();
      if (!alive) return;
      setThreatStatus(res);
    })().catch(() => {
      if (!alive) return;
      setThreatStatus({ platform: 'web', status: 'skipped' });
    });
    return () => {
      alive = false;
    };
  }, []);

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      
      <PageTransition>
        <main className="pt-24 pb-12">
          <div className="mx-auto max-w-[1400px] px-4">
            <div className="border border-[rgba(255,10,42,0.18)] bg-black/60 backdrop-blur-md shadow-[0_10px_40px_rgba(0,0,0,0.55)]">
              <div className="px-5 py-4 border-b border-[rgba(255,10,42,0.14)]">
                <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">SECURITY</div>
              </div>

              <div className="p-5 space-y-5">
                <div className="border border-[rgba(255,10,42,0.14)] p-4 bg-black/40">
                  <div className="inline-flex items-center gap-2 font-mono text-sm tracking-[0.12em] text-white/90">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#ff0a2a] shadow-[0_0_14px_rgba(255,10,42,0.7)] opsec-pulse" />
                    <span>{secureRuntime ? '[✓] RUNTIME: SECURE (TAURI)' : '[!] RUNTIME: BROWSER MODE'}</span>
                  </div>
                  <div className="mt-3 font-mono text-[12px] leading-relaxed text-white/70 space-y-1">
                    <div>{secureRuntime ? '[✓] FORENSIC CLEANUP: HARDENED PROFILE' : '[!] FORENSIC CLEANUP: BEST-EFFORT (GC/CACHING LIMITS APPLY)'}</div>
                    <div>{secureRuntime ? '[✓] PANIC-WIPE HOOKS: ENABLED' : '[!] PANIC-WIPE HOOKS: NOT AVAILABLE IN BROWSERS'}</div>
                  </div>
                </div>

                <div className="border border-[rgba(255,10,42,0.14)] p-4 bg-black/40">
                  <div className="inline-flex items-center gap-2 font-mono text-sm tracking-[0.12em] text-white/90">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#ff0a2a] shadow-[0_0_14px_rgba(255,10,42,0.7)] opsec-pulse" />
                    <span>[✓] CRYPTO: ACTIVE</span>
                  </div>
                  <div className="mt-3 font-mono text-[12px] leading-relaxed text-white/70 space-y-1">
                    <div>[✓] E2E ENCRYPTION: AES-256-GCM</div>
                    <div>[✓] KEY EXCHANGE: ECDH P-256</div>
                    <div>[✓] KDF: PBKDF2-SHA256 (600,000 ITERATIONS)</div>
                    <div>[✓] FINGERPRINT: 128-BIT DISPLAY (MITM VERIFICATION / TOFU PINNING)</div>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">STORAGE MODEL</div>
                    </div>
                    <div className="p-4 font-mono text-[12px] leading-relaxed text-white/70 space-y-2">
                      <div>[✓] MESSAGE BUFFERS: RAM-ONLY</div>
                      <div>[✓] KEYS: RAM-ONLY</div>
                      <div>[✓] SESSION KEYS: NUCLEAR PURGE ON TERMINATION</div>
                      <div>[!] BROWSER LIMITATION: MEMORY MAY PERSIST UNTIL GC</div>
                    </div>
                  </div>

                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">METADATA DISCLOSURE</div>
                    </div>
                    <div className="p-4 font-mono text-[12px] leading-relaxed text-white/70 space-y-2">
                      <div className="text-[#ff0a2a]">[!] IP ADDRESS: VISIBLE ON CLEARNET</div>
                      <div>[!] TIMING: EXISTS AT NETWORK LEVEL</div>
                      <div>[→] MITIGATION: ALWAYS USE TOR BROWSER TO HIDE YOUR IP ADDRESS</div>
                      <div>[→] READ: /TOR AND /LIMITATIONS</div>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">VERIFICATION</div>
                    </div>
                    <div className="p-4 space-y-3">
                      {buildIntegrity && (buildIntegrity.platform === 'tauri' || buildIntegrity.platform === 'android') ? (
                        <div className="border border-[rgba(255,10,42,0.14)] p-3 bg-black/40 font-mono text-[12px] leading-relaxed text-white/70 space-y-1">
                          <div>
                            {buildIntegrity.status === 'verified'
                              ? '[✓] BUILD INTEGRITY: VERIFIED'
                              : buildIntegrity.status === 'unverified'
                                ? '[!] BUILD INTEGRITY: UNVERIFIED'
                                : buildIntegrity.status === 'error'
                                  ? '[!] BUILD INTEGRITY: ERROR'
                                  : '[!] BUILD INTEGRITY: SKIPPED'}
                          </div>
                          {buildIntegrity.expected ? <div>[→] EXPECTED SIGNER SHA-256: {buildIntegrity.expected}</div> : null}
                          {buildIntegrity.observed ? <div>[→] OBSERVED SIGNER SHA-256: {buildIntegrity.observed}</div> : null}
                        </div>
                      ) : null}

                      {versionGuard && (versionGuard.platform === 'tauri' || versionGuard.platform === 'android') ? (
                        <div className="border border-[rgba(255,10,42,0.14)] p-3 bg-black/40 font-mono text-[12px] leading-relaxed text-white/70 space-y-1">
                          <div>
                            {versionGuard.status === 'ok'
                              ? '[✓] VERSION GUARD: OK (ANTI-DOWNGRADE)'
                              : versionGuard.status === 'downgraded'
                                ? '[!] VERSION GUARD: DOWNGRADE DETECTED'
                                : versionGuard.status === 'error'
                                  ? '[!] VERSION GUARD: ERROR'
                                  : '[!] VERSION GUARD: SKIPPED'}
                          </div>
                          {versionGuard.platform === 'tauri' ? (
                            <>
                              {versionGuard.currentVersion ? <div>[→] CURRENT VERSION: {versionGuard.currentVersion}</div> : null}
                              {versionGuard.maxSeenVersion ? <div>[→] MAX SEEN VERSION: {versionGuard.maxSeenVersion}</div> : null}
                            </>
                          ) : (
                            <>
                              {typeof versionGuard.currentVersionCode === 'number' ? (
                                <div>[→] CURRENT VERSION CODE: {versionGuard.currentVersionCode}</div>
                              ) : null}
                              {typeof versionGuard.maxSeenVersionCode === 'number' ? (
                                <div>[→] MAX SEEN VERSION CODE: {versionGuard.maxSeenVersionCode}</div>
                              ) : null}
                            </>
                          )}
                        </div>
                      ) : null}

                      {threatStatus && (threatStatus.platform === 'tauri' || threatStatus.platform === 'android') ? (
                        <div className="border border-[rgba(255,10,42,0.14)] p-3 bg-black/40 font-mono text-[12px] leading-relaxed text-white/70 space-y-1">
                          <div>
                            {threatStatus.status === 'ok'
                              ? '[✓] PLATFORM THREAT STATUS: OK'
                              : threatStatus.status === 'warn'
                                ? '[!] PLATFORM THREAT STATUS: WARN'
                                : threatStatus.status === 'error'
                                  ? '[!] PLATFORM THREAT STATUS: ERROR'
                                  : '[!] PLATFORM THREAT STATUS: SKIPPED'}
                          </div>
                          {threatStatus.platform === 'tauri' ? (
                            <>
                              {typeof threatStatus.debugBuild === 'boolean' ? <div>[→] DEBUG BUILD: {threatStatus.debugBuild ? 'YES' : 'NO'}</div> : null}
                            </>
                          ) : (
                            <>
                              {typeof threatStatus.debuggable === 'boolean' ? <div>[→] DEBUGGABLE: {threatStatus.debuggable ? 'YES' : 'NO'}</div> : null}
                              {typeof threatStatus.debuggerAttached === 'boolean' ? <div>[→] DEBUGGER ATTACHED: {threatStatus.debuggerAttached ? 'YES' : 'NO'}</div> : null}
                              {typeof threatStatus.emulatorLikely === 'boolean' ? <div>[→] EMULATOR LIKELY: {threatStatus.emulatorLikely ? 'YES' : 'NO'}</div> : null}
                              {typeof threatStatus.rootLikely === 'boolean' ? <div>[→] ROOT LIKELY: {threatStatus.rootLikely ? 'YES' : 'NO'}</div> : null}
                            </>
                          )}
                        </div>
                      ) : null}
                      <a
                        href={repoUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        SOURCE (GITHUB)
                        <span className="text-white/50">EXTERNAL</span>
                      </a>
                      <div className="font-mono text-[12px] leading-relaxed text-white/65">
                        VERIFY BUILDS. REVIEW DIFFS. CONFIRM CSP AND HEADER POLICY.
                      </div>
                    </div>
                  </div>

                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">REPORTING</div>
                    </div>
                    <div className="p-4 space-y-3">
                      <a
                        href={bugReportUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        REPORT VULNERABILITY (TELEGRAM)
                        <span className="text-white/50">EXTERNAL</span>
                      </a>
                      <div className="font-mono text-[12px] leading-relaxed text-white/65">
                        RESPONSIBLE DISCLOSURE. DO NOT PUBLISH 0-DAYS.
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </main>
      </PageTransition>

      <Footer />
    </div>
  );
};

export default Security;