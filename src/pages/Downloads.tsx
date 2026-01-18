import Navbar from '@/components/Ghost/Navbar';
import Footer from '@/components/Ghost/Footer';
import PageTransition from '@/components/Ghost/PageTransition';
import { useEffect, useMemo, useState } from 'react';

const Downloads = () => {
  const [hashesText, setHashesText] = useState<string>('');

  useEffect(() => {
    let alive = true;
    fetch('/releases/hashes.txt', { cache: 'no-store' })
      .then((r) => (r.ok ? r.text() : ''))
      .then((t) => {
        if (!alive) return;
        setHashesText(t || '');
      })
      .catch(() => {
        if (!alive) return;
        setHashesText('');
      });
    return () => {
      alive = false;
    };
  }, []);

  const hashes = useMemo(() => {
    const map = new Map<string, string>();
    for (const line of hashesText.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const parts = trimmed.split(/\s+/);
      if (parts.length < 2) continue;
      const sha = parts[0];
      const file = parts.slice(1).join(' ');
      if (sha && file) map.set(file, sha);
    }
    return map;
  }, [hashesText]);

  const releaseTag = 'v0.1.8';
  const windowsExe = 'Ghost Privacy_0.1.4_x64-setup.exe';
  const windowsMsi = 'Ghost Privacy_0.1.4_x64_en-US.msi';
  const androidApk = 'ghost-privacy-android-release.apk';

  const androidApkUrl = `https://github.com/Lucieran-Raven/ghost-privacy/releases/download/${releaseTag}/${androidApk}`;
  const androidShaUrl = `https://github.com/Lucieran-Raven/ghost-privacy/releases/download/${releaseTag}/${androidApk}.sha256`;
  const androidAttestationUrl = `https://github.com/Lucieran-Raven/ghost-privacy/releases/download/${releaseTag}/integrity-attestation-android.txt`;

  const windowsExeUrl = `https://github.com/Lucieran-Raven/ghost-privacy/releases/download/${releaseTag}/${encodeURIComponent(windowsExe)}`;
  const windowsMsiUrl = `https://github.com/Lucieran-Raven/ghost-privacy/releases/download/${releaseTag}/${encodeURIComponent(windowsMsi)}`;
  const windowsShaUrl = `https://github.com/Lucieran-Raven/ghost-privacy/releases/download/${releaseTag}/ghost-privacy-windows.sha256`;
  const windowsAttestationUrl = `https://github.com/Lucieran-Raven/ghost-privacy/releases/download/${releaseTag}/integrity-attestation-windows.txt`;

  const sourceZipUrl = `https://github.com/Lucieran-Raven/ghost-privacy/archive/refs/tags/${releaseTag}.zip`;
  const sourceTarUrl = `https://github.com/Lucieran-Raven/ghost-privacy/archive/refs/tags/${releaseTag}.tar.gz`;

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navbar />

      <PageTransition>
        <main className="pt-24 pb-12">
          <div className="mx-auto max-w-[1400px] px-4">
            <div className="border border-[rgba(255,10,42,0.18)] bg-black/60 backdrop-blur-md shadow-[0_10px_40px_rgba(0,0,0,0.55)]">
              <div className="px-5 py-4 border-b border-[rgba(255,10,42,0.14)]">
                <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">DOWNLOADS</div>
              </div>

              <div className="p-5 space-y-5">
                <div className="border border-[rgba(255,10,42,0.14)] p-4 bg-black/40">
                  <div className="font-mono text-sm tracking-[0.12em] text-white/90">GHOST PRIVACY DOWNLOADS</div>
                  <div className="mt-2 font-mono text-[12px] leading-relaxed text-white/70">
                    VERIFY BEFORE RUNNING. DOWNLOAD LINKS POINT TO THE OFFICIAL GITHUB RELEASE ASSETS.
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">WINDOWS</div>
                    </div>
                    <div className="p-4 space-y-3">
                      <div className="font-mono text-[12px] leading-relaxed text-white/70">
                        SmartScreen warning: More info → Run anyway.
                      </div>
                      <a
                        href={windowsExeUrl}
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        DOWNLOAD
                        <span className="text-white/50">.EXE</span>
                      </a>
                      <a
                        href={windowsMsiUrl}
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        DOWNLOAD
                        <span className="text-white/50">.MSI</span>
                      </a>
                      <a
                        href={windowsShaUrl}
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        DOWNLOAD
                        <span className="text-white/50">SHA256</span>
                      </a>
                      <a
                        href={windowsAttestationUrl}
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        DOWNLOAD
                        <span className="text-white/50">ATTEST</span>
                      </a>
                      {hashes.get(windowsExe) ? (
                        <div className="font-mono text-[11px] leading-relaxed text-white/60">
                          Pinned SHA-256:
                          <div className="mt-2 border border-[rgba(255,10,42,0.14)] bg-black/50 p-3 text-white/80 overflow-x-auto">
                            {hashes.get(windowsExe)}
                          </div>
                        </div>
                      ) : null}
                      <div className="font-mono text-[11px] leading-relaxed text-white/60">
                        Verify SHA-256 in PowerShell:
                        <div className="mt-2 border border-[rgba(255,10,42,0.14)] bg-black/50 p-3 text-white/80 overflow-x-auto">
                          {`Get-FileHash .\\${windowsExe} -Algorithm SHA256`}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">ANDROID</div>
                    </div>
                    <div className="p-4 space-y-3">
                      <div className="font-mono text-[12px] leading-relaxed text-white/70">
                        Enable Install unknown apps for your browser if blocked.
                      </div>
                      <a
                        href={androidApkUrl}
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        DOWNLOAD
                        <span className="text-white/50">.APK</span>
                      </a>
                      <a
                        href={androidShaUrl}
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        DOWNLOAD
                        <span className="text-white/50">SHA256</span>
                      </a>
                      <a
                        href={androidAttestationUrl}
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        DOWNLOAD
                        <span className="text-white/50">ATTEST</span>
                      </a>
                      {hashes.get(androidApk) ? (
                        <div className="font-mono text-[11px] leading-relaxed text-white/60">
                          Pinned SHA-256:
                          <div className="mt-2 border border-[rgba(255,10,42,0.14)] bg-black/50 p-3 text-white/80 overflow-x-auto">
                            {hashes.get(androidApk)}
                          </div>
                        </div>
                      ) : null}
                      <div className="font-mono text-[11px] leading-relaxed text-white/60">
                        Verify SHA-256 on a computer:
                        <div className="mt-2 border border-[rgba(255,10,42,0.14)] bg-black/50 p-3 text-white/80 overflow-x-auto">
                          {`sha256sum ${androidApk}`}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">WEB (PWA)</div>
                    </div>
                    <div className="p-4 space-y-3">
                      <div className="font-mono text-[12px] leading-relaxed text-white/70">
                        Install from browser menu (Chrome/Chromium) or Add to Home Screen (Safari).
                      </div>
                      <a
                        href="/"
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        OPEN APP
                        <span className="text-white/50">WEB</span>
                      </a>
                    </div>
                  </div>
                </div>

                <div className="border border-[rgba(255,10,42,0.14)] p-4 bg-black/40">
                  <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">RELEASE VERIFICATION</div>
                  <div className="mt-2 font-mono text-[12px] leading-relaxed text-white/70 space-y-2">
                    <div>
                      Source code:
                      <a className="underline hover:text-white" href={sourceZipUrl} target="_blank" rel="noopener noreferrer">
                        {` ${releaseTag}.zip`}
                      </a>
                      <span className="text-white/50"> · </span>
                      <a className="underline hover:text-white" href={sourceTarUrl} target="_blank" rel="noopener noreferrer">
                        {` ${releaseTag}.tar.gz`}
                      </a>
                    </div>
                    <div>
                      Read:
                      <a className="underline hover:text-white" href="https://github.com/Lucieran-Raven/ghost-privacy/blob/main/docs/RELEASE_VERIFICATION.md" target="_blank" rel="noopener noreferrer">
                        docs/RELEASE_VERIFICATION.md
                      </a>
                    </div>
                    <div>
                      Install help:
                      <a className="underline hover:text-white" href="https://github.com/Lucieran-Raven/ghost-privacy/blob/main/docs/INSTALL_GUIDE.md" target="_blank" rel="noopener noreferrer">
                        docs/INSTALL_GUIDE.md
                      </a>
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

export default Downloads;
