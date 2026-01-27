import Navbar from '@/components/Ghost/Navbar';
import Footer from '@/components/Ghost/Footer';
import PageTransition from '@/components/Ghost/PageTransition';
import { useMemo } from 'react';

const Downloads = () => {
  const releaseTag = 'v0.1.31';
  const androidApk = 'ghost-privacy-android-release.apk';

  const releasePageUrl = `https://github.com/Lucieran-Raven/ghost-privacy/releases/tag/${releaseTag}`;

  const androidApkUrl = useMemo(
    () => `https://github.com/Lucieran-Raven/ghost-privacy/releases/download/${releaseTag}/${androidApk}`,
    [releaseTag, androidApk]
  );

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

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">WINDOWS</div>
                    </div>
                    <div className="p-4 space-y-3">
                      <div className="font-mono text-[12px] leading-relaxed text-white/70">
                        SmartScreen warning: More info → Run anyway.
                      </div>
                      <a
                        href={releasePageUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        DOWNLOAD
                        <span className="text-white/50">DESKTOP</span>
                      </a>
                    </div>
                  </div>

                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">ANDROID</div>
                    </div>
                    <div className="p-4 space-y-3">
                      <a
                        href={androidApkUrl}
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        DOWNLOAD
                        <span className="text-white/50">ANDROID</span>
                      </a>
                    </div>
                  </div>
                </div>

                <div className="border border-[rgba(255,10,42,0.14)] p-4 bg-black/40">
                  <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">RELEASE VERIFICATION</div>
                  <div className="mt-2 font-mono text-[12px] leading-relaxed text-white/70 space-y-2">
                    <div>
                      More files (checksums, attestations, notes, source):
                      <a className="underline hover:text-white" href={releasePageUrl} target="_blank" rel="noopener noreferrer">
                        {` GitHub ${releaseTag}`}
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
