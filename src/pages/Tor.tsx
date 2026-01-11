import Navbar from '@/components/Ghost/Navbar';
import Footer from '@/components/Ghost/Footer';
import { useEffect, useState } from 'react';
import PageTransition from '@/components/Ghost/PageTransition';

const Tor = () => {
  const [acceptedRisks, setAcceptedRisks] = useState(false);
  const [isTorBrowser, setIsTorBrowser] = useState(false);

  useEffect(() => {
    document.title = 'Tor Access — Coming Soon | Ghost Private Messaging';
  }, []);

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navbar />

      <PageTransition>
        <main className="pt-24 pb-12">
          <div className="mx-auto max-w-[1400px] px-4">
            <div className="border border-[rgba(255,10,42,0.18)] bg-black/60 backdrop-blur-md shadow-[0_10px_40px_rgba(0,0,0,0.55)]">
              <div className="px-5 py-4 border-b border-[rgba(255,10,42,0.14)]">
                <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">TOR</div>
              </div>

              <div className="p-5 space-y-5">
                <div className="border border-[rgba(255,10,42,0.14)] p-4 bg-black/40">
                  <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
                    <div className="font-mono text-sm tracking-[0.12em] inline-flex items-center gap-2">
                      <span
                        className={
                          isTorBrowser
                            ? 'w-2 h-2 rounded-full bg-[#ff0a2a] shadow-[0_0_22px_rgba(255,10,42,0.95)] opsec-pulse'
                            : 'w-2 h-2 rounded-full bg-[#ff0a2a] shadow-[0_0_14px_rgba(255,10,42,0.7)] opsec-pulse'
                        }
                      />
                      {isTorBrowser ? (
                        <span className="text-white/90">[●] USER CONFIRMED: TOR BROWSER</span>
                      ) : (
                        <span className="text-[#ff0a2a] opsec-pulse">[●] UNVERIFIED: ASSUME CLEARNET</span>
                      )}
                    </div>
                    <div className="font-mono text-xs tracking-[0.12em] text-white/60">TOR HIDDEN SERVICE: NOT DEPLOYED</div>
                  </div>
                  <div className="mt-3 font-mono text-[12px] leading-relaxed text-white/70">
                    {isTorBrowser ? (
                      <div>TOR BROWSER SELECTED. THIS APP CANNOT RELIABLY DETECT TOR — VERIFY YOUR CONNECTION OUT-OF-BAND.</div>
                    ) : (
                      <div>NETWORK METADATA EXISTS. IF YOUR THREAT MODEL REQUIRES ANONYMITY, USE TOR BROWSER AND VERIFY IT.</div>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">THREAT MODEL</div>
                    </div>
                    <div className="p-4 font-mono text-[12px] leading-relaxed text-white/70 space-y-2">
                      <div>[✓] MESSAGE CONTENT: ENCRYPTED</div>
                      <div>[!] NETWORK METADATA: EXISTS (IP, TIMING)</div>
                      <div>[→] RECOMMENDATION: TOR BROWSER FOR HIGH-RISK OPERATIONS</div>
                      <div className="text-[#ff0a2a]">[!] NOT A GUARANTEE AGAINST TARGETED OR STATE-LEVEL ADVERSARIES</div>
                    </div>
                  </div>

                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">TOR PROJECT</div>
                    </div>
                    <div className="p-4 space-y-3">
                      <a
                        href="https://www.torproject.org/download/"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        DOWNLOAD TOR BROWSER
                        <span className="text-white/50">EXTERNAL</span>
                      </a>
                      <div className="font-mono text-[12px] leading-relaxed text-white/65">
                        ONLY USE OFFICIAL DISTRIBUTIONS. DO NOT TRUST THIRD-PARTY INSTALLERS.
                      </div>
                      <a
                        href="https://check.torproject.org/"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        VERIFY TOR CONNECTION
                        <span className="text-white/50">EXTERNAL</span>
                      </a>
                    </div>
                  </div>
                </div>

                {!acceptedRisks && !isTorBrowser ? (
                  <div className="border border-[rgba(255,10,42,0.14)] p-4 bg-black/40">
                    <div className="font-mono text-sm text-white/90">ACCESS VIA CLEARNET DETECTED</div>
                    <div className="mt-2 font-mono text-[12px] leading-relaxed text-white/70">
                      CONFIRMATION REQUIRED: YOU ACKNOWLEDGE THAT IP-LEVEL METADATA MAY BE VISIBLE.
                    </div>
                    <div className="mt-3">
                      <button
                        type="button"
                        onClick={() => setAcceptedRisks(true)}
                        className="px-4 py-2 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        ACKNOWLEDGE
                      </button>
                    </div>
                  </div>
                ) : null}

                <div className="border border-[rgba(255,10,42,0.14)] p-4 bg-black/40">
                  <div className="font-mono text-sm text-white/90">TOR BROWSER CONFIRMATION</div>
                  <div className="mt-2 font-mono text-[12px] leading-relaxed text-white/70">
                    THIS APP DOES NOT DETECT TOR RELIABLY. IF YOU ARE USING TOR BROWSER, YOU MUST CONFIRM IT.
                  </div>
                  <div className="mt-3">
                    <button
                      type="button"
                      onClick={() => setIsTorBrowser(v => !v)}
                      className="px-4 py-2 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                    >
                      {isTorBrowser ? 'SET AS CLEARNET' : 'I AM USING TOR BROWSER'}
                    </button>
                  </div>
                </div>

                <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                  <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                    <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">TECHNICAL HONESTY</div>
                  </div>
                  <div className="p-4 font-mono text-[12px] leading-relaxed text-white/70 space-y-2">
                    <div>[•] GHOST DOES NOT BUNDLE TOR</div>
                    <div>[•] GHOST DOES NOT PROXY YOUR TRAFFIC</div>
                    <div>[•] TOR IS EXTERNAL BY DESIGN</div>
                    <div>[•] THIS PAGE DESCRIBES READINESS, NOT AVAILABILITY</div>
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

export default Tor;
