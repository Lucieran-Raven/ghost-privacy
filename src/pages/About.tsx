import Navbar from '@/components/Ghost/Navbar';
import Footer from '@/components/Ghost/Footer';
import PageTransition from '@/components/Ghost/PageTransition';

const About = () => {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navbar />

      <PageTransition>
        <main className="pt-24 pb-12">
          <div className="mx-auto max-w-[1400px] px-4">
            <div className="border border-[rgba(255,10,42,0.18)] bg-black/60 backdrop-blur-md shadow-[0_10px_40px_rgba(0,0,0,0.55)]">
              <div className="px-5 py-4 border-b border-[rgba(255,10,42,0.14)]">
                <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">ABOUT</div>
              </div>

              <div className="p-5 space-y-5">
                <div className="border border-[rgba(255,10,42,0.14)] p-4 bg-black/40">
                  <div className="font-mono text-sm tracking-[0.12em] text-white/90">THREAT MODEL: PUBLISHED. LIMITATIONS: DOCUMENTED.</div>
                  <div className="mt-2 font-mono text-[12px] leading-relaxed text-white/70">
                    THIS INTERFACE IS DESIGNED FOR CONFIDENTIAL COMMUNICATION — INCLUDING JOURNALISTS AND ACTIVISTS WHEN USED WITH TOR BROWSER. OPERATIONAL CLARITY OVER PRESENTATION.
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">MISSION</div>
                    </div>
                    <div className="p-4 font-mono text-[12px] leading-relaxed text-white/70 space-y-2">
                      <div>[✓] CONFIDENTIALITY: CLIENT-SIDE ENCRYPTION</div>
                      <div>[✓] EPHEMERALITY: RAM-ONLY STORAGE</div>
                      <div>[✓] VERIFIABILITY: OPEN CODE + PUBLISHED LIMITATIONS</div>
                      <div>[!] NETWORK ANONYMITY: EXTERNAL (TOR/VPN)</div>
                    </div>
                  </div>

                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">GOVERNANCE</div>
                    </div>
                    <div className="p-4 font-mono text-[12px] leading-relaxed text-white/70 space-y-2">
                      <div>[•] NO ACCOUNTS. NO PHONE NUMBER REQUIREMENT.</div>
                      <div>[•] SECURITY THROUGH VERIFIED CRYPTOGRAPHY.</div>
                      <div>[•] SECURITY THROUGH AUDITABLE IMPLEMENTATION.</div>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">SOURCE</div>
                    </div>
                    <div className="p-4">
                      <a
                        href="https://github.com/Lucieran-Raven/ghost-privacy"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        GITHUB
                        <span className="text-white/50">EXTERNAL</span>
                      </a>
                    </div>
                  </div>

                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">CONTACT</div>
                    </div>
                    <div className="p-4">
                      <a
                        href="mailto:lucieranraven@gmail.com"
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        EMAIL
                        <span className="text-white/50">EXTERNAL</span>
                      </a>
                    </div>
                  </div>

                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">SECURITY</div>
                    </div>
                    <div className="p-4">
                      <a
                        href="https://t.me/ghostdeveloperadmin"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        REPORT
                        <span className="text-white/50">EXTERNAL</span>
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

export default About;
