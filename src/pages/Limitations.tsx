import { Link } from 'react-router-dom';
import Navbar from '@/components/Ghost/Navbar';
import Footer from '@/components/Ghost/Footer';
import PageTransition from '@/components/Ghost/PageTransition';

const Limitations = () => {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      
      <PageTransition>
        <main className="pt-24 pb-12">
          <div className="mx-auto max-w-[1400px] px-4">
            <div className="border border-[rgba(255,10,42,0.18)] bg-black/60 backdrop-blur-md shadow-[0_10px_40px_rgba(0,0,0,0.55)]">
              <div className="px-5 py-4 border-b border-[rgba(255,10,42,0.14)]">
                <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">LIMITATIONS</div>
              </div>

              <div className="p-5 space-y-5">
                <div className="border border-[rgba(255,10,42,0.14)] p-4 bg-black/40">
                  <div className="font-mono text-sm tracking-[0.12em] text-white/90">THREAT MODEL: PUBLISHED</div>
                  <div className="mt-2 font-mono text-[12px] leading-relaxed text-white/70">
                    SECURITY CLAIMS ARE BOUNDED. THIS PAGE IS A CONTRACT.
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">PROTECTS</div>
                    </div>
                    <div className="p-4 font-mono text-[12px] leading-relaxed text-white/70 space-y-2">
                      <div>[✓] MESSAGE CONTENT (AES-256-GCM)</div>
                      <div>[✓] KEY EXCHANGE (ECDH P-256)</div>
                      <div>[✓] MESSAGE STORAGE: MEMORY-FIRST (NO INTENTIONAL PERSISTENCE)</div>
                      <div>[✓] NO ACCOUNTS / NO PHONE NUMBER</div>
                      <div>[✓] FINGERPRINT DISPLAY FOR MITM VERIFICATION</div>
                    </div>
                  </div>

                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">DOES NOT PROTECT</div>
                    </div>
                    <div className="p-4 font-mono text-[12px] leading-relaxed text-white/70 space-y-2">
                      <div className="text-[#ff0a2a]">[!] NETWORK METADATA (IP, TIMING)</div>
                      <div>[!] DEVICE COMPROMISE (MALWARE, KEYLOGGERS)</div>
                      <div>[!] SCREEN CAPTURE BY RECIPIENT</div>
                      <div>[!] BROWSER / EXTENSION EXPLOITS</div>
                      <div>[!] MEMORY TRACES UNTIL GC</div>
                      <div>[!] DEVICE SEIZURE/FORENSICS: APP AIMS TO MINIMIZE ARTIFACTS (BEST-EFFORT), NOT A GUARANTEE</div>
                      <div className="text-[#ff0a2a]">[!] CLEARNET IP EXPOSURE: USE TOR BROWSER FOR FULL ANONYMITY</div>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">OPSEC RECOMMENDATIONS</div>
                    </div>
                    <div className="p-4 font-mono text-[12px] leading-relaxed text-white/70 space-y-2">
                      <div>[→] USE TOR FOR IP ANONYMITY</div>
                      <div>[→] VERIFY FINGERPRINTS OUT-OF-BAND BEFORE FIRST MESSAGE</div>
                      <div>[→] ASSUME COMPROMISED ENDPOINTS ARE GAME OVER</div>
                    </div>
                  </div>

                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">LINKS</div>
                    </div>
                    <div className="p-4 space-y-3">
                      <Link
                        to="/security"
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        SECURITY ARCHITECTURE
                        <span className="text-white/50">/SECURITY</span>
                      </Link>
                      <Link
                        to="/tor"
                        className="inline-flex w-full justify-between items-center px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        TOR STATUS
                        <span className="text-white/50">/TOR</span>
                      </Link>
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

export default Limitations;
