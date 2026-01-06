import { useState } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import { toast } from 'sonner';
import Navbar from '@/components/Ghost/Navbar';
import Footer from '@/components/Ghost/Footer';
import PageTransition from '@/components/Ghost/PageTransition';

const ETH_ADDRESS = '0x0e1a7422cccfd114502bdd7aa0514f28651a8d38';
const BTC_ADDRESS = 'bc1qasazdqwd83y8fq4utgfakv3pfcrdkpg7gfchg0';

const Contribute = () => {
  const [copiedAddress, setCopiedAddress] = useState<string | null>(null);

  const copyToClipboard = async (address: string, label: string) => {
    try {
      await navigator.clipboard.writeText(address);
      setCopiedAddress(label);
      toast.success('Copied');
      setTimeout(() => setCopiedAddress(null), 1500);
    } catch {
      toast.error('Copy failed');
    }
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navbar />

      <PageTransition>
        <main className="pt-24 pb-12">
          <div className="mx-auto max-w-[1400px] px-4">
            <div className="border border-[rgba(255,10,42,0.18)] bg-black/60 backdrop-blur-md shadow-[0_10px_40px_rgba(0,0,0,0.55)]">
              <div className="px-5 py-4 border-b border-[rgba(255,10,42,0.14)]">
                <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">FUND OPERATIONAL INTEGRITY</div>
              </div>

              <div className="p-5 space-y-5">
                <div className="border border-[rgba(255,10,42,0.14)] p-4 bg-black/40">
                  <div className="font-mono text-sm tracking-[0.12em] text-white/90">ACCESS CODE REQUIRED</div>
                  <div className="mt-2 font-mono text-[12px] leading-relaxed text-white/70">
                    CONTRIBUTIONS FUND AUDIT CYCLES, HARDENING, AND OPERATIONAL MAINTENANCE.
                  </div>
                </div>

                <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                  <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                    <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">MISSION IMPACT</div>
                  </div>
                  <div className="p-4 overflow-x-auto">
                    <table className="w-full border-collapse">
                      <thead>
                        <tr className="border-b border-[rgba(255,10,42,0.14)]">
                          <th className="text-left py-3 px-2 font-mono text-xs tracking-[0.16em] uppercase text-white/60">AMOUNT</th>
                          <th className="text-left py-3 px-2 font-mono text-xs tracking-[0.16em] uppercase text-white/60">EFFECT</th>
                        </tr>
                      </thead>
                      <tbody className="font-mono text-[12px] text-white/70">
                        <tr className="border-b border-[rgba(255,10,42,0.14)]">
                          <td className="py-3 px-2 text-white/90">$50</td>
                          <td className="py-3 px-2">1 PENETRATION TEST CYCLE</td>
                        </tr>
                        <tr className="border-b border-[rgba(255,10,42,0.14)]">
                          <td className="py-3 px-2 text-white/90">$500</td>
                          <td className="py-3 px-2">AUDIT VOICE MODULE</td>
                        </tr>
                        <tr className="border-b border-[rgba(255,10,42,0.14)]">
                          <td className="py-3 px-2 text-white/90">$1000</td>
                          <td className="py-3 px-2">ACCELERATE .ONION DEPLOYMENT</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">ETH / ERC-20</div>
                    </div>
                    <div className="p-4 space-y-3">
                      <div className="flex justify-center p-3 bg-white rounded">
                        <QRCodeSVG value={ETH_ADDRESS} size={150} level="H" />
                      </div>
                      <div className="border border-[rgba(255,10,42,0.14)] p-3 bg-black/40">
                        <code className="font-mono text-[12px] break-all text-white/70">{ETH_ADDRESS}</code>
                      </div>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(ETH_ADDRESS, 'ETH')}
                        className="w-full px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        {copiedAddress === 'ETH' ? 'COPIED' : 'COPY ADDRESS'}
                      </button>
                    </div>
                  </div>

                  <div className="border border-[rgba(255,10,42,0.14)] bg-black/35">
                    <div className="px-4 py-3 border-b border-[rgba(255,10,42,0.14)]">
                      <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">BITCOIN</div>
                    </div>
                    <div className="p-4 space-y-3">
                      <div className="flex justify-center p-3 bg-white rounded">
                        <QRCodeSVG value={BTC_ADDRESS} size={150} level="H" />
                      </div>
                      <div className="border border-[rgba(255,10,42,0.14)] p-3 bg-black/40">
                        <code className="font-mono text-[12px] break-all text-white/70">{BTC_ADDRESS}</code>
                      </div>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(BTC_ADDRESS, 'BTC')}
                        className="w-full px-4 py-3 border border-[rgba(255,10,42,0.24)] bg-black/40 font-mono text-xs tracking-[0.16em] uppercase text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)]"
                      >
                        {copiedAddress === 'BTC' ? 'COPIED' : 'COPY ADDRESS'}
                      </button>
                    </div>
                  </div>
                </div>

                <div className="border border-[rgba(255,10,42,0.14)] p-4 bg-black/40">
                  <div className="font-mono text-sm text-white/90">SECURITY NOTICE</div>
                  <div className="mt-2 font-mono text-[12px] leading-relaxed text-white/70">
                    VERIFY ADDRESSES ON THIS PAGE BEFORE SENDING. NO DIRECT MESSAGES. NO THIRD-PARTY COLLECTION.
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

export default Contribute;
