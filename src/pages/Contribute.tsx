import { useState } from "react";
import { motion } from "framer-motion";
import { QRCodeSVG } from "qrcode.react";
import { Copy, Check, Wallet, Shield, Users, Zap, Heart } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import Navbar from "@/components/Ghost/Navbar";
import Footer from "@/components/Ghost/Footer";

const ETH_ADDRESS = "0x0e1a7422cccfd114502bdd7aa0514f28651a8d38";
const BTC_ADDRESS = "bc1qasazdqwd83y8fq4utgfakv3pfcrdkpg7gfchg0";

const Contribute = () => {
  const [copiedAddress, setCopiedAddress] = useState<string | null>(null);

  const copyToClipboard = async (address: string, type: string) => {
    try {
      await navigator.clipboard.writeText(address);
      setCopiedAddress(type);
      toast.success(`${type} address copied!`);
      setTimeout(() => setCopiedAddress(null), 2000);
    } catch {
      toast.error("Failed to copy address");
    }
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navbar />
      
      <main className="pt-24 pb-16">
        {/* Hero Section */}
        <section className="container mx-auto px-4 mb-20">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="text-center max-w-4xl mx-auto"
          >
            <span className="text-4xl mb-4 block">🕶️</span>
            <h1 className="text-4xl md:text-6xl font-bold mb-6 bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              BUILD GHOST WITH US
            </h1>
            <p className="text-xl md:text-2xl text-muted-foreground mb-8">
              You don't fund Ghost. You <span className="text-primary font-semibold">fuel</span> it.
            </p>
            <div className="prose prose-invert max-w-2xl mx-auto text-left">
              <p className="text-muted-foreground leading-relaxed">
                Ghost was built in a dorm room in Malaysia — not a Silicon Valley boardroom.
                No investors. No ads. No backdoors.
              </p>
              <p className="text-muted-foreground leading-relaxed">
                But independence has a cost: servers, audits, development, time.
              </p>
              <p className="text-foreground font-medium mt-4">
                By contributing, you're not "donating."<br />
                <span className="text-primary">You're claiming a seat at the table of the privacy resistance.</span>
              </p>
            </div>
          </motion.div>
        </section>

        {/* Why This Matters */}
        <section className="container mx-auto px-4 mb-20">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="max-w-4xl mx-auto"
          >
            <h2 className="text-3xl font-bold mb-6 flex items-center gap-3">
              <span className="text-2xl">🔥</span> WHY THIS MATTERS
            </h2>
            <blockquote className="border-l-4 border-primary pl-6 py-4 mb-8 bg-card/50 rounded-r-lg">
              <p className="text-lg italic text-muted-foreground">
                "They said secure, ephemeral communication needed billions.<br />
                We proved it only needs math, honesty, and people like you."
              </p>
            </blockquote>
            <div className="grid md:grid-cols-2 gap-4">
              {[
                { icon: Shield, text: "Keeps Ghost free forever" },
                { icon: Users, text: "Shields from VC pressure and enterprise compromise" },
                { icon: Zap, text: "Funds Ghost Guardian — for journalists and activists" },
                { icon: Heart, text: "Proves privacy can be built by the many, not the few" },
              ].map((item, i) => (
                <div key={i} className="flex items-center gap-3 p-4 bg-card rounded-lg border border-border">
                  <item.icon className="w-5 h-5 text-primary flex-shrink-0" />
                  <span className="text-sm">{item.text}</span>
                </div>
              ))}
            </div>
          </motion.div>
        </section>

        {/* Impact Table */}
        <section className="container mx-auto px-4 mb-20">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="max-w-4xl mx-auto"
          >
            <h2 className="text-3xl font-bold mb-6 flex items-center gap-3">
              <span className="text-2xl">🛠️</span> YOUR SUPPORT BUILDS THIS
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse">
                <thead>
                  <tr className="border-b border-border">
                    <th className="text-left py-3 px-4 text-muted-foreground font-medium">Contribution</th>
                    <th className="text-left py-3 px-4 text-muted-foreground font-medium">Impact</th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    { amount: "$10", impact: "1 day of server uptime — keeps Ghost online for 500 users" },
                    { amount: "$50", impact: "Funds a round of penetration testing" },
                    { amount: "$200", impact: "Helps build the Burn Notice animation + sound design" },
                    { amount: "$500", impact: "Pays for a security audit of voice messaging" },
                    { amount: "$1,000+", impact: "Accelerates Ghost Mobile — PWA with Signal-style safety codes" },
                  ].map((row, i) => (
                    <tr key={i} className="border-b border-border/50 hover:bg-card/50 transition-colors">
                      <td className="py-4 px-4 font-semibold text-primary">{row.amount}</td>
                      <td className="py-4 px-4 text-muted-foreground">{row.impact}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="text-sm text-muted-foreground mt-4 flex items-center gap-2">
              <span>💡</span> All contributions are pseudonymous. No names. No tracking. Just action.
            </p>
          </motion.div>
        </section>

        {/* Wallet Addresses */}
        <section className="container mx-auto px-4 mb-20">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="max-w-4xl mx-auto"
          >
            <h2 className="text-3xl font-bold mb-6 flex items-center gap-3">
              <Wallet className="w-8 h-8 text-primary" /> WALLET ADDRESSES
            </h2>
            
            <div className="grid md:grid-cols-2 gap-6">
              {/* ETH Card */}
              <div className="bg-card border border-border rounded-xl p-6">
                <h3 className="text-lg font-semibold mb-2 flex items-center gap-2">
                  <span className="w-6 h-6 bg-[#627EEA] rounded-full flex items-center justify-center text-xs">Ξ</span>
                  ETH / USDT (ERC-20)
                </h3>
                <p className="text-xs text-muted-foreground mb-4">Same address for all ERC-20 tokens</p>
                
                <div className="flex justify-center mb-4 p-4 bg-white rounded-lg">
                  <QRCodeSVG value={ETH_ADDRESS} size={150} level="H" />
                </div>
                
                <div className="bg-muted/50 rounded-lg p-3 mb-4">
                  <code className="text-xs break-all text-muted-foreground">{ETH_ADDRESS}</code>
                </div>
                
                <Button
                  variant="outline"
                  className="w-full"
                  onClick={() => copyToClipboard(ETH_ADDRESS, "ETH")}
                >
                  {copiedAddress === "ETH" ? (
                    <><Check className="w-4 h-4 mr-2" /> Copied!</>
                  ) : (
                    <><Copy className="w-4 h-4 mr-2" /> Copy ETH Address</>
                  )}
                </Button>
              </div>

              {/* BTC Card */}
              <div className="bg-card border border-border rounded-xl p-6">
                <h3 className="text-lg font-semibold mb-2 flex items-center gap-2">
                  <span className="w-6 h-6 bg-[#F7931A] rounded-full flex items-center justify-center text-xs font-bold">₿</span>
                  Bitcoin (BTC)
                </h3>
                <p className="text-xs text-muted-foreground mb-4">Native SegWit address</p>
                
                <div className="flex justify-center mb-4 p-4 bg-white rounded-lg">
                  <QRCodeSVG value={BTC_ADDRESS} size={150} level="H" />
                </div>
                
                <div className="bg-muted/50 rounded-lg p-3 mb-4">
                  <code className="text-xs break-all text-muted-foreground">{BTC_ADDRESS}</code>
                </div>
                
                <Button
                  variant="outline"
                  className="w-full"
                  onClick={() => copyToClipboard(BTC_ADDRESS, "BTC")}
                >
                  {copiedAddress === "BTC" ? (
                    <><Check className="w-4 h-4 mr-2" /> Copied!</>
                  ) : (
                    <><Copy className="w-4 h-4 mr-2" /> Copy BTC Address</>
                  )}
                </Button>
              </div>
            </div>

            <div className="mt-6 p-4 bg-destructive/10 border border-destructive/30 rounded-lg">
              <p className="text-sm text-destructive flex items-start gap-2">
                <span className="text-lg">⚠️</span>
                <span>
                  <strong>Security Notice:</strong> Always verify addresses on this page before sending. 
                  We will <strong>never</strong> DM you for donations. Scammers might.
                </span>
              </p>
            </div>
          </motion.div>
        </section>

        {/* Privacy Tips */}
        <section className="container mx-auto px-4 mb-20">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="max-w-4xl mx-auto"
          >
            <h2 className="text-3xl font-bold mb-6 flex items-center gap-3">
              <span className="text-2xl">🛡️</span> HOW TO CONTRIBUTE PRIVATELY
            </h2>
            <div className="bg-card border border-border rounded-xl p-6">
              <ul className="space-y-3 text-muted-foreground">
                <li className="flex items-start gap-3">
                  <span className="text-primary">→</span>
                  Use <strong className="text-foreground">Tor Browser</strong> + a fresh MetaMask account
                </li>
                <li className="flex items-start gap-3">
                  <span className="text-primary">→</span>
                  Avoid donating from KYC exchanges (Coinbase, Binance)
                </li>
                <li className="flex items-start gap-3">
                  <span className="text-primary">→</span>
                  Consider mixing BTC (Wasabi) or ETH (privacy pools compliant with local laws)
                </li>
                <li className="flex items-start gap-3">
                  <span className="text-primary">→</span>
                  Never reuse this address for other projects
                </li>
              </ul>
              <blockquote className="mt-6 border-l-4 border-primary pl-4 italic text-sm">
                "Privacy isn't just about the message. It's about the act of supporting it."
              </blockquote>
            </div>
          </motion.div>
        </section>

        {/* The Ghost Pledge */}
        <section className="container mx-auto px-4 mb-20">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="max-w-4xl mx-auto text-center"
          >
            <h2 className="text-3xl font-bold mb-6 flex items-center justify-center gap-3">
              <span className="text-2xl">📜</span> THE GHOST PLEDGE
            </h2>
            <blockquote className="text-lg md:text-xl text-muted-foreground leading-relaxed max-w-2xl mx-auto">
              "I contribute not because I owe Ghost anything —<br />
              but because I believe in a world where a conversation can die when it ends.<br /><br />
              I stand with builders who choose <span className="text-primary">math over marketing</span>,<br />
              <span className="text-primary">honesty over hype</span>,<br />
              and <span className="text-primary">users over shareholders</span>.<br /><br />
              This is not a donation.<br />
              <strong className="text-foreground">This is my stake in the future.</strong>"
            </blockquote>
          </motion.div>
        </section>

        {/* Funding Transparency */}
        <section className="container mx-auto px-4 mb-20">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="max-w-4xl mx-auto"
          >
            <h2 className="text-3xl font-bold mb-6 flex items-center gap-3">
              <span className="text-2xl">🎯</span> FUNDING TRANSPARENCY (Q1 2025)
            </h2>
            <div className="bg-card border border-border rounded-xl overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border bg-muted/30">
                    <th className="text-left py-3 px-4 font-medium">Goal</th>
                    <th className="text-left py-3 px-4 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody>
                  <tr className="border-b border-border/50">
                    <td className="py-3 px-4">🌐 Basic Operations</td>
                    <td className="py-3 px-4"><span className="text-green-500">✅ Funded</span></td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-3 px-4">🔍 Security Audit</td>
                    <td className="py-3 px-4"><span className="text-yellow-500">🟡 $1,240/$5,000</span></td>
                  </tr>
                  <tr className="border-b border-border/50">
                    <td className="py-3 px-4">📱 Ghost Mobile</td>
                    <td className="py-3 px-4"><span className="text-muted-foreground">🟤 Not started</span></td>
                  </tr>
                  <tr>
                    <td className="py-3 px-4">🕵️ Ghost Guardian</td>
                    <td className="py-3 px-4"><span className="text-muted-foreground">🟤 Not started</span></td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p className="text-xs text-muted-foreground mt-3">Updated manually each month on GitHub</p>
          </motion.div>
        </section>

        {/* Thank You */}
        <section className="container mx-auto px-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="max-w-4xl mx-auto text-center"
          >
            <h2 className="text-3xl font-bold mb-6">🙏 Thank You</h2>
            <p className="text-muted-foreground mb-4">
              Ghost exists because <span className="text-primary font-semibold">anonymous believers</span> said:
            </p>
            <blockquote className="text-lg italic text-muted-foreground mb-8">
              "The world needs a place where words vanish like they were never spoken."
            </blockquote>
            <p className="text-muted-foreground">
              No strings. No tracking. Just trust.
            </p>
          </motion.div>
        </section>
      </main>

      <Footer />
    </div>
  );
};

export default Contribute;
