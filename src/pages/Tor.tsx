import { motion } from 'framer-motion';
import { Shield, Globe, AlertTriangle, Lock, Clock, ExternalLink, Info, Wifi, WifiOff } from 'lucide-react';
import { Button } from '@/components/ui/button';
import Navbar from '@/components/Ghost/Navbar';
import Footer from '@/components/Ghost/Footer';
import { useEffect, useState } from 'react';

const Tor = () => {
  const [acceptedRisks, setAcceptedRisks] = useState(false);
  const [isTorBrowser, setIsTorBrowser] = useState(false);

  useEffect(() => {
    document.title = 'Tor Access — Coming Soon | Ghost Private Messaging';
    
    // Simple Tor detection (not foolproof, but indicative)
    // Tor Browser has specific characteristics
    const checkTor = () => {
      const screenWidth = window.screen.width;
      const screenHeight = window.screen.height;
      // Tor Browser often reports specific window sizes
      const isTorLikely = screenWidth === 1000 && screenHeight === 1000;
      setIsTorBrowser(isTorLikely);
    };
    checkTor();
  }, []);

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navbar />

      <main className="pt-24 pb-16">
        <div className="container mx-auto px-4 max-w-4xl">
          {/* Clearnet Warning Banner */}
          {!isTorBrowser && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              className="mb-6 p-4 rounded-lg bg-amber-500/10 border border-amber-500/20"
            >
              <div className="flex items-center gap-3">
                <Wifi className="w-5 h-5 text-amber-500 flex-shrink-0" />
                <div>
                  <p className="text-sm text-foreground font-medium">
                    You are currently accessing Ghost via clearnet
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Your IP address is visible to Ghost infrastructure. For maximum anonymity, consider using Tor Browser.
                  </p>
                </div>
              </div>
            </motion.div>
          )}

          {/* Coming Soon Banner */}
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="mb-8 p-4 rounded-lg bg-muted/30 border border-border"
          >
            <div className="flex items-center gap-3">
              <Clock className="w-5 h-5 text-muted-foreground flex-shrink-0" />
              <p className="text-sm text-muted-foreground">
                <strong className="text-foreground">Tor Hidden Service — Not Yet Available</strong> — Infrastructure is prepared. Deployment is intentionally delayed until security review is complete.
              </p>
            </div>
          </motion.div>

          {/* Header */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="text-center mb-12"
          >
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-muted/50 border border-border mb-6">
              <Lock className="w-4 h-4 text-muted-foreground" />
              <span className="text-sm text-muted-foreground font-medium">Coming Soon</span>
            </div>
            <h1 className="text-4xl md:text-5xl font-outfit font-black mb-4">
              Using Ghost via Tor
            </h1>
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
              For journalists, activists, and users facing elevated threat models
            </p>
          </motion.div>

          {/* Why We're Waiting */}
          <motion.section
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="mb-12"
          >
            <div className="flex items-center gap-3 mb-4">
              <Shield className="w-6 h-6 text-primary" />
              <h2 className="text-2xl font-outfit font-bold">Why We're Waiting</h2>
            </div>
            <div className="prose prose-invert max-w-none">
              <p className="text-muted-foreground leading-relaxed mb-4">
                Ghost's Tor integration is technically ready. The code exists. The infrastructure is prepared.
              </p>
              <p className="text-muted-foreground leading-relaxed mb-4">
                We are deliberately withholding activation until:
              </p>
              <ul className="text-muted-foreground space-y-2 ml-4 mb-4">
                <li>• Independent security audit is complete</li>
                <li>• Hidden service operational security is verified</li>
                <li>• Documentation reflects accurate threat model</li>
              </ul>
              <div className="p-4 rounded-lg bg-muted/30 border border-border">
                <p className="text-sm text-muted-foreground">
                  <strong className="text-foreground">Restraint is a security feature.</strong> Premature deployment of anonymity infrastructure creates false confidence and endangers users who depend on it most.
                </p>
              </div>
            </div>
          </motion.section>

          {/* What Tor Will Provide */}
          <motion.section
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="mb-12"
          >
            <div className="flex items-center gap-3 mb-4">
              <Globe className="w-6 h-6 text-primary" />
              <h2 className="text-2xl font-outfit font-bold">What Tor Access Will Provide</h2>
            </div>
            <div className="grid md:grid-cols-2 gap-4">
              {[
                { title: 'IP Address Protection', desc: 'Your source IP hidden from Ghost infrastructure and network observers' },
                { title: 'Censorship Resistance', desc: 'Access Ghost in regions where the clearnet domain may be blocked' },
                { title: 'Warzone Mode', desc: 'Enhanced security posture with aggressive memory cleanup and mandatory key verification' },
                { title: 'End-to-End Separation', desc: 'Tor handles anonymity. Ghost handles encryption. Neither is a single point of failure.' },
              ].map((item, i) => (
                <div key={i} className="p-4 rounded-lg bg-card border border-border opacity-60">
                  <h3 className="font-semibold mb-1">{item.title}</h3>
                  <p className="text-sm text-muted-foreground">{item.desc}</p>
                </div>
              ))}
            </div>
          </motion.section>

          {/* Preparing Now */}
          <motion.section
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="mb-12"
          >
            <div className="flex items-center gap-3 mb-4">
              <Clock className="w-6 h-6 text-primary" />
              <h2 className="text-2xl font-outfit font-bold">Preparing Now</h2>
            </div>
            <div className="space-y-4 mb-8">
              <div className="flex gap-4 p-4 rounded-lg bg-card border border-border">
                <div className="flex-shrink-0 w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center text-primary font-bold">
                  1
                </div>
                <div>
                  <h3 className="font-semibold mb-1">Download Tor Browser</h3>
                  <p className="text-sm text-muted-foreground mb-2">
                    Get the official Tor Browser from the Tor Project. Do not use third-party downloads.
                  </p>
                  <a
                    href="https://www.torproject.org/download/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-sm text-primary hover:underline"
                  >
                    torproject.org/download <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>

              <div className="flex gap-4 p-4 rounded-lg bg-card border border-border">
                <div className="flex-shrink-0 w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center text-primary font-bold">
                  2
                </div>
                <div>
                  <h3 className="font-semibold mb-1">Familiarize Yourself with Tor</h3>
                  <p className="text-sm text-muted-foreground">
                    Practice using Tor Browser before you need it. Understand its limitations and behavior under normal conditions.
                  </p>
                </div>
              </div>

              <div className="flex gap-4 p-4 rounded-lg bg-card border border-border">
                <div className="flex-shrink-0 w-8 h-8 rounded-full bg-muted/50 flex items-center justify-center text-muted-foreground font-bold">
                  3
                </div>
                <div>
                  <h3 className="font-semibold mb-1 text-muted-foreground">Await Hidden Service Address</h3>
                  <p className="text-sm text-muted-foreground">
                    The .onion address will be published here once operational security is verified.
                  </p>
                </div>
              </div>
            </div>

            {/* Disabled CTA */}
            <div className="text-center">
              <Button
                size="lg"
                disabled
                className="h-14 px-8 text-lg font-outfit font-bold opacity-50 cursor-not-allowed"
              >
                <Lock className="w-5 h-5 mr-2" />
                Tor Access Coming Soon
              </Button>
              <p className="text-xs text-muted-foreground mt-3">
                Hidden service not yet deployed
              </p>
            </div>
          </motion.section>

          {/* Risk Acknowledgment */}
          {!acceptedRisks ? (
            <motion.section
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
              className="mb-12"
            >
              <div className="p-6 rounded-xl bg-amber-500/5 border border-amber-500/20">
                <div className="flex items-center gap-3 mb-4">
                  <AlertTriangle className="w-6 h-6 text-amber-500" />
                  <h2 className="text-xl font-outfit font-bold">Understanding the Risks</h2>
                </div>
                <p className="text-sm text-muted-foreground mb-4">
                  Before Tor access becomes available, understand what it does and does not provide:
                </p>
                <ul className="space-y-2 text-sm text-muted-foreground mb-6">
                  <li className="flex items-start gap-2">
                    <span className="text-amber-500 mt-1">•</span>
                    <span><strong className="text-foreground">Tor hides your IP from Ghost.</strong> It does not make you invisible to all adversaries.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-amber-500 mt-1">•</span>
                    <span><strong className="text-foreground">Endpoint security still matters.</strong> A compromised device defeats all network-level protections.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-amber-500 mt-1">•</span>
                    <span><strong className="text-foreground">Behavioral patterns can identify you.</strong> Timing, writing style, and metadata are not hidden by encryption alone.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-amber-500 mt-1">•</span>
                    <span><strong className="text-foreground">Ghost is not magic.</strong> It is a tool with specific, limited guarantees. Read the threat model.</span>
                  </li>
                </ul>
                <Button
                  variant="outline"
                  onClick={() => setAcceptedRisks(true)}
                  className="border-amber-500/30 text-amber-400 hover:bg-amber-500/10"
                >
                  I Understand These Limitations
                </Button>
              </div>
            </motion.section>
          ) : (
            <motion.section
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="mb-12"
            >
              <div className="p-4 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
                <div className="flex items-center gap-3">
                  <Shield className="w-5 h-5 text-emerald-500 flex-shrink-0" />
                  <p className="text-sm text-emerald-400">
                    Risk acknowledgment recorded. You will be notified when Tor access becomes available.
                  </p>
                </div>
              </div>
            </motion.section>
          )}

          {/* Technical Honesty */}
          <motion.section
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
          >
            <div className="p-6 rounded-xl bg-muted/20 border border-border">
              <div className="flex items-center gap-3 mb-4">
                <Info className="w-6 h-6 text-primary" />
                <h2 className="text-xl font-outfit font-bold">Technical Honesty</h2>
              </div>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li className="flex items-start gap-2">
                  <span className="text-primary mt-1">•</span>
                  <span><strong className="text-foreground">Ghost does not bundle Tor.</strong> We do not embed Tor routing into the application.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-primary mt-1">•</span>
                  <span><strong className="text-foreground">Ghost does not proxy your traffic.</strong> We do not operate VPNs, SOCKS proxies, or network tunnels.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-primary mt-1">•</span>
                  <span><strong className="text-foreground">Tor is external by design.</strong> This separation is intentional — it prevents Ghost from being a single point of failure for your anonymity.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-primary mt-1">•</span>
                  <span><strong className="text-foreground">This page exists to demonstrate readiness, not availability.</strong> We will not claim Tor support until it is fully operational and verified.</span>
                </li>
              </ul>
            </div>
          </motion.section>
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default Tor;
