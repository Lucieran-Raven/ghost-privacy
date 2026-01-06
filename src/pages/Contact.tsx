import { Send, Shield, MessageCircle, Github, Mail, AlertTriangle, Clock, ExternalLink } from 'lucide-react';
import { motion } from 'framer-motion';
import Navbar from '@/components/Ghost/Navbar';
import Footer from '@/components/Ghost/Footer';

const Contact = () => {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      
      <main className="pt-24 pb-12">
        <div className="container mx-auto px-4">
          {/* Header */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="max-w-4xl mx-auto text-center mb-16"
          >
            <div className="inline-flex items-center gap-2 px-5 py-2.5 rounded-full glass border border-primary/30 mb-8">
              <Send className="h-5 w-5 text-primary" />
              <span className="text-sm font-bold tracking-wider text-primary uppercase">Contact Ghost</span>
            </div>
            <h1 className="font-outfit font-black text-5xl md:text-6xl lg:text-7xl mb-6">
              <span className="text-foreground">GET IN </span>
              <span className="gradient-text">TOUCH</span>
            </h1>
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
              Questions, feedback, or security reports — we're listening.
            </p>
          </motion.div>

          {/* Simple Contact Methods */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="max-w-4xl mx-auto mb-16"
          >
            <div className="grid md:grid-cols-3 gap-6">
              {/* Telegram - Fast Response */}
              <div className="p-6 rounded-2xl glass border border-primary/20 hover:border-primary/40 transition-colors">
                <div className="flex items-center gap-3 mb-4">
                  <div className="p-3 rounded-xl bg-primary/10">
                    <MessageCircle className="h-6 w-6 text-primary" />
                  </div>
                  <div>
                    <h3 className="font-outfit font-bold text-lg text-foreground">Telegram</h3>
                    <span className="text-xs text-primary font-medium">FASTEST</span>
                  </div>
                </div>
                <p className="text-sm text-muted-foreground mb-4">
                  Quick questions, feedback, or general discussion:
                </p>
                <a 
                  href="https://t.me/ghostdeveloperadmin"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 text-primary hover:text-primary/80 font-medium transition-colors"
                >
                  @ghostdeveloperadmin
                  <ExternalLink className="h-4 w-4" />
                </a>
                <div className="flex items-center gap-2 mt-3 text-xs text-muted-foreground">
                  <Clock className="h-3 w-3" />
                  <span>Usually within hours</span>
                </div>
              </div>

              {/* Email - All Inquiries */}
              <div className="p-6 rounded-2xl glass border border-accent/20 hover:border-accent/40 transition-colors">
                <div className="flex items-center gap-3 mb-4">
                  <div className="p-3 rounded-xl bg-accent/10">
                    <Mail className="h-6 w-6 text-accent" />
                  </div>
                  <div>
                    <h3 className="font-outfit font-bold text-lg text-foreground">Email</h3>
                    <span className="text-xs text-accent font-medium">ALL INQUIRIES</span>
                  </div>
                </div>
                <p className="text-sm text-muted-foreground mb-4">
                  Security reports, business, or detailed discussions:
                </p>
                <a 
                  href="mailto:lucieranraven@gmail.com"
                  className="text-accent hover:text-accent/80 font-mono text-sm transition-colors break-all"
                >
                  lucieranraven@gmail.com
                </a>
                <div className="flex items-center gap-2 mt-3 text-xs text-muted-foreground">
                  <Clock className="h-3 w-3" />
                  <span>Within 24 hours</span>
                </div>
              </div>

              {/* GitHub - Technical */}
              <div className="p-6 rounded-2xl glass border border-ghost-purple/20 hover:border-ghost-purple/40 transition-colors">
                <div className="flex items-center gap-3 mb-4">
                  <div className="p-3 rounded-xl bg-ghost-purple/10">
                    <Github className="h-6 w-6 text-ghost-purple" />
                  </div>
                  <div>
                    <h3 className="font-outfit font-bold text-lg text-foreground">GitHub</h3>
                    <span className="text-xs text-ghost-purple font-medium">TECHNICAL</span>
                  </div>
                </div>
                <p className="text-sm text-muted-foreground mb-4">
                  View code, report bugs, or suggest features:
                </p>
                <a 
                  href="https://github.com/Lucieran-Raven/ghost-privacy"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 text-ghost-purple hover:text-ghost-purple/80 font-medium transition-colors text-sm"
                >
                  Lucieran-Raven/ghost-privacy
                  <ExternalLink className="h-4 w-4" />
                </a>
                <div className="flex items-center gap-2 mt-3 text-xs text-muted-foreground">
                  <span>Issues tracked publicly</span>
                </div>
              </div>
            </div>

            {/* Disclaimer */}
            <div className="mt-8 p-5 rounded-xl bg-yellow-500/10 border border-yellow-500/20">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                <div className="text-sm text-muted-foreground space-y-2">
                  <p><span className="font-semibold text-yellow-500">Please Note:</span></p>
                  <ul className="space-y-1 list-disc list-inside">
                    <li>Ghost is in <strong>active development</strong> by a solo founder</li>
                    <li>Enterprise features are <strong>planned but not yet available</strong></li>
                    <li>For security issues, use email with subject <code className="bg-secondary/50 px-1 rounded">[SECURITY]</code></li>
                    <li>Based in Malaysia. We respond to lawful requests but retain zero user data</li>
                  </ul>
                </div>
              </div>
            </div>
          </motion.div>

          {/* Bug Bounty - Coming Soon */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="max-w-4xl mx-auto mb-16"
          >
            <div className="p-8 rounded-3xl glass border border-accent/20 relative overflow-hidden">
              {/* Coming Soon Badge */}
              <div className="absolute top-4 right-4">
                <div className="px-4 py-2 rounded-full bg-ghost-gold/20 border border-ghost-gold/40">
                  <span className="text-xs font-bold text-ghost-gold uppercase tracking-wider">🚧 Coming Soon</span>
                </div>
              </div>

              <div className="flex items-center gap-3 mb-6">
                <div className="p-2 rounded-lg bg-accent/10">
                  <Shield className="h-5 w-5 text-accent" />
                </div>
                <h2 className="font-outfit font-bold text-xl text-foreground">
                  Security Research & Bug Bounty
                </h2>
              </div>

              <p className="text-muted-foreground mb-6">
                We're establishing a formal bug bounty program. For now, please report security issues directly:
              </p>

              <div className="p-4 rounded-xl bg-ghost-red/10 border border-ghost-red/20 mb-6">
                <a 
                  href="mailto:lucieranraven@gmail.com?subject=[SECURITY] Ghost Vulnerability Report&body=Please include:%0A%0A1. Description of the vulnerability%0A2. Steps to reproduce%0A3. Potential impact%0A4. Suggested fix (if any)%0A%0A---%0A%0AThank you for responsible disclosure."
                  className="text-ghost-red hover:text-ghost-red/80 font-mono text-sm transition-colors"
                >
                  lucieranraven@gmail.com
                </a>
                <p className="text-xs text-muted-foreground mt-2">
                  Subject: <code className="bg-secondary/50 px-1 rounded">[SECURITY] Ghost Vulnerability Report</code>
                </p>
              </div>

              <div className="grid md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-secondary/30 border border-border/30">
                  <h4 className="font-semibold text-foreground mb-2">📅 Planned Program (2026)</h4>
                  <ul className="space-y-1 text-sm text-muted-foreground">
                    <li>💰 Bounties: $100 - $5,000 based on severity</li>
                    <li>🔐 Platform: HackerOne integration</li>
                    <li>📋 Responsible disclosure required</li>
                    <li>⚖️ Safe harbor for ethical researchers</li>
                  </ul>
                </div>

                <div className="p-4 rounded-xl bg-primary/10 border border-primary/20">
                  <h4 className="font-semibold text-foreground mb-2">⚡ Current Status</h4>
                  <ul className="space-y-1 text-sm text-muted-foreground">
                    <li>• All reports investigated within 24 hours</li>
                    <li>• Critical issues: &lt;2 hour response</li>
                    <li>• Fixing identified issues before launch</li>
                    <li>• Hall of fame for contributors</li>
                  </ul>
                </div>
              </div>
            </div>
          </motion.div>

          {/* Open Source Verification */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="max-w-3xl mx-auto"
          >
            <div className="p-6 rounded-2xl glass border border-accent/20 text-center">
              <Github className="h-8 w-8 text-accent mx-auto mb-4" />
              <h3 className="font-outfit font-bold text-lg text-foreground mb-2">
                Open Source Verification
              </h3>
              <p className="text-sm text-muted-foreground mb-4">
                Review every line of code. Security through transparency, not obscurity.
              </p>
              <a
                href="https://github.com/Lucieran-Raven/ghost-privacy"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 px-6 py-3 bg-accent/10 hover:bg-accent/20 border border-accent/30 rounded-xl text-accent font-semibold transition-all duration-300"
              >
                <Github className="h-5 w-5" />
                View on GitHub
                <ExternalLink className="h-4 w-4" />
              </a>
            </div>
          </motion.div>
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default Contact;