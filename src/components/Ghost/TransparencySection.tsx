import { Lock, Code, ExternalLink, Shield, Eye, Server, Zap, AlertTriangle } from 'lucide-react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';

const TransparencySection = () => {
  return (
    <section className="py-32 relative overflow-hidden">
      {/* Background Glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-primary/3 rounded-full blur-[200px]" />
      
      <div className="container mx-auto px-4 relative z-10">
        <div className="max-w-5xl mx-auto">
          {/* Main Card */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="relative p-10 md:p-16 rounded-3xl glass-dark border border-primary/20"
          >
            {/* Corner Accents */}
            <div className="absolute top-0 left-0 w-24 h-24 border-l-2 border-t-2 border-primary/40 rounded-tl-3xl" />
            <div className="absolute bottom-0 right-0 w-24 h-24 border-r-2 border-b-2 border-accent/40 rounded-br-3xl" />
            <div className="absolute top-0 right-0 w-16 h-16 border-r-2 border-t-2 border-ghost-red/30 rounded-tr-3xl" />
            <div className="absolute bottom-0 left-0 w-16 h-16 border-l-2 border-b-2 border-ghost-purple/30 rounded-bl-3xl" />

            <div className="text-center">
              {/* Badge */}
              <motion.div
                initial={{ scale: 0.9, opacity: 0 }}
                whileInView={{ scale: 1, opacity: 1 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: 0.2 }}
                className="inline-flex p-5 rounded-2xl bg-primary/10 mb-8 secure-badge"
              >
                <Lock className="h-12 w-12 text-primary" />
              </motion.div>

              {/* Heading */}
              <h2 className="font-outfit font-black text-4xl md:text-5xl lg:text-6xl mb-6 text-foreground">
                TRANSPARENCY IS
                <br />
                <span className="gradient-text">PART OF SECURITY.</span>
              </h2>

              {/* Main Statement */}
              <p className="text-xl md:text-2xl text-foreground font-semibold mb-8">
                "Trust is earned through verification, not claims."
              </p>

              {/* Description */}
              <p className="text-muted-foreground text-lg mb-12 max-w-3xl mx-auto leading-relaxed">
                Every line of our encryption code is open for inspection. 
                We invite security researchers, cryptographers, and privacy advocates 
                to audit our implementation.
              </p>

              {/* Honest Limitations Warning */}
              <div className="p-6 rounded-2xl bg-yellow-500/10 border border-yellow-500/30 mb-12 text-left">
                <div className="flex items-start gap-4">
                  <AlertTriangle className="h-6 w-6 text-yellow-500 flex-shrink-0 mt-1" />
                  <div>
                    <h3 className="font-outfit font-bold text-lg text-yellow-500 mb-2">What We Can't Prevent</h3>
                    <ul className="space-y-2 text-sm text-muted-foreground">
                      <li>• Your IP address and session timing can be visible at the network and hosting/infrastructure level</li>
                      <li>• Without manual key verification, an active network attacker could impersonate your contact</li>
                      <li>• Browsers may retain traces in memory until garbage collection runs</li>
                    </ul>
                    <p className="mt-3 text-sm text-yellow-500/80 font-medium">
                      We believe honesty is part of security. Ghost minimizes risk—but isn't magic.
                    </p>
                  </div>
                </div>
              </div>

              {/* Live Security Status */}
              <div className="grid md:grid-cols-3 gap-4 mb-12">
                <div className="p-5 rounded-xl bg-accent/10 border border-accent/20">
                  <div className="flex items-center justify-center gap-2 mb-2">
                    <div className="w-2 h-2 rounded-full bg-accent animate-pulse" />
                    <span className="text-accent font-semibold text-sm uppercase tracking-wider">E2E ENCRYPTION ACTIVE</span>
                  </div>
                  <p className="text-xs text-muted-foreground">Keys generated client-side</p>
                </div>
                <div className="p-5 rounded-xl bg-primary/10 border border-primary/20">
                  <div className="flex items-center justify-center gap-2 mb-2">
                    <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                    <span className="text-primary font-semibold text-sm uppercase tracking-wider">KEY VERIFICATION</span>
                  </div>
                  <p className="text-xs text-muted-foreground">Fingerprints for MITM protection</p>
                </div>
                <div className="p-5 rounded-xl bg-ghost-purple/10 border border-ghost-purple/20">
                  <div className="flex items-center justify-center gap-2 mb-2">
                    <div className="w-2 h-2 rounded-full bg-ghost-purple animate-pulse" />
                    <span className="text-ghost-purple font-semibold text-sm uppercase tracking-wider">RAM-ONLY STORAGE</span>
                  </div>
                  <p className="text-xs text-muted-foreground">No disk persistence</p>
                </div>
              </div>

              {/* Crypto Specs */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-12">
                {[
                  { value: '256-bit', label: 'AES-GCM', sublabel: 'Symmetric Encryption', icon: Shield },
                  { value: 'P-256', label: 'ECDH', sublabel: 'Key Exchange', icon: Zap },
                  { value: 'SHA-256', label: 'HMAC', sublabel: 'Message Auth', icon: Eye },
                  { value: 'Web Crypto', label: 'API', sublabel: 'Browser Native', icon: Server },
                ].map((spec, index) => (
                  <motion.div
                    key={spec.label}
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ duration: 0.4, delay: 0.1 * index }}
                    className="p-4 rounded-xl bg-secondary/30 border border-border/30 hover:border-primary/30 transition-all duration-300"
                  >
                    <spec.icon className="h-5 w-5 text-primary mx-auto mb-2" />
                    <div className="font-outfit font-bold text-xl text-foreground">{spec.value}</div>
                    <div className="text-sm text-primary font-medium">{spec.label}</div>
                    <div className="text-xs text-muted-foreground">{spec.sublabel}</div>
                  </motion.div>
                ))}
              </div>

              {/* CTAs */}
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                <Link
                  to="/security"
                  className="inline-flex items-center gap-3 px-8 py-4 bg-primary/10 border border-primary/30 text-primary font-outfit font-bold rounded-xl transition-all duration-300 hover:bg-primary/20 hover:border-primary/50 hover:scale-105"
                >
                  <Code className="h-5 w-5" />
                  VIEW SECURITY ARCHITECTURE
                  <ExternalLink className="h-4 w-4" />
                </Link>
                <Link
                  to="/limitations"
                  className="inline-flex items-center gap-3 px-8 py-4 bg-yellow-500/10 border border-yellow-500/30 text-yellow-500 font-outfit font-bold rounded-xl transition-all duration-300 hover:bg-yellow-500/20 hover:border-yellow-500/50 hover:scale-105"
                >
                  <AlertTriangle className="h-5 w-5" />
                  VIEW LIMITATIONS
                </Link>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
};

export default TransparencySection;
