import { Shield, Flame, ShieldCheck, Globe, Lock, Eye, AlertTriangle } from 'lucide-react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';

const features = [
  {
    icon: Lock,
    title: 'END-TO-END ENCRYPTION',
    tagline: '🔐 ZERO-KNOWLEDGE ARCHITECTURE',
    description: 'All encryption happens in your browser. Keys never touch our servers. We do not store message plaintext, but infrastructure/network metadata may exist outside the app\'s control.',
    color: 'primary',
    stamp: 'VERIFIED'
  },
  {
    icon: Flame,
    title: 'EPHEMERAL BY DEFAULT',
    tagline: '🔥 MEMORY-ONLY STORAGE',
    description: 'Messages exist only in RAM during your session. In browsers, cleanup is best-effort (GC and caching limits apply). In Secure Runtime mode, cleanup is hardened to reduce post-exit traces.',
    color: 'ghost-red',
    stamp: 'EPHEMERAL'
  },
  {
    icon: ShieldCheck,
    title: 'MITM PROTECTION',
    tagline: '🛡️ WHEN YOU VERIFY',
    description: 'MITM protection is provided when fingerprints are verified or pinned (TOFU). Always verify codes out-of-band (phone/in-person) for high-risk conversations.',
    color: 'accent',
    stamp: 'VERIFY'
  },
  {
    icon: Globe,
    title: 'MINIMAL DIGITAL FOOTPRINT',
    tagline: '🌐 NO ACCOUNTS REQUIRED',
    description: 'No accounts. No phone numbers. No email. Share a Ghost ID, talk, then close. Some network metadata unavoidably exists.',
    color: 'ghost-purple',
    stamp: 'MINIMAL'
  },
];

const FeaturesSection = () => {
  return (
    <section id="features" className="py-32 relative overflow-hidden">
      {/* Background Effects */}
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-secondary/10 to-transparent" />
      <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-primary/20 to-transparent" />
      
      <div className="container mx-auto px-4 relative z-10">
        {/* Section Header */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="text-center mb-20"
        >
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-primary/30 bg-primary/5 mb-6">
            <span className="text-xs font-bold tracking-[0.2em] text-primary">SECURITY OVERVIEW</span>
          </div>
          <h2 className="font-heading font-black text-4xl md:text-5xl lg:text-6xl mb-6">
            <span className="text-foreground">BUILT ON </span>
            <span className="gradient-text">OPEN STANDARDS</span>
          </h2>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Four security principles that protect your conversations—
            not promises, but verifiable engineering.
          </p>
        </motion.div>

        {/* Features Grid */}
        <div className="grid md:grid-cols-2 gap-8 max-w-5xl mx-auto">
          {features.map((feature, index) => {
            const Icon = feature.icon;
            
            return (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                className="group relative"
              >
                <div className="relative p-8 rounded-2xl glass border border-border/50 hover:border-primary/30 transition-all duration-500 hover-lift overflow-hidden">
                  {/* Stamp */}
                  <div className={`absolute top-4 right-4 px-2 py-1 text-[10px] font-black tracking-wider border-2 transform rotate-12 ${
                    feature.color === 'ghost-red' ? 'text-ghost-red border-ghost-red' :
                    feature.color === 'accent' ? 'text-accent border-accent' :
                    feature.color === 'ghost-purple' ? 'text-ghost-purple border-ghost-purple' :
                    'text-primary border-primary'
                  } opacity-60`}>
                    {feature.stamp}
                  </div>

                  {/* Icon */}
                  <div className={`inline-flex p-4 rounded-xl mb-6 ${
                    feature.color === 'ghost-red' ? 'bg-ghost-red/10' :
                    feature.color === 'accent' ? 'bg-accent/10' :
                    feature.color === 'ghost-purple' ? 'bg-ghost-purple/10' :
                    'bg-primary/10'
                  }`}>
                    <Icon className={`h-8 w-8 ${
                      feature.color === 'ghost-red' ? 'text-ghost-red' :
                      feature.color === 'accent' ? 'text-accent' :
                      feature.color === 'ghost-purple' ? 'text-ghost-purple' :
                      'text-primary'
                    }`} />
                  </div>

                  {/* Tagline */}
                  <div className="text-sm font-bold tracking-wide text-muted-foreground mb-3">
                    {feature.tagline}
                  </div>

                  {/* Title */}
                  <h3 className="font-heading font-bold text-xl md:text-2xl mb-4 text-foreground">
                    {feature.title}
                  </h3>

                  {/* Description */}
                  <p className="text-muted-foreground leading-relaxed">
                    {feature.description}
                  </p>

                  {/* Hover Glow Effect */}
                  <div className={`absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 ${
                    feature.color === 'ghost-red' ? 'bg-ghost-red/5' :
                    feature.color === 'accent' ? 'bg-accent/5' :
                    feature.color === 'ghost-purple' ? 'bg-ghost-purple/5' :
                    'bg-primary/5'
                  } blur-xl -z-10`} />
                </div>
              </motion.div>
            );
          })}
        </div>

        {/* Honest Disclaimer */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.5 }}
          className="max-w-3xl mx-auto mt-16 p-6 rounded-2xl glass border border-yellow-500/20"
        >
          <div className="flex items-start gap-4">
            <AlertTriangle className="h-6 w-6 text-yellow-500 flex-shrink-0 mt-1" />
            <div>
              <h4 className="font-heading font-bold text-lg text-foreground mb-2">
                Transparency Note
              </h4>
              <p className="text-muted-foreground text-sm leading-relaxed mb-4">
                Ghost minimizes specific risks with end-to-end encryption and in-memory handling. Network metadata (IP address, timing)
                is still observable on clearnet—use Tor Browser for network anonymity. Verify fingerprints out-of-band to reduce active
                interception risk. Browser memory cleanup is best-effort and cannot be reliably ensured.
              </p>
              <Link 
                to="/limitations" 
                className="inline-flex items-center text-sm text-primary hover:text-primary/80 transition-colors"
              >
                Read full limitations →
              </Link>
            </div>
          </div>
        </motion.div>

        {/* Bottom Tagline */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.6 }}
          className="text-center mt-12"
        >
          <p className="text-sm text-muted-foreground font-mono tracking-wider">
            SECURITY CLAIMS: SCOPED. LIMITATIONS: DOCUMENTED.
          </p>
        </motion.div>
      </div>
    </section>
  );
};

export default FeaturesSection;
