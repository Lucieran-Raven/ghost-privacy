import { Ghost, ArrowRight, Lock, AlertTriangle, Play } from 'lucide-react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useState, useEffect } from 'react';
import ParticleField from './ParticleField';

const HeroSection = () => {
  const [displayText, setDisplayText] = useState('');
  const [showCursor, setShowCursor] = useState(true);
  const fullText = "PRIVATE BY DESIGN. EPHEMERAL BY DEFAULT.";
  
  useEffect(() => {
    let index = 0;
    const typingInterval = setInterval(() => {
      if (index <= fullText.length) {
        setDisplayText(fullText.slice(0, index));
        index++;
      } else {
        clearInterval(typingInterval);
      }
    }, 50);

    const cursorInterval = setInterval(() => {
      setShowCursor(prev => !prev);
    }, 530);

    return () => {
      clearInterval(typingInterval);
      clearInterval(cursorInterval);
    };
  }, []);

  return (
    <section className="relative min-h-screen min-h-[100dvh] flex items-center justify-center pt-16 md:pt-20 pb-12 overflow-hidden hero-mobile">
      {/* Cinematic Background */}
      <div className="absolute inset-0 bg-gradient-dark" />
      
      {/* Animated Grid - hidden on mobile for performance */}
      <div className="absolute inset-0 bg-grid-pattern bg-[size:60px_60px] opacity-10 hidden md:block" />
      
      {/* Particle Field - hidden on mobile for performance */}
      <div className="hidden md:block">
        <ParticleField />
      </div>
      
      {/* Glowing Orbs - reduced on mobile */}
      <div className="absolute top-1/4 left-1/4 w-[300px] md:w-[500px] h-[300px] md:h-[500px] bg-primary/5 rounded-full blur-[100px] md:blur-[150px] animate-pulse" />
      <div className="absolute bottom-1/4 right-1/4 w-[250px] md:w-[400px] h-[250px] md:h-[400px] bg-ghost-green/5 rounded-full blur-[80px] md:blur-[120px] animate-pulse hidden sm:block" style={{ animationDelay: '1s' }} />

      <div className="container mx-auto px-4 relative z-10">
        <div className="max-w-5xl mx-auto text-center">
          {/* Ghost Promise Badge */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="inline-flex items-center gap-2 md:gap-3 px-3 md:px-5 py-2 md:py-2.5 rounded-full glass border border-primary/30 mt-2 mb-6 md:mt-3 md:mb-10"
          >
            <Lock className="h-3.5 w-3.5 md:h-4 md:w-4 text-primary flex-shrink-0" />
            <span className="text-[11px] md:text-sm font-semibold tracking-wide text-primary/90 whitespace-nowrap">
              END-TO-END ENCRYPTED
            </span>
          </motion.div>

          {/* Main Heading - Typing Effect */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.3, delay: 0.3 }}
            className="mb-6 md:mb-8"
          >
            <h1 className="font-heading font-black text-3xl sm:text-4xl md:text-6xl lg:text-7xl xl:text-8xl leading-tight mobile-heading px-2">
              <span className="text-foreground">{displayText}</span>
              <span className={`text-primary ${showCursor ? 'opacity-100' : 'opacity-0'} transition-opacity`}>|</span>
            </h1>
          </motion.div>

          {/* Subheadline */}
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 2.5 }}
            className="text-sm md:text-lg lg:text-xl xl:text-2xl text-muted-foreground max-w-3xl mx-auto mb-6 md:mb-8 leading-relaxed px-2 mobile-subheading"
          >
            For <span className="text-primary font-semibold">lawyers and founders</span>. 
            For <span className="text-accent font-semibold">doctors and privacy-conscious professionals</span>. 
            For anyone who needs confidential, ephemeral chats.
          </motion.p>

          {/* Audience Disclaimer */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 2.7 }}
            className="max-w-2xl mx-auto mb-8 md:mb-12 p-3 md:p-4 rounded-xl glass border border-border/30"
          >
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 md:gap-4 text-xs md:text-sm">
              <div className="text-left">
                <p className="text-accent font-semibold mb-1">👥 Ideal for:</p>
                <p className="text-muted-foreground leading-snug">Business professionals, legal teams, healthcare coordination</p>
              </div>
              <div className="text-left">
                <p className="text-yellow-500 font-semibold mb-1">⚠️ Not yet ready for:</p>
                <p className="text-muted-foreground leading-snug">Journalists in active conflict zones, whistleblowers</p>
              </div>
            </div>
          </motion.div>

          {/* CTA Buttons */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 3.0 }}
            className="flex flex-col sm:flex-row items-center justify-center gap-3 md:gap-5 mb-10 md:mb-16 px-2"
          >
            <Link
              to="/session"
              className="group relative w-full sm:w-auto flex items-center justify-center gap-2 md:gap-3 px-6 md:px-8 py-3.5 md:py-4 bg-primary text-primary-foreground font-heading font-bold text-sm md:text-lg rounded-xl overflow-hidden transition-all duration-300 active:scale-[0.98] pulse-glow mobile-cta-primary touch-target"
            >
              <Lock className="h-4 w-4 md:h-5 md:w-5 relative z-10 flex-shrink-0" />
              <span className="relative z-10">START SECURE SESSION</span>
              <ArrowRight className="h-4 w-4 md:h-5 md:w-5 relative z-10 flex-shrink-0" />
            </Link>
            
            <Link
              to="/limitations"
              className="group w-full sm:w-auto flex items-center justify-center gap-2 md:gap-3 px-6 md:px-8 py-3.5 md:py-4 border border-border hover:border-yellow-500/50 active:border-yellow-500/50 text-foreground font-heading font-semibold text-sm md:text-lg rounded-xl transition-all duration-300 active:bg-yellow-500/5 touch-target"
            >
              <AlertTriangle className="h-4 w-4 md:h-5 md:w-5 text-yellow-500 flex-shrink-0" />
              <span>VIEW LIMITATIONS</span>
            </Link>
          </motion.div>

          {/* Security Stats */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 3.3 }}
            className="grid grid-cols-2 md:grid-cols-4 gap-2 md:gap-4 max-w-4xl mx-auto"
          >
            {[
              { value: 'AES-256', label: 'Encryption', color: 'primary' },
              { value: 'RAM Only', label: 'No Storage', color: 'accent' },
              { value: 'P-256', label: 'Key Exchange', color: 'ghost-purple' },
              { value: 'Verifiable', label: 'Fingerprints', color: 'yellow-500' },
            ].map((stat, index) => (
              <div
                key={stat.label}
                className="p-3 md:p-4 rounded-xl glass border border-border/30 hover:border-primary/30 active:border-primary/30 transition-all duration-300"
              >
                <div className={`font-outfit font-bold text-lg md:text-2xl lg:text-3xl text-${stat.color} mb-0.5 md:mb-1`}>
                  {stat.value}
                </div>
                <div className="text-[10px] md:text-xs text-muted-foreground uppercase tracking-wider">
                  {stat.label}
                </div>
              </div>
            ))}
          </motion.div>
        </div>
      </div>

      {/* Bottom Gradient Fade */}
      <div className="absolute bottom-0 left-0 right-0 h-24 md:h-40 bg-gradient-to-t from-background via-background/80 to-transparent" />
      
      {/* Cinematic Scan Line - hidden on mobile */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden hidden md:block">
        <div className="absolute left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-primary/20 to-transparent animate-scan" />
      </div>
    </section>
  );
};

export default HeroSection;
