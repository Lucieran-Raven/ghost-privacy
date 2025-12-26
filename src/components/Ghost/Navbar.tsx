import { Ghost, Shield, Menu, X, Lock } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';
import { useState } from 'react';
import { cn } from '@/lib/utils';
import { motion, AnimatePresence } from 'framer-motion';

const Navbar = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const location = useLocation();

  const navLinks = [
    { href: '/', label: 'Home' },
    { href: '/security', label: 'Security' },
    { href: '/tor', label: 'Tor' },
    { href: '/about', label: 'About' },
    { href: '/contribute', label: 'Contribute' },
  ];

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 glass-dark border-b border-border/20 safe-area-inset-top nav-mobile h-14 md:h-auto">
      <div className="container mx-auto px-3 md:px-4 py-2 md:py-4 h-full">
        <div className="flex items-center justify-between h-full">
          {/* Logo */}
          <Link to="/" className="flex items-center gap-2 group touch-target">
            <div className="relative">
              <Ghost className="h-6 w-6 md:h-9 md:w-9 text-primary transition-all duration-300 group-hover:text-ghost-cyan-glow" />
              <div className="absolute inset-0 bg-primary/30 blur-xl rounded-full opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            </div>
            <span className="font-outfit font-black text-lg md:text-2xl gradient-text tracking-tight">
              GHOST
            </span>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center gap-8">
            {navLinks.map((link) => (
              <Link
                key={link.href}
                to={link.href}
                className={cn(
                  "font-medium text-sm uppercase tracking-wider transition-all duration-200 hover:text-primary relative group",
                  location.pathname === link.href ? "text-primary" : "text-muted-foreground"
                )}
              >
                {link.label}
                <span className="absolute -bottom-1 left-0 w-0 h-0.5 bg-primary transition-all duration-300 group-hover:w-full" />
              </Link>
            ))}
          </div>

          {/* CTA Button */}
          <div className="hidden md:flex items-center gap-4">
            <Link
              to="/session"
              className="group flex items-center gap-2 px-6 py-2.5 bg-primary text-primary-foreground font-outfit font-bold text-sm uppercase tracking-wider rounded-lg transition-all duration-300 hover:shadow-glow-md hover:scale-105"
            >
              <Lock className="h-4 w-4" />
              Secure Session
            </Link>
          </div>

          {/* Mobile Menu Button */}
          <button
            onClick={() => setIsMenuOpen(!isMenuOpen)}
            className="md:hidden p-2 -mr-1 text-foreground hover:text-primary active:text-primary transition-colors touch-target"
            aria-label={isMenuOpen ? "Close menu" : "Open menu"}
          >
            {isMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </div>

      </div>

      {/* Mobile Navigation - Full-screen overlay */}
      <AnimatePresence>
        {isMenuOpen && (
          <>
            {/* Backdrop overlay */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="fixed inset-0 bg-background/80 backdrop-blur-sm z-40 md:hidden"
              onClick={() => setIsMenuOpen(false)}
            />
            {/* Slide-in menu panel - solid distinct color */}
            <motion.div
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 300 }}
              className="fixed top-0 right-0 bottom-0 w-72 z-50 md:hidden safe-area-inset-top"
              style={{ backgroundColor: '#0F1629' }}
            >
              <div className="flex flex-col h-full">
                {/* Menu header */}
                <div className="flex items-center justify-between p-4 border-b border-primary/30" style={{ backgroundColor: '#0A0E27' }}>
                  <span className="font-outfit font-bold text-lg text-primary">Menu</span>
                  <button
                    onClick={() => setIsMenuOpen(false)}
                    className="p-2 text-muted-foreground hover:text-foreground active:text-primary transition-colors touch-target"
                    aria-label="Close menu"
                  >
                    <X className="h-5 w-5" />
                  </button>
                </div>
                
                {/* Nav links */}
                <div className="flex flex-col p-4 gap-2 flex-1" style={{ backgroundColor: '#0F1629' }}>
                  {navLinks.map((link) => (
                    <Link
                      key={link.href}
                      to={link.href}
                      onClick={() => setIsMenuOpen(false)}
                      className={cn(
                        "font-medium py-4 px-4 text-base uppercase tracking-wider transition-all duration-200 rounded-lg",
                        location.pathname === link.href 
                          ? "text-primary bg-primary/20 border-l-4 border-primary" 
                          : "text-foreground hover:bg-primary/10 active:bg-primary/20"
                      )}
                    >
                      {link.label}
                    </Link>
                  ))}
                </div>
                
                {/* CTA button */}
                <div className="p-4 border-t border-primary/30" style={{ backgroundColor: '#0A0E27' }}>
                  <Link
                    to="/session"
                    onClick={() => setIsMenuOpen(false)}
                    className="flex items-center justify-center gap-2 w-full px-5 py-3.5 bg-primary text-primary-foreground font-outfit font-bold rounded-xl min-h-[52px] touch-target active:scale-[0.98] transition-transform"
                  >
                    <Lock className="h-4 w-4" />
                    Secure Session
                  </Link>
                </div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </nav>
  );
};

export default Navbar;
