import { Link, useLocation } from 'react-router-dom';
import { useState } from 'react';
import { cn } from '@/lib/utils';

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
    <nav className="fixed top-0 md:top-9 left-0 right-0 z-50 bg-black/80 border-b border-[rgba(255,10,42,0.18)] backdrop-blur-xl safe-area-inset-top">
      <div className="mx-auto max-w-[1400px] px-4 h-12 flex items-center justify-between">
        <Link
          to="/"
          className="font-heading text-lg tracking-[0.22em] text-white/90 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#ff0a2a]"
        >
          GHOST PRIVACY
        </Link>

        <div className="hidden md:flex items-center gap-6">
            {navLinks.map((link) => (
              <Link
                key={link.href}
                to={link.href}
                className={cn(
                  "font-mono text-xs tracking-[0.16em] uppercase transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#ff0a2a]",
                  location.pathname === link.href
                    ? "text-[#ff0a2a]"
                    : "text-white/60 hover:text-white"
                )}
              >
                {link.label}
              </Link>
            ))}
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/session"
            className="hidden md:inline-flex font-mono text-xs tracking-[0.16em] uppercase px-3 py-2 border border-[rgba(255,10,42,0.24)] text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#ff0a2a]"
          >
            SESSION
          </Link>

          <button
            onClick={() => setIsMenuOpen(!isMenuOpen)}
            className="md:hidden font-mono text-xs tracking-[0.16em] uppercase px-3 py-2 border border-[rgba(255,10,42,0.24)] text-white/85 transition-all active:translate-y-[1px] hover:border-[rgba(255,10,42,0.55)] hover:text-white hover:shadow-[0_0_12px_rgba(255,10,42,0.35)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#ff0a2a]"
            aria-label={isMenuOpen ? 'Close menu' : 'Open menu'}
          >
            {isMenuOpen ? 'CLOSE' : 'MENU'}
          </button>
        </div>
      </div>

      {isMenuOpen && (
        <div className="md:hidden border-t border-[rgba(255,10,42,0.18)] bg-black/90">
          <div className="px-4 py-3 flex flex-col gap-2">
            {navLinks.map((link) => (
              <Link
                key={link.href}
                to={link.href}
                onClick={() => setIsMenuOpen(false)}
                className={cn(
                  "font-mono text-xs tracking-[0.16em] uppercase py-2 transition-colors",
                  location.pathname === link.href ? "text-[#ff0a2a]" : "text-white/85"
                )}
              >
                {link.label}
              </Link>
            ))}
            <Link
              to="/session"
              onClick={() => setIsMenuOpen(false)}
              className="font-mono text-xs tracking-[0.16em] uppercase py-2 text-white/85"
            >
              SESSION
            </Link>
          </div>
        </div>
      )}
    </nav>
  );
};

export default Navbar;
