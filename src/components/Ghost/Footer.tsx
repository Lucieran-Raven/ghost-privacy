import { Ghost, Github, ExternalLink } from 'lucide-react';
import { Link } from 'react-router-dom';

const Footer = () => {
  return (
    <footer className="py-8 md:py-12 border-t border-border/30 footer-mobile safe-area-inset-bottom">
      <div className="container mx-auto px-4">
        <div className="flex flex-col md:flex-row items-center justify-between gap-6">
          {/* Logo */}
          <Link to="/" className="flex items-center gap-2 touch-target">
            <Ghost className="h-5 w-5 md:h-6 md:w-6 text-primary" />
            <span className="font-outfit font-bold text-lg md:text-xl gradient-text">Ghost</span>
          </Link>

          {/* Links */}
          <div className="flex flex-wrap items-center justify-center gap-x-4 gap-y-2 md:gap-6 text-xs md:text-sm text-muted-foreground">
            <Link to="/" className="hover:text-primary active:text-primary transition-colors py-1 touch-target">Home</Link>
            <Link to="/security" className="hover:text-primary active:text-primary transition-colors py-1 touch-target">Security</Link>
            <Link to="/limitations" className="hover:text-yellow-500 active:text-yellow-500 transition-colors py-1 touch-target">Limitations</Link>
            <Link to="/about" className="hover:text-primary active:text-primary transition-colors py-1 touch-target">About</Link>
            <Link to="/contribute" className="hover:text-primary active:text-primary transition-colors py-1 touch-target">Contribute</Link>
            <a 
              href="https://github.com/Lucieran-Raven/ghost-privacy" 
              target="_blank" 
              rel="noopener noreferrer" 
              className="flex items-center gap-1.5 hover:text-primary active:text-primary transition-colors py-1 touch-target"
            >
              <Github className="h-4 w-4" />
              <span className="hidden sm:inline">GitHub</span>
            </a>
          </div>

          {/* Copyright */}
          <p className="text-xs md:text-sm text-muted-foreground">
            © {new Date().getFullYear()} Ghost
          </p>
        </div>

        {/* Bottom Message */}
        <div className="mt-6 md:mt-8 pt-6 md:pt-8 border-t border-border/20 text-center">
          <p className="text-[11px] md:text-xs text-muted-foreground/60 max-w-2xl mx-auto leading-relaxed">
            End-to-end encrypted. No message storage on servers. 
            Built for privacy-conscious professionals.
            <br className="hidden sm:block" />
            <span className="text-yellow-500/60">
              Review our <Link to="/limitations" className="underline hover:text-yellow-500 active:text-yellow-500">limitations</Link> to understand what Ghost can and cannot protect.
            </span>
          </p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
