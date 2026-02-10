import { Link } from 'react-router-dom';

const Footer = () => {
  return (
    <footer className="border-t border-[rgba(255,10,42,0.18)] bg-black/40 safe-area-inset-bottom">
      <div className="mx-auto max-w-[1400px] px-4 py-8">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">
            OPERATIONAL INTERFACE
          </div>

          <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
            <Link to="/security" className="font-mono text-xs tracking-[0.16em] uppercase text-white/60 hover:text-white transition-colors">SECURITY</Link>
            <Link to="/tor" className="font-mono text-xs tracking-[0.16em] uppercase text-white/60 hover:text-white transition-colors">TOR</Link>
            <Link to="/limitations" className="font-mono text-xs tracking-[0.16em] uppercase text-white/60 hover:text-white transition-colors">LIMITATIONS</Link>
            <Link to="/about" className="font-mono text-xs tracking-[0.16em] uppercase text-white/60 hover:text-white transition-colors">ABOUT</Link>
            <Link to="/contribute" className="font-mono text-xs tracking-[0.16em] uppercase text-white/60 hover:text-white transition-colors">CONTRIBUTE</Link>
            <a
              href="https://github.com/Lucieran-Raven/ghost-privacy"
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-xs tracking-[0.16em] uppercase text-white/60 hover:text-white transition-colors"
            >
              GITHUB
            </a>
          </div>

          <div className="font-mono text-xs tracking-[0.16em] uppercase text-white/60">
            © {new Date().getFullYear()} GHOST
          </div>
        </div>

        <div className="mt-6 pt-6 border-t border-[rgba(255,10,42,0.14)]">
          <div className="font-mono text-[11px] leading-relaxed text-white/60">
            THREAT MODEL: PUBLISHED. LIMITATIONS: DOCUMENTED. READ <Link to="/limitations" className="underline hover:text-white">/LIMITATIONS</Link>.
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
