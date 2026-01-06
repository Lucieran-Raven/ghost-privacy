import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, X, Shield } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Link } from 'react-router-dom';

/**
 * Detects if user is likely accessing via Tor Browser
 * Note: This is best-effort detection, not guaranteed
 */
const detectTorBrowser = (): boolean => {
  // Check for .onion in URL
  if (window.location.hostname.endsWith('.onion')) {
    return true;
  }
  
  // Tor Browser has specific fingerprint characteristics
  // These are heuristics, not guarantees
  const canvas = document.createElement('canvas');
  const gl = canvas.getContext('webgl');
  
  // Tor Browser often blocks or spoofs WebGL
  if (!gl) {
    return true; // Possible Tor Browser
  }
  
  // Check for Tor Browser's typical window size (default is 1000x800 or similar rounded)
  const isRoundedSize = 
    (window.innerWidth % 100 === 0 || window.innerWidth % 200 === 0) &&
    (window.innerHeight % 100 === 0 || window.innerHeight % 200 === 0);
  
  // This is a weak signal, so we don't rely on it alone
  return false;
};

interface ClearnetWarningProps {
  className?: string;
}

const ClearnetWarning = ({ className = '' }: ClearnetWarningProps) => {
  const [dismissed, setDismissed] = useState(false);
  const [isTor, setIsTor] = useState(false);

  useEffect(() => {
    // Run Tor detection on mount
    setIsTor(detectTorBrowser());
  }, []);

  // Don't show if using Tor or dismissed
  if (isTor || dismissed) {
    return null;
  }

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -10 }}
        className={`relative bg-destructive/10 border border-destructive/30 rounded-xl p-5 md:p-6 ${className}`}
      >
        <button
          onClick={() => setDismissed(true)}
          className="absolute top-3 right-3 p-1.5 rounded-full hover:bg-destructive/20 transition-colors"
          aria-label="Dismiss warning"
        >
          <X className="w-4 h-4 text-destructive" />
        </button>

        <div className="flex items-start gap-4 pr-8">
          <div className="flex-shrink-0 w-10 h-10 rounded-full bg-destructive/20 flex items-center justify-center">
            <AlertTriangle className="w-5 h-5 text-destructive" />
          </div>
          <div className="space-y-3 flex-1">
            <p className="text-sm md:text-base font-medium text-destructive leading-relaxed">
              You're on the clearnet — your IP address is visible
            </p>
            <p className="text-xs md:text-sm text-muted-foreground leading-relaxed">
              For journalists, activists, and high-risk users: Access Ghost via Tor Browser 
              to hide your network identity.
            </p>
            <div className="flex flex-wrap items-center gap-3 pt-2">
              <Link to="/onion">
                <Button variant="outline" size="sm" className="h-8 md:h-9 text-xs md:text-sm gap-2 border-destructive/30 hover:bg-destructive/10 px-4">
                  <Shield className="w-3.5 h-3.5" />
                  Learn about Tor access
                </Button>
              </Link>
              <button
                onClick={() => setDismissed(true)}
                className="text-xs md:text-sm text-muted-foreground hover:text-foreground transition-colors py-1"
              >
                I understand the risks
              </button>
            </div>
          </div>
        </div>
      </motion.div>
    </AnimatePresence>
  );
};

export default ClearnetWarning;
