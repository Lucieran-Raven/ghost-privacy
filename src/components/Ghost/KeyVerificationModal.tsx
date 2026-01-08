import { useState, useEffect } from 'react';
import { Shield, CheckCircle, XCircle, AlertTriangle, Copy, Check } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

interface KeyVerificationModalProps {
  localFingerprint: string;
  remoteFingerprint: string;
  onVerified: () => void;
  onCancel: () => void;
  isVisible: boolean;
}

const KeyVerificationModal = ({
  localFingerprint,
  remoteFingerprint,
  onVerified,
  onCancel,
  isVisible
}: KeyVerificationModalProps) => {
  const [copiedLocal, setCopiedLocal] = useState(false);
  const [copiedRemote, setCopiedRemote] = useState(false);

  const copyToClipboard = async (text: string, type: 'local' | 'remote') => {
    await navigator.clipboard.writeText(text);

    // Best-effort: clear clipboard shortly after copy to reduce persistence.
    // (User can still paste immediately; this is a strict-mode hygiene measure.)
    setTimeout(() => {
      try {
        void navigator.clipboard.writeText('');
      } catch {
      }
    }, 30000);
    if (type === 'local') {
      setCopiedLocal(true);
      setTimeout(() => setCopiedLocal(false), 2000);
    } else {
      setCopiedRemote(true);
      setTimeout(() => setCopiedRemote(false), 2000);
    }
  };

  // Format fingerprint for display (groups of 4)
  const formatFingerprint = (fp: string) => {
    return fp.match(/.{1,4}/g)?.join(' ') || fp;
  };

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-[100] flex items-center justify-center bg-background/95 backdrop-blur-xl p-3 md:p-4 mobile-modal safe-area-inset-top safe-area-inset-bottom"
        >
          <motion.div
            initial={{ scale: 0.95, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.95, opacity: 0 }}
            className="max-w-2xl w-full p-5 md:p-8 rounded-2xl glass border border-primary/30 max-h-[calc(100vh-24px)] max-h-[calc(100dvh-24px)] overflow-y-auto mobile-modal-content verification-modal-mobile"
          >
            {/* Header */}
            <div className="text-center mb-5 md:mb-8">
              <div className="inline-flex p-3 md:p-4 rounded-full bg-primary/10 mb-3 md:mb-4">
                <Shield className="h-8 w-8 md:h-10 md:w-10 text-primary" />
              </div>
              <h2 className="font-outfit font-bold text-xl md:text-2xl lg:text-3xl text-foreground mb-2">
                Verify Secure Connection
              </h2>
              <p className="text-muted-foreground text-sm md:text-base">
                Compare codes with your partner to prevent interception
              </p>
            </div>

            {/* Warning Banner */}
            <div className="flex items-start gap-2.5 md:gap-3 p-3 md:p-4 rounded-xl bg-yellow-500/10 border border-yellow-500/30 mb-5 md:mb-6">
              <AlertTriangle className="h-4 w-4 md:h-5 md:w-5 text-yellow-500 flex-shrink-0 mt-0.5" />
              <div className="text-xs md:text-sm">
                <p className="text-yellow-500 font-semibold mb-1">Important Security Step</p>
                <p className="text-muted-foreground leading-relaxed">
                  Contact your partner through a separate channel (phone, in-person) 
                  to verify these codes match.
                </p>
              </div>
            </div>

            {/* Fingerprint Display */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 md:gap-4 mb-5 md:mb-8">
              {/* Your Code */}
              <div className="p-4 md:p-5 rounded-xl bg-secondary/50 border border-border/50">
                <div className="flex items-center justify-between mb-2 md:mb-3">
                  <h3 className="text-xs md:text-sm font-medium text-primary uppercase tracking-wider">Your Code</h3>
                  <button
                    onClick={() => copyToClipboard(localFingerprint, 'local')}
                    className="p-1.5 rounded hover:bg-secondary active:bg-secondary/80 transition-colors touch-target"
                    title="Copy to clipboard"
                  >
                    {copiedLocal ? (
                      <Check className="h-4 w-4 text-accent" />
                    ) : (
                      <Copy className="h-4 w-4 text-muted-foreground" />
                    )}
                  </button>
                </div>
                <code className="block text-lg md:text-xl lg:text-2xl font-mono font-bold text-foreground tracking-wider break-all">
                  {formatFingerprint(localFingerprint)}
                </code>
                <p className="text-[11px] md:text-xs text-muted-foreground mt-2">Read this to your partner</p>
              </div>

              {/* Partner's Code */}
              <div className="p-4 md:p-5 rounded-xl bg-secondary/50 border border-border/50">
                <div className="flex items-center justify-between mb-2 md:mb-3">
                  <h3 className="text-xs md:text-sm font-medium text-accent uppercase tracking-wider">Partner's Code</h3>
                  <button
                    onClick={() => copyToClipboard(remoteFingerprint, 'remote')}
                    className="p-1.5 rounded hover:bg-secondary active:bg-secondary/80 transition-colors touch-target"
                    title="Copy to clipboard"
                  >
                    {copiedRemote ? (
                      <Check className="h-4 w-4 text-accent" />
                    ) : (
                      <Copy className="h-4 w-4 text-muted-foreground" />
                    )}
                  </button>
                </div>
                <code className="block text-lg md:text-xl lg:text-2xl font-mono font-bold text-foreground tracking-wider break-all">
                  {formatFingerprint(remoteFingerprint)}
                </code>
                <p className="text-[11px] md:text-xs text-muted-foreground mt-2">Have them read their code to you</p>
              </div>
            </div>

            {/* Actions */}
            <div className="flex flex-col gap-2.5 md:gap-3">
              <button
                onClick={onVerified}
                className="w-full flex items-center justify-center gap-2 px-5 py-3.5 md:py-4 bg-accent text-accent-foreground font-semibold rounded-xl hover:opacity-90 active:scale-[0.98] transition-all min-h-[52px] touch-target"
              >
                <CheckCircle className="h-5 w-5 flex-shrink-0" />
                <span className="text-sm md:text-base">Codes Match - Proceed</span>
              </button>
              <button
                onClick={onCancel}
                className="w-full flex items-center justify-center gap-2 px-5 py-3.5 md:py-4 bg-destructive/10 border border-destructive/30 text-destructive font-semibold rounded-xl hover:bg-destructive/20 active:scale-[0.98] transition-all min-h-[52px] touch-target"
              >
                <XCircle className="h-5 w-5 flex-shrink-0" />
                <span className="text-sm md:text-base">Don't Match - Cancel</span>
              </button>
            </div>

            {/* Help Text */}
            <p className="text-center text-[11px] md:text-xs text-muted-foreground mt-4 md:mt-6 leading-relaxed">
              This verification ensures no one is intercepting your connection.
            </p>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default KeyVerificationModal;
