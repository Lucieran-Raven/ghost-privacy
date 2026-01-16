import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, AlertCircle, Loader2, Lock } from 'lucide-react';
import { trapState } from '@/utils/trapState';
import { trapAudio } from '@/utils/trapAudio';
import { secureRandomInt } from '@/utils/secureRng';

interface FakeTwoFactorModalProps {
  isOpen: boolean;
  onClose: () => void;
}

/**
 * GHOST MIRAGE: Non-Terminating 2FA Loop
 * 
 * Any code entered → "Invalid. Try again."
 * After 5 attempts → 30-second cooldown → loops forever
 * Creates illusion of security verification while wasting time.
 * 
 * ⚠️ TRANSPARENT SIMULATION LABEL ⚠️
 * This is a SECURITY TESTING SIMULATION for honeypot detection.
 * No authentication codes are validated.
 */
const FakeTwoFactorModal = ({ isOpen, onClose }: FakeTwoFactorModalProps) => {
  const [code, setCode] = useState('');
  const [attempts, setAttempts] = useState(0);
  const [isVerifying, setIsVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState(0);
  const [phase, setPhase] = useState<'input' | 'verifying' | 'cooldown' | 'retry'>('input');

  // Cooldown timer
  useEffect(() => {
    if (cooldown > 0) {
      const timer = setTimeout(() => setCooldown(cooldown - 1), 1000);
      return () => clearTimeout(timer);
    } else if (phase === 'cooldown') {
      setPhase('retry');
      setAttempts(0);
      setError(null);
    }
  }, [cooldown, phase]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (code.length !== 6 || phase !== 'input') return;

    trapState.recordTwoFactorAttempt();
    trapAudio.playTick();
    
    setIsVerifying(true);
    setPhase('verifying');
    setError(null);

    // Fake verification delay (3-5 seconds)
    await new Promise(resolve => setTimeout(resolve, 3000 + secureRandomInt(2001)));

    setIsVerifying(false);
    const newAttempts = attempts + 1;
    setAttempts(newAttempts);

    if (newAttempts >= 5) {
      // Trigger cooldown
      setPhase('cooldown');
      setCooldown(30);
      setError('Too many failed attempts. Security lockout initiated.');
    } else {
      // Show invalid error
      setPhase('input');
      setError(`Invalid verification code. ${5 - newAttempts} attempts remaining.`);
      setCode('');
    }
  };

  const handleRetry = () => {
    setPhase('input');
    setError(null);
    setCode('');
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-center justify-center bg-background/95 backdrop-blur-sm p-4"
      >
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          className="w-full max-w-md bg-card border border-border rounded-2xl shadow-2xl overflow-hidden"
        >
          {/* Header */}
          <div className="p-6 border-b border-border bg-muted/30">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center">
                <Shield className="w-6 h-6 text-primary" />
              </div>
              <div>
                <h2 className="text-xl font-outfit font-bold text-foreground">Security Verification</h2>
                <p className="text-sm text-muted-foreground">Additional authentication required</p>
              </div>
            </div>
          </div>

          {/* Content */}
          <div className="p-6">
            {phase === 'cooldown' ? (
              <div className="text-center py-8">
                <div className="w-16 h-16 rounded-full bg-destructive/10 flex items-center justify-center mx-auto mb-4">
                  <Lock className="w-8 h-8 text-destructive" />
                </div>
                <h3 className="text-lg font-semibold text-foreground mb-2">Security Lockout</h3>
                <p className="text-muted-foreground mb-4">Too many failed verification attempts.</p>
                <div className="text-3xl font-mono font-bold text-primary">{cooldown}s</div>
                <p className="text-xs text-muted-foreground mt-2">Please wait before trying again</p>
              </div>
            ) : phase === 'retry' ? (
              <div className="text-center py-8">
                <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4">
                  <Shield className="w-8 h-8 text-primary" />
                </div>
                <h3 className="text-lg font-semibold text-foreground mb-2">Lockout Expired</h3>
                <p className="text-muted-foreground mb-6">You may now attempt verification again.</p>
                <button
                  onClick={handleRetry}
                  className="px-6 py-3 bg-primary text-primary-foreground font-outfit font-semibold rounded-xl hover:shadow-glow-md transition-all"
                >
                  Try Again
                </button>
              </div>
            ) : (
              <form onSubmit={handleSubmit}>
                <p className="text-sm text-muted-foreground mb-6">
                  Enter the 6-digit verification code sent to your registered device to continue.
                </p>

                {/* Code input */}
                <div className="mb-6">
                  <label className="block text-sm font-medium text-foreground mb-2">
                    Verification Code
                  </label>
                  <input
                    type="text"
                    value={code}
                    onChange={(e) => {
                      const val = e.target.value.replace(/\D/g, '').slice(0, 6);
                      setCode(val);
                      setError(null);
                    }}
                    placeholder="000000"
                    maxLength={6}
                    className="w-full px-4 py-4 bg-background border border-border rounded-xl text-center text-2xl font-mono tracking-[0.5em] focus:outline-none focus:border-primary transition-colors"
                    disabled={isVerifying}
                    autoFocus
                  />
                </div>

                {/* Error message */}
                {error && (
                  <motion.div
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="flex items-center gap-2 p-3 mb-6 rounded-lg bg-destructive/10 border border-destructive/20"
                  >
                    <AlertCircle className="w-4 h-4 text-destructive flex-shrink-0" />
                    <p className="text-sm text-destructive">{error}</p>
                  </motion.div>
                )}

                {/* Submit button */}
                <button
                  type="submit"
                  disabled={code.length !== 6 || isVerifying}
                  className="w-full py-4 bg-primary text-primary-foreground font-outfit font-semibold rounded-xl hover:shadow-glow-md transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                >
                  {isVerifying ? (
                    <>
                      <Loader2 className="w-5 h-5 animate-spin" />
                      Verifying...
                    </>
                  ) : (
                    'Verify Code'
                  )}
                </button>

                {/* Attempt counter */}
                {attempts > 0 && (
                  <p className="text-xs text-muted-foreground text-center mt-4">
                    Failed attempts: {attempts}/5
                  </p>
                )}
              </form>
            )}
          </div>

          {/* Footer */}
          <div className="px-6 py-4 bg-muted/20 border-t border-border">
            <p className="text-xs text-muted-foreground text-center">
              Verification codes expire after 5 minutes. If you haven't received a code, check your device settings.
            </p>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
};

export default FakeTwoFactorModal;
