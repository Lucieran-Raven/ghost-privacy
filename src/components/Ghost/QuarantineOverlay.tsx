import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, AlertTriangle, Clock } from 'lucide-react';
import { trapState } from '@/utils/trapState';
import { honeypotAudio } from '@/utils/honeypotAudio';

interface QuarantineOverlayProps {
  isActive: boolean;
}

/**
 * GHOST MIRAGE: Quarantine Overlay
 * 
 * Visual state degradation overlay that appears after
 * extended time in honeypot or suspicious behavior.
 * 
 * Features:
 * - Gray overlay with reduced interactivity
 * - Professional "flagged for review" messaging
 * - Ambient audio drone
 * - No threats, no claims - just ambiguity
 */
const QuarantineOverlay = ({ isActive }: QuarantineOverlayProps) => {
  const [sessionRef] = useState(trapState.generateSessionReference());
  const [degradation, setDegradation] = useState(0);

  // Start ambient audio and track degradation
  useEffect(() => {
    if (isActive) {
      honeypotAudio.startAmbient();
      
      // Gradually increase degradation
      const interval = setInterval(() => {
        setDegradation(trapState.getVisualDegradation());
      }, 5000);
      
      return () => {
        clearInterval(interval);
        honeypotAudio.stopAmbient();
      };
    }
  }, [isActive]);

  if (!isActive) return null;

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 0.95 }}
      className="fixed inset-0 z-[100] pointer-events-none"
      style={{
        background: `linear-gradient(180deg, 
          rgba(0,0,0,${0.3 + degradation * 0.4}) 0%, 
          rgba(0,0,0,${0.5 + degradation * 0.3}) 100%
        )`,
      }}
    >
      {/* Scan lines effect */}
      <div 
        className="absolute inset-0 opacity-10"
        style={{
          backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,255,255,0.03) 2px, rgba(255,255,255,0.03) 4px)',
        }}
      />

      {/* Center message */}
      <div className="absolute inset-0 flex items-center justify-center">
        <motion.div
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.5 }}
          className="text-center max-w-md mx-4 p-8 rounded-2xl bg-background/80 backdrop-blur-sm border border-border/50 pointer-events-auto"
        >
          <div className="w-16 h-16 rounded-full bg-amber-500/10 flex items-center justify-center mx-auto mb-6">
            <Shield className="w-8 h-8 text-amber-500" />
          </div>
          
          <h2 className="text-xl font-outfit font-bold text-foreground mb-3">
            Session Flagged for Review
          </h2>
          
          <p className="text-muted-foreground mb-6 leading-relaxed">
            This session has been routed through enhanced integrity checks. 
            No further actions are available at this time.
          </p>

          {/* Session reference */}
          <div className="p-3 bg-muted/50 rounded-lg mb-6">
            <div className="flex items-center justify-center gap-2 text-sm">
              <span className="text-muted-foreground">Reference:</span>
              <span className="font-mono text-foreground">{sessionRef}</span>
            </div>
          </div>

          {/* Status indicators */}
          <div className="flex items-center justify-center gap-6 text-xs text-muted-foreground">
            <div className="flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
              <span>Integrity Check Active</span>
            </div>
            <div className="flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5" />
              <span>Manual Review Pending</span>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Corner reference */}
      <div className="absolute bottom-4 right-4 text-xs font-mono text-muted-foreground/50">
        {sessionRef}
      </div>
    </motion.div>
  );
};

export default QuarantineOverlay;
