import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, AlertTriangle, Clock } from 'lucide-react';
import { useSearchParams } from 'react-router-dom';
import { trapState } from '@/utils/trapState';
import { trapAudio } from '@/utils/deceptionAudioEngine';

/**
 * GHOST QUARANTINE: Deep Trap Endpoint
 * 
 * Shown when escalationLevel === 3
 * Static, minimal page with only:
 * - Transparent simulation banner
 * - Session reference
 * - No interactive elements
 * - No escape routes
 * 
 * ⚠️ TRANSPARENT SIMULATION LABEL ⚠️
 * This page appears ONLY in simulated honeypot sessions.
 * Real users are NEVER shown this page.
 * All data displayed is synthesized for security testing.
 */
const Quarantine = () => {
  const [searchParams] = useSearchParams();
  const [sessionRef] = useState(trapState.generateSessionReference());
  const [quarantineTime] = useState(Date.now());
  const [degradation, setDegradation] = useState(0);
  const isQuarantineMode = searchParams.get('mode') === 'quarantine';

  // Start ambient audio and track degradation
  useEffect(() => {
    if (isQuarantineMode) {
      trapAudio.startAmbient();
      
      // Gradually increase visual degradation
      const interval = setInterval(() => {
        setDegradation(trapState.getVisualDegradation());
      }, 5000);
      
      return () => {
        clearInterval(interval);
        trapAudio.stopAmbient();
      };
    }
  }, [isQuarantineMode]);

  if (!isQuarantineMode) {
    return <div className="min-h-screen flex items-center justify-center text-muted-foreground">Invalid quarantine request</div>;
  }

  const quarantineMinutes = Math.floor((Date.now() - quarantineTime) / 60000);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="min-h-screen w-full flex flex-col items-center justify-center p-4 relative overflow-hidden"
      style={{
        background: `linear-gradient(180deg, 
          rgba(0,0,0,${0.3 + degradation * 0.4}) 0%, 
          rgba(0,0,0,${0.5 + degradation * 0.3}) 100%
        )`,
      }}
    >
      {/* Scan lines effect */}
      <div 
        className="absolute inset-0 pointer-events-none opacity-10"
        style={{
          backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,255,255,0.03) 2px, rgba(255,255,255,0.03) 4px)',
        }}
      />

      {/* Main content container */}
      <motion.div
        initial={{ scale: 0.95, opacity: 0, y: 20 }}
        animate={{ scale: 1, opacity: 1, y: 0 }}
        transition={{ delay: 0.3, duration: 0.5 }}
        className="relative z-10 max-w-2xl w-full"
      >
        {/* Transparent Simulation Banner */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="mb-8 p-4 rounded-lg border border-amber-500/50 bg-amber-500/10 backdrop-blur-sm"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <h3 className="font-semibold text-amber-600 mb-1">Recovery console</h3>
              <p className="text-sm text-amber-600/80">
                This session has been routed through enhanced integrity verification.
                Access is restricted while diagnostic checks are in progress.
              </p>
            </div>
          </div>
        </motion.div>

        {/* Main card */}
        <motion.div
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.7 }}
          className="p-12 rounded-2xl bg-card/95 backdrop-blur-md border border-border/50 shadow-2xl text-center"
        >
          {/* Icon */}
          <div className="w-20 h-20 rounded-full bg-amber-500/10 flex items-center justify-center mx-auto mb-8">
            <Shield className="w-10 h-10 text-amber-500" />
          </div>
          
          {/* Heading */}
          <h1 className="text-3xl font-outfit font-bold text-foreground mb-4">
            Session Quarantined
          </h1>
          
          {/* Description */}
          <p className="text-lg text-muted-foreground mb-8 leading-relaxed max-w-lg mx-auto">
            This session has been routed through enhanced integrity verification checks.
            No further actions are available.
          </p>

          {/* Session details */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 1 }}
            className="space-y-4 my-8"
          >
            {/* Session reference */}
            <div className="p-4 bg-muted/50 rounded-lg border border-border/30">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Session Reference</span>
                <span className="font-mono font-semibold text-foreground">{sessionRef}</span>
              </div>
            </div>

            {/* Quarantine timestamp */}
            <div className="p-4 bg-muted/50 rounded-lg border border-border/30">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Quarantine Initiated</span>
                <span className="font-mono text-sm text-foreground">
                  {new Date(quarantineTime).toLocaleTimeString()}
                </span>
              </div>
            </div>

            {/* Escalation level */}
            <div className="p-4 bg-muted/50 rounded-lg border border-border/30">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Escalation Level</span>
                <span className="inline-flex items-center gap-2">
                  <span className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
                  <span className="font-mono text-foreground">3 / QUARANTINE</span>
                </span>
              </div>
            </div>
          </motion.div>

          {/* Status indicators */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 1.2 }}
            className="flex flex-col gap-3 mt-12 pt-8 border-t border-border/30"
          >
            <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
              <AlertTriangle className="w-4 h-4 text-amber-500" />
              <span>Integrity Check Active</span>
            </div>
            <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
              <Clock className="w-4 h-4" />
              <span>Manual Review Pending - {quarantineMinutes}m elapsed</span>
            </div>
          </motion.div>
        </motion.div>

        {/* Footer reference */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 0.5 }}
          transition={{ delay: 1.5 }}
          className="mt-8 text-center text-xs font-mono text-muted-foreground/50"
        >
          {sessionRef} • Escalation Level 3
        </motion.div>
      </motion.div>

      {/* Memory cleanup notification (developer info only) */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 0.3 }}
        transition={{ delay: 2 }}
        className="fixed bottom-4 left-4 text-xs font-mono text-muted-foreground/40 max-w-xs"
      >
        <details>
          <summary className="cursor-help">Developer Info</summary>
          <div className="mt-2 text-xs space-y-1 bg-background/30 p-2 rounded border border-border/20">
            <p>Escalation Level: {trapState.getState().escalationLevel}</p>
            <p>Time in Trap: {Math.floor(trapState.getTimeInTrap() / 1000)}s</p>
            <p>Memory Cleanup: Active on level 3</p>
          </div>
        </details>
      </motion.div>
    </motion.div>
  );
};

export default Quarantine;
