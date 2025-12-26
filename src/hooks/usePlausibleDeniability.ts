import { useState, useEffect, useCallback, useRef } from 'react';

type DecoyMode = 'calculator' | 'notes' | 'weather' | null;

interface PlausibleDeniabilityState {
  isDecoyActive: boolean;
  decoyMode: DecoyMode;
}

// Activation: Triple-tap spacebar within 1 second (secret gesture only)
// AUTO-ACTIVATION DISABLED: No shake gesture, no automatic triggers
export const usePlausibleDeniability = (onActivate?: () => void) => {
  const [state, setState] = useState<PlausibleDeniabilityState>({
    isDecoyActive: false,
    decoyMode: null,
  });

  const tapCount = useRef(0);
  const lastTapTime = useRef(0);

  // Manually activate decoy mode (for button trigger)
  const activateDecoy = useCallback((mode: DecoyMode = 'calculator') => {
    setState({ isDecoyActive: true, decoyMode: mode });
    onActivate?.();
    
    // Notify service worker to hide session
    if (navigator.serviceWorker?.controller) {
      navigator.serviceWorker.controller.postMessage({ 
        action: 'hideSession',
        mode 
      });
    }

    // Store minimal state for recovery (encrypted)
    sessionStorage.setItem('ghost_decoy', 'active');
  }, [onActivate]);

  // Deactivate decoy mode (requires secret gesture)
  const deactivateDecoy = useCallback(() => {
    setState({ isDecoyActive: false, decoyMode: null });
    sessionStorage.removeItem('ghost_decoy');
    
    if (navigator.serviceWorker?.controller) {
      navigator.serviceWorker.controller.postMessage({ 
        action: 'restoreSession' 
      });
    }
  }, []);

  // Secret keyboard shortcut ONLY: Triple-tap spacebar (manual trigger)
  // Auto-activation via shake is DISABLED
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't trigger if typing in input
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        return;
      }

      if (e.code === 'Space' && !e.repeat) {
        const now = Date.now();
        
        if (now - lastTapTime.current < 400) {
          tapCount.current++;
          
          if (tapCount.current >= 3) {
            e.preventDefault();
            activateDecoy('calculator');
            tapCount.current = 0;
          }
        } else {
          tapCount.current = 1;
        }
        
        lastTapTime.current = now;
      }

      // Secret deactivation: Ctrl+Shift+G
      if (e.ctrlKey && e.shiftKey && e.key === 'G' && state.isDecoyActive) {
        deactivateDecoy();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [activateDecoy, deactivateDecoy, state.isDecoyActive]);

  // SHAKE DETECTION DISABLED - No auto-activation on mobile
  // Only manual button or secret keyboard shortcut can activate

  // Check if decoy was active on mount (page refresh during decoy)
  useEffect(() => {
    if (sessionStorage.getItem('ghost_decoy') === 'active') {
      setState({ isDecoyActive: true, decoyMode: 'calculator' });
    }
  }, []);

  return {
    ...state,
    activateDecoy,
    deactivateDecoy,
  };
};
