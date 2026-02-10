import { useState, useEffect, useCallback, useRef } from 'react';

type DecoyMode = 'calculator' | 'notes' | 'weather' | null;

interface PlausibleDeniabilityState {
  isDecoyActive: boolean;
  decoyMode: DecoyMode;
}

let globalState: PlausibleDeniabilityState = {
  isDecoyActive: false,
  decoyMode: null
};

const listeners = new Set<(s: PlausibleDeniabilityState) => void>();
let handlersRegistered = false;

function setGlobalState(next: PlausibleDeniabilityState) {
  globalState = next;
  for (const l of listeners) {
    try {
      l(globalState);
    } catch {
    }
  }
}

// Activation: Triple-tap spacebar within 1 second (secret gesture only)
// AUTO-ACTIVATION DISABLED: No shake gesture, no automatic triggers
export const usePlausibleDeniability = (onActivate?: () => void) => {
  const [state, setState] = useState<PlausibleDeniabilityState>(globalState);

  const tapCount = useRef(0);
  const lastTapTime = useRef(0);

  // Manually activate decoy mode (for button trigger)
  const activateDecoy = useCallback((mode: DecoyMode = 'calculator') => {
    setGlobalState({ isDecoyActive: true, decoyMode: mode });
    onActivate?.();
  }, [onActivate]);

  // Deactivate decoy mode (requires secret gesture)
  const deactivateDecoy = useCallback(() => {
    setGlobalState({ isDecoyActive: false, decoyMode: null });
  }, []);

  // Secret keyboard shortcut ONLY: Triple-tap spacebar (manual trigger)
  // Auto-activation via shake is DISABLED
  useEffect(() => {
    const listener = (s: PlausibleDeniabilityState) => setState(s);
    listeners.add(listener);
    setState(globalState);
    return () => {
      listeners.delete(listener);
    };
  }, []);

  useEffect(() => {
    if (handlersRegistered) {
      return;
    }
    handlersRegistered = true;

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
      if (e.ctrlKey && e.shiftKey && e.key === 'G' && globalState.isDecoyActive) {
        setGlobalState({ isDecoyActive: false, decoyMode: null });
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      handlersRegistered = false;
    };
  }, [activateDecoy]);

  // SHAKE DETECTION DISABLED - No auto-activation on mobile
  // Only manual button or secret keyboard shortcut can activate

  return {
    ...state,
    activateDecoy,
    deactivateDecoy,
  };
};
