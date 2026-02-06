/**
 * Responsibilities:
 * - Owns session-adjacent lifecycle effects: visibility, blur/focus, beforeunload/pagehide.
 * - Toggles platform privacy affordances (e.g. Tauri content-protection) while mounted.
 * - Triggers best-effort artifact cleanup on plausible deniability activation.
 *
 * Security guarantees:
 * - Attempts to clear in-memory session artifacts on termination paths.
 * - Avoids persisting any session secret state.
 *
 * Caveats / limitations:
 * - Browsers/OS may not deliver unload events reliably; cleanup is best-effort.
 *
 * Cross-module dependencies:
 * - Requires transport-provided termination refs and cleanup callbacks.
 */

import { useEffect, useRef, useState, type MutableRefObject } from 'react';
import { usePlausibleDeniability } from '@/hooks/usePlausibleDeniability';
import { setTauriContentProtected } from '@/utils/runtime';
import { SessionService } from '@/lib/sessionService';

export function useQuarantine(params: {
  sessionId: string;
  isTerminatingRef: MutableRefObject<boolean>;
  isCapacitorNative: () => boolean;
  destroyLocalSessionData: () => void;
  purgeActiveNativeVideoDropsBestEffort: () => void;
  setInputText: (v: string) => void;
}): {
  isWindowVisible: boolean;
  setIsWindowVisible: (v: boolean) => void;
} {
  const {
    sessionId,
    isTerminatingRef,
    isCapacitorNative,
    destroyLocalSessionData,
    purgeActiveNativeVideoDropsBestEffort,
    setInputText,
  } = params;

  const [isWindowVisible, setIsWindowVisible] = useState(true);
  const hideDebounceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  usePlausibleDeniability(() => {
    purgeActiveNativeVideoDropsBestEffort();
  });

  useEffect(() => {
    const handleVisibilityChange = () => {
      if (typeof document === 'undefined') return;

      if (hideDebounceTimerRef.current) {
        clearTimeout(hideDebounceTimerRef.current);
        hideDebounceTimerRef.current = null;
      }

      if (document.hidden) {
        hideDebounceTimerRef.current = setTimeout(() => {
          try {
            if (typeof document !== 'undefined' && document.hidden) {
              setIsWindowVisible(false);
              if (!isCapacitorNative()) {
                setInputText('');
              }
            }
          } catch {
          }
        }, 400);
      } else {
        setIsWindowVisible(true);
        purgeActiveNativeVideoDropsBestEffort();
      }
    };

    const handleBlur = () => {
      if (typeof document !== 'undefined' && document.hidden) {
        setIsWindowVisible(false);
        if (!isCapacitorNative()) {
          setInputText('');
        }
      }
    };

    const handleFocus = () => {
      if (hideDebounceTimerRef.current) {
        clearTimeout(hideDebounceTimerRef.current);
        hideDebounceTimerRef.current = null;
      }
      setIsWindowVisible(true);
      purgeActiveNativeVideoDropsBestEffort();
    };

    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', handleVisibilityChange);
    }
    if (typeof window !== 'undefined') {
      window.addEventListener('blur', handleBlur);
      window.addEventListener('focus', handleFocus);
    }

    return () => {
      if (hideDebounceTimerRef.current) {
        clearTimeout(hideDebounceTimerRef.current);
        hideDebounceTimerRef.current = null;
      }
      if (typeof document !== 'undefined') {
        document.removeEventListener('visibilitychange', handleVisibilityChange);
      }
      if (typeof window !== 'undefined') {
        window.removeEventListener('blur', handleBlur);
        window.removeEventListener('focus', handleFocus);
      }
    };
  }, [isCapacitorNative, purgeActiveNativeVideoDropsBestEffort, setInputText]);

  useEffect(() => {
    void setTauriContentProtected(true);
    return () => {
      void setTauriContentProtected(false);
    };
  }, []);

  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = 'Leave Ghost session? Click "End Session" to properly terminate.';
      return e.returnValue;
    };

    if (typeof window !== 'undefined') {
      window.addEventListener('beforeunload', handleBeforeUnload);
      return () => window.removeEventListener('beforeunload', handleBeforeUnload);
    }
    return;
  }, [sessionId]);

  useEffect(() => {
    const handlePageHide = () => {
      if (!isTerminatingRef.current) {
        return;
      }

      if (isCapacitorNative()) {
        return;
      }

      try {
        destroyLocalSessionData();
      } catch {
      }

      try {
        SessionService.clearValidationCache(sessionId);
      } catch {
      }
    };

    if (typeof window !== 'undefined') {
      window.addEventListener('pagehide', handlePageHide);
      window.addEventListener('unload', handlePageHide);
      return () => {
        window.removeEventListener('pagehide', handlePageHide);
        window.removeEventListener('unload', handlePageHide);
      };
    }
    return;
  }, [destroyLocalSessionData, isCapacitorNative, isTerminatingRef, sessionId]);

  return {
    isWindowVisible,
    setIsWindowVisible,
  };
}
