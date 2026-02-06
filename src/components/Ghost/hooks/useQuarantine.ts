import { useEffect, useState, type MutableRefObject } from 'react';
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

  usePlausibleDeniability(() => {
    purgeActiveNativeVideoDropsBestEffort();
  });

  useEffect(() => {
    const handleVisibilityChange = () => {
      if (typeof document === 'undefined') return;
      setIsWindowVisible(!document.hidden);
      if (document.hidden) {
        if (!isCapacitorNative()) {
          setInputText('');
        }
      } else {
        purgeActiveNativeVideoDropsBestEffort();
      }
    };

    const handleBlur = () => {
      setIsWindowVisible(false);
      if (!isCapacitorNative()) {
        setInputText('');
      }
    };

    const handleFocus = () => {
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
