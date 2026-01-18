import { useCallback, useEffect, useRef, useState } from 'react';

export function usePrivacyShield() {
  const [isShieldActive, setIsShieldActive] = useState(false);
  const [canDismiss, setCanDismiss] = useState(false);

  const lastBlurAtRef = useRef<number>(0);

  const dismiss = useCallback(() => {
    if (!canDismiss) return;
    setIsShieldActive(false);
    setCanDismiss(false);
  }, [canDismiss]);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
      return;
    }

    const activate = () => {
      lastBlurAtRef.current = Date.now();
      setIsShieldActive(true);
      setCanDismiss(false);
    };

    const armDismiss = () => {
      if (document.hidden) return;
      if (!isShieldActive) return;
      const elapsed = Date.now() - lastBlurAtRef.current;
      const min = 120;
      if (elapsed >= min) {
        setCanDismiss(true);
        return;
      }
      setTimeout(() => {
        setCanDismiss(true);
      }, min - elapsed);
    };

    const onVisibilityChange = () => {
      if (document.hidden) {
        activate();
        return;
      }
      if (isShieldActive) {
        armDismiss();
      }
    };

    const onBlur = () => {
      activate();
    };

    const onFocus = () => {
      if (isShieldActive) {
        armDismiss();
      }
    };

    window.addEventListener('blur', onBlur);
    window.addEventListener('focus', onFocus);
    document.addEventListener('visibilitychange', onVisibilityChange);

    return () => {
      window.removeEventListener('blur', onBlur);
      window.removeEventListener('focus', onFocus);
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [isShieldActive]);

  return { isShieldActive, canDismiss, dismiss };
}
