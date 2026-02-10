import { useEffect } from 'react';
import { cn } from '@/lib/utils';

interface PrivacyShieldProps {
  active: boolean;
  canDismiss: boolean;
  onDismiss: () => void;
}

const PrivacyShield = ({ active, canDismiss, onDismiss }: PrivacyShieldProps) => {
  useEffect(() => {
    if (!active) return;

    const onKeyDown = (e: KeyboardEvent) => {
      if (!canDismiss) return;
      if (e.key === 'Escape' || e.key === 'Enter' || e.key === ' ') {
        onDismiss();
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [active, canDismiss, onDismiss]);

  if (!active) return null;

  return (
    <div
      className={cn(
        'fixed inset-0 z-[10000] bg-background/95 backdrop-blur-xl',
        canDismiss ? 'cursor-pointer' : 'cursor-wait'
      )}
      role="presentation"
      aria-hidden="true"
      onMouseDown={() => {
        if (canDismiss) onDismiss();
      }}
      onTouchStart={() => {
        if (canDismiss) onDismiss();
      }}
    />
  );
};

export default PrivacyShield;
