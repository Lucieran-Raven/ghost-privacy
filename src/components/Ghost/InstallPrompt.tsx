import { useState, useEffect } from 'react';
import { Download, X, Smartphone, Share, Plus } from 'lucide-react';
import { usePWAInstall } from '@/hooks/usePWAInstall';
import { cn } from '@/lib/utils';

interface InstallPromptProps {
  showAfterMs?: number;
  position?: 'bottom' | 'top';
}

const InstallPrompt = ({ showAfterMs = 10000, position = 'bottom' }: InstallPromptProps) => {
  const { isInstallable, isInstalled, isIOSSafari, promptInstall } = usePWAInstall();
  const [isVisible, setIsVisible] = useState(false);
  const [isDismissed, setIsDismissed] = useState(false);

  useEffect(() => {
    if (isInstallable && !isInstalled) {
      const timer = setTimeout(() => {
        setIsVisible(true);
      }, showAfterMs);
      return () => clearTimeout(timer);
    }
  }, [isInstallable, isInstalled, showAfterMs]);

  // Auto-hide iOS instructions after 10 seconds
  useEffect(() => {
    if (isVisible && isIOSSafari) {
      const autoHideTimer = setTimeout(() => {
        handleDismiss();
      }, 10000);
      return () => clearTimeout(autoHideTimer);
    }
  }, [isVisible, isIOSSafari]);

  const handleInstall = async () => {
    const success = await promptInstall();
    if (success) {
      setIsVisible(false);
    }
  };

  const handleDismiss = () => {
    setIsVisible(false);
    setIsDismissed(true);
  };

  if (isInstalled || !isInstallable || isDismissed || !isVisible) {
    return null;
  }

  // iOS Safari - show manual install instructions
  if (isIOSSafari) {
    return (
      <div
        className={cn(
          "fixed left-4 right-4 z-[100] animate-in slide-in-from-bottom-4 duration-300",
          position === 'bottom' ? "bottom-20 md:bottom-6" : "top-20 md:top-6"
        )}
      >
        <div className="max-w-md mx-auto glass border border-primary/30 rounded-2xl p-5 shadow-xl shadow-primary/10">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-primary/20 flex-shrink-0">
                <Smartphone className="h-5 w-5 text-primary" />
              </div>
              <h3 className="font-outfit font-bold text-foreground">
                Install Ghost on iOS
              </h3>
            </div>
            <button
              onClick={handleDismiss}
              className="p-1 rounded-lg hover:bg-secondary/50 text-muted-foreground"
              aria-label="Dismiss"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
          
          <div className="space-y-3 mb-4">
            <div className="flex items-center gap-3 text-sm text-muted-foreground">
              <div className="flex items-center justify-center w-7 h-7 rounded-full bg-primary/20 text-primary font-bold text-xs flex-shrink-0">
                1
              </div>
              <div className="flex items-center gap-2">
                <span>Tap the</span>
                <Share className="h-4 w-4 text-primary" />
                <span className="font-medium text-foreground">Share</span>
                <span>button below</span>
              </div>
            </div>
            
            <div className="flex items-center gap-3 text-sm text-muted-foreground">
              <div className="flex items-center justify-center w-7 h-7 rounded-full bg-primary/20 text-primary font-bold text-xs flex-shrink-0">
                2
              </div>
              <div className="flex items-center gap-2">
                <span>Select</span>
                <Plus className="h-4 w-4 text-primary" />
                <span className="font-medium text-foreground">"Add to Home Screen"</span>
              </div>
            </div>
            
            <div className="flex items-center gap-3 text-sm text-muted-foreground">
              <div className="flex items-center justify-center w-7 h-7 rounded-full bg-primary/20 text-primary font-bold text-xs flex-shrink-0">
                3
              </div>
              <span>Tap <span className="font-medium text-foreground">"Add"</span> to confirm</span>
            </div>
          </div>

          <button
            onClick={handleDismiss}
            className="w-full px-4 py-2.5 rounded-lg bg-secondary/50 text-muted-foreground font-medium active:scale-95 transition-transform text-sm"
          >
            Got it
          </button>
        </div>
      </div>
    );
  }

  // Android / Desktop - show standard install button
  return (
    <div
      className={cn(
        "fixed left-4 right-4 z-[100] animate-in slide-in-from-bottom-4 duration-300",
        position === 'bottom' ? "bottom-20 md:bottom-6" : "top-20 md:top-6"
      )}
    >
      <div className="max-w-md mx-auto glass border border-primary/30 rounded-2xl p-4 shadow-xl shadow-primary/10">
        <div className="flex items-start gap-4">
          <div className="p-3 rounded-xl bg-primary/20 flex-shrink-0">
            <Smartphone className="h-6 w-6 text-primary" />
          </div>
          
          <div className="flex-1 min-w-0">
            <h3 className="font-outfit font-bold text-foreground mb-1">
              Install Ghost
            </h3>
            <p className="text-sm text-muted-foreground leading-relaxed">
              Add Ghost to your home screen for instant access and a native app experience.
            </p>
          </div>
          
          <button
            onClick={handleDismiss}
            className="p-1 rounded-lg hover:bg-secondary/50 text-muted-foreground"
            aria-label="Dismiss"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
        
        <div className="flex gap-3 mt-4">
          <button
            onClick={handleDismiss}
            className="flex-1 px-4 py-2.5 rounded-lg bg-secondary/50 text-muted-foreground font-medium active:scale-95 transition-transform"
          >
            Not now
          </button>
          <button
            onClick={handleInstall}
            className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-primary text-primary-foreground font-medium active:scale-95 transition-transform shadow-lg shadow-primary/30"
          >
            <Download className="h-4 w-4" />
            Install
          </button>
        </div>
      </div>
    </div>
  );
};

export default InstallPrompt;
