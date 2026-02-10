import { motion, AnimatePresence } from 'framer-motion';
import { Mic, Video, AlertTriangle, Settings, Upload, X } from 'lucide-react';
import { createPortal } from 'react-dom';

type PermissionType = 'microphone' | 'camera';

interface PermissionModalProps {
  type: PermissionType;
  isOpen: boolean;
  onClose: () => void;
  onRetry: () => void;
  onFallback?: () => void;
}

const PermissionModal = ({ type, isOpen, onClose, onRetry, onFallback }: PermissionModalProps) => {
  if (typeof window === 'undefined' || typeof navigator === 'undefined' || typeof document === 'undefined') {
    return null;
  }

  const isCamera = type === 'camera';
  const Icon = isCamera ? Video : Mic;
  const title = isCamera ? 'Camera Access Required' : 'Microphone Access Required';
  const fallbackText = isCamera ? 'Upload Video Instead' : 'Upload Audio Instead';

  const openBrowserSettings = async () => {
    const ua = navigator.userAgent.toLowerCase();
    const isIOS = /iphone|ipad|ipod/.test(ua);
    const isAndroid = /android/.test(ua);
    const isSafari = /safari/.test(ua) && !/chrome/.test(ua);
    const isChrome = /chrome/.test(ua);
    const isFirefox = /firefox/.test(ua);

    try {
      const mod = await import('@capacitor/core');
      if (isAndroid && mod.Capacitor?.isNativePlatform?.()) {
        const AppSettings = mod.registerPlugin('AppSettings') as { openAppSettings: () => Promise<void> };
        await AppSettings.openAppSettings();
        return;
      }
    } catch {
    }

    if (isIOS) {
      // iOS - open Safari settings directly
      window.location.href = 'App-Prefs:Preferences&path=Safari';
    } else if (isAndroid && isChrome) {
      // Android Chrome - open content settings
      window.open('chrome://settings/content');
    } else if (isChrome) {
      // Desktop Chrome - open site settings
      window.open('chrome://settings/content/siteDetails?site=' + window.location.origin);
    } else if (isFirefox) {
      // Firefox - open page info
      window.open('about:permissions#' + window.location.origin);
    } else {
      // Fallback - open browser settings
      window.open('about:preferences');
    }
  };

  const getInstructions = () => {
    const ua = navigator.userAgent.toLowerCase();
    const isIOS = /iphone|ipad|ipod/.test(ua);
    const isAndroid = /android/.test(ua);
    const isSafari = /safari/.test(ua) && !/chrome/.test(ua);
    const isChrome = /chrome/.test(ua);
    const isFirefox = /firefox/.test(ua);

    let isAndroidNative = false;
    try {
      const w = window as any;
      isAndroidNative = Boolean(isAndroid && w && w.Capacitor);
    } catch {
      isAndroidNative = false;
    }

    if (isIOS) {
      return {
        browser: 'iOS Safari',
        steps: [
          'Open the Settings app',
          `Scroll down and tap "Safari"`,
          `Tap "${isCamera ? 'Camera' : 'Microphone'}"`,
          `Set to "Allow" for this site`,
          'Return here and tap "Try Again"'
        ]
      };
    }

    if (isAndroidNative) {
      return {
        browser: 'Android App Settings',
        steps: [
          'Tap "Open Settings" below',
          'Go to "Permissions"',
          `Enable "${isCamera ? 'Camera' : 'Microphone'}"`,
          'Return here and tap "Try Again"'
        ]
      };
    }

    if (isAndroid && isChrome) {
      return {
        browser: 'Chrome on Android',
        steps: [
          'Tap the lock icon in the address bar',
          'Tap "Permissions" or "Site settings"',
          `Find "${isCamera ? 'Camera' : 'Microphone'}" and set to "Allow"`,
          'Tap "Try Again" below'
        ]
      };
    }

    if (isSafari) {
      return {
        browser: 'Safari',
        steps: [
          'Go to Safari → Settings → Websites',
          `Find "${isCamera ? 'Camera' : 'Microphone'}" in the sidebar`,
          'Find this website and set to "Allow"',
          'Reload the page'
        ]
      };
    }

    if (isChrome) {
      return {
        browser: 'Chrome',
        steps: [
          'Click the lock/tune icon in the address bar',
          'Click "Site settings"',
          `Find "${isCamera ? 'Camera' : 'Microphone'}" and set to "Allow"`,
          'Reload the page'
        ]
      };
    }

    if (isFirefox) {
      return {
        browser: 'Firefox',
        steps: [
          'Click the lock icon in the address bar',
          'Click "Connection secure" → "More information"',
          'Go to "Permissions" tab',
          `Find "${isCamera ? 'Use the Camera' : 'Use the Microphone'}" and allow it`,
          'Reload the page'
        ]
      };
    }

    return {
      browser: 'Your browser',
      steps: [
        'Open browser settings',
        'Find "Site permissions" or "Privacy settings"',
        `Enable ${isCamera ? 'Camera' : 'Microphone'} access for this site`,
        'Reload and try again'
      ]
    };
  };

  const instructions = getInstructions();

  return createPortal(
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 bg-background/95 backdrop-blur-sm z-[200] flex min-h-[100svh] items-center justify-center overflow-y-auto p-4"
        >
          <motion.div
            initial={{ scale: 0.95, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.95, opacity: 0 }}
            className="max-h-[calc(100svh-2rem)] max-w-md w-full overflow-y-auto p-6 rounded-2xl glass border border-yellow-500/30"
          >
            {/* Header */}
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="p-3 rounded-xl bg-yellow-500/20">
                  <Icon className="h-6 w-6 text-yellow-500" />
                </div>
                <div>
                  <h3 className="font-outfit font-bold text-lg text-foreground">
                    {title}
                  </h3>
                  <p className="text-sm text-muted-foreground">
                    Permission was denied
                  </p>
                </div>
              </div>
              <button
                onClick={onClose}
                className="p-2 rounded-lg hover:bg-muted/50 transition-colors"
              >
                <X className="h-5 w-5 text-muted-foreground" />
              </button>
            </div>

            {/* Why needed */}
            <div className="flex items-start gap-3 p-3 rounded-lg bg-muted/30 mb-4">
              <AlertTriangle className="h-5 w-5 text-yellow-500 mt-0.5 flex-shrink-0" />
              <p className="text-sm text-muted-foreground">
                {isCamera 
                  ? 'Video messages require camera access to record. Your video is encrypted before sending.'
                  : 'Voice messages require microphone access to record. Your audio is encrypted before sending.'
                }
              </p>
            </div>

            {/* Instructions */}
            <div className="mb-6">
              <div className="flex items-center gap-2 mb-3">
                <Settings className="h-4 w-4 text-primary" />
                <h4 className="font-medium text-foreground text-sm">
                  How to enable in {instructions.browser}:
                </h4>
              </div>
              <ol className="space-y-2 text-sm text-muted-foreground">
                {instructions.steps.map((step, index) => (
                  <li key={index} className="flex gap-2">
                    <span className="flex-shrink-0 w-5 h-5 rounded-full bg-primary/20 text-primary text-xs flex items-center justify-center font-medium">
                      {index + 1}
                    </span>
                    <span>{step}</span>
                  </li>
                ))}
              </ol>
            </div>

            {/* Actions */}
            <div className="flex flex-col gap-2">
              <button
                onClick={onRetry}
                className="w-full min-h-[48px] px-4 py-3 bg-primary text-primary-foreground rounded-lg font-medium active:scale-95 transition-transform flex items-center justify-center gap-2"
              >
                <Icon className="h-4 w-4" />
                Try Again
              </button>
              
              <button
                onClick={() => {
                  void openBrowserSettings();
                }}
                className="w-full min-h-[48px] px-4 py-3 bg-blue-500 text-white rounded-lg font-medium active:scale-95 transition-transform flex items-center justify-center gap-2"
              >
                <Settings className="h-4 w-4" />
                Open Settings
              </button>
              
              {onFallback && (
                <button
                  onClick={onFallback}
                  className="w-full min-h-[48px] px-4 py-3 bg-muted text-foreground rounded-lg font-medium active:scale-95 transition-colors flex items-center justify-center gap-2"
                >
                  <Upload className="h-4 w-4" />
                  {fallbackText}
                </button>
              )}
              
              <button
                onClick={onClose}
                className="w-full min-h-[48px] px-4 py-3 text-muted-foreground rounded-lg font-medium hover:bg-muted/30 transition-colors"
              >
                Cancel
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
    , document.body
  );
};

export default PermissionModal;
