import Bugsnag from '@bugsnag/js';

const BUGSNAG_API_KEY = 'fa219feec3980f82be3de8349e986592';
const APP_VERSION = '0.4.1'; // Sync with package.json version

export function initializeBugsnag(): void {
  Bugsnag.start({
    apiKey: BUGSNAG_API_KEY,
    appType: 'ghost-privacy',
    appVersion: APP_VERSION,
    collectUserIp: false,
    autoTrackSessions: true,
    enabledBreadcrumbTypes: ['error', 'manual'],
    onError: (event) => {
      event.addMetadata('app', {
        platform: typeof window !== 'undefined' ? 'web' : 'unknown',
        userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : 'unknown',
      });
      return true;
    },
  });
}

export function notifyBugsnag(error: Error, context?: string): void {
  Bugsnag.notify(error, (event) => {
    if (context) {
      event.context = context;
    }
  });
}

export function leaveBreadcrumb(message: string, metadata?: Record<string, unknown>): void {
  Bugsnag.leaveBreadcrumb(message, metadata);
}

export default Bugsnag;
