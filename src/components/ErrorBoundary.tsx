import { Component, ErrorInfo, ReactNode } from 'react';
import { notifyBugsnag } from '@/utils/bugsnag';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  // Security: Never store error objects in state - prevents accidental leakage
  errorId: string | null;
}

// Build-time constant - Vite replaces this at compile time, not runtime
const IS_DEV = import.meta.env.DEV === true;

// Generate unique error ID for internal tracking without exposing details
const generateErrorId = (): string => {
  return `ERR-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 8)}`;
};

class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    errorId: null,
  };

  public static getDerivedStateFromError(): State {
    // Security: Only set error flag, never store error object
    return { hasError: true, errorId: generateErrorId() };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Report to Bugsnag for crash analytics
    notifyBugsnag(error, 'ErrorBoundary');
    
    void error;
    void errorInfo;
    void IS_DEV;
  }

  private handleReload = () => {
    // Clear service worker cache before reload
    if ('caches' in window) {
      caches.keys().then((names) => {
        names.forEach((name) => caches.delete(name));
      });
    }
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-background flex items-center justify-center p-4">
          <div className="max-w-md w-full text-center space-y-6">
            <div className="p-4 rounded-full bg-destructive/20 w-fit mx-auto">
              <svg 
                className="h-12 w-12 text-destructive" 
                fill="none" 
                stroke="currentColor" 
                viewBox="0 0 24 24"
              >
                <path 
                  strokeLinecap="round" 
                  strokeLinejoin="round" 
                  strokeWidth={2} 
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" 
                />
              </svg>
            </div>
            
            <div>
              <h1 className="text-2xl font-bold text-foreground mb-2">
                Something went wrong
              </h1>
              <p className="text-muted-foreground">
                Ghost encountered an unexpected error. Your messages remain secure.
              </p>
              {/* Security: Only show error ID, never error details */}
              <p className="text-xs text-muted-foreground/50 mt-2 font-mono">
                Reference: {this.state.errorId}
              </p>
            </div>

            <button
              onClick={this.handleReload}
              className="inline-flex items-center justify-center gap-2 px-6 py-3 bg-primary text-primary-foreground rounded-lg font-medium hover:opacity-90 transition-opacity"
            >
              <svg 
                className="h-5 w-5" 
                fill="none" 
                stroke="currentColor" 
                viewBox="0 0 24 24"
              >
                <path 
                  strokeLinecap="round" 
                  strokeLinejoin="round" 
                  strokeWidth={2} 
                  d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" 
                />
              </svg>
              Reload Ghost
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
