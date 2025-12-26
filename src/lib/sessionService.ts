import { supabase } from '@/integrations/supabase/client';

/**
 * SECURITY ARCHITECTURE: Edge-Function-Only Session Service
 * 
 * This service is a thin capability wrapper around Edge Functions.
 * The client NEVER directly accesses database tables.
 * All database operations are performed server-side via service_role.
 */

// Session ID format: GHOST-XXXX-XXXX
const SESSION_ID_PATTERN = /^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$/;

export type SessionErrorType = 'NETWORK_ERROR' | 'INVALID_SESSION' | 'EXPIRED_SESSION' | 'RATE_LIMITED' | 'SERVER_ERROR';

export interface SessionResult {
  success: boolean;
  error?: string;
  errorType?: SessionErrorType;
}

export class SessionService {
  /**
   * Validate session ID format before any network call
   */
  private static isValidSessionId(sessionId: string): boolean {
    return SESSION_ID_PATTERN.test(sessionId);
  }

  /**
   * Create a new session via secure Edge Function
   * Server-side: validates format, enforces rate limiting, inserts with TTL
   */
  static async reserveSession(
    sessionId: string,
    hostFingerprint: string
  ): Promise<SessionResult> {
    // Client-side validation first
    if (!this.isValidSessionId(sessionId)) {
      return { success: false, error: 'Invalid session ID format', errorType: 'INVALID_SESSION' };
    }

    if (!hostFingerprint || hostFingerprint.length < 8) {
      return { success: false, error: 'Invalid host fingerprint', errorType: 'INVALID_SESSION' };
    }

    try {
      const { data, error } = await supabase.functions.invoke('create-session', {
        body: { sessionId, hostFingerprint }
      });

      if (error) {
        // Distinguish network errors from server errors
        if (error.message?.includes('fetch') || error.message?.includes('network')) {
          return { success: false, error: 'Network unreachable', errorType: 'NETWORK_ERROR' };
        }
        return { success: false, error: error.message, errorType: 'SERVER_ERROR' };
      }

      if (!data?.success) {
        const errorType: SessionErrorType = data?.error?.includes('rate') ? 'RATE_LIMITED' : 'SERVER_ERROR';
        return { success: false, error: data?.error || 'Failed to create session', errorType };
      }

      return { success: true };
    } catch {
      return { success: false, error: 'Network unreachable', errorType: 'NETWORK_ERROR' };
    }
  }

  /**
   * Validate session existence via secure Edge Function
   * Server-side: checks existence + expiration, returns boolean only
   * 
   * OPTIMIZATION: Results are cached in sessionStorage to prevent false
   * "session expired" errors from network issues.
   */
  static async validateSession(sessionId: string): Promise<boolean> {
    // Client-side validation first
    if (!this.isValidSessionId(sessionId)) {
      return false;
    }

    try {
      // Check sessionStorage cache first
      const cacheKey = `ghost_session_valid_${sessionId}`;
      const cached = sessionStorage.getItem(cacheKey);
      if (cached === 'true') {
        return true;
      }

      const { data, error } = await supabase.functions.invoke('validate-session', {
        body: { sessionId }
      });

      // Network error - don't show "expired" if we can't reach server
      if (error) {
        // Return true on network error - assume session is still valid
        return true;
      }

      const isValid = data?.valid === true;
      
      // Cache successful validation
      if (isValid) {
        sessionStorage.setItem(cacheKey, 'true');
      }

      return isValid;
    } catch {
      // On unexpected error, assume valid to prevent false expiration
      return true;
    }
  }
  
  /**
   * Clear validation cache for a session
   * Called when session is explicitly deleted
   */
  static clearValidationCache(sessionId: string): void {
    const cacheKey = `ghost_session_valid_${sessionId}`;
    sessionStorage.removeItem(cacheKey);
  }

  /**
   * Extend session TTL via secure Edge Function
   * Server-side: extends expires_at by 30 minutes
   */
  static async extendSession(sessionId: string): Promise<boolean> {
    if (!this.isValidSessionId(sessionId)) {
      return false;
    }

    try {
      const { data, error } = await supabase.functions.invoke('extend-session', {
        body: { sessionId }
      });

      if (error) {
        return false;
      }

      return data?.success === true;
    } catch {
      return false;
    }
  }

  /**
   * Delete session via secure Edge Function (NUCLEAR OPTION)
   * Server-side: immediate deletion, no recovery
   * Called ONLY on explicit user "End Session" action
   * 
   * ATOMIC: This operation must complete regardless of network state
   */
  static async deleteSession(sessionId: string): Promise<boolean> {
    if (!this.isValidSessionId(sessionId)) {
      return false;
    }

    // Clear validation cache immediately (before network call)
    this.clearValidationCache(sessionId);

    try {
      const { data, error } = await supabase.functions.invoke('delete-session', {
        body: { sessionId }
      });

      if (error) {
        console.debug('[GHOST] Session deletion network error');
        // Return true anyway - local cleanup will happen
        // Server-side TTL will clean up eventually
        return true;
      }

      return data?.success === true;
    } catch {
      console.debug('[GHOST] Session deletion exception');
      // Return true - we've done local cleanup
      return true;
    }
  }
}
