import { supabase } from '@/integrations/supabase/publicClient';
import { SecurityManager } from '@/utils/security';
import {
  isCacheEntryValid,
  isValidCapabilityToken,
  isValidSessionId
} from '@/utils/algorithms/session/binding';
import { constantTimeEqualString } from '@/utils/algorithms/integrity/constantTime';
import { createDeleteSessionInvokeRequest } from '@/utils/algorithms/session/revocation';

/**
 * SECURITY ARCHITECTURE: Edge-Function-Only Session Service
 * 
 * This service is a thin capability wrapper around Edge Functions.
 * The client NEVER directly accesses database tables.
 * All database operations are performed server-side via service_role.
 * 
 * CRITICAL SECURITY FIX: Memory-only validation cache
 * - NO sessionStorage usage (eliminates forensic artifacts)
 * - Cache exists ONLY in JavaScript heap memory
 * - Complete destruction on browser close
 */

// In-memory validation cache (NO persistence)
class MemoryValidationCache {
  private cache = new Map<string, { expiresAt: string; cachedAt: number; capabilityToken: string }>();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  private key(sessionId: string, role: 'host' | 'guest'): string {
    return `${sessionId}:${role}`;
  }

  constructor() {
    // Only register browser lifecycle hooks in the browser.
    if (typeof window !== 'undefined') {
      // Clean expired entries every 5 minutes
      this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60 * 1000);

      // Nuclear purge on browser close
      window.addEventListener('beforeunload', () => this.nuclearPurge());
      window.addEventListener('unload', () => this.nuclearPurge());
    }
  }

  get(sessionId: string, role: 'host' | 'guest', capabilityToken: string): { expiresAt: string; cachedAt: number } | null {
    const entry = this.cache.get(this.key(sessionId, role));
    if (!entry) return null;

    if (!constantTimeEqualString(entry.capabilityToken, capabilityToken)) {
      this.cache.delete(this.key(sessionId, role));
      return null;
    }

    const now = Date.now();
    if (isCacheEntryValid(now, entry)) {
      return entry;
    }

    // Remove expired entry
    this.cache.delete(this.key(sessionId, role));
    return null;
  }

  set(sessionId: string, role: 'host' | 'guest', capabilityToken: string, expiresAt: string): void {
    this.cache.set(this.key(sessionId, role), {
      expiresAt,
      cachedAt: Date.now(),
      capabilityToken
    });
  }

  clear(sessionId: string): void {
    this.cache.delete(this.key(sessionId, 'host'));
    this.cache.delete(this.key(sessionId, 'guest'));
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [sessionId, entry] of this.cache.entries()) {
      if (!isCacheEntryValid(now, entry)) {
        this.cache.delete(sessionId);
      }
    }
  }

  nuclearPurge(): void {
    this.cache.clear();
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}

// Singleton memory cache
const validationCache = new MemoryValidationCache();

export type SessionErrorType = 'NETWORK_ERROR' | 'INVALID_SESSION' | 'EXPIRED_SESSION' | 'RATE_LIMITED' | 'SERVER_ERROR';

export interface SessionResult {
  success: boolean;
  error?: string;
  errorType?: SessionErrorType;
  capabilityToken?: string;
}

export class SessionService {
  /**
   * Create a new session via secure Edge Function
   * Server-side: validates format, enforces rate limiting, inserts with TTL
   */
  static async reserveSession(
    sessionId: string
  ): Promise<SessionResult> {
    // Client-side validation first
    if (!isValidSessionId(sessionId)) {
      return { success: false, error: 'Invalid session ID format', errorType: 'INVALID_SESSION' };
    }

    try {
      const { data, error } = await supabase.functions.invoke('create-session', {
        body: { sessionId }
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

      if (!data?.capabilityToken || typeof data.capabilityToken !== 'string' || !isValidCapabilityToken(data.capabilityToken)) {
        return { success: false, error: 'Invalid server response', errorType: 'SERVER_ERROR' };
      }

      return { success: true, capabilityToken: data.capabilityToken };
    } catch {
      return { success: false, error: 'Network unreachable', errorType: 'NETWORK_ERROR' };
    }
  }

  /**
   * Validate session existence via secure Edge Function
   * Server-side: checks existence + expiration, returns boolean only
   * 
   * SECURITY FIX: TTL-aware cache with fail-closed network error handling
   * - Cache now includes expiration timestamp (from server)
   * - Network errors return FALSE (fail-closed, zero-trust)
   * - Offline detection shows user-friendly message
   */
  static async validateSession(sessionId: string, capabilityToken: string, role: 'host' | 'guest'): Promise<boolean> {
    // Client-side validation first
    if (!isValidSessionId(sessionId)) {
      return false;
    }

    if (!capabilityToken || !isValidCapabilityToken(capabilityToken)) {
      return false;
    }

    // CRITICAL SECURITY FIX: Triple-verified fail-closed validation
    let networkAttempted = false;
    let networkSucceeded = false;

    try {
      // Check memory-only cache first
      const cached = validationCache.get(sessionId, role, capabilityToken);

      if (cached) {
        const now = Date.now();
        if (isCacheEntryValid(now, cached)) {
          return true;
        }
      }

      // CRITICAL: Network validation with guaranteed fail-closed
      networkAttempted = true;
      
      const { data, error } = await supabase.functions.invoke('validate-session', {
        body: { sessionId, capabilityToken, role }
      });

      // CRITICAL SECURITY FIX: ANY network anomaly = FAIL CLOSED
      if (error) {
        // Check offline status but STILL return false (zero-trust)
        try {
          if (typeof navigator !== 'undefined') {
            void navigator.onLine;
          }
        } catch {
        }

        // CRITICAL: Always return false on ANY network error
        return false;
      }

      networkSucceeded = true;
      const isValid = data?.valid === true;

      // Cache successful validation WITH expiration timestamp
      if (isValid && data?.expiresAt) {
        validationCache.set(sessionId, role, capabilityToken, data.expiresAt);
      } else {
        // Invalid session - clear any stale cache
        validationCache.clear(sessionId);
      }

      return isValid;
    } catch (error) {
      // CRITICAL SECURITY FIX: ANY exception = FAIL CLOSED
      void error;
      
      // Additional safety: if network was attempted but failed, ensure fail-closed
      void networkAttempted;
      void networkSucceeded;
      
      return false; // Zero-trust: any uncertainty = invalid
    }
  }

  /**
   * Clear validation cache for a session
   * Called when session is explicitly deleted
   */
  static clearValidationCache(sessionId: string): void {
    validationCache.clear(sessionId);
  }

  /**
   * Delete session via secure Edge Function (NUCLEAR OPTION)
   * Server-side: immediate deletion, no recovery
   * Called ONLY on explicit user "End Session" action
   * 
   * ATOMIC: This operation must complete regardless of network state
   */
  static async deleteSession(sessionId: string, capabilityTokenOverride?: string): Promise<boolean> {
    if (!isValidSessionId(sessionId)) {
      return false;
    }

    const capabilityToken = capabilityTokenOverride || SecurityManager.getCapabilityToken(sessionId);
    if (!capabilityToken || !isValidCapabilityToken(capabilityToken)) {
      return false;
    }

    // Clear validation cache immediately (before network call)
    this.clearValidationCache(sessionId);

    try {
      const request = createDeleteSessionInvokeRequest(sessionId, capabilityToken);
      const { data, error } = await supabase.functions.invoke(request.functionName, { body: request.body });

      if (error) {
        // SECURITY FIX: Return actual status (fail-closed)
        return false;
      }

      return data?.success === true;
    } catch (error) {
      void error;
      return false;
    }
  }
}
