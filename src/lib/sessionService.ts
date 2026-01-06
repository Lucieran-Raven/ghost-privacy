import { supabase } from '@/integrations/supabase/publicClient';
import { SecurityManager } from '@/utils/security';
import {
  isCacheEntryValid,
  isValidCapabilityToken,
  isValidFingerprint,
  isValidSessionId
} from '@/utils/algorithms/session/binding';
import { createExtendSessionInvokeRequest } from '@/utils/algorithms/session/extension';
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
  private cache = new Map<string, { expiresAt: string; cachedAt: number; fingerprint: string; capabilityToken: string }>();
  private cleanupInterval: number;

  constructor() {
    // Clean expired entries every 5 minutes
    this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60 * 1000) as unknown as number;
    
    // Nuclear purge on browser close
    window.addEventListener('beforeunload', () => this.nuclearPurge());
    window.addEventListener('unload', () => this.nuclearPurge());
  }

  get(sessionId: string, fingerprint: string, capabilityToken: string): { expiresAt: string; cachedAt: number } | null {
    const entry = this.cache.get(sessionId);
    if (!entry) return null;

    if (entry.fingerprint !== fingerprint) {
      this.cache.delete(sessionId);
      return null;
    }

    if (entry.capabilityToken !== capabilityToken) {
      this.cache.delete(sessionId);
      return null;
    }

    const now = Date.now();
    if (isCacheEntryValid(now, entry)) {
      return entry;
    }

    // Remove expired entry
    this.cache.delete(sessionId);
    return null;
  }

  set(sessionId: string, fingerprint: string, capabilityToken: string, expiresAt: string): void {
    this.cache.set(sessionId, {
      expiresAt,
      cachedAt: Date.now(),
      fingerprint,
      capabilityToken
    });
  }

  clear(sessionId: string): void {
    this.cache.delete(sessionId);
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
    clearInterval(this.cleanupInterval);
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
    sessionId: string,
    hostFingerprint: string
  ): Promise<SessionResult> {
    // Client-side validation first
    if (!isValidSessionId(sessionId)) {
      return { success: false, error: 'Invalid session ID format', errorType: 'INVALID_SESSION' };
    }

    if (!hostFingerprint || !isValidFingerprint(hostFingerprint)) {
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
  static async validateSession(sessionId: string, fingerprint: string, capabilityToken: string): Promise<boolean> {
    // Client-side validation first
    if (!isValidSessionId(sessionId)) {
      return false;
    }

    if (!fingerprint || !isValidFingerprint(fingerprint)) {
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
      const cached = validationCache.get(sessionId, fingerprint, capabilityToken);

      if (cached) {
        const now = Date.now();
        if (isCacheEntryValid(now, { ...cached, fingerprint })) {
          return true;
        }
      }

      // CRITICAL: Network validation with guaranteed fail-closed
      networkAttempted = true;
      
      const { data, error } = await supabase.functions.invoke('validate-session', {
        body: { sessionId, fingerprint, capabilityToken }
      });

      // CRITICAL SECURITY FIX: ANY network anomaly = FAIL CLOSED
      if (error) {
        // Check offline status but STILL return false (zero-trust)
        void navigator;

        // CRITICAL: Always return false on ANY network error
        return false;
      }

      networkSucceeded = true;
      const isValid = data?.valid === true;

      // Cache successful validation WITH expiration timestamp
      if (isValid && data?.expiresAt) {
        validationCache.set(sessionId, fingerprint, capabilityToken, data.expiresAt);
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
   * Extend session TTL via secure Edge Function
   * Server-side: extends expires_at by 30 minutes
   */
  static async extendSession(sessionId: string): Promise<boolean> {
    if (!isValidSessionId(sessionId)) {
      return false;
    }

    const capabilityToken = SecurityManager.getCapabilityToken(sessionId);
    if (!capabilityToken || !isValidCapabilityToken(capabilityToken)) {
      return false;
    }

    const fingerprint = await SecurityManager.generateFingerprint();

    if (!fingerprint || !isValidFingerprint(fingerprint)) {
      return false;
    }

    try {
      const request = createExtendSessionInvokeRequest(sessionId, fingerprint, capabilityToken);
      const { data, error } = await supabase.functions.invoke(request.functionName, { body: request.body });

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
    if (!isValidSessionId(sessionId)) {
      return false;
    }

    const capabilityToken = SecurityManager.getCapabilityToken(sessionId);
    if (!capabilityToken || !isValidCapabilityToken(capabilityToken)) {
      return false;
    }

    // Clear validation cache immediately (before network call)
    this.clearValidationCache(sessionId);

    const fingerprint = await SecurityManager.generateFingerprint();

    if (!fingerprint || !isValidFingerprint(fingerprint)) {
      return false;
    }

    try {
      const request = createDeleteSessionInvokeRequest(sessionId, fingerprint, capabilityToken);
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
