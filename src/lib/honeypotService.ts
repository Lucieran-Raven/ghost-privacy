import { supabase } from '@/integrations/supabase/publicClient';

/**
 * GHOST MIRAGE: Honeypot Detection Service
 * 
 * Client-side service for detecting honeypot sessions.
 * Uses edge function to check if a session is a trap.
 */

export interface HoneypotCheckResult {
  isHoneypot: boolean;
  trapType: 'explicit_trap' | 'dead_session' | 'unknown' | null;
}

export class HoneypotService {
  /**
   * Check if a session ID is a honeypot/trap
   * This is called BEFORE attempting to join a session
   */
  static async checkSession(
    sessionId: string,
    accessorFingerprint?: string
  ): Promise<HoneypotCheckResult> {
    try {
      const { data, error } = await supabase.functions.invoke('detect-honeypot', {
        body: { sessionId, accessorFingerprint }
      });

      if (error) {
        return { isHoneypot: false, trapType: null };
      }

      return {
        isHoneypot: data.isHoneypot === true,
        trapType: data.trapType || null
      };
    } catch {
      return { isHoneypot: false, trapType: null };
    }
  }

  /**
   * Generate a honeytoken session ID
   * These can be planted in documents, code, etc. to detect leaks
   */
  static generateHoneytoken(prefix: 'TRAP' | 'DECOY' = 'TRAP'): string {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let result = `GHOST-${prefix}-`;
    for (let i = 0; i < 4; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  /**
   * Check if session ID has honeypot prefix (quick local check)
   */
  static hasHoneypotPrefix(sessionId: string): boolean {
    return sessionId.startsWith('GHOST-TRAP-') || sessionId.startsWith('GHOST-DECOY-');
  }
}
