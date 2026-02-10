import { supabase } from '@/integrations/supabase/publicClient';
import { isResearchFeaturesEnabled } from '@/utils/researchFeatures';
import { fillRandomBytes } from '@/utils/secureRng';

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

function isReasonableIdentifier(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  if (value.length < 1 || value.length > 128) return false;
  // Conservative allowlist for client->edge payloads
  return /^[A-Za-z0-9_-]+$/.test(value) || /^GHOST-[A-Za-z0-9_-]+$/.test(value);
}

function sanitizeOptionalFingerprint(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (trimmed.length < 8 || trimmed.length > 256) return undefined;
  // Fingerprints in this app are typically hex/base64-like; avoid sending arbitrary blobs
  if (!/^[A-Za-z0-9+/=_:-]+$/.test(trimmed)) return undefined;
  return trimmed;
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
      if (!isResearchFeaturesEnabled()) {
        return { isHoneypot: false, trapType: null };
      }

      // Quick local check for planted honeytokens (avoid network + prevent false negatives)
      if (this.hasHoneypotPrefix(sessionId)) {
        return { isHoneypot: true, trapType: 'explicit_trap' };
      }

      if (!isReasonableIdentifier(sessionId)) {
        // Avoid sending attacker-controlled large/unexpected strings to the edge function.
        return { isHoneypot: false, trapType: null };
      }

      const safeFingerprint = sanitizeOptionalFingerprint(accessorFingerprint);

      const { data, error } = await supabase.functions.invoke('detect-honeypot', {
        method: 'POST',
        body: { sessionId, accessorFingerprint: safeFingerprint }
      });

      if (error) {
        return { isHoneypot: false, trapType: null };
      }

      return {
        isHoneypot: (data as any)?.isHoneypot === true,
        trapType: (data as any)?.trapType || null
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
    const bytes = new Uint8Array(12);
    fillRandomBytes(bytes);

    let suffix = '';
    for (let i = 0; i < bytes.length; i++) {
      suffix += chars[bytes[i] % chars.length];
    }
    return `GHOST-${prefix}-${suffix}`;
  }

  /**
   * Check if session ID has honeypot prefix (quick local check)
   */
  static hasHoneypotPrefix(sessionId: string): boolean {
    return sessionId.startsWith('GHOST-TRAP-') || sessionId.startsWith('GHOST-DECOY-');
  }
}
