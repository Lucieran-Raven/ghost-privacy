/**
 * Session Binding Validation
 * Purpose: Validate session identifiers and binding tokens (fingerprints) before any privileged operation.
 * Input: sessionId (string), fingerprint (string).
 * Output: boolean validation results and normalized request payloads.
 * Privacy: NEVER logs, NEVER stores, NEVER makes network requests, NEVER persists beyond caller-managed memory.
 */

export const SESSION_ID_PATTERN = /^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$/;

export function isValidSessionId(sessionId: string): boolean {
  return SESSION_ID_PATTERN.test(sessionId);
}

export function isValidFingerprint(fingerprint: string): boolean {
  return fingerprint.length >= 8 && fingerprint.length <= 128;
}

export function isValidCapabilityToken(token: string): boolean {
  return token.length >= 16 && token.length <= 64;
}

export interface SessionBindingBody {
  sessionId: string;
  fingerprint: string;
}

export interface SessionCapabilityBindingBody extends SessionBindingBody {
  capabilityToken: string;
}

export function createSessionBindingBody(sessionId: string, fingerprint: string): SessionBindingBody {
  return { sessionId, fingerprint };
}

export function createSessionCapabilityBindingBody(
  sessionId: string,
  fingerprint: string,
  capabilityToken: string
): SessionCapabilityBindingBody {
  return { sessionId, fingerprint, capabilityToken };
}

export interface ValidationCacheEntry {
  expiresAt: string;
  cachedAt: number;
  fingerprint: string;
}

export function isCacheEntryValid(now: number, entry: ValidationCacheEntry): boolean {
  const expiresAtMs = new Date(entry.expiresAt).getTime();
  const cacheAge = now - entry.cachedAt;
  return expiresAtMs > now && cacheAge < 5 * 60 * 1000;
}
