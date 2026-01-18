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

export function isValidCapabilityToken(token: string): boolean {
  // Canonical capability tokens are base64url (no padding) of 16 random bytes.
  // 16 bytes => 22 base64url chars (unpadded).
  if (token.length !== 22) return false;
  return /^[A-Za-z0-9_-]+$/.test(token);
}

export interface SessionBindingBody {
  sessionId: string;
}

export interface SessionCapabilityBindingBody extends SessionBindingBody {
  capabilityToken: string;
}

export interface SessionChannelBindingBody extends SessionBindingBody {
  channelToken: string;
}

export interface SessionValidateBody extends SessionBindingBody {
  token: string;
  channelToken: string;
  role: 'host' | 'guest';
}

export interface SessionHostActionBody extends SessionBindingBody {
  hostToken: string;
  channelToken: string;
}

export function createSessionBindingBody(sessionId: string): SessionBindingBody {
  return { sessionId };
}

export function createSessionCapabilityBindingBody(
  sessionId: string,
  capabilityToken: string
): SessionCapabilityBindingBody {
  return { sessionId, capabilityToken };
}

export function createSessionHostActionBody(
  sessionId: string,
  hostToken: string,
  channelToken: string
): SessionHostActionBody {
  return { sessionId, hostToken, channelToken };
}

export interface ValidationCacheEntry {
  expiresAt: string;
  cachedAt: number;
}

export function isCacheEntryValid(now: number, entry: ValidationCacheEntry): boolean {
  const expiresAtMs = new Date(entry.expiresAt).getTime();
  const cacheAge = now - entry.cachedAt;
  return expiresAtMs > now && cacheAge < 5 * 60 * 1000;
}
