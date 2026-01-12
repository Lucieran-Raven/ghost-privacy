import { isValidCapabilityToken, isValidSessionId } from './binding';

export type ParsedAccessCode = {
  sessionId: string;
  capabilityToken: string;
};

export function parseAccessCode(raw: string): ParsedAccessCode | null {
  const trimmed = (raw || '').trim();
  if (!trimmed) return null;

  // Defensive limit: avoid pathological inputs.
  if (trimmed.length > 256) return null;

  const dot = trimmed.indexOf('.');
  if (dot <= 0) return null;
  if (trimmed.indexOf('.', dot + 1) !== -1) return null;

  const rawSessionId = trimmed.slice(0, dot);
  const rawCapabilityToken = trimmed.slice(dot + 1);
  const sessionId = (rawSessionId || '').trim().toUpperCase();
  const capabilityToken = (rawCapabilityToken || '').trim();

  if (!isValidSessionId(sessionId)) return null;
  if (!isValidCapabilityToken(capabilityToken)) return null;

  return { sessionId, capabilityToken };
}
