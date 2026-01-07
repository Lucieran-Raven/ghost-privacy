import { isValidCapabilityToken, isValidSessionId } from './binding';

export type ParsedAccessCode = {
  sessionId: string;
  capabilityToken: string;
};

export function parseAccessCode(raw: string): ParsedAccessCode | null {
  const trimmed = (raw || '').trim();
  if (!trimmed) return null;

  const [rawSessionId, rawCapabilityToken] = trimmed.split('.', 2);
  const sessionId = (rawSessionId || '').trim().toUpperCase();
  const capabilityToken = (rawCapabilityToken || '').trim();

  if (!isValidSessionId(sessionId)) return null;
  if (!isValidCapabilityToken(capabilityToken)) return null;

  return { sessionId, capabilityToken };
}
