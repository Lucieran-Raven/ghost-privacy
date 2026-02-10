import { isValidCapabilityToken, isValidSessionId } from './binding';

export type ParsedAccessCode = {
  sessionId: string;
  guestToken: string;
  channelToken: string;
};

export function parseAccessCode(raw: string): ParsedAccessCode | null {
  const trimmed = (raw || '').trim();
  if (!trimmed) return null;

  // Defensive limit: avoid pathological inputs.
  if (trimmed.length > 256) return null;

  const firstDot = trimmed.indexOf('.');
  if (firstDot <= 0) return null;
  const secondDot = trimmed.indexOf('.', firstDot + 1);
  if (secondDot === -1) return null;
  if (trimmed.indexOf('.', secondDot + 1) !== -1) return null;

  const rawSessionId = trimmed.slice(0, firstDot);
  const rawGuestToken = trimmed.slice(firstDot + 1, secondDot);
  const rawChannelToken = trimmed.slice(secondDot + 1);
  const sessionId = (rawSessionId || '').trim().toUpperCase();
  const guestToken = (rawGuestToken || '').trim();
  const channelToken = (rawChannelToken || '').trim();

  if (!isValidSessionId(sessionId)) return null;
  if (!isValidCapabilityToken(guestToken)) return null;
  if (!isValidCapabilityToken(channelToken)) return null;

  return { sessionId, guestToken, channelToken };
}
