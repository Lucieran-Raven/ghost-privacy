export type TofuPinResult =
  | { status: 'pinned' }
  | { status: 'match' }
  | { status: 'mismatch'; pinnedFingerprint: string };

type TofuPinRecord = {
  fp: string;
  firstSeen: number;
  lastSeen: number;
};
const MAX_AGE_MS = 48 * 60 * 60 * 1000;

const now = () => Date.now();

const pins = new Map<string, TofuPinRecord>();

const gcPins = (): void => {
  const cutoff = now() - MAX_AGE_MS;
  for (const [k, rec] of pins.entries()) {
    if (!rec || typeof rec.lastSeen !== 'number' || rec.lastSeen < cutoff) {
      pins.delete(k);
    }
  }
};

export const checkOrPinFingerprint = (pinKey: string, remoteFingerprint: string): TofuPinResult => {
  const fp = String(remoteFingerprint || '').toUpperCase();
  if (!fp) return { status: 'match' };

  gcPins();

  const existing = pins.get(pinKey);
  if (!existing) {
    const ts = now();
    pins.set(pinKey, { fp, firstSeen: ts, lastSeen: ts });
    return { status: 'pinned' };
  }

  existing.lastSeen = now();

  if (existing.fp !== fp) {
    return { status: 'mismatch', pinnedFingerprint: existing.fp };
  }

  return { status: 'match' };
};
