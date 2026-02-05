let fallbackState = 0;

function nextFallbackUint32(): number {
  // xorshift32
  if (fallbackState === 0) {
    const seed = (Date.now() ^ (typeof performance !== 'undefined' ? Math.floor(performance.now() * 1000) : 0)) >>> 0;
    fallbackState = seed === 0 ? 0x6d2b79f5 : seed;
  }
  let x = fallbackState >>> 0;
  x ^= x << 13;
  x ^= x >>> 17;
  x ^= x << 5;
  fallbackState = x >>> 0;
  return fallbackState;
}

function hasCryptoGetRandomValues(): boolean {
  return typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function';
}

function requireCryptoGetRandomValues(): void {
  if (!hasCryptoGetRandomValues()) {
    throw new Error('Secure RNG unavailable: crypto.getRandomValues is required');
  }
}

export function randomUint32(): number {
  requireCryptoGetRandomValues();
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0] >>> 0;
}

export function fillRandomBytes(bytes: Uint8Array): void {
  if (!(bytes instanceof Uint8Array)) return;
  requireCryptoGetRandomValues();
  crypto.getRandomValues(bytes);
}

export function bestEffortRandomUint32(): number {
  if (hasCryptoGetRandomValues()) {
    const buf = new Uint32Array(1);
    crypto.getRandomValues(buf);
    return buf[0] >>> 0;
  }
  return nextFallbackUint32();
}

export function fillBestEffortRandomBytes(bytes: Uint8Array): void {
  if (!(bytes instanceof Uint8Array)) return;
  if (hasCryptoGetRandomValues()) {
    crypto.getRandomValues(bytes);
    return;
  }
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = bestEffortRandomUint32() & 0xff;
  }
}

export function secureRandomInt(maxExclusive: number): number {
  if (!Number.isFinite(maxExclusive) || maxExclusive <= 0) return 0;
  const max = Math.floor(maxExclusive);
  if (max <= 1) return 0;

  const limit = Math.floor(0x100000000 / max) * max;
  while (true) {
    const v = randomUint32();
    if (v < limit) return v % max;
  }
}

export function secureRandomFloat01(): number {
  return randomUint32() / 0x100000000;
}

export function pickRandom<T>(items: readonly T[]): T {
  const idx = secureRandomInt(items.length);
  return items[idx];
}

export function bestEffortRandomInt(maxExclusive: number): number {
  if (!Number.isFinite(maxExclusive) || maxExclusive <= 0) return 0;
  const max = Math.floor(maxExclusive);
  if (max <= 1) return 0;

  const limit = Math.floor(0x100000000 / max) * max;
  while (true) {
    const v = bestEffortRandomUint32();
    if (v < limit) return v % max;
  }
}

export function bestEffortRandomFloat01(): number {
  return bestEffortRandomUint32() / 0x100000000;
}

export function bestEffortPickRandom<T>(items: readonly T[]): T {
  const idx = bestEffortRandomInt(items.length);
  return items[idx];
}
