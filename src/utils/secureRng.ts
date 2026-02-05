/**
 * Security RNG API
 *
 * - `secure*` APIs are fail-closed and throw if CSPRNG is unavailable.
 * - `bestEffort*` APIs are for UX-only randomness (animations, decoys, timers).
 */

function requireCryptoOrThrow(): Crypto {
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    return crypto;
  }
  throw new Error('Secure RNG unavailable: crypto.getRandomValues is required for security-sensitive randomness.');
}

export function randomUint32(): number {
  const c = requireCryptoOrThrow();
  const buf = new Uint32Array(1);
  c.getRandomValues(buf);
  return buf[0] >>> 0;
}

export function fillRandomBytes(bytes: Uint8Array): void {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('fillRandomBytes expects Uint8Array');
  }
  requireCryptoOrThrow().getRandomValues(bytes);
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

function fallbackUint32(): number {
  // UX-only fallback entropy, intentionally non-cryptographic.
  const now = Date.now() >>> 0;
  const perf = typeof performance !== 'undefined' ? Math.floor(performance.now() * 1000) >>> 0 : 0;
  const mixed = (now ^ perf ^ ((Math.random() * 0xffffffff) >>> 0)) >>> 0;
  return mixed;
}

export function bestEffortRandomInt(maxExclusive: number): number {
  if (!Number.isFinite(maxExclusive) || maxExclusive <= 0) return 0;
  const max = Math.floor(maxExclusive);
  if (max <= 1) return 0;
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    return secureRandomInt(max);
  }
  return fallbackUint32() % max;
}

export function bestEffortPickRandom<T>(items: readonly T[]): T {
  return items[bestEffortRandomInt(items.length)];
}
