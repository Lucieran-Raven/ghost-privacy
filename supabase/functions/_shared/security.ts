export type JsonErrorBody = { error: string; code: string };

declare const Deno: {
  env: {
    get(key: string): string | undefined;
  };
};

export function jsonResponse(
  body: unknown,
  options: { status?: number; headers?: Record<string, string> } = {}
): Response {
  const status = options.status ?? 200;
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers ?? {})
    }
  });
}

export function jsonError(
  error: string,
  code: string,
  options: { status?: number; headers?: Record<string, string> } = {}
): Response {
  return jsonResponse({ error, code } satisfies JsonErrorBody, {
    status: options.status ?? 500,
    headers: options.headers
  });
}

function arrayBufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecodeToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Extract client IP from request headers with fallback chain:
 * 1. cf-connecting-ip (Cloudflare)
 * 2. x-forwarded-for (first IP before comma)
 * 3. x-real-ip
 * 
 * Returns trimmed IP or null if none found
 */
function extractClientIp(req: Request): string | null {
  // Try Cloudflare header first
  const cfIp = (req.headers.get('cf-connecting-ip') || '').trim();
  if (cfIp) return cfIp;

  // Try x-forwarded-for (use first IP in chain)
  const forwardedFor = req.headers.get('x-forwarded-for');
  if (forwardedFor) {
    const firstIp = forwardedFor.split(',')[0]?.trim();
    if (firstIp) return firstIp;
  }

  // Try x-real-ip
  const realIp = (req.headers.get('x-real-ip') || '').trim();
  if (realIp) return realIp;

  return null;
}

/**
 * Validate if a string looks like a valid IPv4 or IPv6 address
 */
function isValidIpFormat(ip: string): boolean {
  const looksLikeIpv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip);
  const looksLikeIpv6 = /^[0-9a-fA-F:]+$/.test(ip) && ip.includes(':');
  return looksLikeIpv4 || looksLikeIpv6;
}

export async function getClientIpHashHex(req: Request): Promise<string> {
  const rawIp = extractClientIp(req);

  const env = Deno.env.get('ENVIRONMENT') || 'development';

  // In production, we must have a real client IP from the platform headers.
  // Falling back would collapse all clients into the same IP hash and weaken
  // rate limiting + IP-binding.
  if (env === 'production' && !rawIp) {
    throw new Error('Client IP unavailable');
  }

  // Development fallback for localhost
  const finalIp = rawIp || "127.0.0.1";

  // For localhost development, accept the fallback
  if (finalIp === "127.0.0.1" && !rawIp) {
    // This is expected for localhost development
  } else if (!isValidIpFormat(finalIp)) {
    throw new Error('Client IP unavailable (invalid ip)');
  }
  const envSalt = Deno.env.get('IP_HASH_SALT');
  const fallbackSalt = 'development-salt-32-chars-long-0000';
  const salt = envSalt || (env === 'production' ? '' : fallbackSalt);

  if (!salt || salt.length < 32) {
    throw new Error('IP_HASH_SALT missing or too short (min 32 bytes)');
  }

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(salt),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const hash = await crypto.subtle.sign('HMAC', key, encoder.encode(finalIp));
  return arrayBufferToHex(hash);
}

export function hexToBytea(hex: string): string {
  if (hex.length !== 64) {
    throw new Error('Invalid HMAC hex length');
  }
  return `\\x${hex.toLowerCase()}`;
}

export async function getClientIpHashBytea(req: Request): Promise<string> {
  const hex = await getClientIpHashHex(req);
  return hexToBytea(hex);
}

const ZERO_32_BYTES_HEX = '00'.repeat(32);

export type SessionIpHashParts = {
  hostHex: string;
  guestHex: string;
};

export function parsePostgresByteaHex(bytea: string | null | undefined): string | null {
  if (!bytea) return null;
  return bytea.startsWith('\\x') ? bytea.slice(2) : bytea;
}

export function generateCapabilityToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return base64UrlEncode(bytes);
}

export async function hashCapabilityTokenToBytea(token: string): Promise<string> {
  const bytes = base64UrlDecodeToBytes(token);
  const copy = new Uint8Array(bytes);
  const digest = await crypto.subtle.digest('SHA-256', copy.buffer as ArrayBuffer);
  return `\\x${arrayBufferToHex(digest)}`;
}

export async function verifyCapabilityHash(
  storedBytea: string | null | undefined,
  token: string
): Promise<boolean> {
  const storedHex = parsePostgresByteaHex(storedBytea);
  if (!storedHex || storedHex.length !== 64) return false;

  const expectedBytea = await hashCapabilityTokenToBytea(token);
  const expectedHex = parsePostgresByteaHex(expectedBytea);
  if (!expectedHex) return false;

  const storedBytes = new Uint8Array(storedHex.match(/.{1,2}/g)!.map(h => parseInt(h, 16)));
  const expectedBytes = new Uint8Array(expectedHex.match(/.{1,2}/g)!.map(h => parseInt(h, 16)));
  return timingSafeEqualBytes(storedBytes, expectedBytes);
}

export function parseSessionIpHash(bytea: string | null | undefined): SessionIpHashParts | null {
  const hex = parsePostgresByteaHex(bytea);
  if (!hex) return null;
  if (hex.length !== 128) return null;
  const hostHex = hex.slice(0, 64);
  const guestHex = hex.slice(64, 128);
  return { hostHex, guestHex };
}

export function buildSessionIpHashBytea(parts: Partial<SessionIpHashParts>): string {
  const hostHex = (parts.hostHex || ZERO_32_BYTES_HEX).toLowerCase();
  const guestHex = (parts.guestHex || ZERO_32_BYTES_HEX).toLowerCase();
  if (hostHex.length !== 64 || guestHex.length !== 64) {
    throw new Error('Invalid ip_hash parts');
  }
  return `\\x${hostHex}${guestHex}`;
}

export function isZero32Hex(hex: string | null | undefined): boolean {
  if (!hex) return false;
  return hex.toLowerCase() === ZERO_32_BYTES_HEX;
}

export function requireCronAuth(req: Request, headers?: Record<string, string>): Response | null {
  const secret = Deno.env.get('CRON_SECRET');
  if (!secret || secret.length < 32) {
    return jsonError('Server misconfigured', 'SERVER_MISCONFIG', { status: 500, headers });
  }

  const authHeader = req.headers.get('authorization');
  const expected = `Bearer ${secret}`;
  if (authHeader !== expected) {
    return jsonError('Unauthorized', 'AUTH_REQUIRED', { status: 401, headers });
  }

  return null;
}
