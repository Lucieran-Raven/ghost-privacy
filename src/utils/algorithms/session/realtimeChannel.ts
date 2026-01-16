import { base64UrlToBytes } from '@/utils/algorithms/encoding/base64';
import { isValidCapabilityToken, isValidSessionId } from './binding';

export interface RealtimeChannelDeps {
  subtle: SubtleCrypto;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
  return hex;
}

async function hmacSha256Hex(deps: RealtimeChannelDeps, keyBytes: Uint8Array, message: string): Promise<string> {
  const keyMaterial = new Uint8Array(keyBytes.byteLength);
  keyMaterial.set(keyBytes);
  try {
    const key = await deps.subtle.importKey('raw', keyMaterial, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await deps.subtle.sign('HMAC', key, new TextEncoder().encode(message));
    return bytesToHex(new Uint8Array(sig));
  } finally {
    keyMaterial.fill(0);
  }
}

export async function deriveRealtimeChannelName(deps: RealtimeChannelDeps, sessionId: string, capabilityToken: string): Promise<string> {
  if (!isValidSessionId(sessionId)) {
    throw new Error('invalid session id');
  }
  if (!isValidCapabilityToken(capabilityToken)) {
    throw new Error('invalid capability token');
  }
  const keyBytes = base64UrlToBytes(capabilityToken);

  const mac = await hmacSha256Hex(deps, keyBytes, sessionId);
  keyBytes.fill(0);
  const tag = mac.slice(0, 32);
  return `ghost-session-${tag}`;
}
