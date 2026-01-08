import { base64UrlToBytes } from '@/utils/algorithms/encoding/base64';

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
  const key = await deps.subtle.importKey('raw', keyMaterial, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await deps.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return bytesToHex(new Uint8Array(sig));
}

export async function deriveRealtimeChannelName(deps: RealtimeChannelDeps, sessionId: string, capabilityToken: string): Promise<string> {
  let keyBytes: Uint8Array;
  try {
    keyBytes = base64UrlToBytes(capabilityToken);
  } catch {
    keyBytes = new TextEncoder().encode(capabilityToken);
  }

  const mac = await hmacSha256Hex(deps, keyBytes, sessionId);
  const tag = mac.slice(0, 32);
  return `ghost-session-${sessionId}-${tag}`;
}
