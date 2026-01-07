function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
  return hex;
}

async function hmacSha256Hex(keyBytes: Uint8Array, message: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return bytesToHex(new Uint8Array(sig));
}

export async function deriveRealtimeChannelName(sessionId: string, capabilityToken: string): Promise<string> {
  let keyBytes: Uint8Array;
  try {
    keyBytes = base64UrlToBytes(capabilityToken);
  } catch {
    keyBytes = new TextEncoder().encode(capabilityToken);
  }

  const mac = await hmacSha256Hex(keyBytes, sessionId);
  const tag = mac.slice(0, 32);
  return `ghost-session-${sessionId}-${tag}`;
}
