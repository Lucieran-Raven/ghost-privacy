/**
 * Voice Encryption (chunked)
 * Purpose: Provide AES-GCM primitives for encrypting/decrypting voice chunks and best-effort zeroization primitives.
 * Input: Crypto dependencies, session key, chunk bytes.
 * Output: Base64 ciphertext/IV pairs and decrypted ArrayBuffers.
 * Privacy: NEVER logs, NEVER stores, NEVER makes network requests, NEVER persists beyond caller-managed memory.
 */

export type GetRandomValues = <T extends ArrayBufferView>(array: T) => T;

export interface VoiceCryptoDeps {
  subtle: SubtleCrypto;
  getRandomValues: GetRandomValues;
  now: () => number;
}

export interface EncryptedChunk {
  encrypted: string;
  iv: string;
}

export interface EncryptedVoiceMessage {
  messageId: string;
  chunks: EncryptedChunk[];
  totalDuration: number;
  timestamp: number;
  playedCount: number;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer.slice(0, bytes.byteLength);
}

export function secureZeroBuffer(deps: Pick<VoiceCryptoDeps, 'getRandomValues'>, buffer: ArrayBuffer): void {
  const view = new Uint8Array(buffer);
  deps.getRandomValues(view);
  view.fill(0);
}

export async function encryptAudioChunk(
  deps: VoiceCryptoDeps,
  chunk: ArrayBuffer,
  sessionKey: CryptoKey,
  chunkIndex: number
): Promise<EncryptedChunk> {
  const timestamp = deps.now();
  const iv = deps.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(`voice-chunk-${chunkIndex}-${timestamp}`);

  const encrypted = await deps.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    sessionKey,
    chunk
  );

  return {
    encrypted: arrayBufferToBase64(encrypted),
    iv: arrayBufferToBase64(iv.buffer)
  };
}

export async function decryptAudioChunk(
  deps: Pick<VoiceCryptoDeps, 'subtle'>,
  encryptedBase64: string,
  ivBase64: string,
  sessionKey: CryptoKey,
  chunkIndex: number,
  timestamp: number
): Promise<ArrayBuffer> {
  const encrypted = base64ToArrayBuffer(encryptedBase64);
  const iv = new Uint8Array(base64ToArrayBuffer(ivBase64));
  const aad = new TextEncoder().encode(`voice-chunk-${chunkIndex}-${timestamp}`);

  return deps.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, sessionKey, encrypted);
}
