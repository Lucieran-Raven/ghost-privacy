/**
 * Voice Encryption (chunked)
 * Purpose: Provide AES-GCM primitives for encrypting/decrypting voice chunks and best-effort zeroization primitives.
 * Input: Crypto dependencies, session key, chunk bytes.
 * Output: Base64 ciphertext/IV pairs and decrypted ArrayBuffers.
 * Privacy: NEVER logs, NEVER stores, NEVER makes network requests, NEVER persists beyond caller-managed memory.
 */

import { base64ToBytes, bytesToBase64 } from '@/utils/algorithms/encoding/base64';

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
  return bytesToBase64(new Uint8Array(buffer));
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const bytes = base64ToBytes(base64);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
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

  try {
    const encrypted = await deps.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad },
      sessionKey,
      chunk
    );

    return {
      encrypted: arrayBufferToBase64(encrypted),
      iv: arrayBufferToBase64(iv.buffer)
    };
  } finally {
    try {
      aad.fill(0);
    } catch {
      // Ignore
    }
  }
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

  try {
    return await deps.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, sessionKey, encrypted);
  } finally {
    try {
      aad.fill(0);
    } catch {
      // Ignore
    }
  }
}
