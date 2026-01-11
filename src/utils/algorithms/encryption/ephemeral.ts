/**
 * Ephemeral Encryption (real-time messages)
 * Purpose: Provide AES-GCM encryption/decryption and ECDH key exchange primitives in a dependency-injected, auditable form.
 * Input: Crypto dependencies, keys, plaintext/ciphertext.
 * Output: Base64-encoded ciphertext/IV pairs, derived keys, fingerprints.
 * Privacy: NEVER logs, NEVER stores, NEVER makes network requests, NEVER persists beyond caller-managed memory.
 */

import { base64ToBytes, bytesToBase64 } from '@/utils/algorithms/encoding/base64';

export type GetRandomValues = <T extends ArrayBufferView>(array: T) => T;

export interface EphemeralCryptoDeps {
  subtle: SubtleCrypto;
  getRandomValues: GetRandomValues;
}

export interface EncryptResult {
  encrypted: string;
  iv: string;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return bytesToBase64(new Uint8Array(buffer));
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const bytes = base64ToBytes(base64);
  try {
    // slice() copies into a new ArrayBuffer, allowing us to wipe the decode buffer.
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  } finally {
    try {
      bytes.fill(0);
    } catch {
      // Ignore
    }
  }
}

export function generateNonce(deps: EphemeralCryptoDeps): string {
  const array = deps.getRandomValues(new Uint8Array(16));
  return arrayBufferToBase64(array.buffer);
}

export function generateGhostId(deps: EphemeralCryptoDeps): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const charCount = chars.length;

  const maxUnbiased = Math.floor(256 / charCount) * charCount;
  const getUnbiasedChar = (initial: number): string => {
    let v = initial;
    for (let attempts = 0; attempts < 128; attempts++) {
      if (v < maxUnbiased) {
        return chars[v % charCount];
      }
      v = deps.getRandomValues(new Uint8Array(1))[0];
    }
    return chars[v % charCount];
  };

  const randomBytes = deps.getRandomValues(new Uint8Array(8));

  let part1 = '';
  for (let i = 0; i < 4; i++) {
    part1 += getUnbiasedChar(randomBytes[i]);
  }

  let part2 = '';
  for (let i = 4; i < 8; i++) {
    part2 += getUnbiasedChar(randomBytes[i]);
  }
  return `GHOST-${part1}-${part2}`;
}

export function isValidGhostId(id: string): boolean {
  return /^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(id);
}

export async function aesGcmEncryptString(
  deps: EphemeralCryptoDeps,
  key: CryptoKey,
  message: string
): Promise<EncryptResult> {
  const iv = deps.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(message);

  try {
    const encrypted = await deps.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
    return {
      encrypted: arrayBufferToBase64(encrypted),
      iv: arrayBufferToBase64(iv.buffer)
    };
  } finally {
    try {
      encoded.fill(0);
    } catch {
      // Ignore
    }
  }
}

export async function aesGcmEncryptBytes(
  deps: EphemeralCryptoDeps,
  key: CryptoKey,
  plaintext: ArrayBuffer
): Promise<EncryptResult> {
  const iv = deps.getRandomValues(new Uint8Array(12));
  const encrypted = await deps.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return {
    encrypted: arrayBufferToBase64(encrypted),
    iv: arrayBufferToBase64(iv.buffer)
  };
}

export async function aesGcmDecryptString(
  deps: EphemeralCryptoDeps,
  key: CryptoKey,
  encryptedBase64: string,
  ivBase64: string
): Promise<string> {
  const encrypted = base64ToArrayBuffer(encryptedBase64);
  const iv = new Uint8Array(base64ToArrayBuffer(ivBase64));

  try {
    const decrypted = await deps.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted);
    const bytes = new Uint8Array(decrypted);
    try {
      return new TextDecoder().decode(bytes);
    } finally {
      try {
        bytes.fill(0);
      } catch {
        // Ignore
      }
    }
  } finally {
    try {
      iv.fill(0);
    } catch {
      // Ignore
    }
    try {
      new Uint8Array(encrypted).fill(0);
    } catch {
      // Ignore
    }
  }
}

export async function aesGcmDecryptBytes(
  deps: EphemeralCryptoDeps,
  key: CryptoKey,
  encryptedBase64: string,
  ivBase64: string
): Promise<ArrayBuffer> {
  const encrypted = base64ToArrayBuffer(encryptedBase64);
  const iv = new Uint8Array(base64ToArrayBuffer(ivBase64));

  try {
    return await deps.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted);
  } finally {
    try {
      iv.fill(0);
    } catch {
      // Ignore
    }
    try {
      new Uint8Array(encrypted).fill(0);
    } catch {
      // Ignore
    }
  }
}

export async function generateAesGcmKey(deps: EphemeralCryptoDeps, extractable: boolean = false): Promise<CryptoKey> {
  return deps.subtle.generateKey({ name: 'AES-GCM', length: 256 }, extractable, ['encrypt', 'decrypt']);
}

export async function exportAesKeyRawBase64(deps: EphemeralCryptoDeps, key: CryptoKey): Promise<string> {
  if (!key.extractable) {
    throw new Error('Key is non-extractable');
  }
  const exported = await deps.subtle.exportKey('raw', key);
  return arrayBufferToBase64(exported);
}

export async function importAesKeyRawBase64(
  deps: EphemeralCryptoDeps,
  keyBase64: string,
  extractable: boolean = false
): Promise<CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(keyBase64);
  try {
    return await deps.subtle.importKey('raw', keyBuffer, { name: 'AES-GCM', length: 256 }, extractable, ['encrypt', 'decrypt']);
  } finally {
    try {
      new Uint8Array(keyBuffer).fill(0);
    } catch {
      // Ignore
    }
  }
}

export async function generateEcdhKeyPair(deps: EphemeralCryptoDeps): Promise<CryptoKeyPair> {
  const keyPair = await deps.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
  const privateKeyPkcs8 = await deps.subtle.exportKey('pkcs8', keyPair.privateKey);

  try {
    const privateKey = await deps.subtle.importKey(
      'pkcs8',
      privateKeyPkcs8,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveKey', 'deriveBits']
    );
    return { publicKey: keyPair.publicKey, privateKey };
  } finally {
    try {
      new Uint8Array(privateKeyPkcs8).fill(0);
    } catch {
      // Ignore
    }
  }
}

export async function exportEcdhPublicKeySpkiBase64(deps: EphemeralCryptoDeps, publicKey: CryptoKey): Promise<string> {
  const exported = await deps.subtle.exportKey('spki', publicKey);
  return arrayBufferToBase64(exported);
}

export async function importEcdhPublicKeySpkiBase64(deps: EphemeralCryptoDeps, publicKeyBase64: string): Promise<CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(publicKeyBase64);
  return deps.subtle.importKey('spki', keyBuffer, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
}

export async function deriveSharedSecretAesGcmKey(
  deps: EphemeralCryptoDeps,
  privateKey: CryptoKey,
  publicKey: CryptoKey
): Promise<CryptoKey> {
  return deps.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function deriveSharedSecretBytes(
  deps: EphemeralCryptoDeps,
  privateKey: CryptoKey,
  publicKey: CryptoKey
): Promise<ArrayBuffer> {
  return deps.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey,
    256
  );
}

export async function generateFingerprintHex(deps: EphemeralCryptoDeps, publicKey: CryptoKey): Promise<string> {
  const exported = await deps.subtle.exportKey('spki', publicKey);
  const hash = await deps.subtle.digest('SHA-256', exported);
  const hashArray = Array.from(new Uint8Array(hash));
  const fingerprint = hashArray
    .slice(0, 16)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return fingerprint.toUpperCase();
}
