/**
 * Ephemeral Encryption (real-time messages)
 * Purpose: Provide AES-GCM encryption/decryption and ECDH key exchange primitives in a dependency-injected, auditable form.
 * Input: Crypto dependencies, keys, plaintext/ciphertext.
 * Output: Base64-encoded ciphertext/IV pairs, derived keys, fingerprints.
 * Privacy: NEVER logs, NEVER stores, NEVER makes network requests, NEVER persists beyond caller-managed memory.
 */

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

export function generateNonce(deps: EphemeralCryptoDeps): string {
  const array = deps.getRandomValues(new Uint8Array(16));
  return arrayBufferToBase64(array.buffer);
}

export function generateGhostId(deps: EphemeralCryptoDeps): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const charCount = chars.length;
  
  // Generate unbiased random characters using rejection sampling
  const getUnbiasedChar = (randomValue: number): string => {
    const maxUnbiased = Math.floor(256 / charCount) * charCount;
    if (randomValue >= maxUnbiased) {
      // Reject and get new value
      return getUnbiasedChar(deps.getRandomValues(new Uint8Array(1))[0]);
    }
    return chars[randomValue % charCount];
  };
  
  // Generate 8 unbiased random bytes for 8 characters
  const randomBytes = deps.getRandomValues(new Uint8Array(8));
  
  const part1 = Array.from(randomBytes.slice(0, 4))
    .map(byte => getUnbiasedChar(byte))
    .join('');
  
  const part2 = Array.from(randomBytes.slice(4, 8))
    .map(byte => getUnbiasedChar(byte))
    .join('');
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

  const encrypted = await deps.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);

  return {
    encrypted: arrayBufferToBase64(encrypted),
    iv: arrayBufferToBase64(iv.buffer)
  };
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

  const decrypted = await deps.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted);
  return new TextDecoder().decode(decrypted);
}

export async function aesGcmDecryptBytes(
  deps: EphemeralCryptoDeps,
  key: CryptoKey,
  encryptedBase64: string,
  ivBase64: string
): Promise<ArrayBuffer> {
  const encrypted = base64ToArrayBuffer(encryptedBase64);
  const iv = new Uint8Array(base64ToArrayBuffer(ivBase64));

  return deps.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted);
}

export async function generateAesGcmKey(deps: EphemeralCryptoDeps): Promise<CryptoKey> {
  return deps.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function exportAesKeyRawBase64(deps: EphemeralCryptoDeps, key: CryptoKey): Promise<string> {
  const exported = await deps.subtle.exportKey('raw', key);
  return arrayBufferToBase64(exported);
}

export async function importAesKeyRawBase64(deps: EphemeralCryptoDeps, keyBase64: string): Promise<CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(keyBase64);
  return deps.subtle.importKey('raw', keyBuffer, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function generateEcdhKeyPair(deps: EphemeralCryptoDeps): Promise<CryptoKeyPair> {
  return deps.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
}

export async function exportEcdhPublicKeySpkiBase64(deps: EphemeralCryptoDeps, publicKey: CryptoKey): Promise<string> {
  const exported = await deps.subtle.exportKey('spki', publicKey);
  return arrayBufferToBase64(exported);
}

export async function importEcdhPublicKeySpkiBase64(deps: EphemeralCryptoDeps, publicKeyBase64: string): Promise<CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(publicKeyBase64);
  return deps.subtle.importKey('spki', keyBuffer, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
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
  const exported = await deps.subtle.exportKey('raw', publicKey);
  const hash = await deps.subtle.digest('SHA-256', exported);
  const hashArray = Array.from(new Uint8Array(hash));
  const fingerprint = hashArray
    .slice(0, 16)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return fingerprint.toUpperCase();
}
