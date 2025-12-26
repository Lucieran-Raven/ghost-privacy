// Military-grade encryption engine using Web Crypto API
// AES-256-GCM for symmetric encryption, ECDH P-256 for key exchange

export class EncryptionEngine {
  private key: CryptoKey | null = null;

  static async generateKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  async initialize(key?: CryptoKey): Promise<void> {
    this.key = key || await EncryptionEngine.generateKey();
  }

  async setKey(key: CryptoKey): Promise<void> {
    this.key = key;
  }

  async encryptMessage(message: string): Promise<{ encrypted: string; iv: string }> {
    if (!this.key) throw new Error('Encryption key not initialized');

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(message);

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      this.key,
      encoded
    );

    return {
      encrypted: arrayBufferToBase64(encrypted),
      iv: arrayBufferToBase64(iv.buffer)
    };
  }

  async decryptMessage(encryptedBase64: string, ivBase64: string): Promise<string> {
    if (!this.key) throw new Error('Encryption key not initialized');

    const encrypted = base64ToArrayBuffer(encryptedBase64);
    const ivBuffer = base64ToArrayBuffer(ivBase64);
    const iv = new Uint8Array(ivBuffer);

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      this.key,
      encrypted
    );

    return new TextDecoder().decode(decrypted);
  }

  async exportKey(): Promise<string> {
    if (!this.key) throw new Error('Encryption key not initialized');
    const exported = await crypto.subtle.exportKey('raw', this.key);
    return arrayBufferToBase64(exported);
  }

  static async importKey(keyBase64: string): Promise<CryptoKey> {
    const keyBuffer = base64ToArrayBuffer(keyBase64);
    return crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }
}

// ECDH Key Exchange for establishing shared secrets
export class KeyExchange {
  static async generateKeyPair(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey']
    );
  }

  static async exportPublicKey(publicKey: CryptoKey): Promise<string> {
    const exported = await crypto.subtle.exportKey('spki', publicKey);
    return arrayBufferToBase64(exported);
  }

  static async importPublicKey(publicKeyBase64: string): Promise<CryptoKey> {
    const keyBuffer = base64ToArrayBuffer(publicKeyBase64);
    return crypto.subtle.importKey(
      'spki',
      keyBuffer,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    );
  }

  static async deriveSharedSecret(
    privateKey: CryptoKey,
    publicKey: CryptoKey
  ): Promise<CryptoKey> {
    return crypto.subtle.deriveKey(
      { name: 'ECDH', public: publicKey },
      privateKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  // Generate 16-character fingerprint from public key for MITM verification
  static async generateFingerprint(publicKey: CryptoKey): Promise<string> {
    const exported = await crypto.subtle.exportKey('raw', publicKey);
    const hash = await crypto.subtle.digest('SHA-256', exported);
    const hashArray = Array.from(new Uint8Array(hash));
    // Take first 8 bytes (16 hex characters) for display - SECURITY FIX: Extended from 4 to 8 bytes
    const fingerprint = hashArray.slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
    return fingerprint.toUpperCase();
  }
}

// Utility functions
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
  // Return a slice to ensure we get an ArrayBuffer of exact size
  return bytes.buffer.slice(0, bytes.byteLength);
}

// Generate cryptographically secure Ghost ID
export const generateGhostId = (): string => {
  const array = new Uint8Array(8);
  crypto.getRandomValues(array);
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const part1 = Array.from(array.slice(0, 4))
    .map(b => chars[b % chars.length]).join('');
  const part2 = Array.from(array.slice(4, 8))
    .map(b => chars[b % chars.length]).join('');
  return `GHOST-${part1}-${part2}`;
};

// Validate Ghost ID format
export const isValidGhostId = (id: string): boolean => {
  return /^GHOST-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(id);
};

// Generate message nonce for uniqueness
export const generateNonce = (): string => {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return arrayBufferToBase64(array.buffer);
};
