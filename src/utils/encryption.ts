// Military-grade encryption engine using Web Crypto API
// AES-256-GCM for symmetric encryption, ECDH P-256 for key exchange

import {
  aesGcmDecryptBytes,
  aesGcmDecryptString,
  aesGcmEncryptBytes,
  aesGcmEncryptString,
  deriveSharedSecretAesGcmKey,
  deriveSharedSecretBytes,
  exportAesKeyRawBase64,
  exportEcdhPublicKeySpkiBase64,
  generateAesGcmKey,
  generateEcdhKeyPair,
  generateFingerprintHex,
  generateGhostId as generateGhostIdAlgorithm,
  generateNonce as generateNonceAlgorithm,
  importAesKeyRawBase64,
  importEcdhPublicKeySpkiBase64,
  isValidGhostId as isValidGhostIdAlgorithm,
  type EphemeralCryptoDeps
} from '@/utils/algorithms/encryption/ephemeral';
import { isTauriRuntime, tauriInvoke } from '@/utils/runtime';

function bytesToBase64(bytes: Uint8Array): string {
  const chunkSize = 0x8000;
  const chunks: string[] = [];
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const sub = bytes.subarray(i, i + chunkSize);
    chunks.push(String.fromCharCode.apply(null, sub as unknown as number[]));
  }
  return btoa(chunks.join(''));
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

const deps: EphemeralCryptoDeps = {
  subtle: crypto.subtle,
  getRandomValues: crypto.getRandomValues.bind(crypto)
};

export class EncryptionEngine {
  private key: CryptoKey | null = null;
  private tauriSessionId: string | null = null;

  static async generateKey(): Promise<CryptoKey> {
    return generateAesGcmKey(deps);
  }

  async initialize(key?: CryptoKey): Promise<void> {
    this.key = key || await EncryptionEngine.generateKey();
  }

  async setKey(key: CryptoKey): Promise<void> {
    this.key = key;
  }

  enableTauriVault(sessionId: string): void {
    this.tauriSessionId = sessionId;
  }

  async encryptMessage(message: string): Promise<{ encrypted: string; iv: string }> {
    if (this.tauriSessionId && isTauriRuntime()) {
      try {
        const res = await tauriInvoke<{ ciphertext: string; iv: string }>('vault_encrypt_utf8', {
          session_id: this.tauriSessionId,
          plaintext: message
        });
        return { encrypted: res.ciphertext, iv: res.iv };
      } catch {
        const bytes = new TextEncoder().encode(message);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        const plaintextBase64 = btoa(binary);
        const res = await tauriInvoke<{ ciphertext: string; iv: string }>('vault_encrypt', {
          session_id: this.tauriSessionId,
          plaintext_base64: plaintextBase64
        });
        return { encrypted: res.ciphertext, iv: res.iv };
      }
    }

    if (!this.key) throw new Error('Encryption key not initialized');
    return aesGcmEncryptString(deps, this.key, message);
  }

  async encryptBytes(plaintext: ArrayBuffer): Promise<{ encrypted: string; iv: string }> {
    if (this.tauriSessionId && isTauriRuntime()) {
      const bytes = new Uint8Array(plaintext);
      const plaintextBase64 = bytesToBase64(bytes);
      const res = await tauriInvoke<{ ciphertext: string; iv: string }>('vault_encrypt', {
        session_id: this.tauriSessionId,
        plaintext_base64: plaintextBase64
      });
      return { encrypted: res.ciphertext, iv: res.iv };
    }

    if (!this.key) throw new Error('Encryption key not initialized');
    return aesGcmEncryptBytes(deps, this.key, plaintext);
  }

  async decryptMessage(encryptedBase64: string, ivBase64: string): Promise<string> {
    if (this.tauriSessionId && isTauriRuntime()) {
      try {
        return await tauriInvoke<string>('vault_decrypt_utf8', {
          session_id: this.tauriSessionId,
          ciphertext_base64: encryptedBase64,
          iv_base64: ivBase64
        });
      } catch {
        const plaintextBase64 = await tauriInvoke<string>('vault_decrypt', {
          session_id: this.tauriSessionId,
          ciphertext_base64: encryptedBase64,
          iv_base64: ivBase64
        });
        const binary = atob(plaintextBase64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
          bytes[i] = binary.charCodeAt(i);
        }
        return new TextDecoder().decode(bytes);
      }
    }

    if (!this.key) throw new Error('Encryption key not initialized');
    return aesGcmDecryptString(deps, this.key, encryptedBase64, ivBase64);
  }

  async decryptBytes(encryptedBase64: string, ivBase64: string): Promise<ArrayBuffer> {
    if (this.tauriSessionId && isTauriRuntime()) {
      const plaintextBase64 = await tauriInvoke<string>('vault_decrypt', {
        session_id: this.tauriSessionId,
        ciphertext_base64: encryptedBase64,
        iv_base64: ivBase64
      });
      const bytes = base64ToBytes(plaintextBase64);
      return bytes.slice().buffer;
    }

    if (!this.key) throw new Error('Encryption key not initialized');
    return aesGcmDecryptBytes(deps, this.key, encryptedBase64, ivBase64);
  }

  async exportKey(): Promise<string> {
    throw new Error('Key export is disabled');
  }

  static async importKey(keyBase64: string): Promise<CryptoKey> {
    return importAesKeyRawBase64(deps, keyBase64);
  }
}

// ECDH Key Exchange for establishing shared secrets
export class KeyExchange {
  static async generateKeyPair(): Promise<CryptoKeyPair> {
    return generateEcdhKeyPair(deps);
  }

  static async exportPublicKey(publicKey: CryptoKey): Promise<string> {
    return exportEcdhPublicKeySpkiBase64(deps, publicKey);
  }

  static async importPublicKey(publicKeyBase64: string): Promise<CryptoKey> {
    return importEcdhPublicKeySpkiBase64(deps, publicKeyBase64);
  }

  static async deriveSharedSecret(
    privateKey: CryptoKey,
    publicKey: CryptoKey
  ): Promise<CryptoKey> {
    return deriveSharedSecretAesGcmKey(deps, privateKey, publicKey);
  }

  static async deriveSharedSecretBytes(
    privateKey: CryptoKey,
    publicKey: CryptoKey
  ): Promise<ArrayBuffer> {
    return deriveSharedSecretBytes(deps, privateKey, publicKey);
  }

// Generate 32-character fingerprint from public key for MITM verification
  // SECURITY FIX: Extended from 64-bit to 128-bit entropy for brute force resistance
  static async generateFingerprint(publicKey: CryptoKey): Promise<string> {
    return generateFingerprintHex(deps, publicKey);
  }
}

// Generate cryptographically secure Ghost ID
export const generateGhostId = (): string => {
  return generateGhostIdAlgorithm(deps);
};

// Validate Ghost ID format
export const isValidGhostId = (id: string): boolean => {
  return isValidGhostIdAlgorithm(id);
};

// Generate message nonce for uniqueness
export const generateNonce = (): string => {
  return generateNonceAlgorithm(deps);
};
