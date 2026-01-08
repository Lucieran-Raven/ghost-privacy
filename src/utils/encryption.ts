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
import { base64ToBytes, bytesToBase64 } from '@/utils/algorithms/encoding/base64';
import { isTauriRuntime, tauriInvoke } from '@/utils/runtime';

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
        const plaintextBase64 = bytesToBase64(bytes);
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
        const bytes = base64ToBytes(plaintextBase64);
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
