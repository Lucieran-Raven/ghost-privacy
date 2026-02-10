// Deniable File Encryption - VeraCrypt-style hidden volumes
// Two-key system: outer key shows decoy, inner key reveals real content

import {
  DeniableEncryption as DeniableEncryptionAlgorithm,
  generateDecoyContent as generateDecoyContentAlgorithm,
  type DeniableCryptoDeps
} from '@/utils/algorithms/encryption/deniable';

const deps: DeniableCryptoDeps = {
  subtle: crypto.subtle,
  getRandomValues: crypto.getRandomValues.bind(crypto)
};

export class DeniableEncryption {
  /**
   * Create a hidden volume with two layers:
   * - Outer layer: decoy content (shown with wrong password)
   * - Inner layer: real content (shown with correct password)
   */
  static async createHiddenVolume(
    realContent: string,
    decoyContent: string,
    outerPassword: string,
    innerPassword: string
  ): Promise<string> {
    return DeniableEncryptionAlgorithm.createHiddenVolume(
      deps,
      realContent,
      decoyContent,
      outerPassword,
      innerPassword
    );
  }

  /**
   * Attempt to decrypt hidden volume
   * Returns decoy if outer password, real content if inner password
   * Returns null if neither password works
   */
  static async decryptHiddenVolume(
    packedData: string,
    password: string
  ): Promise<{ content: string; isDecoy: boolean } | null> {
    return DeniableEncryptionAlgorithm.decryptHiddenVolume(deps, packedData, password);
  }

  /**
   * Create a hidden file (wraps file data in hidden volume)
   */
  static async createHiddenFile(
    realFileBase64: string,
    decoyFileBase64: string,
    outerPassword: string,
    innerPassword: string
  ): Promise<string> {
    return DeniableEncryptionAlgorithm.createHiddenFile(
      deps,
      realFileBase64,
      decoyFileBase64,
      outerPassword,
      innerPassword
    );
  }

  /**
   * Decrypt a hidden file
   */
  static async decryptHiddenFile(
    packedData: string,
    password: string
  ): Promise<{ content: string; isDecoy: boolean } | null> {
    return DeniableEncryptionAlgorithm.decryptHiddenFile(deps, packedData, password);
  }
}

// Generate secure decoy content based on file type
export function generateDecoyContent(fileType: string): string {
  const randomInt = (maxExclusive: number): number => {
    if (!Number.isFinite(maxExclusive) || maxExclusive <= 0) return 0;
    const max = Math.floor(maxExclusive);
    if (max <= 1) return 0;

    const limit = Math.floor(0x100000000 / max) * max;
    const buf = new Uint32Array(1);
    while (true) {
      crypto.getRandomValues(buf);
      const v = buf[0];
      if (v < limit) return v % max;
    }
  };

  return generateDecoyContentAlgorithm(fileType, randomInt);
}
