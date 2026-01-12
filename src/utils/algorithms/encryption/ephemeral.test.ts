import { describe, expect, it } from 'vitest';
import {
  aesGcmDecryptString,
  aesGcmEncryptString,
  deriveSharedSecretBytes,
  exportAesKeyRawBase64,
  exportEcdhPublicKeySpkiBase64,
  generateAesGcmKey,
  generateEcdhKeyPair,
  generateFingerprintHex,
  generateGhostId,
  importAesKeyRawBase64,
  importEcdhPublicKeySpkiBase64,
  isValidGhostId
} from './ephemeral';

describe('ephemeral.generateGhostId', () => {
  it('generates a valid ID even under worst-case rejection sampling', () => {
    const deps = {
      subtle: crypto.subtle,
      getRandomValues: <T extends ArrayBufferView>(arr: T): T => {
        const u8 = new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
        u8.fill(255);
        return arr;
      }
    };

    const id = generateGhostId(deps);
    expect(isValidGhostId(id)).toBe(true);
    expect(id).toBe('GHOST-DDDD-DDDD');
  });
});

describe('ephemeral.aesGcmEncryptString/aesGcmDecryptString', () => {
  it('roundtrips plaintext', async () => {
    const deps = { subtle: crypto.subtle, getRandomValues: crypto.getRandomValues.bind(crypto) };
    const key = await generateAesGcmKey(deps, false);

    const message = 'hello-world';
    const enc = await aesGcmEncryptString(deps, key, message);
    const dec = await aesGcmDecryptString(deps, key, enc.encrypted, enc.iv);
    expect(dec).toBe(message);
  });

  it('rejects tampered ciphertext', async () => {
    const deps = { subtle: crypto.subtle, getRandomValues: crypto.getRandomValues.bind(crypto) };
    const key = await generateAesGcmKey(deps, false);

    const enc = await aesGcmEncryptString(deps, key, 'hello');
    const tampered = enc.encrypted.slice(0, -2) + (enc.encrypted.endsWith('A=') ? 'B=' : 'A=');
    await expect(aesGcmDecryptString(deps, key, tampered, enc.iv)).rejects.toBeTruthy();
  });
});

describe('ephemeral.ECDH shared secret', () => {
  it('derives identical secret bytes for both parties', async () => {
    const deps = { subtle: crypto.subtle, getRandomValues: crypto.getRandomValues.bind(crypto) };
    const a = await generateEcdhKeyPair(deps);
    const b = await generateEcdhKeyPair(deps);

    const aPubB64 = await exportEcdhPublicKeySpkiBase64(deps, a.publicKey);
    const bPubB64 = await exportEcdhPublicKeySpkiBase64(deps, b.publicKey);

    const aPub = await importEcdhPublicKeySpkiBase64(deps, aPubB64);
    const bPub = await importEcdhPublicKeySpkiBase64(deps, bPubB64);

    const ab = new Uint8Array(await deriveSharedSecretBytes(deps, a.privateKey, bPub));
    const ba = new Uint8Array(await deriveSharedSecretBytes(deps, b.privateKey, aPub));

    expect(ab.byteLength).toBe(ba.byteLength);
    expect(Array.from(ab)).toEqual(Array.from(ba));
  });

  it('produces different shared secrets for different peer keys (forward secrecy property check)', async () => {
    const deps = { subtle: crypto.subtle, getRandomValues: crypto.getRandomValues.bind(crypto) };
    const a = await generateEcdhKeyPair(deps);
    const b1 = await generateEcdhKeyPair(deps);
    const b2 = await generateEcdhKeyPair(deps);

    const b1Pub = await importEcdhPublicKeySpkiBase64(deps, await exportEcdhPublicKeySpkiBase64(deps, b1.publicKey));
    const b2Pub = await importEcdhPublicKeySpkiBase64(deps, await exportEcdhPublicKeySpkiBase64(deps, b2.publicKey));

    const ab1 = new Uint8Array(await deriveSharedSecretBytes(deps, a.privateKey, b1Pub));
    const ab2 = new Uint8Array(await deriveSharedSecretBytes(deps, a.privateKey, b2Pub));

    expect(Array.from(ab1)).not.toEqual(Array.from(ab2));
  });
});

describe('ephemeral key import/export', () => {
  it('exports and re-imports AES key (extractable) for decryption', async () => {
    const deps = { subtle: crypto.subtle, getRandomValues: crypto.getRandomValues.bind(crypto) };
    const key = await generateAesGcmKey(deps, true);
    const rawB64 = await exportAesKeyRawBase64(deps, key);
    const key2 = await importAesKeyRawBase64(deps, rawB64, false);

    const enc = await aesGcmEncryptString(deps, key, 'abc');
    const dec = await aesGcmDecryptString(deps, key2, enc.encrypted, enc.iv);
    expect(dec).toBe('abc');
  });
});

describe('ephemeral.generateFingerprintHex', () => {
  it('returns uppercase hex with fixed length', async () => {
    const deps = { subtle: crypto.subtle, getRandomValues: crypto.getRandomValues.bind(crypto) };
    const kp = await generateEcdhKeyPair(deps);
    const fp = await generateFingerprintHex(deps, kp.publicKey);
    expect(fp).toMatch(/^[A-F0-9]{32}$/);
  });
});
