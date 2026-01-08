import { describe, expect, it } from 'vitest';
import { DeniableEncryption } from './deniable';
import { base64ToBytes, bytesToBase64 } from '@/utils/algorithms/encoding/base64';

describe('deniable.decryptHiddenFile', () => {
  it(
    'decrypts decoy content with outer password and real content with inner password',
    async () => {
      let ctr = 0;
      const deps = {
        subtle: crypto.subtle,
        pbkdf2Iterations: 5_000,
        getRandomValues: <T extends ArrayBufferView>(arr: T): T => {
          const u8 = new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
          for (let i = 0; i < u8.length; i++) {
            u8[i] = ctr & 0xff;
            ctr = (ctr + 1) >>> 0;
          }
          return arr;
        }
      };

      const packed = await DeniableEncryption.createHiddenFile(deps, 'REAL', 'DECOY', 'outer', 'inner');

      const asOuter = await DeniableEncryption.decryptHiddenFile(deps, packed, 'outer');
      expect(asOuter).not.toBe(null);
      expect(asOuter?.isDecoy).toBe(true);
      expect(asOuter?.content).toBe('DECOY');

      const asInner = await DeniableEncryption.decryptHiddenFile(deps, packed, 'inner');
      expect(asInner).not.toBe(null);
      expect(asInner?.isDecoy).toBe(false);
      expect(asInner?.content).toBe('REAL');
    },
    20_000
  );

  it(
    'returns null for a tampered container (no throw)',
    async () => {
      let ctr = 0;
      const deps = {
        subtle: crypto.subtle,
        pbkdf2Iterations: 5_000,
        getRandomValues: <T extends ArrayBufferView>(arr: T): T => {
          const u8 = new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
          for (let i = 0; i < u8.length; i++) {
            u8[i] = ctr & 0xff;
            ctr = (ctr + 1) >>> 0;
          }
          return arr;
        }
      };

      const packed = await DeniableEncryption.createHiddenFile(deps, 'REAL', 'DECOY', 'outer', 'inner');
      const bytes = base64ToBytes(packed);
      bytes[100] = bytes[100] ^ 0xff;
      const tampered = bytesToBase64(bytes);

      const out = await DeniableEncryption.decryptHiddenFile(deps, tampered, 'outer');
      expect(out).toBe(null);
    },
    20_000
  );

  it('rejects oversized base64 input without attempting to decode', async () => {
    const deps = {
      subtle: crypto.subtle,
      getRandomValues: crypto.getRandomValues.bind(crypto)
    };

    const containerSizeBytes = 10 * 1024 * 1024;
    const expectedLen = 4 * Math.ceil(containerSizeBytes / 3);
    const oversized = 'A'.repeat(expectedLen + 2048);

    const result = await DeniableEncryption.decryptHiddenFile(deps, oversized, 'pw');
    expect(result).toBe(null);
  });
});
