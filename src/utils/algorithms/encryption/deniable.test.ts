import { describe, expect, it } from 'vitest';
import { DeniableEncryption } from './deniable';

describe('deniable.decryptHiddenFile', () => {
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
