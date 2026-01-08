import { describe, expect, it } from 'vitest';
import { generateGhostId, isValidGhostId } from './ephemeral';

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
