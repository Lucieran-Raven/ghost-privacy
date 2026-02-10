import { describe, expect, it } from 'vitest';
import { constantTimeEqualBytes, constantTimeEqualString } from './constantTime';

describe('constantTimeEqualString', () => {
  it('returns true for equal strings', () => {
    expect(constantTimeEqualString('abc', 'abc')).toBe(true);
  });

  it('returns false for different strings (same length)', () => {
    expect(constantTimeEqualString('abc', 'abd')).toBe(false);
  });

  it('returns false for different lengths', () => {
    expect(constantTimeEqualString('abc', 'abcd')).toBe(false);
    expect(constantTimeEqualString('', 'a')).toBe(false);
  });
});

describe('constantTimeEqualBytes', () => {
  it('returns true for equal byte arrays', () => {
    expect(constantTimeEqualBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
  });

  it('returns false for different byte arrays (same length)', () => {
    expect(constantTimeEqualBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
  });

  it('returns false for different lengths', () => {
    expect(constantTimeEqualBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3, 4]))).toBe(false);
    expect(constantTimeEqualBytes(new Uint8Array([]), new Uint8Array([0]))).toBe(false);
  });
});
