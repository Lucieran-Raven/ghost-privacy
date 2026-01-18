import { describe, expect, it } from 'vitest';
import { parseAccessCode } from './accessCode';

describe('parseAccessCode', () => {
  it('returns null for empty input', () => {
    expect(parseAccessCode('')).toBeNull();
    expect(parseAccessCode('   ')).toBeNull();
  });

  it('normalizes sessionId to uppercase', () => {
    const parsed = parseAccessCode('ghost-abcd-1234.aaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbb');
    expect(parsed).not.toBeNull();
    expect(parsed!.sessionId).toBe('GHOST-ABCD-1234');
  });

  it('rejects when token is missing', () => {
    expect(parseAccessCode('GHOST-ABCD-1234')).toBeNull();
    expect(parseAccessCode('GHOST-ABCD-1234.')).toBeNull();
    expect(parseAccessCode('GHOST-ABCD-1234.aaaaaaaaaaaaaaaaaaaaaa')).toBeNull();
    expect(parseAccessCode('GHOST-ABCD-1234.aaaaaaaaaaaaaaaaaaaaaa.')).toBeNull();
  });

  it('rejects invalid sessionId', () => {
    expect(parseAccessCode('NOTGHOST-ABCD-1234.aaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbb')).toBeNull();
  });
});
