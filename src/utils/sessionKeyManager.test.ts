import { describe, expect, it } from 'vitest';
import { destroySessionKeyManager, getSessionKeyManager } from './sessionKeyManager';
import { generateEcdhKeyPair } from './algorithms/encryption/ephemeral';

describe('sessionKeyManager', () => {
  it('rejects extractable encryption keys', async () => {
    const mgr = getSessionKeyManager();
    const sessionId = 'GHOST-AAAA-BBBB';

    const extractableKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    expect(() => mgr.setEncryptionKey(sessionId, extractableKey)).toThrow(/non-extractable/i);

    destroySessionKeyManager();
  });

  it('accepts non-extractable encryption keys', async () => {
    const mgr = getSessionKeyManager();
    const sessionId = 'GHOST-CCCC-DDDD';

    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    expect(() => mgr.setEncryptionKey(sessionId, key)).not.toThrow();

    destroySessionKeyManager();
  });

  it('rejects keyPairs with extractable private key', async () => {
    const mgr = getSessionKeyManager();
    const sessionId = 'GHOST-EEEE-FFFF';

    const badKeyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
    expect(() => mgr.setKeyPair(sessionId, badKeyPair)).toThrow(/non-extractable/i);

    destroySessionKeyManager();
  });

  it('accepts keyPairs with non-extractable private key (ephemeral.generateEcdhKeyPair)', async () => {
    const mgr = getSessionKeyManager();
    const sessionId = 'GHOST-GGGG-HHHH';

    const deps = { subtle: crypto.subtle, getRandomValues: crypto.getRandomValues.bind(crypto) };
    const keyPair = await generateEcdhKeyPair(deps);
    expect(keyPair.privateKey.extractable).toBe(false);

    expect(() => mgr.setKeyPair(sessionId, keyPair)).not.toThrow();

    destroySessionKeyManager();
  });
});
