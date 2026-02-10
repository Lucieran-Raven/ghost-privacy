import { describe, expect, it } from 'vitest';
import { decryptAudioChunk, encryptAudioChunk } from './voice';
import { base64ToBytes } from '../encoding/base64';

describe('voice encryption', () => {
  it('encrypts chunks with unique IVs', async () => {
    let ctr = 0;
    const deps = {
      subtle: crypto.subtle,
      now: () => 1234567890,
      getRandomValues: <T extends ArrayBufferView>(arr: T): T => {
        const u8 = new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
        for (let i = 0; i < u8.length; i++) u8[i] = (ctr++ & 0xff);
        return arr;
      }
    };

    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const chunk = new TextEncoder().encode('chunk-data').buffer;

    const c0 = await encryptAudioChunk(deps, chunk, key, 0);
    const c1 = await encryptAudioChunk(deps, chunk, key, 1);

    expect(c0.iv).not.toBe(c1.iv);

    const iv0 = base64ToBytes(c0.iv);
    const iv1 = base64ToBytes(c1.iv);
    expect(iv0.byteLength).toBe(12);
    expect(iv1.byteLength).toBe(12);
  });

  it('roundtrips chunk when timestamp and chunkIndex match AAD', async () => {
    const deps = {
      subtle: crypto.subtle,
      now: () => 424242,
      getRandomValues: crypto.getRandomValues.bind(crypto)
    };

    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const plaintext = new TextEncoder().encode('hello-voice').buffer;

    const enc = await encryptAudioChunk(deps, plaintext, key, 7);
    const dec = await decryptAudioChunk({ subtle: crypto.subtle }, enc.encrypted, enc.iv, key, 7, 424242);

    expect(new TextDecoder().decode(dec)).toBe('hello-voice');
  });

  it('fails decryption when timestamp differs (AAD mismatch)', async () => {
    const deps = {
      subtle: crypto.subtle,
      now: () => 111,
      getRandomValues: crypto.getRandomValues.bind(crypto)
    };

    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const plaintext = new TextEncoder().encode('hello-voice').buffer;

    const enc = await encryptAudioChunk(deps, plaintext, key, 1);

    await expect(
      decryptAudioChunk({ subtle: crypto.subtle }, enc.encrypted, enc.iv, key, 1, 222)
    ).rejects.toBeTruthy();
  });
});
