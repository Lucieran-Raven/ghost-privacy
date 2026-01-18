import { describe, expect, it, vi } from 'vitest';
import { RealtimeManager } from './realtimeManager';

describe('RealtimeManager replay suppression', () => {
  it('rejects duplicate (senderId, nonce) within TTL window', () => {
    const rm = new RealtimeManager('GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaaaaaaaa', 'me');

    const payload = {
      type: 'chat-message',
      senderId: 'peer',
      data: { encrypted: 'x', iv: 'y' },
      timestamp: Date.now(),
      nonce: 'n1'
    };

    expect((rm as any).shouldAcceptIncoming(payload)).toBe(true);
    expect((rm as any).shouldAcceptIncoming(payload)).toBe(false);
  });

  it('accepts same (senderId, nonce) after TTL expiry', () => {
    const rm = new RealtimeManager('GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaaaaaaaa', 'me');

    const baseTime = 1_700_000_000_000;
    const nowSpy = vi.spyOn(Date, 'now');
    nowSpy.mockReturnValue(baseTime);

    const payload = {
      type: 'chat-message',
      senderId: 'peer',
      data: { encrypted: 'x', iv: 'y' },
      timestamp: baseTime,
      nonce: 'n1'
    };

    expect((rm as any).shouldAcceptIncoming(payload)).toBe(true);
    expect((rm as any).shouldAcceptIncoming(payload)).toBe(false);

    nowSpy.mockReturnValue(baseTime + 11 * 60 * 1000);
    payload.timestamp = baseTime + 11 * 60 * 1000;
    expect((rm as any).shouldAcceptIncoming(payload)).toBe(true);

    nowSpy.mockRestore();
  });

  it('accepts same nonce from different senderId', () => {
    const rm = new RealtimeManager('GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaaaaaaaa', 'me');

    const p1 = { type: 'chat-message', senderId: 'peerA', data: {}, timestamp: Date.now(), nonce: 'n1' };
    const p2 = { type: 'chat-message', senderId: 'peerB', data: {}, timestamp: Date.now(), nonce: 'n1' };

    expect((rm as any).shouldAcceptIncoming(p1)).toBe(true);
    expect((rm as any).shouldAcceptIncoming(p2)).toBe(true);
  });

  it('rejects malformed nonce inputs (whitespace / oversized)', () => {
    const rm = new RealtimeManager('GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaaaaaaaa', 'me');
    const baseTime = Date.now();

    const payloadBase = {
      type: 'chat-message',
      senderId: 'peer',
      data: { encrypted: 'x', iv: 'y' },
      timestamp: baseTime,
      nonce: 'n1'
    };

    expect((rm as any).shouldAcceptIncoming({ ...payloadBase, nonce: 'n 1' })).toBe(false);
    expect((rm as any).shouldAcceptIncoming({ ...payloadBase, nonce: 'n\n1' })).toBe(false);
    expect((rm as any).shouldAcceptIncoming({ ...payloadBase, nonce: 'a'.repeat(257) })).toBe(false);
  });

  it('rejects payloads with timestamps too far in the past/future', () => {
    const rm = new RealtimeManager('GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaaaaaaaa', 'me');
    const baseTime = 1_700_000_000_000;
    const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(baseTime);

    const p = {
      type: 'chat-message',
      senderId: 'peer',
      data: { encrypted: 'x', iv: 'y' },
      timestamp: baseTime,
      nonce: 'n1'
    };

    expect((rm as any).shouldAcceptIncoming(p)).toBe(true);
    expect((rm as any).shouldAcceptIncoming({ ...p, nonce: 'n2', timestamp: baseTime - 16 * 60 * 1000 })).toBe(false);
    expect((rm as any).shouldAcceptIncoming({ ...p, nonce: 'n3', timestamp: baseTime + 16 * 60 * 1000 })).toBe(false);

    nowSpy.mockRestore();
  });

  it('rejects oversized incoming payloads (DoS prevention)', () => {
    const rm = new RealtimeManager('GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaaaaaaaa', 'me');
    const baseTime = Date.now();

    const huge = 'x'.repeat(300_000);
    const p = {
      type: 'chat-message',
      senderId: 'peer',
      data: { encrypted: huge, iv: 'y' },
      timestamp: baseTime,
      nonce: 'n1'
    };

    expect((rm as any).shouldAcceptIncoming(p)).toBe(false);
  });

  it('rejects non-stringifiable payloads for non-chat types', () => {
    const rm = new RealtimeManager('GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaaaaaaaa', 'me');
    const baseTime = Date.now();

    const circular: any = { a: 1 };
    circular.self = circular;

    const p = {
      type: 'file',
      senderId: 'peer',
      data: circular,
      timestamp: baseTime,
      nonce: 'n1'
    };

    expect((rm as any).shouldAcceptIncoming(p)).toBe(false);
  });

  it('caps replay-cache size (attack simulation: many unique nonces)', () => {
    const rm = new RealtimeManager('GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaaaaaaaa', 'me');
    const baseTime = 1_700_000_000_000;
    const nowSpy = vi.spyOn(Date, 'now').mockReturnValue(baseTime);

    for (let i = 0; i < 4100; i++) {
      expect(
        (rm as any).shouldAcceptIncoming({
          type: 'chat-message',
          senderId: 'peer',
          data: { encrypted: 'x', iv: 'y' },
          timestamp: baseTime,
          nonce: `n${i}`
        })
      ).toBe(true);
    }

    expect(((rm as any).seenIncoming as Map<string, number>).size).toBeLessThanOrEqual(4096);

    nowSpy.mockRestore();
  });
});

describe('RealtimeManager sealed padded-frame v2', () => {
  it('pads to a minimum 8-frame power-of-two bucket with fixed-size frame strings', async () => {
    const rm = new RealtimeManager('GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaaaaaaaa', 'me');

    const inner = {
      type: 'typing',
      senderId: 'me',
      data: { isTyping: true },
      timestamp: Date.now(),
      nonce: 'mid-1'
    };

    const frames = await (rm as any).toPaddedFrames(inner);

    expect(Array.isArray(frames)).toBe(true);
    expect(frames.length).toBeGreaterThanOrEqual(8);
    expect((frames.length & (frames.length - 1)) === 0).toBe(true);

    for (const f of frames) {
      expect(f.type).toBe('padded-frame');
      expect(typeof f.data?.p).toBe('string');
      expect(f.data.p.length).toBe(1024);

      const len = Number.parseInt(String(f.data.p).slice(0, 6), 10);
      const innerJson = String(f.data.p).slice(6, 6 + len);
      const meta = JSON.parse(innerJson);
      expect(meta.v).toBe(2);
      expect(meta.total).toBe(frames.length);
      expect(typeof meta.iv).toBe('string');
      expect(meta.iv.length).toBe(16);
      expect(typeof meta.chunk).toBe('string');
      expect(meta.chunk.length).toBe(512);
    }
  });

  it('decrypts and dispatches the original inner payload once all frames arrive', async () => {
    const sessionId = 'GHOST-ABCD-1234';
    const channelToken = 'aaaaaaaaaaaaaaaaaaaaaa';

    const sender = new RealtimeManager(sessionId, channelToken, 'me');
    const receiver = new RealtimeManager(sessionId, channelToken, 'peer');

    const handler = vi.fn();
    receiver.onMessage('chat-message', handler);

    const inner = {
      type: 'chat-message',
      senderId: 'me',
      data: { encrypted: 'ciphertext', iv: 'iv', sequence: 1, type: 'text' },
      timestamp: Date.now(),
      nonce: 'msg-123'
    };

    const frames = await (sender as any).toPaddedFrames(inner);
    for (const f of frames) {
      await (receiver as any).handleIncomingPaddedFrame(f);
    }

    expect(handler).toHaveBeenCalledTimes(1);
    const delivered = handler.mock.calls[0]?.[0];
    expect(delivered.type).toBe('chat-message');
    expect(delivered.senderId).toBe('me');
    expect(delivered.nonce).toBe('msg-123');
    expect(delivered.data.encrypted).toBe('ciphertext');
  });
});
