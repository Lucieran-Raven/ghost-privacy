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
