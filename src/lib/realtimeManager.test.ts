import { describe, expect, it } from 'vitest';
import { RealtimeManager } from './realtimeManager';

describe('RealtimeManager replay suppression', () => {
  it('rejects duplicate (senderId, nonce) within TTL window', () => {
    const rm = new RealtimeManager('GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaa', 'me');

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

  it('accepts same nonce from different senderId', () => {
    const rm = new RealtimeManager('GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaa', 'me');

    const p1 = { type: 'chat-message', senderId: 'peerA', data: {}, timestamp: Date.now(), nonce: 'n1' };
    const p2 = { type: 'chat-message', senderId: 'peerB', data: {}, timestamp: Date.now(), nonce: 'n1' };

    expect((rm as any).shouldAcceptIncoming(p1)).toBe(true);
    expect((rm as any).shouldAcceptIncoming(p2)).toBe(true);
  });
});
