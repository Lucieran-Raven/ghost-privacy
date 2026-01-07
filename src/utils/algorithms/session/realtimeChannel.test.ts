import { describe, expect, it } from 'vitest';
import { deriveRealtimeChannelName } from './realtimeChannel';

describe('deriveRealtimeChannelName', () => {
  it('is deterministic for same inputs', async () => {
    const a = await deriveRealtimeChannelName('GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaa');
    const b = await deriveRealtimeChannelName('GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaa');
    expect(a).toBe(b);
  });

  it('changes when token changes', async () => {
    const a = await deriveRealtimeChannelName('GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaa');
    const b = await deriveRealtimeChannelName('GHOST-ABCD-1234', 'bbbbbbbbbbbbbbbb');
    expect(a).not.toBe(b);
  });

  it('changes when sessionId changes', async () => {
    const a = await deriveRealtimeChannelName('GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaa');
    const b = await deriveRealtimeChannelName('GHOST-EEEE-9999', 'aaaaaaaaaaaaaaaa');
    expect(a).not.toBe(b);
  });

  it('includes the sessionId for debuggability while still being unguessable', async () => {
    const name = await deriveRealtimeChannelName('GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaa');
    expect(name.startsWith('ghost-session-GHOST-ABCD-1234-')).toBe(true);
  });
});
