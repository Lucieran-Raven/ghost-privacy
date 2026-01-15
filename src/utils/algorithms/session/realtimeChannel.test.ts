import { describe, expect, it } from 'vitest';
import { deriveRealtimeChannelName } from './realtimeChannel';

const deps = { subtle: crypto.subtle };

describe('deriveRealtimeChannelName', () => {
  it('is deterministic for same inputs', async () => {
    const a = await deriveRealtimeChannelName(deps, 'GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaa');
    const b = await deriveRealtimeChannelName(deps, 'GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaa');
    expect(a).toBe(b);
  });

  it('changes when token changes', async () => {
    const a = await deriveRealtimeChannelName(deps, 'GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaa');
    const b = await deriveRealtimeChannelName(deps, 'GHOST-ABCD-1234', 'bbbbbbbbbbbbbbbb');
    expect(a).not.toBe(b);
  });

  it('changes when sessionId changes', async () => {
    const a = await deriveRealtimeChannelName(deps, 'GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaa');
    const b = await deriveRealtimeChannelName(deps, 'GHOST-EEEE-9999', 'aaaaaaaaaaaaaaaa');
    expect(a).not.toBe(b);
  });

  it('does not embed the sessionId (metadata leak prevention)', async () => {
    const name = await deriveRealtimeChannelName(deps, 'GHOST-ABCD-1234', 'aaaaaaaaaaaaaaaa');
    expect(name.startsWith('ghost-session-')).toBe(true);
    expect(/^ghost-session-[a-f0-9]{32}$/.test(name)).toBe(true);
    expect(name.includes('GHOST-')).toBe(false);
  });
});
