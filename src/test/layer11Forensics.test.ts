import { describe, expect, it } from 'vitest';

import { SecurityManager } from '@/utils/security';
import { nuclearPurgeAll } from '@/utils/memory/lifecycle';

function validSessionId(): string {
  return 'GHOST-ABCD-1234';
}

function validToken(): string {
  return 'AAAAAAAAAAAAAAAAAAAAAA';
}

describe('layer 11 memory/logs/forensics', () => {
  it('nuclearPurgeAll clears in-memory capability tokens', () => {
    const sessionId = validSessionId();
    const token = validToken();

    SecurityManager.setHostToken(sessionId, token);
    expect(SecurityManager.getHostToken(sessionId)).toBe(token);

    nuclearPurgeAll();

    expect(SecurityManager.getHostToken(sessionId)).toBeNull();
  });
});
