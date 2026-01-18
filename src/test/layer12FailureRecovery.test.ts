import { describe, expect, it, vi } from 'vitest';

import fs from 'node:fs';
import path from 'node:path';

const invokeMock = vi.fn();

vi.mock('@/integrations/supabase/publicClient', () => {
  return {
    supabase: {
      functions: {
        invoke: invokeMock
      }
    }
  };
});

describe('layer 12 failure/recovery/degradation', () => {
  it('SessionService.reserveSession does not leak underlying error messages', async () => {
    invokeMock.mockResolvedValueOnce({
      data: null,
      error: { message: 'DB: relation does not exist; stacktrace...' }
    });

    const { SessionService } = await import('@/lib/sessionService');

    const result = await SessionService.reserveSession('GHOST-ABCD-1234');

    expect(result.success).toBe(false);
    expect(result.error).not.toContain('relation');
    expect(result.error).not.toContain('stack');
  });

  it('RealtimeManager backoff is deterministic (no jitter/randomInt) and errors are uniform', () => {
    const file = path.resolve(process.cwd(), 'src', 'lib', 'realtimeManager.ts');
    const raw = fs.readFileSync(file, 'utf8');

    expect(raw).not.toContain('randomInt(401)');
    expect(raw).not.toContain('Channel failed:');
    expect(raw).not.toContain('Connection timeout');
  });
});
