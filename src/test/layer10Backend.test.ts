import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

function listFiles(dir: string): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const out: string[] = [];
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...listFiles(p));
    else out.push(p);
  }
  return out;
}

describe('layer10 backend/database invariants', () => {
  it('derives rate-limit keys per-action and per-window in edge functions', () => {
    const root = path.resolve(process.cwd(), 'supabase', 'functions');
    const files = listFiles(root).filter((f) => f.endsWith('.ts'));

    const violations: string[] = [];

    for (const file of files) {
      const rel = path.relative(process.cwd(), file);
      const raw = fs.readFileSync(file, 'utf8');

      if (raw.includes('getRateLimitKeyHex(req, windowStartIso')) {
        violations.push(rel);
        continue;
      }

      if (/getRateLimitKeyHex\(\s*req\s*,\s*windowStartIso\s*\)/.test(raw)) {
        violations.push(rel);
      }

      if (/getRateLimitKeyHex\(\s*req\s*,\s*[^,\)]+\s*\)/.test(raw)) {
        violations.push(rel);
      }
    }

    expect(violations).toEqual([]);
  });

  it('uses hash-only session identifiers in edge functions (no raw sessionId in DB filters/inserts)', () => {
    const root = path.resolve(process.cwd(), 'supabase', 'functions');
    const files = listFiles(root)
      .filter((f) => f.endsWith('.ts'))
      .filter((f) => !f.includes(`${path.sep}_shared${path.sep}`));

    const violations: Array<{ file: string; needle: string }> = [];

    for (const file of files) {
      const rel = path.relative(process.cwd(), file);
      const raw = fs.readFileSync(file, 'utf8');

      if (/\.eq\(\s*['\"]session_id['\"]\s*,\s*sessionId\s*\)/.test(raw)) {
        violations.push({ file: rel, needle: ".eq('session_id', sessionId)" });
      }

      if (/session_id\s*:\s*sessionId\b/.test(raw)) {
        violations.push({ file: rel, needle: 'session_id: sessionId' });
      }

      if (/\.eq\(\s*['\"]session_id['\"]\s*,\s*body\.sessionId\s*\)/.test(raw)) {
        violations.push({ file: rel, needle: ".eq('session_id', body.sessionId)" });
      }
    }

    expect(violations).toEqual([]);
  });

  it('includes a migration to enforce sha256-hex session_id storage', () => {
    const root = path.resolve(process.cwd(), 'supabase', 'migrations');
    const files = listFiles(root).filter((f) => f.endsWith('.sql'));

    const needle = 'ghost_sessions_session_id_sha256_hex_chk';
    const has = files.some((file) => fs.readFileSync(file, 'utf8').includes(needle));
    expect(has).toBe(true);
  });

  it('does not store raw IP address fields in migrations (hash-only identifiers)', () => {
    const root = path.resolve(process.cwd(), 'supabase', 'migrations');
    const files = listFiles(root).filter((f) => f.endsWith('.sql'));

    const banned: Array<{ name: string; re: RegExp }> = [
      { name: 'ip_address', re: /\bip_address\b/i },
      { name: 'client_ip', re: /\bclient_ip\b/i },
      { name: 'remote_addr', re: /\bremote_addr\b/i },
      { name: 'x_forwarded_for', re: /\bx_forwarded_for\b/i },
      { name: 'user_agent', re: /\buser_agent\b/i },
    ];

    const violations: Array<{ file: string; needle: string }> = [];

    for (const file of files) {
      const rel = path.relative(process.cwd(), file);
      const raw = fs.readFileSync(file, 'utf8');
      for (const b of banned) {
        if (b.re.test(raw)) {
          violations.push({ file: rel, needle: b.name });
        }
      }
    }

    expect(violations).toEqual([]);
  });
});
