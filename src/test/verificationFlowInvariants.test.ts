import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

import { destroySessionKeyManager, getSessionKeyManager } from '@/utils/sessionKeyManager';
import { generateEcdhKeyPair } from '@/utils/algorithms/encryption/ephemeral';

function readUtf8(p: string): string {
  return fs.readFileSync(p, 'utf8');
}

function between(haystack: string, start: RegExp, end: RegExp): string {
  const s = haystack.search(start);
  if (s === -1) throw new Error('start not found');
  const afterStart = haystack.slice(s);
  const e = afterStart.search(end);
  if (e === -1) throw new Error('end not found');
  return afterStart.slice(0, e);
}

describe('Layer 9: constant-time structural guardrails', () => {
  it('constantTimeEqualString / constantTimeEqualBytes contain no early-return mismatch paths', () => {
    const repoRoot = process.cwd();
    const constantTimePath = path.join(repoRoot, 'src', 'utils', 'algorithms', 'integrity', 'constantTime.ts');
    const src = readUtf8(constantTimePath);

    const bytesBody = between(src, /export function constantTimeEqualBytes\(/, /export function constantTimeEqualString\(/);
    expect(bytesBody).toContain('for (let i = 0; i < len; i++)');
    expect(bytesBody).not.toMatch(/return\s+false/);
    expect(bytesBody).not.toMatch(/break\s*;/);

    const strBody = between(src, /export function constantTimeEqualString\(/, /}\s*$/);
    expect(strBody).toContain('for (let i = 0; i < len; i++)');
    expect(strBody).not.toMatch(/return\s+false/);
    expect(strBody).not.toMatch(/break\s*;/);
  });

  it('Supabase security helpers use timing-safe comparisons for auth and capability checks (static verification)', () => {
    const repoRoot = process.cwd();
    const securityPath = path.join(repoRoot, 'supabase', 'functions', '_shared', 'security.ts');
    const src = readUtf8(securityPath);

    expect(src).toMatch(/export function timingSafeEqualString\(/);
    expect(src).toMatch(/return timingSafeEqualBytes\(storedBytes, expectedBytes\)/);
    expect(src).toMatch(/!authHeader \|\| !timingSafeEqualString\(authHeader, expected\)/);
  });
});

describe('Layer 9: memory zeroization (sessionKeyManager)', () => {
  it('destroySession nullifies key references even if SessionKeyData object is retained', async () => {
    const mgr = getSessionKeyManager();
    const sessionId = 'GHOST-ZERO-0001';

    const encryptionKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    mgr.setEncryptionKey(sessionId, encryptionKey);

    const deps = { subtle: crypto.subtle, getRandomValues: crypto.getRandomValues.bind(crypto) };
    const keyPair = await generateEcdhKeyPair(deps);
    mgr.setKeyPair(sessionId, keyPair);
    mgr.setPartnerPublicKey(sessionId, keyPair.publicKey);

    const dataRef = (mgr as any).keys.get(sessionId);
    expect(dataRef).toBeTruthy();

    mgr.destroySession(sessionId);

    expect(mgr.hasSession(sessionId)).toBe(false);
    expect((mgr as any).keys.has(sessionId)).toBe(false);

    expect(dataRef.encryptionKey).toBeNull();
    expect(dataRef.keyPair).toBeNull();
    expect(dataRef.partnerPublicKey).toBeNull();
    expect(dataRef.sessionId).toBe('');
    expect(dataRef.createdAt).toBe(0);
    expect(dataRef.lastAccessedAt).toBe(0);

    destroySessionKeyManager();
  });

  it('nuclearPurge nullifies all session data and clears the map', async () => {
    const mgr = getSessionKeyManager();

    const deps = { subtle: crypto.subtle, getRandomValues: crypto.getRandomValues.bind(crypto) };

    const sessions = ['GHOST-ZERO-0002', 'GHOST-ZERO-0003'];
    const refs: any[] = [];

    for (const sessionId of sessions) {
      const encryptionKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
      mgr.setEncryptionKey(sessionId, encryptionKey);

      const keyPair = await generateEcdhKeyPair(deps);
      mgr.setKeyPair(sessionId, keyPair);
      mgr.setPartnerPublicKey(sessionId, keyPair.publicKey);

      refs.push((mgr as any).keys.get(sessionId));
    }

    mgr.nuclearPurge();

    expect((mgr as any).keys.size).toBe(0);

    for (const ref of refs) {
      expect(ref.encryptionKey).toBeNull();
      expect(ref.keyPair).toBeNull();
      expect(ref.partnerPublicKey).toBeNull();
      expect(ref.sessionId).toBe('');
      expect(ref.createdAt).toBe(0);
      expect(ref.lastAccessedAt).toBe(0);
    }

    destroySessionKeyManager();
  });
});

describe('Layer 9: build/test reproducibility invariants', () => {
  it('repo is lockfile-pinned and test runner is deterministic (package.json)', () => {
    const repoRoot = process.cwd();
    const pkgPath = path.join(repoRoot, 'package.json');
    const lockPath = path.join(repoRoot, 'package-lock.json');

    expect(fs.existsSync(lockPath)).toBe(true);

    const pkg = JSON.parse(readUtf8(pkgPath));
    expect(typeof pkg.packageManager).toBe('string');
    expect(pkg.packageManager.startsWith('npm@')).toBe(true);
    expect(pkg.scripts.test).toBe('vitest run');
  });
});
