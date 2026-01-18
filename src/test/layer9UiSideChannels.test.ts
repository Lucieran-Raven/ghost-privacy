import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

function read(relPath: string): string {
  return fs.readFileSync(path.resolve(process.cwd(), relPath), 'utf8');
}

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

describe('layer9 ui/human side-channel invariants', () => {
  it('wires global PrivacyShield into App', () => {
    const src = read('src/App.tsx');
    expect(src).toMatch(/usePrivacyShield\(/);
    expect(src).toMatch(/<PrivacyShield\b/);
  });

  it('disables autofill/autocorrect/spellcheck for chat textarea', () => {
    const src = read('src/components/Ghost/ChatInterface.tsx');
    expect(src).toMatch(/<textarea[\s\S]*autoComplete="off"/);
    expect(src).toMatch(/<textarea[\s\S]*autoCorrect="off"/);
    expect(src).toMatch(/<textarea[\s\S]*autoCapitalize="off"/);
    expect(src).toMatch(/<textarea[\s\S]*spellCheck=\{false\}/);
  });

  it('disables autofill/autocorrect/spellcheck for join access code input', () => {
    const src = read('src/components/Ghost/SessionCreator.tsx');
    expect(src).toMatch(/<input[\s\S]*autoComplete="off"/);
    expect(src).toMatch(/<input[\s\S]*autoCorrect="off"/);
    expect(src).toMatch(/<input[\s\S]*autoCapitalize="off"/);
    expect(src).toMatch(/<input[\s\S]*spellCheck=\{false\}/);
  });

  it('normalizes create/join timing with shared min-delay helper', () => {
    const src = read('src/components/Ghost/SessionCreator.tsx');
    expect(src).toMatch(/createMinDelay\(350\)/);
  });

  it('hides verification fingerprints from accessibility tree', () => {
    const src = read('src/components/Ghost/KeyVerificationModal.tsx');
    expect(src).toMatch(/<code[\s\S]*aria-hidden="true"/);
  });

  it('disables autofill/autocorrect/spellcheck for hidden volume passwords', () => {
    const src = read('src/components/Ghost/HiddenFileModal.tsx');
    expect(src).toMatch(/autoComplete="new-password"/);
    expect(src).toMatch(/autoCorrect="off"/);
    expect(src).toMatch(/autoCapitalize="off"/);
    expect(src).toMatch(/spellCheck=\{false\}/);
  });

  it('does not use direct clipboard APIs outside ephemeralClipboard', () => {
    const root = path.resolve(process.cwd(), 'src');
    const files = listFiles(root).filter((f) => /\.(ts|tsx)$/.test(f));
    const violations: string[] = [];

    for (const file of files) {
      const rel = path.relative(process.cwd(), file);
      if (rel.replace(/\\/g, '/').endsWith('src/utils/ephemeralClipboard.ts')) {
        continue;
      }
      const raw = fs.readFileSync(file, 'utf8');
      if (/navigator\s*\.\s*clipboard\b/i.test(raw)) {
        violations.push(rel);
        continue;
      }
      if (/clipboard\s*\.\s*(writeText|readText)\s*\(/i.test(raw)) {
        violations.push(rel);
      }
    }

    expect(violations).toEqual([]);
  });
});
