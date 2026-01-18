import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

function read(relPath: string): string {
  return fs.readFileSync(path.resolve(process.cwd(), relPath), 'utf8');
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

  it('disables autofill/autocorrect/spellcheck for hidden volume passwords', () => {
    const src = read('src/components/Ghost/HiddenFileModal.tsx');
    expect(src).toMatch(/autoComplete="new-password"/);
    expect(src).toMatch(/autoCorrect="off"/);
    expect(src).toMatch(/autoCapitalize="off"/);
    expect(src).toMatch(/spellCheck=\{false\}/);
  });
});
