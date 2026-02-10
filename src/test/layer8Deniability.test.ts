import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

function read(relPath: string): string {
  return fs.readFileSync(path.resolve(process.cwd(), relPath), 'utf8');
}

function extractStringLiterals(src: string): string[] {
  const out: string[] = [];
  const re = /'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)"|`([^`\\]*(?:\\.[^`\\]*)*)`/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) {
    const s = m[1] ?? m[2] ?? m[3] ?? '';
    out.push(s);
  }
  return out;
}

describe('layer8 deniability invariants', () => {
  it('does not explicitly label decoy/real in HiddenFileModal UI copy', () => {
    const src = read('src/components/Ghost/HiddenFileModal.tsx');
    const literals = extractStringLiterals(src).join('\n');
    const bannedUiPhrases: RegExp[] = [
      /Decoy Content/i,
      /Generate Random Decoy/i,
      /Outer Password/i,
      /Inner Password/i,
      /wrong password/i,
      /real file/i,
      /fake content/i
    ];
    for (const re of bannedUiPhrases) {
      expect(literals).not.toMatch(re);
    }
  });

  it('does not render a visible exit affordance for the decoy overlay calculator', () => {
    const src = read('src/pages/Session.tsx');
    expect(src).toMatch(/<DecoyCalculator[^>]*showExitButton=\{false\}/);
  });

  it('suppresses toast renderers and install prompt while in decoy mode', () => {
    const src = read('src/App.tsx');
    expect(src).toMatch(/!isDecoyActive\s*&&\s*<Toaster\s*\/>/);
    expect(src).toMatch(/!isDecoyActive\s*&&\s*<Sonner\b/);
    expect(src).toMatch(/!isDecoyActive\s*&&\s*<InstallPrompt\b/);
  });
});
