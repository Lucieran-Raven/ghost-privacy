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

function stripComments(input: string): string {
  let s = input;
  s = s.replace(/\/\*[\s\S]*?\*\//g, '');
  s = s.replace(/(^|\n)\s*\/\/.*(?=\n|$)/g, '$1');
  return s;
}

describe('forensic artifact regression checks', () => {
  it('does not introduce disk persistence primitives in application source (non-comment)', () => {
    const root = path.resolve(process.cwd(), 'src');
    const files = listFiles(root).filter(f => /\.(ts|tsx)$/.test(f));

    const banned = [
      'localStorage.',
      'sessionStorage.',
      'indexedDB',
      'document.cookie',
    ];

    const violations: Array<{ file: string; needle: string }> = [];

    for (const file of files) {
      const raw = fs.readFileSync(file, 'utf8');
      const code = stripComments(raw);
      for (const needle of banned) {
        if (code.includes(needle)) {
          violations.push({ file: path.relative(process.cwd(), file), needle });
        }
      }
    }

    expect(violations).toEqual([]);
  });
});
