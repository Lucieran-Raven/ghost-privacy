import { describe, expect, it } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

function walkFiles(dir: string, out: string[]): void {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      walkFiles(full, out);
    } else if (e.isFile()) {
      if (!e.name.endsWith('.ts')) continue;
      if (e.name.endsWith('.test.ts')) continue;
      out.push(full);
    }
  }
}

describe('Layer-0 purity guard (src/utils/algorithms)', () => {
  it('contains no platform/runtime dependencies', () => {
    const algorithmsRoot = path.resolve(__dirname);
    const files: string[] = [];
    walkFiles(algorithmsRoot, files);

    const bannedPatterns: Array<{ name: string; re: RegExp }> = [
      { name: 'atob/btoa', re: /\b(atob|btoa)\b/ },
      { name: 'tauri runtime', re: /\b(isTauriRuntime|tauriInvoke)\b/ },
      { name: 'supabase', re: /\bsupabase\b/ },
      { name: 'fetch/websocket/xhr', re: /\b(fetch\s*\(|WebSocket\b|XMLHttpRequest\b)/ },
      { name: 'window/document/navigator usage', re: /\b(window|document|navigator)\s*\./ },
      { name: 'storage APIs', re: /\b(localStorage|sessionStorage|indexedDB)\b/ },
      { name: 'node process/require', re: /\b(process\.|require\s*\()/ },
      { name: 'node fs import', re: /from\s+['\"]fs['\"]|require\(['\"]fs['\"]\)/ },
      { name: 'global crypto usage', re: /\bcrypto\.(subtle|getRandomValues)\b/ }
    ];

    const violations: Array<{ file: string; pattern: string }> = [];

    for (const file of files) {
      const src = fs.readFileSync(file, 'utf8');
      for (const p of bannedPatterns) {
        if (p.re.test(src)) {
          violations.push({ file, pattern: p.name });
        }
      }
    }

    expect(violations, `Layer-0 purity violations:\n${violations.map(v => `- ${v.file}: ${v.pattern}`).join('\n')}`).toEqual([]);
  });
});
