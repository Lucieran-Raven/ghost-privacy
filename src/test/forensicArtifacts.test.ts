import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

function tokenFromCharCodes(codes: number[]): string {
  return String.fromCharCode(...codes);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
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

function stripComments(input: string): string {
  let s = input;
  s = s.replace(/\/\*[\s\S]*?\*\//g, '');
  s = s.replace(/(^|\n)\s*\/\/.*(?=\n|$)/g, '$1');
  s = s.replace(/(?<!:)\/\/.*(?=\n|$)/g, '');
  return s;
}

function listFilesIfExists(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  return listFiles(dir);
}

function stripRustComments(input: string): string {
  let s = input;
  s = s.replace(/\/\*[\s\S]*?\*\//g, '');
  s = s.replace(/(^|\n)\s*\/\/\/.*(?=\n|$)/g, '$1');
  s = s.replace(/(^|\n)\s*\/\/.*(?=\n|$)/g, '$1');
  return s;
}

function stripXmlComments(input: string): string {
  return input.replace(/<!--[\s\S]*?-->/g, '');
}

describe('forensic artifact regression checks', () => {
  it('stripComments removes line and block comments but preserves executable code', () => {
    const ls = tokenFromCharCodes([108, 111, 99, 97, 108, 83, 116, 111, 114, 97, 103, 101]);
    const ss = tokenFromCharCodes([115, 101, 115, 115, 105, 111, 110, 83, 116, 111, 114, 97, 103, 101]);
    const raw = [
      `const a = 1; // ${ls}.setItem("k","v")`,
      `/* ${ss}.setItem("k","v") */`,
      'const b = 2;',
      `${ls}.setItem("k","v")`
    ].join('\n');

    const code = stripComments(raw);
    expect(code).not.toContain(`${ss}.setItem`);
    expect(code).not.toContain(`// ${ls}.setItem`);
    expect(code).toContain(`${ls}.setItem`);
  });

  it('does not contain persistence primitives anywhere in application source (raw, including comments/strings)', () => {
    const root = path.resolve(process.cwd(), 'src');
    const files = listFiles(root)
      .filter(f => /\.(ts|tsx)$/.test(f))
      .filter(f => !f.includes(`${path.sep}test${path.sep}`))
      .filter(f => !/\.test\.(ts|tsx)$/.test(f));

    const ls = tokenFromCharCodes([108, 111, 99, 97, 108, 83, 116, 111, 114, 97, 103, 101]);
    const ss = tokenFromCharCodes([115, 101, 115, 115, 105, 111, 110, 83, 116, 111, 114, 97, 103, 101]);
    const idbGlobal = tokenFromCharCodes([105, 110, 100, 101, 120, 101, 100, 68, 66]);
    const openDb = tokenFromCharCodes([111, 112, 101, 110, 68, 66]);
    const dexie = tokenFromCharCodes([68, 101, 120, 105, 101]);
    const idbLib = tokenFromCharCodes([105, 100, 98]);

    const bannedRegexes: Array<{ name: string; re: RegExp }> = [
      { name: ls, re: new RegExp(`\\b${escapeRegExp(ls)}\\b`) },
      { name: ss, re: new RegExp(`\\b${escapeRegExp(ss)}\\b`) },
      { name: idbGlobal, re: new RegExp(`\\b${escapeRegExp(idbGlobal)}\\b`) },
      { name: openDb, re: new RegExp(`\\b${escapeRegExp(openDb)}\\b`) },
      { name: dexie, re: new RegExp(`\\b${escapeRegExp(dexie)}\\b`) },
      { name: idbLib, re: new RegExp(`\\b${escapeRegExp(idbLib)}\\b`) }
    ];

    const violations: Array<{ file: string; token: string }> = [];

    for (const file of files) {
      const raw = fs.readFileSync(file, 'utf8');
      for (const b of bannedRegexes) {
        if (b.re.test(raw)) {
          violations.push({ file: path.relative(process.cwd(), file), token: b.name });
        }
      }
    }

    expect(violations).toEqual([]);
  });

  it('does not introduce disk persistence primitives in application source (non-comment)', () => {
    const root = path.resolve(process.cwd(), 'src');
    const files = listFiles(root)
      .filter(f => /\.(ts|tsx)$/.test(f))
      .filter(f => !f.includes(`${path.sep}test${path.sep}`))
      .filter(f => !/\.test\.(ts|tsx)$/.test(f));

    const ls = tokenFromCharCodes([108, 111, 99, 97, 108, 83, 116, 111, 114, 97, 103, 101]);
    const ss = tokenFromCharCodes([115, 101, 115, 115, 105, 111, 110, 83, 116, 111, 114, 97, 103, 101]);
    const idb = tokenFromCharCodes([105, 110, 100, 101, 120, 101, 100, 68, 66]);

    const banned = [
      `${ls}.`,
      `${ss}.`,
      idb,
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

  it('does not introduce console logs in Supabase edge functions (non-comment)', () => {
    const root = path.resolve(process.cwd(), 'supabase', 'functions');
    const files = listFilesIfExists(root)
      .filter(f => /\.(ts)$/.test(f));

    const banned = [
      'console.'
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

  it('does not introduce obvious Rust filesystem write primitives in Tauri backend source (non-comment)', () => {
    const root = path.resolve(process.cwd(), 'src-tauri', 'src');
    const files = listFilesIfExists(root)
      .filter(f => /\.(rs)$/.test(f));

    const banned = [
      'std::fs::',
      'File::create',
      'OpenOptions',
      'create_dir',
      'create_dir_all',
      'write_all',
      'std::io::Write',
    ];

    const violations: Array<{ file: string; needle: string }> = [];

    for (const file of files) {
      const raw = fs.readFileSync(file, 'utf8');
      const code = stripRustComments(raw);
      for (const needle of banned) {
        if (code.includes(needle)) {
          violations.push({ file: path.relative(process.cwd(), file), needle });
        }
      }
    }

    expect(violations).toEqual([]);
  });

  it('does not introduce obvious Android persistence primitives in native layer (non-comment)', () => {
    const root = path.resolve(process.cwd(), 'android', 'app', 'src', 'main', 'java');
    const files = listFilesIfExists(root)
      .filter(f => /\.(java)$/.test(f));

    const banned = [
      'SharedPreferences',
      'getSharedPreferences(',
      'PreferenceManager',
      'SQLiteDatabase',
      'RoomDatabase',
      'openOrCreateDatabase(',
      'openFileOutput(',
      'FileOutputStream',
      'RandomAccessFile',
      'ObjectOutputStream',
      'FileWriter',
      'BufferedWriter',
      'getExternalFilesDir',
      'Environment.getExternalStorage',
      'android.permission.WRITE_EXTERNAL_STORAGE',
      'MODE_WORLD_READABLE',
      'MODE_WORLD_WRITEABLE'
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

  it('does not regress Android manifest security flags', () => {
    const manifestPath = path.resolve(process.cwd(), 'android', 'app', 'src', 'main', 'AndroidManifest.xml');
    if (!fs.existsSync(manifestPath)) return;

    const raw = fs.readFileSync(manifestPath, 'utf8');
    const xml = stripXmlComments(raw);

    expect(xml).toMatch(/android:allowBackup\s*=\s*"false"/);
    expect(xml).toMatch(/android:fullBackupContent\s*=\s*"false"/);
    expect(xml).toMatch(/android:usesCleartextTraffic\s*=\s*"false"/);
    expect(xml).toMatch(/android:networkSecurityConfig\s*=\s*"@xml\/network_security_config"/);
  });
});
