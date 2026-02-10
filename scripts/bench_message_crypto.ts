import { performance } from 'node:perf_hooks';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto) {
  // @ts-ignore
  globalThis.crypto = webcrypto;
}

if (typeof globalThis.atob === 'undefined') {
  // @ts-ignore
  globalThis.atob = (b64: string) => Buffer.from(b64, 'base64').toString('binary');
}

if (typeof globalThis.btoa === 'undefined') {
  // @ts-ignore
  globalThis.btoa = (bin: string) => Buffer.from(bin, 'binary').toString('base64');
}

const { EncryptionEngine } = await import('../src/utils/encryption');

async function benchEncryptDecryptText(iterations: number) {
  const engine = new EncryptionEngine();
  await engine.initialize();

  const message = 'hello ghost privacy '.repeat(64);

  // Warm-up
  const warm = await engine.encryptMessage(message);
  const warmPlain = await engine.decryptMessage(warm.encrypted, warm.iv);
  if (warmPlain !== message) {
    throw new Error('warm-up decrypt mismatch');
  }

  const t0 = performance.now();
  let last = warm;
  for (let i = 0; i < iterations; i++) {
    last = await engine.encryptMessage(message);
  }
  const t1 = performance.now();

  const t2 = performance.now();
  for (let i = 0; i < iterations; i++) {
    const plain = await engine.decryptMessage(last.encrypted, last.iv);
    if (plain !== message) {
      throw new Error('decrypt mismatch');
    }
  }
  const t3 = performance.now();

  process.stdout.write(
    `encryptMessage: ${iterations} ops, avg ${((t1 - t0) / iterations).toFixed(4)} ms/op\n`
  );
  process.stdout.write(
    `decryptMessage: ${iterations} ops, avg ${((t3 - t2) / iterations).toFixed(4)} ms/op\n`
  );
}

async function main() {
  const iterations = 500;
  await benchEncryptDecryptText(iterations);
}

await main();
