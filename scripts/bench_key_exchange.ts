import { performance } from 'node:perf_hooks';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto) {
  // @ts-ignore
  globalThis.crypto = webcrypto;
}

const { KeyExchange } = await import('../src/utils/encryption');

async function benchKeyPair(iterations: number) {
  // Warm-up
  const warm = await KeyExchange.generateKeyPair();
  void warm;

  const t0 = performance.now();
  for (let i = 0; i < iterations; i++) {
    await KeyExchange.generateKeyPair();
  }
  const t1 = performance.now();

  process.stdout.write(
    `KeyExchange.generateKeyPair: ${iterations} ops, avg ${((t1 - t0) / iterations).toFixed(4)} ms/op\n`
  );
}

async function benchDeriveSharedSecret(iterations: number) {
  // Create two parties
  const a = await KeyExchange.generateKeyPair();
  const b = await KeyExchange.generateKeyPair();

  // Warm-up
  const warm = await KeyExchange.deriveSharedSecret(a.privateKey, b.publicKey);
  void warm;

  const t0 = performance.now();
  for (let i = 0; i < iterations; i++) {
    await KeyExchange.deriveSharedSecret(a.privateKey, b.publicKey);
  }
  const t1 = performance.now();

  process.stdout.write(
    `KeyExchange.deriveSharedSecret: ${iterations} ops, avg ${((t1 - t0) / iterations).toFixed(4)} ms/op\n`
  );
}

async function main() {
  await benchKeyPair(50);
  await benchDeriveSharedSecret(200);
}

await main();
