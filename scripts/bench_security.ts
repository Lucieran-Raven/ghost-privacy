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

const { deriveRealtimeChannelName } = await import('../src/utils/algorithms/session/realtimeChannel');

async function main() {
  const sessionId = 'GHOST-ABCD-1234';
  const token = 'aaaaaaaaaaaaaaaa';

  const iterations = 2000;

  const t0 = performance.now();
  for (let i = 0; i < iterations; i++) {
    await deriveRealtimeChannelName(sessionId, token);
  }
  const t1 = performance.now();

  const perOpMs = (t1 - t0) / iterations;
  process.stdout.write(`deriveRealtimeChannelName: ${iterations} ops, avg ${perOpMs.toFixed(4)} ms/op\n`);
}

await main();
