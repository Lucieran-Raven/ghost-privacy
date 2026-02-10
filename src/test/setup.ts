import { webcrypto } from 'node:crypto';

// Ensure WebCrypto exists for algorithms that use crypto.subtle
if (!globalThis.crypto) {
  // @ts-expect-error - polyfill
  globalThis.crypto = webcrypto;
}

// Basic atob/btoa polyfills for Node test runtime
if (!globalThis.atob) {
  globalThis.atob = (b64: string) => Buffer.from(b64, 'base64').toString('binary');
}

if (!globalThis.btoa) {
  globalThis.btoa = (bin: string) => Buffer.from(bin, 'binary').toString('base64');
}
