/**
 * Memory Zeroization
 * Purpose: Best-effort overwrite of sensitive buffers in JS-managed memory.
 * Input: Buffers (ArrayBuffer/TypedArray) and randomness source.
 * Output: Mutated buffer contents (best-effort) to reduce post-compromise recovery likelihood.
 * Privacy: NEVER logs, NEVER stores, NEVER makes network requests, NEVER persists beyond caller-managed memory.
 */

export type GetRandomValues = <T extends ArrayBufferView>(array: T) => T;

export interface ZeroizationDeps {
  getRandomValues: GetRandomValues;
}

export function secureZeroArrayBuffer(deps: ZeroizationDeps, buffer: ArrayBuffer): void {
  const view = new Uint8Array(buffer);
  deps.getRandomValues(view);
  view.fill(0);
}

export function secureZeroUint8Array(deps: ZeroizationDeps, view: Uint8Array): void {
  // Overwrite with random data first
  deps.getRandomValues(view);
  view.fill(0);
  // Also zero the full underlying buffer if view is a subset
  const fullBuffer = new Uint8Array(view.buffer);
  if (fullBuffer.length !== view.length || view.byteOffset !== 0) {
    fullBuffer.fill(0);
  }
}
