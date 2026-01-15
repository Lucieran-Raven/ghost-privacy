export type { GetRandomValues, ZeroizationDeps } from '@/utils/algorithms/memory/zeroization';
export { secureZeroArrayBuffer, secureZeroUint8Array } from '@/utils/algorithms/memory/zeroization';

export function secureZeroStringBestEffort(deps: { getRandomValues: <T extends ArrayBufferView>(array: T) => T }, value: string): void {
  const bytes = new TextEncoder().encode(value);
  try {
    deps.getRandomValues(bytes);
  } finally {
    bytes.fill(0);
  }
}
