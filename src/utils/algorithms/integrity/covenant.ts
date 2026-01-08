/**
 * Self-Integrity Covenant (optional)
 * Purpose: Provide pure hashing utilities to support self-integrity checks.
 * Input: bytes and crypto digest dependency.
 * Output: hex/base64 digests.
 * Privacy: NEVER logs, NEVER stores, NEVER makes network requests, NEVER persists beyond caller-managed memory.
 */

import { bytesToBase64 } from '@/utils/algorithms/encoding/base64';

export interface IntegrityDeps {
  subtle: SubtleCrypto;
}

export async function sha256(deps: IntegrityDeps, data: ArrayBuffer): Promise<ArrayBuffer> {
  return deps.subtle.digest('SHA-256', data);
}

export function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function toBase64(buffer: ArrayBuffer): string {
  return bytesToBase64(new Uint8Array(buffer));
}
