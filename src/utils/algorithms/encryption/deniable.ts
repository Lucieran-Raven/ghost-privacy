/**
 * Deniable Encryption (VeraCrypt-style hidden volumes)
 * Purpose: Provide dual-password encryption where the outer password reveals decoy content and the inner password reveals real content.
 * Input: Plaintext real content (string), plaintext decoy content (string), passwords (string), packed data (string).
 * Output: Packed hidden volume data and decrypted content metadata.
 * Privacy: NEVER logs, NEVER stores, NEVER makes network requests, NEVER persists beyond caller-managed memory.
 */

import { base64ToBytes, bytesToBase64 } from '@/utils/algorithms/encoding/base64';

type GetRandomValues = <T extends ArrayBufferView>(array: T) => T;

export interface DeniableCryptoDeps {
  subtle: SubtleCrypto;
  getRandomValues: GetRandomValues;
  pbkdf2Iterations?: number;
  allowWeakPbkdf2ForTesting?: boolean;
}

export interface DecryptHiddenVolumeResult {
  content: string;
  isDecoy: boolean;
}

const PBKDF2_ITERATIONS = 600000;

function normalizePbkdf2Iterations(deps: Pick<DeniableCryptoDeps, 'pbkdf2Iterations' | 'allowWeakPbkdf2ForTesting'>): number {
  const maxIterations = 5_000_000;

  let it = deps.pbkdf2Iterations ?? PBKDF2_ITERATIONS;
  if (!Number.isFinite(it)) {
    it = PBKDF2_ITERATIONS;
  }
  it = Math.floor(it);
  if (it <= 0) {
    it = PBKDF2_ITERATIONS;
  }

  if (!deps.allowWeakPbkdf2ForTesting && it < PBKDF2_ITERATIONS) {
    it = PBKDF2_ITERATIONS;
  }

  if (it > maxIterations) {
    it = maxIterations;
  }

  return it;
}

const SALT_SIZE = 16;
const IV_SIZE = 12;
const HEADER_PLAINTEXT_SIZE = 256;
const GCM_TAG_SIZE = 16;
const HEADER_CIPHERTEXT_SIZE = HEADER_PLAINTEXT_SIZE + GCM_TAG_SIZE;
const HEADER_TOTAL_SIZE = IV_SIZE + HEADER_CIPHERTEXT_SIZE;

const CONTAINER_SIZE_BYTES = 10 * 1024 * 1024;
const INNER_REGION_BYTES = 5 * 1024 * 1024;

const MAGIC_OUTER = 0x4f485047; // 'GPHO' little-endian
const MAGIC_INNER = 0x49485047; // 'GPHI' little-endian

function expectedBase64Len(byteLen: number): number {
  return 4 * Math.ceil(byteLen / 3);
}

function fillRandomBytesChunked(deps: Pick<DeniableCryptoDeps, 'getRandomValues'>, out: Uint8Array): Uint8Array {
  const maxChunk = 65536;
  for (let i = 0; i < out.byteLength; i += maxChunk) {
    const chunk = out.subarray(i, Math.min(i + maxChunk, out.byteLength));
    deps.getRandomValues(chunk);
  }
  return out;
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const bytes = base64ToBytes(base64);
  try {
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  } finally {
    try {
      bytes.fill(0);
    } catch {
      // Ignore
    }
  }
}

async function deriveKeyFromPassword(
  deps: DeniableCryptoDeps,
  password: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  const keyMaterial = await deps.subtle.importKey('raw', passwordBuffer, 'PBKDF2', false, ['deriveKey']);
  try {
    passwordBuffer.fill(0);
  } catch {
    // Ignore
  }

  const saltBuffer = new Uint8Array(salt).buffer as ArrayBuffer;

  return deps.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: normalizePbkdf2Iterations(deps),
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength) as ArrayBuffer;
}

export class DeniableEncryption {
  private static buildHeaderPlaintext(params: { magic: number; payloadCipherLen: number; payloadIv: Uint8Array }): Uint8Array {
    const header = new Uint8Array(HEADER_PLAINTEXT_SIZE);
    const view = new DataView(header.buffer);
    view.setUint32(0, params.magic, true);
    view.setUint32(4, 1, true);
    view.setUint32(8, params.payloadCipherLen >>> 0, true);
    header.set(params.payloadIv, 12);
    return header;
  }

  private static parseHeaderPlaintext(header: Uint8Array): { magic: number; payloadCipherLen: number; payloadIv: Uint8Array } | null {
    if (header.length < HEADER_PLAINTEXT_SIZE) return null;
    const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
    const magic = view.getUint32(0, true);
    const version = view.getUint32(4, true);
    if (version !== 1) return null;
    const payloadCipherLen = view.getUint32(8, true);
    const payloadIv = header.slice(12, 24);
    return { magic, payloadCipherLen, payloadIv };
  }

  private static async encryptHeader(
    deps: DeniableCryptoDeps,
    key: CryptoKey,
    headerPlain: Uint8Array
  ): Promise<{ headerIv: Uint8Array; headerCipher: Uint8Array }> {
    const headerIv = deps.getRandomValues(new Uint8Array(IV_SIZE));
    const encrypted = await deps.subtle.encrypt({ name: 'AES-GCM', iv: toArrayBuffer(headerIv) }, key, toArrayBuffer(headerPlain));
    return { headerIv, headerCipher: new Uint8Array(encrypted) };
  }

  private static async decryptHeader(
    deps: DeniableCryptoDeps,
    key: CryptoKey,
    headerIv: Uint8Array,
    headerCipher: Uint8Array
  ): Promise<Uint8Array> {
    const decrypted = await deps.subtle.decrypt({ name: 'AES-GCM', iv: toArrayBuffer(headerIv) }, key, toArrayBuffer(headerCipher));
    return new Uint8Array(decrypted);
  }

  private static async encryptPayload(
    deps: DeniableCryptoDeps,
    key: CryptoKey,
    payloadPlain: Uint8Array
  ): Promise<{ payloadIv: Uint8Array; payloadCipher: Uint8Array }> {
    const payloadIv = deps.getRandomValues(new Uint8Array(IV_SIZE));
    const encrypted = await deps.subtle.encrypt({ name: 'AES-GCM', iv: toArrayBuffer(payloadIv) }, key, toArrayBuffer(payloadPlain));
    return { payloadIv, payloadCipher: new Uint8Array(encrypted) };
  }

  private static async decryptPayload(
    deps: DeniableCryptoDeps,
    key: CryptoKey,
    payloadIv: Uint8Array,
    payloadCipher: Uint8Array
  ): Promise<Uint8Array> {
    const decrypted = await deps.subtle.decrypt({ name: 'AES-GCM', iv: toArrayBuffer(payloadIv) }, key, toArrayBuffer(payloadCipher));
    return new Uint8Array(decrypted);
  }

  static async createHiddenVolume(
    deps: DeniableCryptoDeps,
    realContent: string,
    decoyContent: string,
    outerPassword: string,
    innerPassword: string
  ): Promise<string> {
    return this.createHiddenFile(deps, realContent, decoyContent, outerPassword, innerPassword);
  }

  static async decryptHiddenVolume(
    deps: DeniableCryptoDeps,
    packedData: string,
    password: string
  ): Promise<DecryptHiddenVolumeResult | null> {
    return this.decryptHiddenFile(deps, packedData, password);
  }

  static async createHiddenFile(
    deps: DeniableCryptoDeps,
    realFileBase64: string,
    decoyFileBase64: string,
    outerPassword: string,
    innerPassword: string
  ): Promise<string> {
    const container = fillRandomBytesChunked(deps, new Uint8Array(CONTAINER_SIZE_BYTES));
    const salt = deps.getRandomValues(new Uint8Array(SALT_SIZE));
    container.set(salt, 0);

    const outerKey = await deriveKeyFromPassword(deps, outerPassword, salt);
    const innerKey = await deriveKeyFromPassword(deps, innerPassword, salt);

    const innerRegionOffset = CONTAINER_SIZE_BYTES - INNER_REGION_BYTES;
    const outerHeaderOffset = SALT_SIZE;
    const decoyPayloadOffset = SALT_SIZE + HEADER_TOTAL_SIZE;
    const innerHeaderOffset = innerRegionOffset;
    const realPayloadOffset = innerHeaderOffset + HEADER_TOTAL_SIZE;

    const decoyMax = innerRegionOffset - decoyPayloadOffset;
    const realMax = CONTAINER_SIZE_BYTES - realPayloadOffset;

    const decoyPlain = new TextEncoder().encode(decoyFileBase64);
    const realPlain = new TextEncoder().encode(realFileBase64);

    const { payloadIv: decoyIv, payloadCipher: decoyCipher } = await this.encryptPayload(deps, outerKey, decoyPlain);
    const { payloadIv: realIv, payloadCipher: realCipher } = await this.encryptPayload(deps, innerKey, realPlain);

    try {
      if (decoyCipher.byteLength > decoyMax) {
        throw new Error('Decoy content too large for fixed container');
      }
      if (realCipher.byteLength > realMax) {
        throw new Error('Real content too large for fixed container');
      }

      const outerHeaderPlain = this.buildHeaderPlaintext({ magic: MAGIC_OUTER, payloadCipherLen: decoyCipher.byteLength, payloadIv: decoyIv });
      const innerHeaderPlain = this.buildHeaderPlaintext({ magic: MAGIC_INNER, payloadCipherLen: realCipher.byteLength, payloadIv: realIv });

      const { headerIv: outerHeaderIv, headerCipher: outerHeaderCipher } = await this.encryptHeader(deps, outerKey, outerHeaderPlain);
      const { headerIv: innerHeaderIv, headerCipher: innerHeaderCipher } = await this.encryptHeader(deps, innerKey, innerHeaderPlain);

      container.set(outerHeaderIv, outerHeaderOffset);
      container.set(outerHeaderCipher, outerHeaderOffset + IV_SIZE);
      container.set(decoyCipher, decoyPayloadOffset);

      container.set(innerHeaderIv, innerHeaderOffset);
      container.set(innerHeaderCipher, innerHeaderOffset + IV_SIZE);
      container.set(realCipher, realPayloadOffset);

      const encoded = bytesToBase64(container);

      try {
        outerHeaderIv.fill(0);
        outerHeaderCipher.fill(0);
        innerHeaderIv.fill(0);
        innerHeaderCipher.fill(0);
        decoyIv.fill(0);
        decoyCipher.fill(0);
        realIv.fill(0);
        realCipher.fill(0);
      } catch {
        // Ignore
      }

      return encoded;
    } finally {
      try {
        decoyPlain.fill(0);
        realPlain.fill(0);
      } catch {
        // Ignore
      }

      try {
        container.fill(0);
      } catch {
        // Ignore
      }

      try {
        salt.fill(0);
      } catch {
        // Ignore
      }
    }
  }

  static async decryptHiddenFile(
    deps: DeniableCryptoDeps,
    packedData: string,
    password: string
  ): Promise<DecryptHiddenVolumeResult | null> {
    const expectedLen = expectedBase64Len(CONTAINER_SIZE_BYTES);
    if (packedData.length > expectedLen + 1024) {
      return null;
    }

    const compact = /\s/.test(packedData) ? packedData.replace(/\s+/g, '') : packedData;
    if (compact.length !== expectedLen) {
      return null;
    }

    let container: Uint8Array;
    try {
      container = base64ToBytes(compact);
    } catch {
      return null;
    }

    try {
      if (container.byteLength !== CONTAINER_SIZE_BYTES) {
        return null;
      }

      const salt = container.slice(0, SALT_SIZE);
      const key = await deriveKeyFromPassword(deps, password, salt);

    const innerRegionOffset = CONTAINER_SIZE_BYTES - INNER_REGION_BYTES;
    const outerHeaderOffset = SALT_SIZE;
    const decoyPayloadOffset = SALT_SIZE + HEADER_TOTAL_SIZE;
    const innerHeaderOffset = innerRegionOffset;
    const realPayloadOffset = innerHeaderOffset + HEADER_TOTAL_SIZE;

    const decoyMax = innerRegionOffset - decoyPayloadOffset;
    const realMax = CONTAINER_SIZE_BYTES - realPayloadOffset;

    const dummyIv = new Uint8Array(IV_SIZE);
    const TIMING_BURN_CIPHERTEXT_BYTES = 512 * 1024 + GCM_TAG_SIZE;
    const burnLen = Math.max(0, Math.min(TIMING_BURN_CIPHERTEXT_BYTES, Math.min(decoyMax, realMax)));

    const burnDecrypt = async (payloadOffset: number): Promise<void> => {
      try {
        const end = payloadOffset + burnLen;
        if (burnLen <= GCM_TAG_SIZE) return;
        if (end > container.byteLength) return;
        const view = container.subarray(payloadOffset, end);
        await deps.subtle.decrypt({ name: 'AES-GCM', iv: dummyIv }, key, view);
      } catch {
      }
    };

    const tryDecryptAt = async (
      headerOffset: number,
      payloadOffset: number,
      expectedMagic: number,
      isDecoy: boolean,
      maxCipherLen: number
    ): Promise<DecryptHiddenVolumeResult | null> => {
      try {
        const headerIv = container.slice(headerOffset, headerOffset + IV_SIZE);
        const headerCipher = container.slice(headerOffset + IV_SIZE, headerOffset + IV_SIZE + HEADER_CIPHERTEXT_SIZE);
        const headerPlain = await this.decryptHeader(deps, key, headerIv, headerCipher);
        const parsed = this.parseHeaderPlaintext(headerPlain);
        try {
          headerPlain.fill(0);
        } catch {
          // Ignore
        }
        if (!parsed || parsed.magic !== expectedMagic) {
          return null;
        }

        const cipherLen = parsed.payloadCipherLen;
        if (cipherLen <= 0) return null;
        if (cipherLen > maxCipherLen) return null;
        if (payloadOffset + cipherLen > container.byteLength) return null;
        const payloadCipher = container.slice(payloadOffset, payloadOffset + cipherLen);
        const payloadPlain = await this.decryptPayload(deps, key, parsed.payloadIv, payloadCipher);
        const content = new TextDecoder().decode(payloadPlain);

        try {
          payloadPlain.fill(0);
        } catch {
          // Ignore
        }

        return { content, isDecoy };
      } catch {
        return null;
      } finally {
        await burnDecrypt(payloadOffset);
      }
    };

      const [inner, outer] = await Promise.all([
        tryDecryptAt(innerHeaderOffset, realPayloadOffset, MAGIC_INNER, false, realMax),
        tryDecryptAt(outerHeaderOffset, decoyPayloadOffset, MAGIC_OUTER, true, decoyMax)
      ]);

      if (inner) return inner;
      if (outer) return outer;
      return null;
    } finally {
      try {
        container.fill(0);
      } catch {
        // Ignore
      }
    }
  }
}

export function generateDecoyContent(
  fileType: string,
  randomInt: (maxExclusive: number) => number
): string {
  const decoys: Record<string, string[]> = {
    image: [
      'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
      'Family vacation photo - Summer 2024',
      'Random cat photo from internet'
    ],
    document: [
      'Shopping list:\n- Milk\n- Bread\n- Eggs\n- Butter',
      'Meeting notes - Q4 Planning\nAttendees: Marketing team\nAgenda: Budget review',
      'Recipe: Chocolate Chip Cookies\n1. Preheat oven to 350°F\n2. Mix ingredients...'
    ],
    spreadsheet: [
      'Monthly Budget\nRent: $1500\nUtilities: $200\nGroceries: $400',
      'Workout Log\nMonday: Chest\nTuesday: Back\nWednesday: Rest'
    ],
    default: [
      'Lorem ipsum dolor sit amet, consectetur adipiscing elit.',
      'Nothing to see here - just random text.',
      'Personal notes - miscellaneous'
    ]
  };

  const category = decoys[fileType] || decoys.default;
  const idx = randomInt(category.length);
  const clamped = idx >= 0 && idx < category.length ? idx : 0;
  return category[clamped];
}
