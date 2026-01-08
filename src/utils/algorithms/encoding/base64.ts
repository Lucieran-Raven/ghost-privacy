const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const BASE64_LOOKUP = (() => {
  const table = new Int16Array(256);
  table.fill(-1);
  for (let i = 0; i < BASE64_ALPHABET.length; i++) {
    table[BASE64_ALPHABET.charCodeAt(i)] = i;
  }
  table['-'.charCodeAt(0)] = 62;
  table['_'.charCodeAt(0)] = 63;
  return table;
})();

function assertValidBase64Char(code: number): number {
  const v = BASE64_LOOKUP[code];
  if (v === -1) {
    throw new Error('Invalid base64 character');
  }
  return v;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;

    const triplet = (b0 << 16) | (b1 << 8) | b2;

    out += BASE64_ALPHABET[(triplet >>> 18) & 0x3f];
    out += BASE64_ALPHABET[(triplet >>> 12) & 0x3f];
    out += i + 1 < bytes.length ? BASE64_ALPHABET[(triplet >>> 6) & 0x3f] : '=';
    out += i + 2 < bytes.length ? BASE64_ALPHABET[triplet & 0x3f] : '=';
  }
  return out;
}

export function base64ToBytes(input: string): Uint8Array {
  const str = input.replace(/\s+/g, '');
  if (str.length === 0) return new Uint8Array(0);

  const padLen = str.endsWith('==') ? 2 : str.endsWith('=') ? 1 : 0;
  const cleanLen = str.length;
  const baseLen = cleanLen - padLen;

  if (cleanLen % 4 !== 0) {
    throw new Error('Invalid base64 length');
  }

  const outLen = (cleanLen / 4) * 3 - padLen;
  const out = new Uint8Array(outLen);

  let outIdx = 0;
  for (let i = 0; i < cleanLen; i += 4) {
    const c0 = str.charCodeAt(i);
    const c1 = str.charCodeAt(i + 1);
    const c2 = str.charCodeAt(i + 2);
    const c3 = str.charCodeAt(i + 3);

    const v0 = assertValidBase64Char(c0);
    const v1 = assertValidBase64Char(c1);

    const isPad2 = c2 === '='.charCodeAt(0);
    const isPad3 = c3 === '='.charCodeAt(0);

    const v2 = isPad2 ? 0 : assertValidBase64Char(c2);
    const v3 = isPad3 ? 0 : assertValidBase64Char(c3);

    const triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;

    if (outIdx < outLen) out[outIdx++] = (triple >>> 16) & 0xff;
    if (outIdx < outLen && !isPad2) out[outIdx++] = (triple >>> 8) & 0xff;
    if (outIdx < outLen && !isPad3) out[outIdx++] = triple & 0xff;
  }

  return out;
}

export function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  return base64ToBytes(padded);
}
