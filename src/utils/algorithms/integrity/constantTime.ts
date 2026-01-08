export function constantTimeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  const len = Math.max(a.byteLength, b.byteLength);
  let diff = a.byteLength ^ b.byteLength;

  for (let i = 0; i < len; i++) {
    const av = i < a.byteLength ? a[i] : 0;
    const bv = i < b.byteLength ? b[i] : 0;
    diff |= av ^ bv;
  }

  return diff === 0;
}

export function constantTimeEqualString(a: string, b: string): boolean {
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;

  for (let i = 0; i < len; i++) {
    const av = i < a.length ? a.charCodeAt(i) : 0;
    const bv = i < b.length ? b.charCodeAt(i) : 0;
    diff |= av ^ bv;
  }

  return diff === 0;
}
