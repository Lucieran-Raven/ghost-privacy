import { bytesToBase64 } from '@/utils/algorithms/encoding/base64';

export function generateSafeFileTransferId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  try {
    return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  } finally {
    try {
      bytes.fill(0);
    } catch {
    }
  }
}

export function makeNativeDropId(baseId: string): string {
  const base = String(baseId || '').replace(/[^a-zA-Z0-9_-]/g, '');
  const safeBase = base.length > 0 ? base : 'drop';
  const suffix = generateSafeFileTransferId().slice(0, 10);
  const combined = `${safeBase}-${suffix}`;
  return combined.length > 128 ? combined.slice(0, 128) : combined;
}

export function waitForFileAck(
  pendingAcks: Map<string, (ok: boolean) => void>,
  seenAcks: Map<string, number>,
  key: string,
  timeoutMs: number,
): Promise<boolean> {
  return new Promise((resolve) => {
    const seenAt = seenAcks.get(key);
    if (typeof seenAt === 'number') {
      seenAcks.delete(key);
      resolve(true);
      return;
    }

    pendingAcks.set(key, resolve);

    setTimeout(() => {
      const resolver = pendingAcks.get(key);
      if (resolver) {
        pendingAcks.delete(key);
        resolver(false);
      }
    }, timeoutMs);
  });
}

export type FileTransferState = {
  chunks: string[];
  received: number;
  total: number;
  iv: string;
  fileName: string;
  fileType: string;
  sealedKind: string;
  timestamp: number;
  senderId: string;
  cleanupTimer: ReturnType<typeof setTimeout> | null;
};

export function purgeFileTransfer(transfers: Map<string, FileTransferState>, fileId: string): void {
  const t = transfers.get(fileId);
  if (!t) return;

  if (t.cleanupTimer) {
    clearTimeout(t.cleanupTimer);
  }

  try {
    t.chunks.fill('');
  } catch {
  }

  t.received = 0;
  t.total = 0;
  t.iv = '';
  t.fileName = '';
  t.fileType = '';
  t.sealedKind = '';
  t.timestamp = 0;
  t.senderId = '';
  t.cleanupTimer = null;

  transfers.delete(fileId);
}

export function sniffMimeFromBytes(bytes: Uint8Array): string | null {
  try {
    const header = Array.from(bytes.slice(0, 16))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    if (header.startsWith('25504446')) return 'application/pdf';
    if (header.startsWith('89504e47')) return 'image/png';
    if (header.startsWith('ffd8ff')) return 'image/jpeg';
    if (header.startsWith('47494638')) return 'image/gif';
    if (header.startsWith('52494646')) return 'image/webp';
    return null;
  } catch {
    return null;
  }
}

export function normalizeFileNameForMime(safeFileName: string, mime: string | null): string {
  if (!mime) return safeFileName;
  const extByMime: Record<string, string> = {
    'application/pdf': 'pdf',
    'image/png': 'png',
    'image/jpeg': 'jpg',
    'image/gif': 'gif',
    'image/webp': 'webp',
  };
  const desiredExt = extByMime[mime];
  if (!desiredExt) return safeFileName;

  const idx = safeFileName.lastIndexOf('.');
  const currentExt = idx >= 0 ? safeFileName.slice(idx + 1).toLowerCase() : '';
  if (currentExt === desiredExt) return safeFileName;

  const base = idx >= 0 ? safeFileName.slice(0, idx) : safeFileName;
  return `${base}.${desiredExt}`.slice(0, 256);
}
