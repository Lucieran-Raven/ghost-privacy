import { useCallback, useRef, useState, type ChangeEvent, type MutableRefObject } from 'react';
import { toast } from 'sonner';
import { bytesToBase64 } from '@/utils/algorithms/encoding/base64';
import { validateFile, sanitizeFileName } from '@/utils/security';
import type { EncryptionEngine } from '@/utils/encryption';
import type { QueuedMessage } from '@/utils/clientMessageQueue';
import type { RealtimeManager, BroadcastPayload } from '@/lib/realtimeManager';
import { generatePlausibleTimestamp } from '@/utils/plausibleTimestamp';
import { isTauriRuntime, tauriInvoke } from '@/utils/runtime';
import {
  generateSafeFileTransferId,
  makeNativeDropId,
  normalizeFileNameForMime,
  purgeFileTransfer,
  sniffMimeFromBytes,
  waitForFileAck,
  type FileTransferState,
} from './fileTransferUtils';

export function useFileTransfers(params: {
  sessionId: string;
  encryptionEngineRef: MutableRefObject<EncryptionEngine | null>;
  realtimeManagerRef: MutableRefObject<RealtimeManager | null>;
  getParticipantId: () => string;
  getNextSequence: () => number;
  isKeyExchangeComplete: boolean;
  isVerified: boolean;
  onRequireVerification: () => void;
  markActivity: () => void;
  buildFileAad: (args: { senderId: string; fileId: string }) => Uint8Array;
  addMessageToQueue: (sessionId: string, message: Omit<QueuedMessage, 'receivedAt' | 'acknowledged'>) => void;
  scheduleSyncMessagesFromQueue: () => void;
  getIsCapacitorNative: () => Promise<boolean>;
  fileTransferTtlMs: number;
}): {
  fileTransfersRef: MutableRefObject<Map<string, FileTransferState>>;
  downloadedVideoDrops: Set<string>;
  downloadedFileDrops: Set<string>;
  purgeActiveNativeVideoDropsBestEffort: () => void;
  destroyFileTransferState: () => void;
  handleRealtimeFileMessage: (payload: BroadcastPayload) => Promise<void>;
  handleFileUpload: (event: ChangeEvent<HTMLInputElement>) => void;
  handleVideoUpload: (event: ChangeEvent<HTMLInputElement>) => void;
  handleDownloadVideoDrop: (fileId: string) => Promise<void>;
  handleDownloadFileDrop: (fileId: string) => Promise<void>;
} {
  const {
    sessionId,
    encryptionEngineRef,
    realtimeManagerRef,
    getParticipantId,
    getNextSequence,
    isKeyExchangeComplete,
    isVerified,
    onRequireVerification,
    markActivity,
    buildFileAad,
    addMessageToQueue,
    scheduleSyncMessagesFromQueue,
    getIsCapacitorNative,
    fileTransferTtlMs,
  } = params;

  const fileTransfersRef = useRef<Map<string, FileTransferState>>(new Map());
  const pendingFileAcksRef = useRef<Map<string, (ok: boolean) => void>>(new Map());
  const seenFileAcksRef = useRef<Map<string, number>>(new Map());
  const activeNativeVideoDropIdsRef = useRef<Set<string>>(new Set());

  const [downloadedVideoDrops, setDownloadedVideoDrops] = useState<Set<string>>(new Set());
  const [downloadedFileDrops, setDownloadedFileDrops] = useState<Set<string>>(new Set());

  const waitForFileAckLocal = useCallback((key: string, timeoutMs: number): Promise<boolean> => {
    return waitForFileAck(pendingFileAcksRef.current, seenFileAcksRef.current, key, timeoutMs);
  }, []);

  const purgeFileTransferLocal = useCallback((fileId: string): void => {
    purgeFileTransfer(fileTransfersRef.current, fileId);
  }, []);

  const destroyFileTransferState = useCallback(() => {
    try {
      for (const fileId of fileTransfersRef.current.keys()) {
        purgeFileTransferLocal(fileId);
      }
    } catch {
    }

    try {
      pendingFileAcksRef.current.clear();
    } catch {
    }

    try {
      seenFileAcksRef.current.clear();
    } catch {
    }

    try {
      activeNativeVideoDropIdsRef.current.clear();
    } catch {
    }

    setDownloadedVideoDrops(new Set());
    setDownloadedFileDrops(new Set());
  }, [purgeFileTransferLocal]);

  const purgeActiveNativeVideoDropsBestEffort = useCallback(() => {
    const ids = Array.from(activeNativeVideoDropIdsRef.current);
    if (ids.length === 0) return;

    activeNativeVideoDropIdsRef.current.clear();

    void (async () => {
      try {
        if (isTauriRuntime()) {
          for (const id of ids) {
            try {
              await tauriInvoke('video_drop_purge', { id });
            } catch {
            }
          }
          return;
        }

        const mod = await import('@capacitor/core');
        if (mod.Capacitor?.isNativePlatform?.()) {
          const isPluginAvailableFn = (mod.Capacitor as any)?.isPluginAvailable;
          const pluginAvailable = typeof isPluginAvailableFn === 'function'
            ? Boolean(isPluginAvailableFn('VideoDrop'))
            : false;
          if (pluginAvailable) {
            const VideoDrop = mod.registerPlugin('VideoDrop') as {
              purge: (args: { id: string }) => Promise<{ ok?: boolean }>;
            };
            for (const id of ids) {
              try {
                await VideoDrop.purge({ id });
              } catch {
              }
            }
          }
        }
      } catch {
      }
    })();
  }, []);

  const handleRealtimeFileMessage = useCallback(async (payload: BroadcastPayload) => {
    const manager = realtimeManagerRef.current;
    if (!manager) return;

    try {
      markActivity();
      if (!encryptionEngineRef.current) return;

      const data: any = payload.data;
      if (!data || !data.fileId || !data.kind) return;

      if (data.kind === 'ack') {
        const fileId = String(data.fileId || '');
        if (!fileId) return;
        const ackKind = String(data.ackKind || '');
        if (ackKind === 'init') {
          const key = `${fileId}:init`;
          const resolver = pendingFileAcksRef.current.get(key);
          if (resolver) {
            pendingFileAcksRef.current.delete(key);
            resolver(true);
          } else {
            const seen = seenFileAcksRef.current;
            if (seen.size > 2048) {
              for (const k of Array.from(seen.keys()).slice(0, 512)) {
                seen.delete(k);
              }
            }
            seen.set(key, Date.now());
          }
          return;
        }

        if (ackKind === 'chunk') {
          const idx = Number(data.index);
          if (!Number.isFinite(idx) || idx < 0) return;
          const k = `${fileId}:${idx}`;
          const resolver = pendingFileAcksRef.current.get(k);
          if (resolver) {
            pendingFileAcksRef.current.delete(k);
            resolver(true);
          } else {
            const seen = seenFileAcksRef.current;
            if (seen.size > 2048) {
              for (const key of Array.from(seen.keys()).slice(0, 512)) {
                seen.delete(key);
              }
            }
            seen.set(k, Date.now());
          }
          return;
        }

        return;
      }

      if (data.kind === 'init') {
        const MAX_FILE_CHUNKS = 4096;
        const MAX_FILE_ID_CHARS = 128;
        const MAX_IV_CHARS = 256;
        const total = Math.max(0, Number(data.totalChunks) || 0);
        if (!Number.isFinite(total) || total <= 0 || total > MAX_FILE_CHUNKS) return;

        const fileId = String(data.fileId || '');
        if (fileId.length === 0 || fileId.length > MAX_FILE_ID_CHARS) return;

        const iv = String(data.iv || '');
        if (iv.length === 0 || iv.length > MAX_IV_CHARS) return;

        const sealedKind = String(data.sealedKind || '');
        const effectiveSealedKind = sealedKind === 'video-drop' ? 'video-drop' : 'file';

        const existing = fileTransfersRef.current.get(fileId);
        if (existing) {
          if (existing.cleanupTimer) {
            clearTimeout(existing.cleanupTimer);
          }

          existing.cleanupTimer = setTimeout(() => {
            purgeFileTransferLocal(fileId);
          }, fileTransferTtlMs);

          if (existing.received > 0) {
            if (existing.total !== total || existing.iv !== iv) {
            } else {
              existing.fileName = sanitizeFileName(String(data.fileName || existing.fileName || 'unknown_file')).slice(0, 256);
              existing.fileType = String(data.fileType || existing.fileType || 'application/octet-stream').slice(0, 128);
              if (effectiveSealedKind === 'video-drop') {
                existing.sealedKind = 'video-drop';
              }
              existing.timestamp = Number(data.timestamp) || existing.timestamp || payload.timestamp;
              existing.senderId = payload.senderId || existing.senderId;
            }

            void manager.send('file', { kind: 'ack', ackKind: 'init', fileId });
            return;
          }

          if (existing.total === total && existing.iv === iv) {
            existing.fileName = sanitizeFileName(String(data.fileName || existing.fileName || 'unknown_file')).slice(0, 256);
            existing.fileType = String(data.fileType || existing.fileType || 'application/octet-stream').slice(0, 128);
            existing.sealedKind = effectiveSealedKind;
            existing.timestamp = Number(data.timestamp) || existing.timestamp || payload.timestamp;
            existing.senderId = payload.senderId || existing.senderId;

            void manager.send('file', { kind: 'ack', ackKind: 'init', fileId });
            return;
          }
        }

        const cleanupTimer = setTimeout(() => {
          purgeFileTransferLocal(fileId);
        }, fileTransferTtlMs);

        fileTransfersRef.current.set(fileId, {
          chunks: new Array(total).fill(''),
          received: 0,
          total,
          iv,
          fileName: sanitizeFileName(String(data.fileName || 'unknown_file')).slice(0, 256),
          fileType: String(data.fileType || 'application/octet-stream').slice(0, 128),
          sealedKind: effectiveSealedKind,
          timestamp: Number(data.timestamp) || payload.timestamp,
          senderId: payload.senderId,
          cleanupTimer,
        });

        if (effectiveSealedKind === 'video-drop') {
          addMessageToQueue(sessionId, {
            id: fileId,
            content: '',
            sender: 'partner',
            timestamp: Number(data.timestamp) || payload.timestamp,
            type: 'video',
            fileName: sanitizeFileName(String(data.fileName || 'secure_video.mp4')).slice(0, 256),
          });
          scheduleSyncMessagesFromQueue();
        }

        if (effectiveSealedKind === 'file') {
          const current = fileTransfersRef.current.get(fileId);
          const isImage = current?.fileType.startsWith('image/') || /\.(jpg|jpeg|png)$/i.test(current?.fileName || '');
          const capNative = await getIsCapacitorNative();
          const shouldPlaceholder = (isTauriRuntime() || capNative) || !isImage;
          if (shouldPlaceholder) {
            addMessageToQueue(sessionId, {
              id: fileId,
              content: '',
              sender: 'partner',
              timestamp: Number(data.timestamp) || payload.timestamp,
              type: 'file',
              fileName: current?.fileName,
            });
            scheduleSyncMessagesFromQueue();
          }
        }

        void manager.send('file', { kind: 'ack', ackKind: 'init', fileId });
        return;
      }

      if (data.kind === 'chunk') {
        const MAX_FILE_CHUNKS = 4096;
        const MAX_CHUNK_CHARS = 20000;
        const MAX_FILE_ID_CHARS = 128;
        const MAX_IV_CHARS = 256;

        const fileId = String(data.fileId || '');
        if (fileId.length === 0 || fileId.length > MAX_FILE_ID_CHARS) return;

        let t = fileTransfersRef.current.get(fileId);
        if (!t) {
          const total = Math.max(0, Number(data.totalChunks) || 0);
          if (!Number.isFinite(total) || total <= 0 || total > MAX_FILE_CHUNKS) return;

          const iv = String(data.iv || '');
          if (iv.length === 0 || iv.length > MAX_IV_CHARS) return;

          const sealedKind = String(data.sealedKind || '');
          const effectiveSealedKind = sealedKind === 'video-drop' ? 'video-drop' : 'file';

          const cleanupTimer = setTimeout(() => {
            purgeFileTransferLocal(fileId);
          }, fileTransferTtlMs);

          t = {
            chunks: new Array(total).fill(''),
            received: 0,
            total,
            iv,
            fileName: sanitizeFileName(String(data.fileName || 'unknown_file')).slice(0, 256),
            fileType: String(data.fileType || 'application/octet-stream').slice(0, 128),
            sealedKind: effectiveSealedKind,
            timestamp: Number(data.timestamp) || payload.timestamp,
            senderId: payload.senderId,
            cleanupTimer,
          };
          fileTransfersRef.current.set(fileId, t);

          if (effectiveSealedKind === 'video-drop') {
            addMessageToQueue(sessionId, {
              id: fileId,
              content: '',
              sender: 'partner',
              timestamp: Number(data.timestamp) || payload.timestamp,
              type: 'video',
              fileName: sanitizeFileName(String(data.fileName || 'secure_video.mp4')).slice(0, 256),
            });
            scheduleSyncMessagesFromQueue();
          }

          if (effectiveSealedKind === 'file') {
            const isImage = t.fileType.startsWith('image/') || /\.(jpg|jpeg|png)$/i.test(t.fileName);
            const capNative = await getIsCapacitorNative();
            const shouldPlaceholder = (isTauriRuntime() || capNative) || !isImage;
            if (shouldPlaceholder) {
              addMessageToQueue(sessionId, {
                id: fileId,
                content: '',
                sender: 'partner',
                timestamp: t.timestamp,
                type: 'file',
                fileName: t.fileName,
              });
              scheduleSyncMessagesFromQueue();
            }
          }
        }

        try {
          const sealedKind = String(data.sealedKind || '');
          if (sealedKind === 'video-drop') {
            t.sealedKind = 'video-drop';
          }
        } catch {
        }
        const idx = Number(data.index);
        if (!Number.isFinite(idx) || idx < 0 || idx >= t.total) return;

        if (t.chunks[idx]) {
          void manager.send('file', { kind: 'ack', ackKind: 'chunk', fileId, index: idx });
          return;
        }

        const chunk = String(data.chunk || '');
        if (chunk.length === 0 || chunk.length > MAX_CHUNK_CHARS) {
          purgeFileTransferLocal(fileId);
          return;
        }

        if (t.cleanupTimer) {
          clearTimeout(t.cleanupTimer);
        }
        t.cleanupTimer = setTimeout(() => {
          purgeFileTransferLocal(fileId);
        }, fileTransferTtlMs);

        t.chunks[idx] = chunk;
        t.received += 1;

        void manager.send('file', { kind: 'ack', ackKind: 'chunk', fileId, index: idx });

        if (t.received >= t.total && t.total > 0) {
          if (t.sealedKind === 'video-drop') {
            scheduleSyncMessagesFromQueue();
            return;
          }

          const capNative = await getIsCapacitorNative();
          if (isTauriRuntime() || capNative) {
            scheduleSyncMessagesFromQueue();
            return;
          }

          if (t.sealedKind === 'file') {
            const isImage = t.fileType.startsWith('image/') || /\.(jpg|jpeg|png)$/i.test(t.fileName);
            if (!isImage) {
              scheduleSyncMessagesFromQueue();
              return;
            }
          }

          const encrypted = t.chunks.join('');
          const aad = buildFileAad({ senderId: t.senderId, fileId });
          const decrypted = await encryptionEngineRef.current.decryptBytes(encrypted, t.iv, aad);
          try {
            aad.fill(0);
          } catch {
          }
          const decryptedBytes = new Uint8Array(decrypted);

          const fileType = sniffMimeFromBytes(decryptedBytes) || 'application/octet-stream';
          const displayFileName = normalizeFileNameForMime(t.fileName, fileType);
          const displayTimestamp = t.timestamp;

          const blob = new Blob([decryptedBytes], { type: fileType || 'application/octet-stream' });
          const objectUrl = URL.createObjectURL(blob);
          decryptedBytes.fill(0);

          purgeFileTransferLocal(fileId);

          addMessageToQueue(sessionId, {
            id: fileId,
            content: objectUrl,
            sender: 'partner',
            timestamp: displayTimestamp,
            type: 'file',
            fileName: displayFileName,
          });
          scheduleSyncMessagesFromQueue();
        }

        if (t.sealedKind === 'video-drop') {
          if (t.received === 1 || t.received === t.total || t.received % 8 === 0) {
            scheduleSyncMessagesFromQueue();
          }
        }

        return;
      }
    } catch {
      toast.error('File transfer failed - please try again');
    }
  }, [addMessageToQueue, buildFileAad, encryptionEngineRef, fileTransferTtlMs, getIsCapacitorNative, markActivity, purgeFileTransferLocal, realtimeManagerRef, scheduleSyncMessagesFromQueue, sessionId]);

  const handleFileUpload = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    event.target.value = '';

    const validation = validateFile(file);
    if (!validation.valid) {
      toast.error(validation.error);
      return;
    }

    if (validation.warning) {
      toast.warning(validation.warning);
    }

    if (!encryptionEngineRef.current || !isKeyExchangeComplete) {
      toast.error('Secure connection not established yet');
      return;
    }

    if (!isVerified) {
      toast.error('Please verify security codes before sending files');
      onRequireVerification();
      return;
    }

    void (async () => {
      try {
        markActivity();
        const sanitizedName = sanitizeFileName(file.name);
        const messageId = generateSafeFileTransferId();

        const { displayTimestamp } = generatePlausibleTimestamp();

        const arrayBuffer = await file.arrayBuffer();
        const aad = buildFileAad({ senderId: getParticipantId(), fileId: messageId });
        const { encrypted, iv } = await encryptionEngineRef.current!.encryptBytes(arrayBuffer, aad);
        try {
          aad.fill(0);
        } catch {
        }

        try {
          const { secureZeroArrayBuffer } = await import('@/utils/algorithms/memory/zeroization');
          const crypto = window.crypto;
          secureZeroArrayBuffer({ getRandomValues: (arr) => crypto.getRandomValues(arr) }, arrayBuffer);
        } catch {
          try {
            new Uint8Array(arrayBuffer).fill(0);
          } catch {
          }
        }

        if (typeof URL === 'undefined' || typeof URL.createObjectURL !== 'function') {
          toast.error('File previews are not supported in this environment');
          return;
        }
        const objectUrl = URL.createObjectURL(file);

        addMessageToQueue(sessionId, {
          id: messageId,
          content: objectUrl,
          sender: 'me',
          timestamp: displayTimestamp,
          type: 'file',
          fileName: sanitizedName,
        });
        scheduleSyncMessagesFromQueue();

        const MAX_FILE_CHUNKS = 4096;
        const chunkSize = 16_000;
        const totalChunks = Math.ceil(encrypted.length / chunkSize);

        if (!Number.isFinite(totalChunks) || totalChunks <= 0 || totalChunks > MAX_FILE_CHUNKS) {
          toast.error('File too large to send');
          return;
        }

        let legacyPeer = false;
        let fastPathStartIndex = 0;

        const initAckPromise = waitForFileAckLocal(`${messageId}:init`, 6000);
        let sent = (await realtimeManagerRef.current?.send('file', {
          kind: 'init',
          fileId: messageId,
          fileName: sanitizedName,
          fileType: file.type,
          iv,
          totalChunks,
          timestamp: displayTimestamp,
        })) ?? false;

        if (!sent) {
          toast.error('File send failed at init (transport)');
          return;
        }

        if (sent) {
          const initAck = await initAckPromise;
          let ackCapable = initAck;

          if (!ackCapable && totalChunks > 0) {
            const probeChunk = encrypted.slice(0, chunkSize);
            const probeAckPromise = waitForFileAckLocal(`${messageId}:0`, 6000);
            const probeOk = (await realtimeManagerRef.current?.send('file', {
              kind: 'chunk',
              fileId: messageId,
              index: 0,
              chunk: probeChunk,
              totalChunks,
              iv,
              fileName: sanitizedName,
              fileType: file.type,
              timestamp: displayTimestamp,
            })) ?? false;

            if (probeOk) {
              ackCapable = await probeAckPromise;
              if (ackCapable) {
                fastPathStartIndex = 1;
              }
            }
          }

          legacyPeer = !ackCapable;
        }

        if (sent && legacyPeer && totalChunks <= 1) {
          const seq = getNextSequence();
          sent = (await realtimeManagerRef.current?.send('chat-message', {
            encrypted,
            iv,
            type: 'file',
            fileName: sanitizedName,
            fileType: file.type,
            messageId,
            sequence: seq,
          })) ?? false;
        }

        if (sent) {
          if (legacyPeer) {
            for (let i = 0; i < totalChunks; i++) {
              const chunk = encrypted.slice(i * chunkSize, (i + 1) * chunkSize);
              const ok = (await realtimeManagerRef.current?.send('file', {
                kind: 'chunk',
                fileId: messageId,
                index: i,
                chunk,
                totalChunks,
                iv,
                fileName: sanitizedName,
                fileType: file.type,
                timestamp: displayTimestamp,
              })) ?? false;

              if (!ok) {
                toast.error(`File send failed at chunk ${i + 1}/${totalChunks}`);
                sent = false;
                break;
              }

              try {
                await new Promise(resolve => setTimeout(resolve, 80));
              } catch {
              }
              await realtimeManagerRef.current?.send('file', {
                kind: 'chunk',
                fileId: messageId,
                index: i,
                chunk,
                totalChunks,
                iv,
                fileName: sanitizedName,
                fileType: file.type,
                timestamp: displayTimestamp,
              });
            }
          } else {
            const WINDOW = 6;
            type InFlight = { i: number; p: Promise<{ i: number; ok: boolean }> };

            const sendChunkWithRetry = async (i: number): Promise<boolean> => {
              const chunk = encrypted.slice(i * chunkSize, (i + 1) * chunkSize);
              for (let attempt = 0; attempt < 3; attempt++) {
                const ackPromise = waitForFileAckLocal(`${messageId}:${i}`, 6000);
                const ok = (await realtimeManagerRef.current?.send('file', {
                  kind: 'chunk',
                  fileId: messageId,
                  index: i,
                  chunk,
                  totalChunks,
                  iv,
                  fileName: sanitizedName,
                  fileType: file.type,
                  timestamp: displayTimestamp,
                })) ?? false;

                if (!ok) {
                  continue;
                }

                const ackOk = await ackPromise;
                if (ackOk) {
                  return true;
                }
              }
              return false;
            };

            let nextIndex = fastPathStartIndex;
            const inFlight: InFlight[] = [];
            const startChunk = (i: number): InFlight => {
              const p = (async () => ({ i, ok: await sendChunkWithRetry(i) }))();
              return { i, p };
            };

            while (nextIndex < totalChunks || inFlight.length > 0) {
              while (nextIndex < totalChunks && inFlight.length < WINDOW) {
                inFlight.push(startChunk(nextIndex));
                nextIndex += 1;
              }

              const res = await Promise.race(inFlight.map(x => x.p));
              const idx = inFlight.findIndex(x => x.i === res.i);
              if (idx >= 0) {
                inFlight.splice(idx, 1);
              }

              if (!res.ok) {
                toast.error(`File send failed at chunk ${res.i + 1}/${totalChunks}`);
                sent = false;
                break;
              }
            }
          }
        }

        if (!sent) {
          toast.error('File may not have been delivered');
        }
      } catch {
        toast.error('Failed to send file');
      }
    })();
  }, [addMessageToQueue, buildFileAad, encryptionEngineRef, getIsCapacitorNative, getNextSequence, getParticipantId, isKeyExchangeComplete, isVerified, markActivity, realtimeManagerRef, scheduleSyncMessagesFromQueue, sessionId, waitForFileAckLocal]);

  const handleVideoUpload = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    event.target.value = '';

    const validation = validateFile(file);
    if (!validation.valid) {
      toast.error(validation.error);
      return;
    }

    const lowerName = (file.name || '').toLowerCase();
    const isMp4 = file.type === 'video/mp4' || lowerName.endsWith('.mp4');
    if (!isMp4) {
      toast.error('Only MP4 videos are supported');
      return;
    }

    if (validation.warning) {
      toast.warning(validation.warning);
    }

    if (!encryptionEngineRef.current || !isKeyExchangeComplete) {
      toast.error('Secure connection not established yet');
      return;
    }

    if (!isVerified) {
      toast.error('Please verify security codes before sending videos');
      onRequireVerification();
      return;
    }

    void (async () => {
      try {
        markActivity();
        const sanitizedName = sanitizeFileName(file.name);
        const messageId = generateSafeFileTransferId();

        const { displayTimestamp } = generatePlausibleTimestamp();

        const arrayBuffer = await file.arrayBuffer();
        const aad = buildFileAad({ senderId: getParticipantId(), fileId: messageId });
        const { encrypted, iv } = await encryptionEngineRef.current!.encryptBytes(arrayBuffer, aad);
        try {
          aad.fill(0);
        } catch {
        }

        try {
          const { secureZeroArrayBuffer } = await import('@/utils/algorithms/memory/zeroization');
          const crypto = window.crypto;
          secureZeroArrayBuffer({ getRandomValues: (arr) => crypto.getRandomValues(arr) }, arrayBuffer);
        } catch {
          try {
            new Uint8Array(arrayBuffer).fill(0);
          } catch {
          }
        }

        addMessageToQueue(sessionId, {
          id: messageId,
          content: '',
          sender: 'me',
          timestamp: displayTimestamp,
          type: 'video',
          fileName: sanitizedName,
        });
        scheduleSyncMessagesFromQueue();

        const MAX_FILE_CHUNKS = 4096;
        const chunkSize = 16_000;
        const totalChunks = Math.ceil(encrypted.length / chunkSize);

        if (!Number.isFinite(totalChunks) || totalChunks <= 0 || totalChunks > MAX_FILE_CHUNKS) {
          toast.error('Video too large to send');
          return;
        }

        const sentInit = (await realtimeManagerRef.current?.send('file', {
          kind: 'init',
          fileId: messageId,
          fileName: sanitizedName,
          fileType: 'video/mp4',
          sealedKind: 'video-drop',
          iv,
          totalChunks,
          timestamp: displayTimestamp,
        })) ?? false;

        if (!sentInit) {
          toast.error('Video send failed at init (transport)');
          return;
        }

        const initAck = await waitForFileAckLocal(`${messageId}:init`, 4000);
        if (!initAck) {
          toast.warning('Receiver may be slow to acknowledge; continuing...');
        }

        const WINDOW = 6;
        type InFlight = { i: number; p: Promise<{ i: number; ok: boolean }> };
        const sendChunkWithRetry = async (i: number): Promise<boolean> => {
          const chunk = encrypted.slice(i * chunkSize, (i + 1) * chunkSize);
          for (let attempt = 0; attempt < 3; attempt++) {
            const ackPromise = waitForFileAckLocal(`${messageId}:${i}`, 12000);
            const ok = (await realtimeManagerRef.current?.send('file', {
              kind: 'chunk',
              fileId: messageId,
              index: i,
              chunk,
              totalChunks,
              fileName: sanitizedName,
              fileType: 'video/mp4',
              sealedKind: 'video-drop',
              iv,
              timestamp: displayTimestamp,
            })) ?? false;

            if (!ok) {
              continue;
            }

            const ackOk = await ackPromise;
            if (ackOk) {
              return true;
            }
          }

          return false;
        };

        let nextIndex = 0;
        const inFlight: InFlight[] = [];
        const startChunk = (i: number): InFlight => {
          const p = (async () => ({ i, ok: await sendChunkWithRetry(i) }))();
          return { i, p };
        };

        while (nextIndex < totalChunks || inFlight.length > 0) {
          while (nextIndex < totalChunks && inFlight.length < WINDOW) {
            inFlight.push(startChunk(nextIndex));
            nextIndex += 1;
          }

          const res = await Promise.race(inFlight.map(x => x.p));
          const idx = inFlight.findIndex(x => x.i === res.i);
          if (idx >= 0) {
            inFlight.splice(idx, 1);
          }

          if (!res.ok) {
            toast.error(`Video send failed at chunk ${res.i + 1}/${totalChunks}`);
            return;
          }
        }
      } catch {
        toast.error('Failed to send video');
      }
    })();
  }, [addMessageToQueue, buildFileAad, encryptionEngineRef, getParticipantId, getIsCapacitorNative, isKeyExchangeComplete, isVerified, markActivity, realtimeManagerRef, scheduleSyncMessagesFromQueue, sessionId, waitForFileAckLocal]);

  const handleDownloadVideoDrop = useCallback(async (fileId: string) => {
    try {
      if (!encryptionEngineRef.current) {
        toast.error('Download failed');
        return;
      }

      let preOpened: Window | null = null;
      let likelyMobile = false;
      let preferWebShare = false;
      try {
        if (!isTauriRuntime() && typeof window !== 'undefined' && typeof navigator !== 'undefined') {
          const ua = String(navigator.userAgent || '');
          likelyMobile = /Android|iPhone|iPad|iPod/i.test(ua);
          if (likelyMobile) {
            try {
              const nav: any = navigator;
              if (typeof nav.share === 'function' && typeof File !== 'undefined') {
                if (typeof nav.canShare === 'function') {
                  try {
                    const probe = new File([], 'probe.mp4', { type: 'video/mp4' });
                    preferWebShare = !!nav.canShare({ files: [probe] });
                  } catch {
                    preferWebShare = true;
                  }
                } else {
                  preferWebShare = true;
                }
              }
            } catch {
              preferWebShare = false;
            }

            if (!preferWebShare && typeof window.open === 'function') {
              preOpened = window.open('about:blank', '_blank');
            }
          }
        }
      } catch {
      }

      const t = fileTransfersRef.current.get(fileId);
      if (!t) {
        toast.error('Video not available');
        return;
      }
      if (t.sealedKind !== 'video-drop' || t.total <= 0) {
        toast.error('Download failed');
        return;
      }
      if (t.received < t.total) {
        toast.info(`Video still receiving (${t.received}/${t.total})`);
        return;
      }

      const encrypted = t.chunks.join('');
      const aad = buildFileAad({ senderId: t.senderId, fileId });
      const decrypted = await encryptionEngineRef.current.decryptBytes(encrypted, t.iv, aad);
      try {
        aad.fill(0);
      } catch {
      }

      const decryptedBytes = new Uint8Array(decrypted);

      const fileName = t.fileName || 'secure_video.mp4';
      const nativeId = makeNativeDropId(fileId);

      let handledNative = false;
      let nativeFailed = false;
      try {
        if (isTauriRuntime()) {
          try {
            await tauriInvoke('video_drop_start', { id: nativeId, file_name: fileName });
            const chunkBytes = 48 * 1024;
            for (let i = 0; i < decryptedBytes.length; i += chunkBytes) {
              const slice = decryptedBytes.slice(i, Math.min(decryptedBytes.length, i + chunkBytes));
              const chunkBase64 = bytesToBase64(slice);
              try {
                slice.fill(0);
              } catch {
              }
              await tauriInvoke('video_drop_append', { id: nativeId, chunk_base64: chunkBase64 });
            }
            await tauriInvoke('video_drop_finish_open', { id: nativeId, mime_type: 'video/mp4' });
            try {
              await tauriInvoke('video_drop_purge', { id: nativeId });
            } catch {
            }
            activeNativeVideoDropIdsRef.current.add(nativeId);
            handledNative = true;
            toast.success('Video saved');
          } catch {
          }
        } else {
          let isNativePlatform = false;
          let pluginAvailable = false;
          try {
            const mod = await import('@capacitor/core');
            isNativePlatform = Boolean(mod.Capacitor?.isNativePlatform?.());
            const isPluginAvailableFn = (mod.Capacitor as any)?.isPluginAvailable;
            pluginAvailable = isNativePlatform && typeof isPluginAvailableFn === 'function'
              ? Boolean(isPluginAvailableFn('VideoDrop'))
              : false;

            if (pluginAvailable) {
              const VideoDrop = mod.registerPlugin('VideoDrop') as {
                start: (args: { id: string; fileName: string; mimeType: string }) => Promise<{ ok?: boolean }>;
                append: (args: { id: string; chunkBase64: string }) => Promise<{ ok?: boolean }>;
                finishAndOpen: (args: { id: string; mimeType: string }) => Promise<{ ok?: boolean; uri?: string; savedToDownloads?: boolean }>;
                purge: (args: { id: string }) => Promise<{ ok?: boolean }>;
              };
              await VideoDrop.start({ id: nativeId, fileName, mimeType: 'video/mp4' });
              const chunkBytes = 48 * 1024;
              for (let i = 0; i < decryptedBytes.length; i += chunkBytes) {
                const slice = decryptedBytes.slice(i, Math.min(decryptedBytes.length, i + chunkBytes));
                const chunkBase64 = bytesToBase64(slice);
                try {
                  slice.fill(0);
                } catch {
                }
                await VideoDrop.append({ id: nativeId, chunkBase64 });
              }
              const finishRes = await VideoDrop.finishAndOpen({ id: nativeId, mimeType: 'video/mp4' });
              if (!finishRes?.savedToDownloads) {
                throw new Error('save failed');
              }
              activeNativeVideoDropIdsRef.current.add(nativeId);
              handledNative = true;
              toast.success('Video saved');
            }
          } catch {
            nativeFailed = Boolean(isNativePlatform && pluginAvailable);
          }
        }
      } finally {
        if (handledNative) {
          try {
            decryptedBytes.fill(0);
          } catch {
          }
        }
      }

      if (nativeFailed) {
        toast.error('Download failed');
        return;
      }

      if (!handledNative) {
        const blob = new Blob([decryptedBytes], { type: 'video/mp4' });

        let handledWeb = false;
        if (likelyMobile && typeof navigator !== 'undefined') {
          try {
            const nav: any = navigator;
            if (typeof nav.share === 'function' && typeof File !== 'undefined') {
              const f = new File([blob], fileName, { type: 'video/mp4' });
              if (typeof nav.canShare === 'function') {
                if (nav.canShare({ files: [f] })) {
                  await nav.share({ files: [f], title: fileName });
                  handledWeb = true;
                }
              } else {
                await nav.share({ files: [f], title: fileName });
                handledWeb = true;
              }
            }
          } catch {
          }
        }

        if (handledWeb) {
          try {
            decryptedBytes.fill(0);
          } catch {
          }

          if (preOpened) {
            try {
              preOpened.close();
            } catch {
            }
            preOpened = null;
          }
        } else {
          const objectUrl = URL.createObjectURL(blob);

          if (typeof document === 'undefined') {
            try {
              URL.revokeObjectURL(objectUrl);
            } catch {
            }
            toast.error('Download failed');
            return;
          }

          if (preOpened) {
            try {
              preOpened.location.href = objectUrl;
              toast.success('Video opened');
            } catch {
              try {
                preOpened.close();
              } catch {
              }
              preOpened = null;
            }
          }

          if (preOpened) {
            try {
              decryptedBytes.fill(0);
            } catch {
            }
            setTimeout(() => {
              try {
                URL.revokeObjectURL(objectUrl);
              } catch {
              }
            }, 5 * 60 * 1000);
          } else {
            if (likelyMobile && typeof window !== 'undefined') {
              let opened: Window | null = null;
              try {
                opened = window.open(objectUrl, '_blank');
              } catch {
                opened = null;
              }

              if (!opened) {
                try {
                  window.location.href = objectUrl;
                  toast.success('Video opened');
                } catch {
                }
              } else {
                toast.success('Video opened');
              }
            }

            if (!likelyMobile || (typeof window !== 'undefined' && typeof window.location !== 'undefined' && String(window.location.href).startsWith('blob:') === false)) {
              const link = document.createElement('a');
              link.href = objectUrl;
              link.download = fileName;
              link.target = '_blank';
              link.rel = 'noopener noreferrer';
              link.style.display = 'none';
              document.body.appendChild(link);
              try {
                link.click();
              } finally {
                try {
                  document.body.removeChild(link);
                } catch {
                }
              }
            }

            try {
              decryptedBytes.fill(0);
            } catch {
            }
            setTimeout(() => {
              try {
                URL.revokeObjectURL(objectUrl);
              } catch {
              }
            }, 30 * 1000);
          }
        }
      }

      purgeFileTransferLocal(fileId);
      setDownloadedVideoDrops(prev => {
        const next = new Set(prev);
        next.add(fileId);
        return next;
      });
    } catch {
      toast.error('Download failed');
    }
  }, [buildFileAad, encryptionEngineRef, purgeFileTransferLocal]);

  const handleDownloadFileDrop = useCallback(async (fileId: string) => {
    try {
      if (!encryptionEngineRef.current) {
        toast.error('Download failed');
        return;
      }

      const t = fileTransfersRef.current.get(fileId);
      if (!t) {
        toast.error('Download failed');
        return;
      }
      if (t.sealedKind !== 'file' || t.total <= 0) {
        toast.error('Download failed');
        return;
      }
      if (t.received < t.total) {
        toast.info(`File still receiving (${t.received}/${t.total})`);
        return;
      }

      const encrypted = t.chunks.join('');
      const aad = buildFileAad({ senderId: t.senderId, fileId });
      const decrypted = await encryptionEngineRef.current.decryptBytes(encrypted, t.iv, aad);
      try {
        aad.fill(0);
      } catch {
      }

      const decryptedBytes = new Uint8Array(decrypted);
      const sniffedType = sniffMimeFromBytes(decryptedBytes) || t.fileType || 'application/octet-stream';
      const fileName = normalizeFileNameForMime(t.fileName || 'download', sniffedType);
      const nativeId = makeNativeDropId(fileId);

      let handledNative = false;
      let nativeFailed = false;
      try {
        if (isTauriRuntime()) {
          try {
            await tauriInvoke('file_drop_start', { id: nativeId, file_name: fileName });
            const chunkBytes = 48 * 1024;
            for (let i = 0; i < decryptedBytes.length; i += chunkBytes) {
              const slice = decryptedBytes.slice(i, Math.min(decryptedBytes.length, i + chunkBytes));
              const chunkBase64 = bytesToBase64(slice);
              try {
                slice.fill(0);
              } catch {
              }
              await tauriInvoke('file_drop_append', { id: nativeId, chunk_base64: chunkBase64 });
            }
            await tauriInvoke('file_drop_finish_open', { id: nativeId, mime_type: sniffedType });
            try {
              await tauriInvoke('file_drop_purge', { id: nativeId });
            } catch {
            }
            handledNative = true;
            toast.success('File saved');
          } catch {
          }
        } else {
          let isNativePlatform = false;
          let pluginAvailable = false;
          try {
            const mod = await import('@capacitor/core');
            isNativePlatform = Boolean(mod.Capacitor?.isNativePlatform?.());
            const isPluginAvailableFn = (mod.Capacitor as any)?.isPluginAvailable;
            pluginAvailable = isNativePlatform && typeof isPluginAvailableFn === 'function'
              ? Boolean(isPluginAvailableFn('VideoDrop'))
              : false;

            if (pluginAvailable) {
              const VideoDrop = mod.registerPlugin('VideoDrop') as {
                start: (args: { id: string; fileName: string; mimeType: string }) => Promise<{ ok?: boolean }>;
                append: (args: { id: string; chunkBase64: string }) => Promise<{ ok?: boolean }>;
                finishAndOpen: (args: { id: string; mimeType: string }) => Promise<{ ok?: boolean; uri?: string; savedToDownloads?: boolean }>;
                purge: (args: { id: string }) => Promise<{ ok?: boolean }>;
              };
              await VideoDrop.start({ id: nativeId, fileName, mimeType: sniffedType });
              const chunkBytes = 48 * 1024;
              for (let i = 0; i < decryptedBytes.length; i += chunkBytes) {
                const slice = decryptedBytes.slice(i, Math.min(decryptedBytes.length, i + chunkBytes));
                const chunkBase64 = bytesToBase64(slice);
                try {
                  slice.fill(0);
                } catch {
                }
                await VideoDrop.append({ id: nativeId, chunkBase64 });
              }
              const finishRes = await VideoDrop.finishAndOpen({ id: nativeId, mimeType: sniffedType });
              if (!finishRes?.savedToDownloads) {
                throw new Error('save failed');
              }
              activeNativeVideoDropIdsRef.current.add(nativeId);
              handledNative = true;
              toast.success('File saved');
            }
          } catch {
            nativeFailed = Boolean(isNativePlatform && pluginAvailable);
          }
        }
      } finally {
        if (handledNative) {
          try {
            decryptedBytes.fill(0);
          } catch {
          }
        }
      }

      if (nativeFailed) {
        toast.error('Download failed');
        return;
      }

      if (!handledNative) {
        const blob = new Blob([decryptedBytes], { type: sniffedType || 'application/octet-stream' });
        const objectUrl = URL.createObjectURL(blob);
        try {
          if (typeof document === 'undefined') {
            toast.error('Download failed');
            return;
          }
          const link = document.createElement('a');
          link.href = objectUrl;
          link.download = fileName;
          link.target = '_blank';
          link.rel = 'noopener noreferrer';
          link.style.display = 'none';
          document.body.appendChild(link);
          try {
            link.click();
          } finally {
            try {
              document.body.removeChild(link);
            } catch {
            }
          }
          toast.success('File downloaded');
        } finally {
          try {
            decryptedBytes.fill(0);
          } catch {
          }
          setTimeout(() => {
            try {
              URL.revokeObjectURL(objectUrl);
            } catch {
            }
          }, 30 * 1000);
        }
      }

      purgeFileTransferLocal(fileId);
      setDownloadedFileDrops(prev => {
        const next = new Set(prev);
        next.add(fileId);
        return next;
      });
    } catch {
      toast.error('Download failed');
    }
  }, [buildFileAad, encryptionEngineRef]);

  return {
    fileTransfersRef,
    downloadedVideoDrops,
    downloadedFileDrops,
    purgeActiveNativeVideoDropsBestEffort,
    destroyFileTransferState,
    handleRealtimeFileMessage,
    handleFileUpload,
    handleVideoUpload,
    handleDownloadVideoDrop,
    handleDownloadFileDrop,
  };
}
