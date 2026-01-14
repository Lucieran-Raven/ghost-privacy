import { useState, useEffect, useRef, useCallback, type ChangeEvent, type KeyboardEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Ghost, Send, Paperclip, Shield, X, Loader2, Trash2, HardDrive, FileText, FileSpreadsheet, FileImage, FileArchive, FileCode, File, AlertTriangle, Clock, Download } from 'lucide-react';
import { toast } from 'sonner';
import { EncryptionEngine, KeyExchange, generateNonce } from '@/utils/encryption';
import { SecurityManager, validateMessage, validateFile, sanitizeFileName } from '@/utils/security';
import { checkOrPinFingerprint } from '@/utils/tofuFingerprintStore';
import { RealtimeManager, BroadcastPayload, ConnectionState } from '@/lib/realtimeManager';
import { SessionService } from '@/lib/sessionService';
import { getMessageQueue, QueuedMessage } from '@/utils/clientMessageQueue';
import { cn } from '@/lib/utils';
import { generatePlausibleTimestamp, isTimestampObfuscationEnabled } from '@/utils/plausibleTimestamp';
import { useMemoryCleanup } from '@/hooks/useMemoryCleanup';
import { isTauriRuntime, tauriInvoke } from '@/utils/runtime';
import { base64ToBytes, bytesToBase64 } from '@/utils/algorithms/encoding/base64';
import { secureZeroUint8Array } from '@/utils/algorithms/memory/zeroization';
import KeyVerificationModal from './KeyVerificationModal';
import VoiceRecorder from './VoiceRecorder';
import VoiceMessage from './VoiceMessage';
import FilePreviewCard from './FilePreviewCard';
import TimestampSettings from './TimestampSettings';

interface ChatInterfaceProps {
  sessionId: string;
  capabilityToken: string;
  isHost: boolean;
  timerMode: string;
  onEndSession: (showToast?: boolean) => void;
}

type TerminationReason = 'partner_left' | 'connection_lost' | 'channel_dead' | 'manual';

interface VerificationState {
  show: boolean;
  localFingerprint: string;
  remoteFingerprint: string;
  verified: boolean;
}

interface VoiceMessageData {
  id: string;
  blob: Blob;
  duration: number;
  sender: 'me' | 'partner';
  timestamp: number;
  played: boolean;
}

const ChatInterface = ({ sessionId, capabilityToken, isHost, timerMode, onEndSession }: ChatInterfaceProps) => {
  const navigate = useNavigate();
  const { fullCleanup } = useMemoryCleanup();

  const [messages, setMessages] = useState<QueuedMessage[]>([]);
  const [inputText, setInputText] = useState('');
  const [isPartnerConnected, setIsPartnerConnected] = useState(false);
  const [connectionState, setConnectionState] = useState<ConnectionState>({ status: 'connecting', progress: 0 });
  const [isKeyExchangeComplete, setIsKeyExchangeComplete] = useState(false);
  const [memoryStats, setMemoryStats] = useState({ messageCount: 0, estimatedBytes: 0 });
  const [verificationState, setVerificationState] = useState<VerificationState>({
    show: false,
    localFingerprint: '',
    remoteFingerprint: '',
    verified: false
  });
  const [voiceMessages, setVoiceMessages] = useState<VoiceMessageData[]>([]);
  const [voiceVerified, setVoiceVerified] = useState(false);
  const [isWindowVisible, setIsWindowVisible] = useState(true);
  const [showTimestampSettings, setShowTimestampSettings] = useState(false);
  const sessionKeyRef = useRef<CryptoKey | null>(null);

  const realtimeManagerRef = useRef<RealtimeManager | null>(null);
  const encryptionEngineRef = useRef<EncryptionEngine | null>(null);
  const keyPairRef = useRef<CryptoKeyPair | null>(null);
  const partnerPublicKeyRef = useRef<CryptoKey | null>(null);
  const participantIdRef = useRef<string>('');
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messageAreaRef = useRef<HTMLElement>(null);
  const inputBarRef = useRef<HTMLElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const messageQueueRef = useRef(getMessageQueue());
  const partnerWasPresentRef = useRef(false);
  const partnerDisconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const autoTerminateTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const focusScrollTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const partnerCountRef = useRef<number>(0);
  const partnerUnstableShownRef = useRef(false);
  const inactivityIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const lastActivityRef = useRef<number>(Date.now());
  const fileTransfersRef = useRef<Map<string, { chunks: string[]; received: number; total: number; iv: string; fileName: string; fileType: string; timestamp: number; cleanupTimer: ReturnType<typeof setTimeout> | null }>>(new Map());
  const pendingFileAcksRef = useRef<Map<string, (ok: boolean) => void>>(new Map());
  const localFingerprintRef = useRef<string>('');
  const isTerminatingRef = useRef(false);
  const verificationShownRef = useRef(false);
  const systemMessagesShownRef = useRef<Set<string>>(new Set());
  const lastTerminationRef = useRef<number>(0);

  const lastPublicKeySendRef = useRef<number>(0);
  const publicKeyResendIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const publicKeyResendAttemptsRef = useRef<number>(0);
  const isKeyExchangeCompleteRef = useRef<boolean>(false);

  const markActivity = () => {
    lastActivityRef.current = Date.now();
  };

  const MAX_VOICE_MESSAGES = 50;

  const waitForFileAck = (key: string, timeoutMs: number): Promise<boolean> => {
    return new Promise((resolve) => {
      pendingFileAcksRef.current.set(key, resolve);

      setTimeout(() => {
        const resolver = pendingFileAcksRef.current.get(key);
        if (resolver) {
          pendingFileAcksRef.current.delete(key);
          resolver(false);
        }
      }, timeoutMs);
    });
  };

  const purgeFileTransfer = (fileId: string): void => {
    const t = fileTransfersRef.current.get(fileId);
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
    t.timestamp = 0;
    t.cleanupTimer = null;

    fileTransfersRef.current.delete(fileId);
  };

  const sniffMimeFromBytes = (bytes: Uint8Array): string | null => {
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
  };

  const normalizeFileNameForMime = (safeFileName: string, mime: string | null): string => {
    if (!mime) return safeFileName;
    const extByMime: Record<string, string> = {
      'application/pdf': 'pdf',
      'image/png': 'png',
      'image/jpeg': 'jpg',
      'image/gif': 'gif',
      'image/webp': 'webp'
    };
    const desiredExt = extByMime[mime];
    if (!desiredExt) return safeFileName;

    const idx = safeFileName.lastIndexOf('.');
    const currentExt = idx >= 0 ? safeFileName.slice(idx + 1).toLowerCase() : '';
    if (currentExt === desiredExt) return safeFileName;

    const base = idx >= 0 ? safeFileName.slice(0, idx) : safeFileName;
    return `${base}.${desiredExt}`.slice(0, 256);
  };

  const syncMessagesFromQueue = useCallback(() => {
    const queuedMessages = messageQueueRef.current.getMessages(sessionId);
    setMessages([...queuedMessages]);
    setMemoryStats(messageQueueRef.current.getMemoryStats(sessionId));
  }, [sessionId]);

  useEffect(() => {
    try {
      SecurityManager.setCapabilityToken(sessionId, capabilityToken);
    } catch {
      // Ignore
    }

    initializeSession();

    return () => {
      try {
        void SessionService.deleteSession(sessionId, capabilityToken);
      } catch {
        // Ignore
      }
      try {
        void fullCleanup();
      } catch {
        // Ignore
      }
      void cleanup();
    };
  }, [sessionId, capabilityToken]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    const scrollToBottom = () => {
      requestAnimationFrame(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
      });
    };

    if (typeof window !== 'undefined' && window.visualViewport) {
      window.visualViewport.addEventListener('resize', scrollToBottom);
    }

    return () => {
      if (typeof window !== 'undefined' && window.visualViewport) {
        window.visualViewport.removeEventListener('resize', scrollToBottom);
      }
    };
  }, []);

  useEffect(() => {
    const handleVisibilityChange = () => {
      if (typeof document === 'undefined') return;
      setIsWindowVisible(!document.hidden);
    };

    const handleBlur = () => {
      setIsWindowVisible(false);
    };

    const handleFocus = () => {
      setIsWindowVisible(true);
    };

    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', handleVisibilityChange);
    }
    if (typeof window !== 'undefined') {
      window.addEventListener('blur', handleBlur);
      window.addEventListener('focus', handleFocus);
    }

    return () => {
      if (typeof document !== 'undefined') {
        document.removeEventListener('visibilitychange', handleVisibilityChange);
      }
      if (typeof window !== 'undefined') {
        window.removeEventListener('blur', handleBlur);
        window.removeEventListener('focus', handleFocus);
      }
    };
  }, []);

  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = 'Leave Ghost session? Click "End Session" to properly terminate.';
      return e.returnValue;
    };

    if (typeof window !== 'undefined') {
      window.addEventListener('beforeunload', handleBeforeUnload);
      return () => window.removeEventListener('beforeunload', handleBeforeUnload);
    }
    return;
  }, [sessionId]);

  useEffect(() => {
    isKeyExchangeCompleteRef.current = isKeyExchangeComplete;
  }, [isKeyExchangeComplete]);

  const stopPublicKeyResend = () => {
    if (publicKeyResendIntervalRef.current) {
      clearInterval(publicKeyResendIntervalRef.current);
      publicKeyResendIntervalRef.current = null;
    }
    publicKeyResendAttemptsRef.current = 0;
  };

  const startPublicKeyResend = () => {
    stopPublicKeyResend();

    publicKeyResendAttemptsRef.current = 0;
    publicKeyResendIntervalRef.current = setInterval(() => {
      if (isTerminatingRef.current) {
        stopPublicKeyResend();
        return;
      }

      if (partnerPublicKeyRef.current || isKeyExchangeCompleteRef.current) {
        stopPublicKeyResend();
        return;
      }

      publicKeyResendAttemptsRef.current += 1;
      void sendPublicKey();

      if (publicKeyResendAttemptsRef.current >= 6) {
        stopPublicKeyResend();
      }
    }, 2000);
  };

  useEffect(() => {
    const handlePageHide = () => {
      try {
        destroyLocalSessionData();
      } catch {
        // Ignore
      }

      try {
        SessionService.clearValidationCache(sessionId);
      } catch {
        // Ignore
      }
    };

    if (typeof window !== 'undefined') {
      window.addEventListener('pagehide', handlePageHide);
      window.addEventListener('unload', handlePageHide);
      return () => {
        window.removeEventListener('pagehide', handlePageHide);
        window.removeEventListener('unload', handlePageHide);
      };
    }
    return;
  }, [sessionId]);

  const initializeSession = async () => {
    try {
      setConnectionState({ status: 'validating', progress: 10 });

      if (isHost) {
        const valid = await SessionService.validateSession(sessionId, capabilityToken, 'host');
        if (!valid) {
          setConnectionState({ status: 'error', progress: 0, error: 'Invalid or expired session' });
          toast.error('Invalid or expired session');
          return;
        }
      }

      verificationShownRef.current = false;
      localFingerprintRef.current = '';
      partnerPublicKeyRef.current = null;
      sessionKeyRef.current = null;
      stopPublicKeyResend();
      setVerificationState({
        show: false,
        localFingerprint: '',
        remoteFingerprint: '',
        verified: false
      });

      participantIdRef.current = await SecurityManager.generateFingerprint();
      encryptionEngineRef.current = new EncryptionEngine();

      setConnectionState({ status: 'connecting', progress: 30 });

      keyPairRef.current = await KeyExchange.generateKeyPair();
      realtimeManagerRef.current = new RealtimeManager(sessionId, capabilityToken, participantIdRef.current);

      setupMessageHandlers();

      setConnectionState({ status: 'subscribing', progress: 60 });

      await realtimeManagerRef.current.connect();

      // Realtime broadcasts are not queued. If the peer sent their public key before we subscribed,
      // we will miss it. Re-announce our public key for a short window to make the handshake reliable.
      startPublicKeyResend();

      markActivity();

      if (inactivityIntervalRef.current) {
        clearInterval(inactivityIntervalRef.current);
      }
      inactivityIntervalRef.current = setInterval(() => {
        const now = Date.now();
        if (now - lastActivityRef.current >= 10 * 60 * 1000 && !isTerminatingRef.current) {
          void triggerSessionTermination('channel_dead');
        }
      }, 60 * 1000);

      addSystemMessage('🔐 Secure connection established');

    } catch {
      setConnectionState({ status: 'error', progress: 0, error: 'Connection failed' });
      toast.error('Failed to connect to session');
    }
  };

  const setupMessageHandlers = () => {
    const manager = realtimeManagerRef.current;
    if (!manager) return;

    manager.onStatusChange((newState) => {
      setConnectionState(newState);
      if (newState.status === 'connected') {
        sendPublicKey();
        startPublicKeyResend();
      }
    });

    // Handle partner join/leave via presence
    manager.onPresenceChange((participants) => {
      const partnerCount = Math.max(0, participants.length - 1); // Exclude self
      setIsPartnerConnected(partnerCount > 0);
      
      if (partnerCount === 0 && partnerWasPresentRef.current) {
        addSystemMessage('👋 Partner left the session');
      }
    });

    manager.onMessage('file', async (payload) => {
      try {
        markActivity();
        if (!encryptionEngineRef.current) return;

        const data = payload.data;
        if (!data || !data.fileId || !data.kind) return;

        if (data.kind === 'ack') {
          const fileId = String(data.fileId || '');
          if (!fileId) return;
          const ackKind = String(data.ackKind || '');
          if (ackKind === 'init') {
            const resolver = pendingFileAcksRef.current.get(`${fileId}:init`);
            if (resolver) {
              pendingFileAcksRef.current.delete(`${fileId}:init`);
              resolver(true);
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
            }
            return;
          }

          return;
        }

        if (data.kind === 'init') {
          const MAX_FILE_CHUNKS = 512;
          const MAX_FILE_ID_CHARS = 128;
          const MAX_IV_CHARS = 256;
          const total = Math.max(0, Number(data.totalChunks) || 0);
          if (!Number.isFinite(total) || total <= 0 || total > MAX_FILE_CHUNKS) return;

          const fileId = String(data.fileId || '');
          if (fileId.length === 0 || fileId.length > MAX_FILE_ID_CHARS) return;

          const iv = String(data.iv || '');
          if (iv.length === 0 || iv.length > MAX_IV_CHARS) return;

          const existing = fileTransfersRef.current.get(fileId);
          if (existing?.cleanupTimer) {
            clearTimeout(existing.cleanupTimer);
          }

          const cleanupTimer = setTimeout(() => {
            purgeFileTransfer(fileId);
          }, 5 * 60 * 1000);

          fileTransfersRef.current.set(fileId, {
            chunks: new Array(total).fill(''),
            received: 0,
            total,
            iv,
            fileName: sanitizeFileName(String(data.fileName || 'unknown_file')).slice(0, 256),
            fileType: String(data.fileType || 'application/octet-stream').slice(0, 128),
            timestamp: Number(data.timestamp) || payload.timestamp,
            cleanupTimer
          });

          await manager.send('file', { kind: 'ack', ackKind: 'init', fileId });
          return;
        }

        if (data.kind === 'chunk') {
          const MAX_FILE_CHUNKS = 512;
          const MAX_CHUNK_CHARS = 60000;
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

            const cleanupTimer = setTimeout(() => {
              purgeFileTransfer(fileId);
            }, 5 * 60 * 1000);

            t = {
              chunks: new Array(total).fill(''),
              received: 0,
              total,
              iv,
              fileName: sanitizeFileName(String(data.fileName || 'unknown_file')).slice(0, 256),
              fileType: String(data.fileType || 'application/octet-stream').slice(0, 128),
              timestamp: Number(data.timestamp) || payload.timestamp,
              cleanupTimer
            };
            fileTransfersRef.current.set(fileId, t);
          }
          const idx = Number(data.index);
          if (!Number.isFinite(idx) || idx < 0 || idx >= t.total) return;

          if (t.chunks[idx]) {
            await manager.send('file', { kind: 'ack', ackKind: 'chunk', fileId, index: idx });
            return;
          }

          const chunk = String(data.chunk || '');
          if (chunk.length === 0 || chunk.length > MAX_CHUNK_CHARS) {
            purgeFileTransfer(fileId);
            return;
          }

          t.chunks[idx] = chunk;
          t.received += 1;

          await manager.send('file', { kind: 'ack', ackKind: 'chunk', fileId, index: idx });

          if (t.received >= t.total && t.total > 0) {
            const encrypted = t.chunks.join('');
            const decrypted = await encryptionEngineRef.current.decryptBytes(encrypted, t.iv);
            const decryptedBytes = new Uint8Array(decrypted);

            const fileType = sniffMimeFromBytes(decryptedBytes) || 'application/octet-stream';
            const displayFileName = normalizeFileNameForMime(t.fileName, fileType);
            const displayTimestamp = t.timestamp;
            
            const blob = new Blob([decryptedBytes], { type: fileType || 'application/octet-stream' });
            const objectUrl = URL.createObjectURL(blob);
            decryptedBytes.fill(0);

            purgeFileTransfer(fileId);

            messageQueueRef.current.addMessage(sessionId, {
              id: fileId,
              content: objectUrl,
              sender: 'partner',
              timestamp: displayTimestamp,
              type: 'file',
              fileName: displayFileName
            });
            syncMessagesFromQueue();
          }

          return;
        }
      } catch (error) {
        // Show user-friendly error for file transfer failures
        toast.error('File transfer failed - please try again');
      }
    });

    manager.onMessage('key-exchange', async (payload) => {
      try {
        let remoteFingerprint = '';
        try {
          const pkB64 = String(payload.data?.publicKey || '');
          if (pkB64) {
            const pkBytes = base64ToBytes(pkB64);
            const hash = await crypto.subtle.digest('SHA-256', pkBytes);
            remoteFingerprint = Array.from(new Uint8Array(hash))
              .slice(0, 16)
              .map((b) => b.toString(16).padStart(2, '0'))
              .join('')
              .toUpperCase();
            pkBytes.fill(0);
          }
        } catch {
        }

        if (remoteFingerprint) {
          const senderId = String(payload.senderId || 'partner');
          const pinKey = `session:${sessionId}:peer:${senderId}`;
          const pinRes = checkOrPinFingerprint(pinKey, remoteFingerprint);
          if (pinRes.status === 'mismatch') {
            toast.error('Security alert: partner key changed. Session blocked.');
            addSystemMessage('🚫 Security alert: partner fingerprint changed — session ended');
            await handleEndSession();
            return;
          }
          if (pinRes.status === 'pinned') {
            addSystemMessage('📌 Fingerprint pinned (TOFU). Always verify codes for high-risk conversations.');
          }
        }

        const partnerPublicKey = await KeyExchange.importPublicKey(payload.data.publicKey);
        partnerPublicKeyRef.current = partnerPublicKey;
        setIsPartnerConnected(true);
        partnerWasPresentRef.current = true;

        // Ensure the peer gets our public key even if they missed our initial broadcast.
        // Throttle to avoid ping-pong.
        if (!isKeyExchangeCompleteRef.current) {
          void sendPublicKey();
        }

        if (keyPairRef.current) {
          if (isTauriRuntime()) {
            const sharedSecretBytes = await KeyExchange.deriveSharedSecretBytes(
              keyPairRef.current.privateKey,
              partnerPublicKey
            );

            const bytes = new Uint8Array(sharedSecretBytes);
            const keyBase64 = bytesToBase64(bytes);

            try {
              await tauriInvoke('vault_set_key', { session_id: sessionId, key_base64: keyBase64 });
              encryptionEngineRef.current?.enableTauriVault(sessionId);
            } catch {
              const sharedSecret = await KeyExchange.deriveSharedSecret(
                keyPairRef.current.privateKey,
                partnerPublicKey
              );
              sessionKeyRef.current = sharedSecret;
              await encryptionEngineRef.current?.setKey(sharedSecret);
            } finally {
              try {
                bytes.fill(0);
              } catch {
              }
            }
          } else {
            const sharedSecret = await KeyExchange.deriveSharedSecret(
              keyPairRef.current.privateKey,
              partnerPublicKey
            );

            sessionKeyRef.current = sharedSecret;
            await encryptionEngineRef.current?.setKey(sharedSecret);
          }
          setIsKeyExchangeComplete(true);
          stopPublicKeyResend();

          try {
            if (keyPairRef.current) {
              localFingerprintRef.current = await KeyExchange.generateFingerprint(keyPairRef.current.publicKey);
            }
          } catch {
          }

          if (!remoteFingerprint) {
            remoteFingerprint = await KeyExchange.generateFingerprint(partnerPublicKey);
          }

          if (!localFingerprintRef.current) {
            localFingerprintRef.current = '...';
          }

          // Only show verification modal ONCE per session
          if (!verificationShownRef.current && localFingerprintRef.current && remoteFingerprint) {
            verificationShownRef.current = true;
            setVerificationState(prev => ({
              ...prev,
              show: true,
              localFingerprint: localFingerprintRef.current,
              remoteFingerprint
            }));
          }

          addSystemMessage('🔐 Encryption established - verify security codes');
        }
      } catch {
        toast.error('Failed to establish secure connection');
      }
    });

    manager.onMessage('chat-message', async (payload) => {
      try {
        markActivity();
        if (!encryptionEngineRef.current) return;

        if (payload.data.type === 'file') {
          const MAX_SINGLE_FILE_ENCRYPTED_CHARS = 60000;
          const encrypted = String(payload.data.encrypted || '');
          const iv = String(payload.data.iv || '');
          const rawFileName = String(payload.data.fileName || 'unknown_file');
          const safeFileName = sanitizeFileName(rawFileName).slice(0, 256);

          if (encrypted.length === 0 || encrypted.length > MAX_SINGLE_FILE_ENCRYPTED_CHARS) {
            return;
          }
          if (iv.length === 0 || iv.length > 256) {
            return;
          }

          const decrypted = await encryptionEngineRef.current.decryptBytes(
            encrypted,
            iv
          );
          const decryptedBytes = new Uint8Array(decrypted);
          const sniffedMime = sniffMimeFromBytes(decryptedBytes);
          const displayFileName = normalizeFileNameForMime(safeFileName, sniffedMime);
          const blob = new Blob([decryptedBytes], { type: sniffedMime || 'application/octet-stream' });
          const objectUrl = URL.createObjectURL(blob);

          decryptedBytes.fill(0);

          messageQueueRef.current.addMessage(sessionId, {
            id: payload.nonce,
            content: objectUrl,
            sender: 'partner',
            timestamp: payload.timestamp,
            type: 'file',
            fileName: displayFileName
          });
        } else {
          const MAX_TEXT_ENCRYPTED_CHARS = 60000;
          const MAX_IV_CHARS = 256;
          const encrypted = String(payload.data.encrypted || '');
          const iv = String(payload.data.iv || '');

          if (encrypted.length === 0 || encrypted.length > MAX_TEXT_ENCRYPTED_CHARS) {
            return;
          }
          if (iv.length === 0 || iv.length > MAX_IV_CHARS) {
            return;
          }

          const rawType = String(payload.data.type || 'text');
          const safeType = (rawType === 'text' || rawType === 'system' || rawType === 'video' || rawType === 'voice')
            ? rawType
            : 'text';

          const decrypted = await encryptionEngineRef.current.decryptBytes(
            encrypted,
            iv
          );
          const decryptedBytes = new Uint8Array(decrypted);

          messageQueueRef.current.addMessage(sessionId, {
            id: payload.nonce,
            content: decryptedBytes,
            sender: 'partner',
            timestamp: payload.timestamp,
            type: safeType,
            fileName: undefined
          });
        }

        syncMessagesFromQueue();
        await manager.send('message-ack', { messageId: payload.nonce });

      } catch {
        // Silent - message decryption failed
      }
    });

    manager.onMessage('voice-message', async (payload) => {
      try {
        markActivity();
        if (!encryptionEngineRef.current) return;

        const decrypted = await encryptionEngineRef.current.decryptBytes(
          payload.data.encrypted,
          payload.data.iv
        );

        const decryptedBytes = new Uint8Array(decrypted);
        const blob = new Blob([decryptedBytes], { type: 'audio/webm;codecs=opus' });

        decryptedBytes.fill(0);

        setVoiceMessages(prev => {
          const next = [...prev, {
            id: payload.nonce,
            blob,
            duration: payload.data.duration,
            sender: 'partner',
            timestamp: payload.timestamp,
            played: false
          }];
          return next.length > MAX_VOICE_MESSAGES ? next.slice(-MAX_VOICE_MESSAGES) : next;
        });

        messageQueueRef.current.addMessage(sessionId, {
          id: payload.nonce,
          content: '[Voice Message]',
          sender: 'partner',
          timestamp: payload.timestamp,
          type: 'voice',
          fileName: undefined
        });
        syncMessagesFromQueue();
        await manager.send('message-ack', { messageId: payload.nonce });
      } catch {
        // Silent
      }
    });

    manager.onMessage('message-ack', (payload) => {
      markActivity();
      messageQueueRef.current.acknowledgeMessage(sessionId, payload.data.messageId);
    });

    manager.onMessage('session-terminated', async () => {
      if (isTerminatingRef.current) return;
      isTerminatingRef.current = true;
      try {
        SessionService.clearValidationCache(sessionId);
      } catch {
        // Ignore
      }
      try {
        if (inactivityIntervalRef.current) {
          clearInterval(inactivityIntervalRef.current);
          inactivityIntervalRef.current = null;
        }
      } catch {
        // Ignore
      }
      destroyLocalSessionData();
      await fullCleanup();
      await cleanup();
      onEndSession(false);
    });
  };

  const sendPublicKey = async () => {
    if (!realtimeManagerRef.current || !keyPairRef.current) return;

    const now = Date.now();
    if (now - lastPublicKeySendRef.current < 1000) return;
    lastPublicKeySendRef.current = now;

    localFingerprintRef.current = await KeyExchange.generateFingerprint(keyPairRef.current.publicKey);
    const publicKeyExport = await KeyExchange.exportPublicKey(keyPairRef.current.publicKey);
    await realtimeManagerRef.current.send('key-exchange', { publicKey: publicKeyExport });
  };

  const handleVerificationConfirmed = () => {
    setVerificationState(prev => ({ ...prev, show: false, verified: true }));
    setVoiceVerified(true);
    addSystemMessage('✅ Security verified - all features enabled');
    toast.success('Connection verified as secure');
  };

  const handleVerificationCancelled = () => {
    setVerificationState(prev => ({ ...prev, show: false, verified: false }));
    setVoiceVerified(false);
  };

  const handleRequestVoiceVerification = () => {
    if (verificationState.verified) {
      setVoiceVerified(true);
      toast.success('Voice messaging enabled');
    } else if (!verificationShownRef.current || !verificationState.show) {
      setVerificationState(prev => ({ ...prev, show: true }));
    }
  };

  const sendVoiceMessage = async (blob: Blob, duration: number) => {
    if (!encryptionEngineRef.current || !isKeyExchangeComplete) {
      toast.error('Secure connection not established');
      return;
    }

    if (!voiceVerified) {
      toast.error('Please verify security codes first');
      return;
    }

    try {
      markActivity();
      const messageId = generateNonce();

      const arrayBuffer = await blob.arrayBuffer();
      const { encrypted, iv } = await encryptionEngineRef.current.encryptBytes(arrayBuffer);

      try {
        const { secureZeroArrayBuffer } = await import('@/utils/algorithms/memory/zeroization');
        const crypto = window.crypto;
        secureZeroArrayBuffer({ getRandomValues: (arr) => crypto.getRandomValues(arr) }, arrayBuffer);
      } catch {
        // Fallback: simple zero fill
        try {
          new Uint8Array(arrayBuffer).fill(0);
        } catch {
          // Ignore
        }
      }

      setVoiceMessages(prev => {
        const next = [...prev, {
          id: messageId,
          blob,
          duration,
          sender: 'me',
          timestamp: Date.now(),
          played: false
        }];
        return next.length > MAX_VOICE_MESSAGES ? next.slice(-MAX_VOICE_MESSAGES) : next;
      });

      messageQueueRef.current.addMessage(sessionId, {
        id: messageId,
        content: '[Voice Message]',
        sender: 'me',
        timestamp: Date.now(),
        type: 'voice'
      });
      syncMessagesFromQueue();

      const sent = await realtimeManagerRef.current?.send('voice-message', {
        encrypted,
        iv,
        duration,
        messageId
      });

      if (!sent) {
        toast.error('Voice message may not have been delivered');
      }
    } catch {
      toast.error('Failed to send voice message');
    }
  };

  const handleVoiceMessagePlayed = (messageId: string) => {
    setVoiceMessages(prev =>
      prev.map(vm => {
        if (vm.id !== messageId) return vm;
        return { ...vm, played: true, blob: new Blob([], { type: 'application/octet-stream' }) };
      })
    );
  };

  const addSystemMessage = (content: string, unique = true) => {
    // Prevent duplicate system messages
    if (unique && systemMessagesShownRef.current.has(content)) {
      return;
    }
    if (unique) {
      systemMessagesShownRef.current.add(content);
    }

    const systemMessage: QueuedMessage = {
      id: generateNonce(),
      content,
      sender: 'me',
      timestamp: Date.now(),
      type: 'system',
      receivedAt: Date.now(),
      acknowledged: true
    };

    messageQueueRef.current.addMessage(sessionId, systemMessage);
    syncMessagesFromQueue();
  };

  const sendMessage = async () => {
    const validation = validateMessage(inputText);
    if (!validation.valid) {
      toast.error(validation.error);
      return;
    }

    if (!encryptionEngineRef.current || !isKeyExchangeComplete) {
      toast.error('Secure connection not established yet');
      return;
    }

    if (!verificationState.verified) {
      toast.error('Please verify security codes before sending messages');
      if (!verificationState.show) {
        setVerificationState(prev => ({ ...prev, show: true }));
      }
      return;
    }

    try {
      const messageId = generateNonce();
      const trimmed = inputText.trim();
      const messageBytes = new TextEncoder().encode(trimmed);
      const encryptBytes = messageBytes.slice();
      const { encrypted, iv } = await encryptionEngineRef.current.encryptBytes(encryptBytes.buffer);

      try {
        const crypto = window.crypto;
        secureZeroUint8Array({ getRandomValues: (arr) => crypto.getRandomValues(arr) }, encryptBytes);
      } catch {
        try {
          encryptBytes.fill(0);
        } catch {
          // Ignore
        }
      }

      const { displayTimestamp } = generatePlausibleTimestamp();

      messageQueueRef.current.addMessage(sessionId, {
        id: messageId,
        content: messageBytes,
        sender: 'me',
        timestamp: displayTimestamp,
        type: 'text'
      });
      syncMessagesFromQueue();

      const sent = await realtimeManagerRef.current?.send('chat-message', {
        encrypted,
        iv,
        type: 'text',
        messageId
      });

      if (!sent) {
        toast.error('Message may not have been delivered');
      }

      setInputText('');
    } catch {
      toast.error('Failed to send message');
    }
  };

  const handleFileUpload = (event: ChangeEvent<HTMLInputElement>) => {
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

    if (!verificationState.verified) {
      toast.error('Please verify security codes before sending files');
      setVerificationState(prev => ({ ...prev, show: true }));
      return;
    }

    void (async () => {
      try {
        markActivity();
        const sanitizedName = sanitizeFileName(file.name);
        const messageId = generateNonce();

        const { displayTimestamp } = generatePlausibleTimestamp();

        const arrayBuffer = await file.arrayBuffer();
        const { encrypted, iv } = await encryptionEngineRef.current!.encryptBytes(arrayBuffer);

        try {
          const { secureZeroArrayBuffer } = await import('@/utils/algorithms/memory/zeroization');
          const crypto = window.crypto;
          secureZeroArrayBuffer({ getRandomValues: (arr) => crypto.getRandomValues(arr) }, arrayBuffer);
        } catch {
          // Fallback: simple zero fill
          try {
            new Uint8Array(arrayBuffer).fill(0);
          } catch {
            // Ignore
          }
        }

        if (typeof URL === 'undefined' || typeof URL.createObjectURL !== 'function') {
          toast.error('File previews are not supported in this environment');
          return;
        }
        const objectUrl = URL.createObjectURL(file);

        messageQueueRef.current.addMessage(sessionId, {
          id: messageId,
          content: objectUrl,
          sender: 'me',
          timestamp: displayTimestamp,
          type: 'file',
          fileName: sanitizedName
        });
        syncMessagesFromQueue();

        const MAX_FILE_CHUNKS = 512;
        const chunkSize = 45_000;
        const totalChunks = Math.ceil(encrypted.length / chunkSize);

        if (!Number.isFinite(totalChunks) || totalChunks <= 0 || totalChunks > MAX_FILE_CHUNKS) {
          toast.error('File too large to send');
          return;
        }

        let sent = (await realtimeManagerRef.current?.send('file', {
          kind: 'init',
          fileId: messageId,
          fileName: sanitizedName,
          fileType: file.type,
          iv,
          totalChunks,
          timestamp: displayTimestamp
        })) ?? false;

        if (sent) {
          const initAck = await waitForFileAck(`${messageId}:init`, 6000);
          sent = initAck;
        }

        if (sent) {
          for (let i = 0; i < totalChunks; i++) {
            const chunk = encrypted.slice(i * chunkSize, (i + 1) * chunkSize);

            let delivered = false;
            for (let attempt = 0; attempt < 3; attempt++) {
              const ok = (await realtimeManagerRef.current?.send('file', {
                kind: 'chunk',
                fileId: messageId,
                index: i,
                chunk,
                totalChunks,
                iv,
                fileName: sanitizedName,
                fileType: file.type,
                timestamp: displayTimestamp
              })) ?? false;

              if (!ok) {
                continue;
              }

              const ackOk = await waitForFileAck(`${messageId}:${i}`, 6000);
              if (ackOk) {
                delivered = true;
                break;
              }
            }

            if (!delivered) {
              sent = false;
              break;
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
  };

  const triggerSessionTermination = async (reason: TerminationReason) => {
    try {
      await realtimeManagerRef.current?.send('session-terminated', {
        reason,
        timestamp: Date.now(),
        terminatedBy: participantIdRef.current
      });
    } catch {
      // Ignore
    }

    let deleted = false;
    try {
      deleted = await SessionService.deleteSession(sessionId);
    } catch {
      deleted = false;
    }

    destroyLocalSessionData();

    try {
      SessionService.clearValidationCache(sessionId);
    } catch {
      // Ignore
    }

    if (!deleted) {
      toast.error('Server deletion failed - session ended locally', { id: 'server-delete-failed' });
    }
  };

  const destroyLocalSessionData = () => {
    // Clear timeouts
    if (partnerDisconnectTimeoutRef.current) {
      clearTimeout(partnerDisconnectTimeoutRef.current);
      partnerDisconnectTimeoutRef.current = null;
    }

    if (autoTerminateTimeoutRef.current) {
      clearTimeout(autoTerminateTimeoutRef.current);
      autoTerminateTimeoutRef.current = null;
    }

    if (focusScrollTimeoutRef.current) {
      clearTimeout(focusScrollTimeoutRef.current);
      focusScrollTimeoutRef.current = null;
    }

    if (inactivityIntervalRef.current) {
      clearInterval(inactivityIntervalRef.current);
      inactivityIntervalRef.current = null;
    }

    for (const fileId of fileTransfersRef.current.keys()) {
      purgeFileTransfer(fileId);
    }

    pendingFileAcksRef.current.clear();

    if (encryptionEngineRef.current) {
      encryptionEngineRef.current = null;
    }
    sessionKeyRef.current = null;
    keyPairRef.current = null;
    partnerPublicKeyRef.current = null;

    messageQueueRef.current.nuclearPurge();

    try {
      SecurityManager.clearCapabilityToken(sessionId);
    } catch {
      // Ignore
    }

    if (isTauriRuntime()) {
      try {
        void tauriInvoke('secure_panic_wipe');
      } catch {
        // Ignore
      }
    }

    setMessages([]);
    setInputText('');
    setIsPartnerConnected(false);
    setIsKeyExchangeComplete(false);
    setMemoryStats({ messageCount: 0, estimatedBytes: 0 });
    setVoiceMessages([]);
    setVoiceVerified(false);
    setVerificationState({
      show: false,
      localFingerprint: '',
      remoteFingerprint: '',
      verified: false
    });

    // SECURITY FIX: Removed localStorage usage - keys now stored ONLY in memory
    // No disk persistence - true RAM-only storage
    // Previous code (REMOVED):
    // localStorage removeItem(`ghost_session_${sessionId}`);
    // localStorage removeItem(`ghost_keys_${sessionId}`);

    if (typeof (window as any).gc === 'function') {
      try {
        (window as any).gc();
      } catch {
        // Ignore
      }
    }
  };

  const cleanup = async () => {
    if (realtimeManagerRef.current) {
      await realtimeManagerRef.current.disconnect();
      realtimeManagerRef.current = null;
    }

    stopPublicKeyResend();

    if (partnerDisconnectTimeoutRef.current) {
      clearTimeout(partnerDisconnectTimeoutRef.current);
      partnerDisconnectTimeoutRef.current = null;
    }

    if (autoTerminateTimeoutRef.current) {
      clearTimeout(autoTerminateTimeoutRef.current);
      autoTerminateTimeoutRef.current = null;
    }

    if (focusScrollTimeoutRef.current) {
      clearTimeout(focusScrollTimeoutRef.current);
      focusScrollTimeoutRef.current = null;
    }

    await realtimeManagerRef.current?.disconnect();
    messageQueueRef.current.destroySession(sessionId);

    try {
      SecurityManager.clearCapabilityToken(sessionId);
    } catch {
      // Ignore
    }

    if (isTauriRuntime()) {
      try {
        await tauriInvoke('secure_panic_wipe');
      } catch {
        // Ignore
      }
    }

    encryptionEngineRef.current = null;
    keyPairRef.current = null;
    partnerPublicKeyRef.current = null;
  };

  /**
   * CRITICAL: Terminate session - always clickable, debounced, instant
   * - Max 1 execution per 2 seconds (debounce)
   * - No confirmation modal (coercion-resistance)
   * - Atomic server-side deletion
   */
  const handleEndSession = async () => {
    // Debounce: prevent rapid clicks (max 1 per 2 seconds)
    const now = Date.now();
    if (now - lastTerminationRef.current < 2000) {
      return;
    }
    lastTerminationRef.current = now;

    // Mark as terminating immediately
    if (isTerminatingRef.current) {
      return;
    }
    isTerminatingRef.current = true;

    try {
      if (inactivityIntervalRef.current) {
        clearInterval(inactivityIntervalRef.current);
        inactivityIntervalRef.current = null;
      }
    } catch {
      // Ignore
    }

    try {
      await realtimeManagerRef.current?.send('session-terminated', {
        reason: 'manual',
        timestamp: Date.now(),
        terminatedBy: participantIdRef.current
      });
    } catch {
      // Ignore
    }

    // 1. Server-side nuclear wipe (atomic)
    const deleted = await SessionService.deleteSession(sessionId);

    // Android native hardening: clear WebView caches immediately on user-initiated session end.
    try {
      const mod = await import('@capacitor/core');
      if (mod.Capacitor?.isNativePlatform?.()) {
        const WebViewCleanup = mod.registerPlugin('WebViewCleanup') as { clearWebViewData: () => Promise<{ ok: boolean }> };
        await WebViewCleanup.clearWebViewData();
      }
    } catch {
    }

    // 2. Clear all in-memory state
    destroyLocalSessionData();

    // 3. Full memory cleanup (keys, trapState, buffers)
    await fullCleanup();

    // 4. Disconnect realtime
    await cleanup();

    // 5. Redirect with no trace (history.replace)
    onEndSession(false);

    if (!deleted) {
      toast.error('Server deletion failed - session ended locally', { id: 'server-delete-failed' });
    }
  };

  const handleNuclearPurge = () => {
    messageQueueRef.current.destroySession(sessionId);
    setMessages([]);
    setMemoryStats({ messageCount: 0, estimatedBytes: 0 });
    toast.success('All messages purged from memory');
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <>
      <KeyVerificationModal
        localFingerprint={verificationState.localFingerprint}
        remoteFingerprint={verificationState.remoteFingerprint}
        onVerified={handleVerificationConfirmed}
        onCancel={handleVerificationCancelled}
        isVisible={verificationState.show}
      />

      <div className="chat-container-mobile h-[100dvh] flex flex-col bg-background">

        <header className={cn(
          "mobile-header fixed left-0 right-0 z-50 glass border-b border-border/30 h-14 md:h-16",
          "top-[env(safe-area-inset-top,0px)] md:top-9"
        )}>
          <div className="container mx-auto px-2 md:px-4 h-full flex items-center">
            <div className="flex items-center justify-between w-full gap-2">
              <div className="flex items-center gap-1.5 md:gap-3 flex-1 min-w-0">
                <Ghost className="h-5 w-5 md:h-6 md:w-6 text-primary flex-shrink-0" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] md:text-xs text-primary truncate">{sessionId}</span>
                    <div className="md:hidden flex-shrink-0" />
                  </div>
                  <div className="flex items-center gap-1 md:gap-2 text-[9px] md:text-xs text-muted-foreground">
                    <Shield className="h-2.5 w-2.5 md:h-3 md:w-3 flex-shrink-0" />
                    <span className="truncate">{isKeyExchangeComplete ? 'E2E Encrypted' : 'Connecting...'}</span>
                  </div>
                </div>
              </div>

              <div className="hidden md:flex items-center gap-2">
                <ConnectionStatusIndicator state={connectionState} />
              </div>

              <div className="flex items-center gap-0.5 md:gap-2 flex-shrink-0">
                <button
                  onClick={handleNuclearPurge}
                  className="touch-target flex items-center justify-center p-1.5 md:p-2 md:px-3 rounded-lg border border-yellow-500/50 text-yellow-500 hover:bg-yellow-500/10 transition-colors"
                  title="Purge messages"
                >
                  <Trash2 className="h-4 w-4" />
                </button>

                <button
                  onClick={handleEndSession}
                  onTouchEnd={(e) => {
                    e.preventDefault();
                    handleEndSession();
                  }}
                  className="touch-target relative z-[100] flex items-center justify-center p-1.5 md:p-2 md:px-4 rounded-lg border border-destructive/50 text-destructive hover:bg-destructive/10 active:bg-destructive/20 active:scale-95 transition-all cursor-pointer"
                  aria-label="End session"
                >
                  <X className="h-4 w-4 pointer-events-none" />
                </button>
              </div>
            </div>
          </div>
        </header>

        <div className={cn(
          "flex-shrink-0",
          isPartnerConnected && verificationState.verified
            ? "h-[calc(56px+28px+env(safe-area-inset-top,0px))] md:h-[calc(4rem+2.25rem)]"
            : "h-[calc(56px+env(safe-area-inset-top,0px))] md:h-[calc(4rem+2.25rem)]"
        )} />

        {connectionState.status !== 'connected' && connectionState.progress > 0 && (
          <div className={cn(
            "fixed left-0 right-0 z-40",
            isPartnerConnected && verificationState.verified ? "top-[calc(1.75rem+3.5rem)] md:top-[calc(4rem+2.25rem)]" : "top-14 md:top-[calc(4rem+2.25rem)]"
          )}>
            <progress className="ghost-progress h-1 w-full" value={connectionState.progress} max={100} />
          </div>
        )}

        <main
          ref={messageAreaRef}
          className="mobile-message-area flex-1 overflow-y-auto overflow-x-hidden"
        >
          <div className="container mx-auto px-3 md:px-4 py-4 md:py-6">
            <div className="max-w-3xl mx-auto space-y-3 md:space-y-4">
              <div className="flex justify-center">
                <div className="px-3 py-1.5 rounded-full bg-accent/10 border border-accent/20 text-[10px] md:text-xs text-accent flex items-center gap-1.5">
                  <HardDrive className="h-3 w-3" />
                  <span className="hidden sm:inline">Messages stored in memory only - vanish when session ends</span>
                  <span className="sm:hidden">Memory only - auto-vanish</span>
                </div>
              </div>

              <div className={cn(
                "space-y-3 md:space-y-4 transition-all duration-200",
                !isWindowVisible && "message-blur"
              )}>
                {messages.map((message) => {
                  const voiceMessage = message.type === 'voice'
                    ? voiceMessages.find(vm => vm.id === message.id)
                    : null;

                  const contentText = message.content instanceof Uint8Array
                    ? new TextDecoder().decode(message.content)
                    : message.content;

                  return (
                    <div
                      key={message.id}
                      className={cn(
                        "flex",
                        message.type === 'system' ? 'justify-center' : message.sender === 'me' ? 'justify-end' : 'justify-start'
                      )}
                    >
                      {message.type === 'system' ? (
                        <div className="px-4 py-2 rounded-full border border-[rgba(255,10,42,0.14)] bg-black/35 backdrop-blur-md font-mono text-[12px] tracking-[0.12em] text-white/80 max-w-[90%] text-center">
                          {contentText}
                        </div>
                      ) : message.type === 'voice' && voiceMessage ? (
                        <VoiceMessage
                          messageId={voiceMessage.id}
                          audioBlob={voiceMessage.blob}
                          duration={voiceMessage.duration}
                          sender={voiceMessage.sender}
                          timestamp={voiceMessage.timestamp}
                          onPlayed={handleVoiceMessagePlayed}
                        />
                      ) : (
                        <div
                          className={cn(
                            "message-bubble-mobile",
                            message.sender === 'me'
                              ? "bg-primary text-primary-foreground rounded-2xl rounded-br-md"
                              : "glass border border-border/50 rounded-2xl rounded-bl-md"
                          )}
                        >
                          {message.type === 'file' ? (
                            typeof message.content === 'string' && message.content.startsWith('data:image') ? (
                              <div className="relative group">
                                <img
                                  src={message.content}
                                  alt={message.fileName || 'Shared image'}
                                  className="max-w-full rounded-lg mb-2"
                                  loading="lazy"
                                  onContextMenu={(e) => e.preventDefault()}
                                  draggable={false}
                                />
                                <button
                                  onClick={() => {
                                    if (typeof message.content !== 'string') {
                                      return;
                                    }
                                    if (!(message.content.startsWith('blob:') || message.content.startsWith('data:'))) {
                                      return;
                                    }
                                    if (typeof document === 'undefined') {
                                      return;
                                    }
                                    const link = document.createElement('a');
                                    link.href = message.content;
                                    link.download = message.fileName || 'ghost_image.png';
                                    link.click();
                                    toast.success('Image downloaded');
                                  }}
                                  className="absolute top-2 right-2 p-2 rounded-full bg-black/70 backdrop-blur-sm opacity-100 md:opacity-0 md:group-hover:opacity-100 transition-opacity active:scale-95"
                                  aria-label="Download image"
                                  title="Download image"
                                >
                                  <Download className="h-4 w-4 text-white" />
                                </button>
                                {message.fileName && (
                                  <span className="text-xs opacity-70">{sanitizeFileName(message.fileName)}</span>
                                )}
                              </div>
                            ) : (
                              <FilePreviewCard
                                fileName={message.fileName || 'Unknown File'}
                                content={typeof message.content === 'string' ? message.content : ''}
                                sender={message.sender}
                              />
                            )
                          ) : typeof message.content === 'string' && message.content.startsWith('https://') ? (
                            <FilePreviewCard
                              fileName={message.content}
                              content={message.content}
                              sender={message.sender}
                            />
                          ) : (
                            <p className="whitespace-pre-wrap break-words">{contentText}</p>
                          )}
                          <div className={cn(
                            "text-xs mt-2 opacity-60",
                            message.sender === 'me' ? "text-primary-foreground" : "text-muted-foreground"
                          )}>
                            {new Date(message.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
              <div ref={messagesEndRef} className="h-4" />
            </div>
          </div>
        </main>

        <footer
          ref={inputBarRef}
          className="mobile-input-bar"
        >
          <div className="container mx-auto">
            <div className="max-w-3xl mx-auto">
              <div className="flex items-end gap-2 mb-2">
                <textarea
                  value={inputText}
                  onChange={(e) => {
                    setInputText(e.target.value);
                  }}
                  onKeyDown={handleKeyDown}
                  onFocus={() => {
                    if (focusScrollTimeoutRef.current) {
                      clearTimeout(focusScrollTimeoutRef.current);
                    }
                    focusScrollTimeoutRef.current = setTimeout(() => {
                      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
                    }, 300);
                  }}
                  placeholder={isKeyExchangeComplete ? "Type your message..." : "Connecting..."}
                  disabled={!isKeyExchangeComplete}
                  rows={1}
                  className="mobile-text-input flex-1"
                />

                <button
                  onClick={() => {
                    if (!isKeyExchangeComplete) {
                      return;
                    }
                    if (!verificationState.verified) {
                      toast.error('Please verify security codes before sending messages');
                      if (!verificationState.show) {
                        setVerificationState(prev => ({ ...prev, show: true }));
                      }
                      return;
                    }
                    sendMessage();
                  }}
                  disabled={!inputText.trim() || !isKeyExchangeComplete}
                  className="send-button-mobile bg-primary text-primary-foreground flex-shrink-0"
                  aria-label="Send message"
                >
                  <Send className="h-5 w-5" />
                </button>
              </div>

              <div className="flex items-center justify-center gap-3 pb-1">
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".jpg,.jpeg,.png,.gif,.webp,.pdf,.doc,.docx,.txt,.csv,.rtf,.xls,.xlsx,.ppt,.pptx,.zip,.rar,.js,.json,.html,.css,.md,image/jpeg,image/png,image/gif,image/webp,application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/plain,text/csv,application/rtf,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.ms-powerpoint,application/vnd.openxmlformats-officedocument.presentationml.presentation,application/zip,application/x-rar-compressed,text/javascript,application/json,text/html,text/css,text/markdown"
                  onChange={handleFileUpload}
                  className="hidden"
                />
                <button
                  onClick={() => {
                    if (!isKeyExchangeComplete) {
                      return;
                    }
                    if (!verificationState.verified) {
                      toast.error('Please verify security codes before sending files');
                      if (!verificationState.show) {
                        setVerificationState(prev => ({ ...prev, show: true }));
                      }
                      return;
                    }
                    fileInputRef.current?.click();
                  }}
                  disabled={!isKeyExchangeComplete}
                  className="action-button-mobile border border-border/50 bg-secondary/30"
                  aria-label="Attach file"
                  title="Attach file"
                >
                  <Paperclip className="h-5 w-5 text-muted-foreground" />
                </button>

                <button
                  onClick={() => setShowTimestampSettings(true)}
                  className={cn(
                    "action-button-mobile border bg-secondary/30",
                    isTimestampObfuscationEnabled() ? "border-primary/50 text-primary" : "border-border/50"
                  )}
                  aria-label="Timestamp settings"
                  title="Plausible timestamps"
                >
                  <Clock className="h-5 w-5" />
                </button>

                <VoiceRecorder
                  sessionKey={sessionKeyRef.current}
                  onVoiceMessage={sendVoiceMessage}
                  disabled={!isKeyExchangeComplete}
                  voiceVerified={voiceVerified}
                  onRequestVerification={handleRequestVoiceVerification}
                />
              </div>

              <div className="flex items-center justify-center gap-1.5 py-1.5 text-[10px] md:text-xs text-yellow-500/80">
                <AlertTriangle className="h-3 w-3" />
                <span>Recipient can screenshot messages</span>
              </div>
            </div>
          </div>
        </footer>
      </div>

      <TimestampSettings
        open={showTimestampSettings}
        onClose={() => setShowTimestampSettings(false)}
      />
    </>
  );

};

// Connection Status Component
const ConnectionStatusIndicator = ({ state }: { state: ConnectionState }) => {
  const getStatusInfo = () => {
    if (state.status === 'connected') {
      return { text: 'Connected', color: 'text-accent', dot: 'bg-accent' };
    }
    if (state.status === 'reconnecting') {
      return { text: 'Reconnecting...', color: 'text-yellow-500', dot: 'bg-yellow-500' };
    }
    return { text: 'Connecting...', color: 'text-muted-foreground', dot: 'bg-muted-foreground' };
  };

  const { text, color, dot } = getStatusInfo();

  return (
    <div className={cn("flex items-center gap-2 text-xs", color)}>
      <div className={cn("w-2 h-2 rounded-full animate-pulse", dot)} />
      <span>{text}</span>
    </div>
  );
};

export default ChatInterface;
