import { useState, useEffect, useRef, useCallback, type KeyboardEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Ghost, Send, Paperclip, Shield, X, Loader2, Trash2, HardDrive, FileText, FileSpreadsheet, FileImage, FileArchive, FileCode, File as FileIcon, AlertTriangle, Clock, Download, Video } from 'lucide-react';
import { toast } from 'sonner';
import { EncryptionEngine, KeyExchange, generateNonce } from '@/utils/encryption';
import { SecurityManager, validateMessage, sanitizeFileName } from '@/utils/security';
import { checkOrPinFingerprint } from '@/utils/tofuFingerprintStore';
import { RealtimeManager, BroadcastPayload, ConnectionState } from '@/lib/realtimeManager';
import { SessionService } from '@/lib/sessionService';
import { getMessageQueue, QueuedMessage } from '@/utils/clientMessageQueue';
import { cn } from '@/lib/utils';
import { generatePlausibleTimestamp, isTimestampObfuscationEnabled } from '@/utils/plausibleTimestamp';
import { useMemoryCleanup } from '@/hooks/useMemoryCleanup';
import { isTauriRuntime, setTauriContentProtected, tauriInvoke } from '@/utils/runtime';
import { base64ToBytes, bytesToBase64 } from '@/utils/algorithms/encoding/base64';
import { secureZeroUint8Array } from '@/utils/algorithms/memory/zeroization';
import { getReplayProtection, destroyReplayProtection } from '@/utils/replayProtection';
import { usePlausibleDeniability } from '@/hooks/usePlausibleDeniability';
import { createMinDelay } from '@/utils/interactionTiming';
import { useVoiceMessaging } from './hooks/useVoiceMessaging';
import { normalizeFileNameForMime, sniffMimeFromBytes } from './hooks/fileTransferUtils';
import { useFileTransfers } from './hooks/useFileTransfers';
import KeyVerificationModal from './KeyVerificationModal';
import ConnectionStatusIndicator from './ConnectionStatusIndicator';
import VoiceRecorder from './VoiceRecorder';
import VoiceMessage from './VoiceMessage';
import FilePreviewCard from './FilePreviewCard';
import TimestampSettings from './TimestampSettings';

interface ChatInterfaceProps {
  sessionId: string;
  token: string;
  channelToken: string;
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

const ChatInterface = ({ sessionId, token, channelToken, isHost, timerMode, onEndSession }: ChatInterfaceProps) => {
  const navigate = useNavigate();
  const { fullCleanup } = useMemoryCleanup();

  const textEncoderRef = useRef<TextEncoder | null>(null);
  const textDecoderRef = useRef<TextDecoder | null>(null);
  const aadPrefixesRef = useRef<{ sessionId: string; chat: string; voice: string; file: string } | null>(null);
  const decodedTextCacheRef = useRef<Map<string, string>>(new Map());
  const syncScheduledRef = useRef(false);

  const isCapacitorNative = (): boolean => {
    try {
      const c = (window as any).Capacitor;
      return Boolean(c && typeof c.isNativePlatform === 'function' && c.isNativePlatform());
    } catch {
      return false;
    }
  };

  const capacitorNativeCachedRef = useRef<boolean | null>(null);
  const getIsCapacitorNative = async (): Promise<boolean> => {
    const cached = capacitorNativeCachedRef.current;
    if (cached !== null) {
      return cached;
    }

    let isNative = isCapacitorNative();
    if (!isNative) {
      try {
        const mod = await import('@capacitor/core');
        isNative = Boolean(mod.Capacitor?.isNativePlatform?.());
      } catch {
        isNative = false;
      }
    }

    capacitorNativeCachedRef.current = isNative;
    return isNative;
  };

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
  const videoInputRef = useRef<HTMLInputElement>(null);
  const messageQueueRef = useRef(getMessageQueue());
  const partnerWasPresentRef = useRef(false);
  const partnerDisconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const autoTerminateTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const focusScrollTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const partnerCountRef = useRef<number>(0);
  const partnerUnstableShownRef = useRef(false);
  const inactivityIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const lastActivityRef = useRef<number>(Date.now());
  const localFingerprintRef = useRef<string>('');
  const isTerminatingRef = useRef(false);
  const verificationShownRef = useRef(false);
  const systemMessagesShownRef = useRef<Set<string>>(new Set());

  const isCapacitorNativeShadow = (): boolean => {
    try {
      const c = (window as any).Capacitor;
      return Boolean(c && typeof c.isNativePlatform === 'function' && c.isNativePlatform());
    } catch {
      return false;
    }
  };
  const lastTerminationRef = useRef<number>(0);

  const replayProtectionRef = useRef(getReplayProtection());

  const lastPublicKeySendRef = useRef<number>(0);
  const publicKeyResendIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const publicKeyResendAttemptsRef = useRef<number>(0);
  const isKeyExchangeCompleteRef = useRef<boolean>(false);

  const openFileInputPicker = (input: HTMLInputElement | null): void => {
    if (!input) return;
    try {
      const maybeShowPicker = (input as any).showPicker;
      if (typeof maybeShowPicker === 'function') {
        maybeShowPicker.call(input);
        return;
      }
    } catch {
    }
    try {
      input.click();
    } catch {
    }
  };

  const handleFilePickerGate = (event: React.MouseEvent): void => {
    if (!isKeyExchangeComplete) {
      event.preventDefault();
      return;
    }
    if (!verificationState.verified) {
      event.preventDefault();
      toast.error('Please verify security codes before sending files');
      if (!verificationState.show) {
        setVerificationState(prev => ({ ...prev, show: true }));
      }
      return;
    }
  };

  const handleVideoPickerGate = (event: React.MouseEvent): void => {
    if (!isKeyExchangeComplete) {
      event.preventDefault();
      return;
    }
    if (!verificationState.verified) {
      event.preventDefault();
      toast.error('Please verify security codes before sending videos');
      if (!verificationState.show) {
        setVerificationState(prev => ({ ...prev, show: true }));
      }
      return;
    }
  };

  const markActivity = () => {
    lastActivityRef.current = Date.now();
  };

  const getTextEncoder = (): TextEncoder => {
    const cached = textEncoderRef.current;
    if (cached) return cached;
    const next = new TextEncoder();
    textEncoderRef.current = next;
    return next;
  };

  const getTextDecoder = (): TextDecoder => {
    const cached = textDecoderRef.current;
    if (cached) return cached;
    const next = new TextDecoder();
    textDecoderRef.current = next;
    return next;
  };

  const getAadPrefixes = (): { sessionId: string; chat: string; voice: string; file: string } => {
    const cached = aadPrefixesRef.current;
    if (cached && cached.sessionId === sessionId) {
      return cached;
    }
    const next = {
      sessionId,
      chat: `ghost:aad:v1|chat|${sessionId}|`,
      voice: `ghost:aad:v1|voice|${sessionId}|`,
      file: `ghost:aad:v1|file|${sessionId}|`,
    };
    aadPrefixesRef.current = next;
    return next;
  };

  const buildChatAad = (params: { senderId: string; messageId: string; sequence: number; type: string }): Uint8Array => {
    const prefixes = getAadPrefixes();
    return getTextEncoder().encode(`${prefixes.chat}${params.senderId}|${params.messageId}|${params.sequence}|${params.type}`);
  };

  const buildVoiceAad = (params: { senderId: string; messageId: string; sequence: number; duration: number }): Uint8Array => {
    const prefixes = getAadPrefixes();
    return getTextEncoder().encode(`${prefixes.voice}${params.senderId}|${params.messageId}|${params.sequence}|${params.duration}`);
  };

  const buildFileAad = (params: { senderId: string; fileId: string }): Uint8Array => {
    const prefixes = getAadPrefixes();
    return getTextEncoder().encode(`${prefixes.file}${params.senderId}|${params.fileId}`);
  };

  const {
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
  } = useFileTransfers({
    sessionId,
    encryptionEngineRef,
    realtimeManagerRef,
    getParticipantId: () => participantIdRef.current,
    getNextSequence: () => replayProtectionRef.current.getNextSequence(participantIdRef.current),
    isKeyExchangeComplete,
    isVerified: verificationState.verified,
    onRequireVerification: () => {
      setVerificationState((prev) => ({
        ...prev,
        show: true,
      }));
    },
    markActivity,
    buildFileAad,
    addMessageToQueue: (sid, message) => {
      messageQueueRef.current.addMessage(sid, message);
    },
    scheduleSyncMessagesFromQueue,
    getIsCapacitorNative,
    fileTransferTtlMs: 15 * 60 * 1000,
  });

  usePlausibleDeniability(() => {
    purgeActiveNativeVideoDropsBestEffort();
  });

  const syncMessagesFromQueue = useCallback(() => {
    const queuedMessages = messageQueueRef.current.getMessages(sessionId);
    const decoder = getTextDecoder();
    const cache = decodedTextCacheRef.current;
    const currentIds = new Set<string>();

    const nextMessages = queuedMessages.map((m) => {
      currentIds.add(m.id);
      if (m.content instanceof Uint8Array) {
        let decoded = cache.get(m.id);
        if (typeof decoded !== 'string') {
          decoded = decoder.decode(m.content);
          cache.set(m.id, decoded);
        }
        return { ...m, content: decoded };
      }
      return m;
    });

    if (cache.size > currentIds.size) {
      for (const key of cache.keys()) {
        if (!currentIds.has(key)) {
          cache.delete(key);
        }
      }
    }

    setMessages(nextMessages);
    setMemoryStats(messageQueueRef.current.getMemoryStats(sessionId));
  }, [sessionId]);

  const scheduleSyncMessagesFromQueue = useCallback(() => {
    if (syncScheduledRef.current) return;
    syncScheduledRef.current = true;

    const flush = () => {
      syncScheduledRef.current = false;
      syncMessagesFromQueue();
    };

    if (typeof queueMicrotask === 'function') {
      queueMicrotask(flush);
    } else {
      void Promise.resolve().then(flush);
    }
  }, [syncMessagesFromQueue]);

  const {
    voiceMessages,
    voiceMessagesById,
    sendVoiceMessage,
    addIncomingVoiceMessage,
    handleVoiceMessagePlayed,
    clearVoiceMessages,
  } = useVoiceMessaging({
    sessionId,
    getParticipantId: () => participantIdRef.current,
    encryptionEngineRef,
    realtimeManagerRef,
    replayProtectionRef,
    isKeyExchangeComplete,
    voiceVerified,
    markActivity,
    buildVoiceAad,
    addMessageToQueue: (sid, message) => {
      messageQueueRef.current.addMessage(sid, message);
    },
    scheduleSyncMessagesFromQueue,
  });

  useEffect(() => {
    try {
      if (isHost) {
        SecurityManager.setHostToken(sessionId, token);
      }
    } catch {
      // Ignore
    }

    initializeSession();

    return () => {
      try {
        if (isHost && isTerminatingRef.current) {
          void SessionService.deleteSession(sessionId, channelToken, token);
        }
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
  }, [sessionId, token, channelToken, isHost]);

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
      if (document.hidden) {
        if (!isCapacitorNative()) {
          setInputText('');
        }
      } else {
        purgeActiveNativeVideoDropsBestEffort();
      }
    };

    const handleBlur = () => {
      setIsWindowVisible(false);
      if (!isCapacitorNative()) {
        setInputText('');
      }
    };

    const handleFocus = () => {
      setIsWindowVisible(true);
      purgeActiveNativeVideoDropsBestEffort();
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
    void setTauriContentProtected(true);
    return () => {
      void setTauriContentProtected(false);
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
      if (!isTerminatingRef.current) {
        return;
      }

      if (isCapacitorNative()) {
        return;
      }

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
        const res = await SessionService.validateSession(sessionId, token, channelToken, 'host');
        if (!res.valid) {
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

      try {
        replayProtectionRef.current.resetSession(participantIdRef.current);
      } catch {
      }

      setConnectionState({ status: 'connecting', progress: 30 });

      keyPairRef.current = await KeyExchange.generateKeyPair();
      realtimeManagerRef.current = new RealtimeManager(sessionId, channelToken, participantIdRef.current);

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

      addSystemMessage('Secure connection established');

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

    manager.onPresenceChange((participants) => {
      const partnerCount = Math.max(0, participants.length - 1); // Exclude self
      partnerCountRef.current = partnerCount;

      if (partnerCount > 0) {
        setIsPartnerConnected(true);
        partnerWasPresentRef.current = true;
        if (partnerDisconnectTimeoutRef.current) {
          clearTimeout(partnerDisconnectTimeoutRef.current);
          partnerDisconnectTimeoutRef.current = null;
        }
        return;
      }

      if (!partnerWasPresentRef.current) {
        setIsPartnerConnected(false);
        return;
      }

      if (typeof document !== 'undefined' && document.hidden) {
        return;
      }

      if (partnerCount === 0 && partnerWasPresentRef.current) {
        if (partnerDisconnectTimeoutRef.current) {
          clearTimeout(partnerDisconnectTimeoutRef.current);
        }
        partnerDisconnectTimeoutRef.current = setTimeout(() => {
          if (typeof document !== 'undefined' && document.hidden) {
            return;
          }
          if (partnerCountRef.current === 0 && partnerWasPresentRef.current) {
            setIsPartnerConnected(false);
            addSystemMessage('Partner left the session');
          }
        }, 12000);
        return;
      }
    });

    manager.onMessage('file', handleRealtimeFileMessage);

    manager.onMessage('key-exchange', async (payload) => {
      try {
        const seq = Number(payload.data?.sequence);
        const rp = replayProtectionRef.current;
        const replayRes = rp.validateMessage(sessionId, payload.nonce, seq, payload.timestamp);
        if (!replayRes.valid) {
          return;
        }

        let remoteFingerprint = '';
        try {
          const pkB64 = String(payload.data?.publicKey || '');
          if (pkB64) {
            const pkBytes = base64ToBytes(pkB64);
            const view = pkBytes.buffer instanceof ArrayBuffer ? pkBytes : new Uint8Array(pkBytes);
            const digestBuf = view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);
            const hash = await crypto.subtle.digest('SHA-256', digestBuf);
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
          const pinKey = `session:${sessionId}:peer`;
          const pinRes = checkOrPinFingerprint(pinKey, remoteFingerprint);
          if (pinRes.status === 'mismatch') {
            toast.error('Security alert: partner key changed. Session blocked.');
            addSystemMessage('Security alert: partner fingerprint changed — session ended');
            await handleEndSession();
            return;
          }
          if (pinRes.status === 'pinned') {
            addSystemMessage('Fingerprint pinned (TOFU). Always verify codes for high-risk conversations.');
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
            const sharedSecretBytes = await KeyExchange.deriveSharedSecretKeyBytes(
              keyPairRef.current.privateKey,
              partnerPublicKey,
              sessionId
            );

            const bytes = new Uint8Array(sharedSecretBytes);
            const keyBase64 = bytesToBase64(bytes);

            try {
              await tauriInvoke('vault_bind_capability', { session_id: sessionId, capability_token: token });
              await tauriInvoke('vault_set_key', { session_id: sessionId, capability_token: token, key_base64: keyBase64 });
              encryptionEngineRef.current?.enableTauriVault(sessionId, token);
            } catch {
              const sharedSecret = await KeyExchange.deriveSharedSecret(
                keyPairRef.current.privateKey,
                partnerPublicKey,
                sessionId
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
              partnerPublicKey,
              sessionId
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

          addSystemMessage('Encryption established - verify security codes');
        }
      } catch {
        toast.error('Failed to establish secure connection');
      }
    });

    manager.onMessage('chat-message', async (payload) => {
      const ensureMinAckDelay = createMinDelay(35);
      try {
        markActivity();
        if (!encryptionEngineRef.current) return;

        const seq = Number(payload.data?.sequence);
        const rp = replayProtectionRef.current;
        const replayRes = rp.validateMessage(sessionId, payload.nonce, seq, payload.timestamp);
        if (!replayRes.valid) {
          return;
        }

        if (payload.data.type === 'file') {
          const MAX_SINGLE_FILE_ENCRYPTED_CHARS = 60000;
          const MAX_IV_CHARS = 256;

          const encrypted = String(payload.data.encrypted || '');
          const iv = String(payload.data.iv || '');
          const safeFileName = sanitizeFileName(String(payload.data.fileName || 'unknown_file')).slice(0, 256);

          if (encrypted.length === 0 || encrypted.length > MAX_SINGLE_FILE_ENCRYPTED_CHARS) {
            return;
          }
          if (iv.length === 0 || iv.length > MAX_IV_CHARS) {
            return;
          }

          const aad = buildFileAad({ senderId: payload.senderId, fileId: payload.nonce });
          const decrypted = await encryptionEngineRef.current.decryptBytes(encrypted, iv, aad);
          try {
            aad.fill(0);
          } catch {
          }
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

          const aad = buildChatAad({ senderId: payload.senderId, messageId: payload.nonce, sequence: seq, type: safeType });
          const decrypted = await encryptionEngineRef.current.decryptBytes(encrypted, iv, aad);
          try {
            aad.fill(0);
          } catch {
          }
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

        scheduleSyncMessagesFromQueue();
        await ensureMinAckDelay();
        await manager.send('message-ack', { messageId: payload.nonce });
      } catch {
        // Silent - message decryption failed
      }
    });

    manager.onMessage('voice-message', async (payload) => {
      try {
        markActivity();
        if (!encryptionEngineRef.current) return;

        const seq = Number(payload.data?.sequence);
        const rp = replayProtectionRef.current;
        const replayRes = rp.validateMessage(sessionId, payload.nonce, seq, payload.timestamp);
        if (!replayRes.valid) {
          return;
        }

        const duration = Number(payload.data?.duration) || 0;
        const aad = buildVoiceAad({ senderId: payload.senderId, messageId: payload.nonce, sequence: seq, duration });
        const decrypted = await encryptionEngineRef.current.decryptBytes(payload.data.encrypted, payload.data.iv, aad);
        try {
          aad.fill(0);
        } catch {
        }

        const decryptedBytes = new Uint8Array(decrypted);
        const blob = new Blob([decryptedBytes], { type: 'audio/webm;codecs=opus' });
        decryptedBytes.fill(0);

        addIncomingVoiceMessage({
          id: payload.nonce,
          blob,
          duration,
          sender: 'partner',
          timestamp: payload.timestamp,
          played: false,
        });

        messageQueueRef.current.addMessage(sessionId, {
          id: payload.nonce,
          content: '[Voice Message]',
          sender: 'partner',
          timestamp: payload.timestamp,
          type: 'voice',
          fileName: undefined
        });
        scheduleSyncMessagesFromQueue();
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
    const seq = replayProtectionRef.current.getNextSequence(participantIdRef.current);
    await realtimeManagerRef.current.send('key-exchange', { publicKey: publicKeyExport, sequence: seq });
  };

  const handleVerificationConfirmed = () => {
    setVerificationState(prev => ({ ...prev, show: false, verified: true }));
    setVoiceVerified(true);
    addSystemMessage('Security verified - all features enabled');
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
    scheduleSyncMessagesFromQueue();
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
      markActivity();
      const messageId = generateNonce();
      const seq = replayProtectionRef.current.getNextSequence(participantIdRef.current);
      const trimmed = inputText.trim();
      const messageBytes = new TextEncoder().encode(trimmed);
      const encryptBytes = messageBytes.slice();
      const aad = buildChatAad({ senderId: participantIdRef.current, messageId, sequence: seq, type: 'text' });
      const { encrypted, iv } = await encryptionEngineRef.current.encryptBytes(encryptBytes.buffer, aad);
      try {
        aad.fill(0);
      } catch {
      }

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
      scheduleSyncMessagesFromQueue();

      const sent = await realtimeManagerRef.current?.send('chat-message', {
        encrypted,
        iv,
        type: 'text',
        messageId,
        sequence: seq
      });

      if (!sent) {
        toast.error('Message may not have been delivered');
      }

      setInputText('');
    } catch {
      toast.error('Failed to send message');
    }
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

    let deleted = !isHost;
    if (isHost) {
      try {
        deleted = await SessionService.deleteSession(sessionId, channelToken, token);
      } catch {
        deleted = false;
      }
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

    destroyFileTransferState();

    try {
      destroyReplayProtection();
      replayProtectionRef.current = getReplayProtection();
    } catch {
    }

    if (encryptionEngineRef.current) {
      encryptionEngineRef.current = null;
    }
    sessionKeyRef.current = null;
    keyPairRef.current = null;
    partnerPublicKeyRef.current = null;

    messageQueueRef.current.nuclearPurge();

    try {
      decodedTextCacheRef.current.clear();
    } catch {
    }
    aadPrefixesRef.current = null;
    textEncoderRef.current = null;
    textDecoderRef.current = null;

    try {
      SecurityManager.clearHostToken(sessionId);
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
    clearVoiceMessages();
    setVoiceVerified(false);
    setVerificationState({
      show: false,
      localFingerprint: '',
      remoteFingerprint: '',
      verified: false
    });

    // SECURITY FIX: Removed disk-backed browser storage usage - keys now stored ONLY in memory

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
      SecurityManager.clearHostToken(sessionId);
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

    try {
      destroyReplayProtection();
      replayProtectionRef.current = getReplayProtection();
    } catch {
    }
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
    const deleted = isHost ? await SessionService.deleteSession(sessionId, channelToken, token) : true;

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
    try {
      decodedTextCacheRef.current.clear();
    } catch {
    }
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

        {!isWindowVisible && (
          <div
            className="fixed inset-0 z-[200] bg-background/95 backdrop-blur-xl"
            onClick={() => setIsWindowVisible(true)}
            role="button"
            tabIndex={0}
          />
        )}

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
                    <Shield className="h-2.5 w-2.5" />
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
                    ? (voiceMessagesById.get(message.id) || null)
                    : null;

                  const contentText = message.content as string;

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
                      ) : message.type === 'video' ? (
                        <div
                          className={cn(
                            "message-bubble-mobile px-4 py-3 rounded-2xl",
                            message.sender === 'me'
                              ? "bg-primary/20 rounded-br-md"
                              : "glass border border-border/50 rounded-bl-md"
                          )}
                        >
                          <div className="flex items-center gap-3">
                            <div className={cn(
                              "p-2 rounded-full",
                              message.sender === 'me' ? "bg-primary/25" : "bg-muted/30"
                            )}>
                              <Video className={cn(
                                "h-4 w-4",
                                message.sender === 'me' ? "text-primary-foreground" : "text-muted-foreground"
                              )} />
                            </div>
                            <div className="flex-1 min-w-0">
                              <p className={cn(
                                "text-sm",
                                message.sender === 'me' ? "text-primary-foreground" : "text-foreground"
                              )}>
                                {message.sender === 'me' ? 'Secure video sent' : 'Secure video received'}
                              </p>
                              <p className={cn(
                                "text-xs mt-0.5",
                                message.sender === 'me' ? "text-primary-foreground/70" : "text-muted-foreground"
                              )}>
                                {(() => {
                                  if (message.sender === 'me') {
                                    return 'Download-only';
                                  }
                                  const t = fileTransfersRef.current.get(message.id);
                                  if (!t || t.sealedKind !== 'video-drop' || t.total <= 0) {
                                    return 'Download-only';
                                  }
                                  if (t.received < t.total) {
                                    return `Receiving ${t.received}/${t.total}`;
                                  }
                                  return 'Ready to download';
                                })()}
                              </p>
                              {message.fileName && (
                                <p className={cn(
                                  "text-xs mt-0.5 truncate",
                                  message.sender === 'me' ? "text-primary-foreground/60" : "text-muted-foreground/80"
                                )}>
                                  {sanitizeFileName(message.fileName)}
                                </p>
                              )}
                            </div>
                            {message.sender !== 'me' && !downloadedVideoDrops.has(message.id) && (
                              <button
                                onClick={() => {
                                  const t = fileTransfersRef.current.get(message.id);
                                  if (!t || t.sealedKind !== 'video-drop' || t.total <= 0) {
                                    toast.error('Video not available');
                                    return;
                                  }
                                  if (t.received < t.total) {
                                    toast.info(`Video still receiving (${t.received}/${t.total})`);
                                    return;
                                  }
                                  void handleDownloadVideoDrop(message.id);
                                }}
                                className={cn(
                                  "p-2 rounded-full transition-colors active:scale-95",
                                  "bg-accent/20 text-accent hover:bg-accent/30",
                                  (() => {
                                    const t = fileTransfersRef.current.get(message.id);
                                    if (!t || t.sealedKind !== 'video-drop' || t.total <= 0 || t.received < t.total) {
                                      return 'opacity-80';
                                    }
                                    return '';
                                  })()
                                )}
                                aria-label="Download video"
                                title="Download video"
                              >
                                <Download className="h-4 w-4" />
                              </button>
                            )}
                          </div>
                          {message.sender !== 'me' && downloadedVideoDrops.has(message.id) && (
                            <div className="mt-2 text-xs text-muted-foreground/70">
                              Securely destroyed after download
                            </div>
                          )}
                          <div className={cn(
                            "text-xs mt-2 opacity-60",
                            message.sender === 'me' ? "text-primary-foreground" : "text-muted-foreground"
                          )}>
                            {new Date(message.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          </div>
                        </div>
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
                              <div className="space-y-1">
                                {message.sender !== 'me' && typeof message.content === 'string' && message.content.length === 0 && (
                                  <p className={cn(
                                    "text-xs",
                                    "text-muted-foreground"
                                  )}>
                                    {(() => {
                                      const t = fileTransfersRef.current.get(message.id);
                                      if (!t || t.sealedKind !== 'file' || t.total <= 0) {
                                        return 'Download-only';
                                      }
                                      if (t.received < t.total) {
                                        return `Receiving ${t.received}/${t.total}`;
                                      }
                                      return 'Ready to download';
                                    })()}
                                  </p>
                                )}
                                <FilePreviewCard
                                  fileName={message.fileName || 'Unknown File'}
                                  content={typeof message.content === 'string' ? message.content : ''}
                                  sender={message.sender}
                                />
                              </div>
                            )
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
                  onBlur={() => {
                  }}
                  onFocus={() => {
                    if (focusScrollTimeoutRef.current) {
                      clearTimeout(focusScrollTimeoutRef.current);
                    }
                    focusScrollTimeoutRef.current = setTimeout(() => {
                      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
                    }, 300);
                  }}
                  autoComplete="off"
                  autoCorrect="off"
                  autoCapitalize="off"
                  spellCheck={false}
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
                  id="ghost-file-input"
                  type="file"
                  accept=".pdf,.doc,.docx,.ppt,.pptx,.jpg,.jpeg,.png,application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.ms-powerpoint,application/vnd.openxmlformats-officedocument.presentationml.presentation,image/jpeg,image/png"
                  onChange={handleFileUpload}
                  className="sr-only"
                />
                <input
                  ref={videoInputRef}
                  id="ghost-video-input"
                  type="file"
                  accept=".mp4,video/mp4"
                  onChange={handleVideoUpload}
                  className="sr-only"
                />
                <label
                  htmlFor="ghost-file-input"
                  onClick={handleFilePickerGate}
                  className="action-button-mobile border border-border/50 bg-secondary/30"
                  aria-label="Attach file"
                  title="Attach file"
                >
                  <Paperclip className="h-5 w-5 text-muted-foreground" />
                </label>

                <label
                  htmlFor="ghost-video-input"
                  onClick={handleVideoPickerGate}
                  className="action-button-mobile border border-border/50 bg-secondary/30"
                  aria-label="Secure Video Drop"
                  title="Secure Video Drop"
                >
                  <Video className="h-5 w-5 text-muted-foreground" />
                </label>

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

export default ChatInterface;
