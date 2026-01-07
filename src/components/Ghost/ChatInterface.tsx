import { useState, useEffect, useRef, useCallback, type ChangeEvent, type KeyboardEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Ghost, Send, Paperclip, Shield, X, Loader2, Trash2, HardDrive, FileText, FileSpreadsheet, FileImage, FileArchive, FileCode, File, AlertTriangle, Clock, Download } from 'lucide-react';
import { toast } from 'sonner';
import { EncryptionEngine, KeyExchange, generateNonce } from '@/utils/encryption';
import { SecurityManager, validateMessage, validateFile, sanitizeFileName } from '@/utils/security';
import { RealtimeManager, BroadcastPayload, ConnectionState } from '@/lib/realtimeManager';
import { SessionService } from '@/lib/sessionService';
import { getMessageQueue, QueuedMessage } from '@/utils/clientMessageQueue';
import { cn } from '@/lib/utils';
import { generatePlausibleTimestamp, isTimestampObfuscationEnabled } from '@/utils/plausibleTimestamp';
import { useMemoryCleanup } from '@/hooks/useMemoryCleanup';
import { isTauriRuntime, tauriInvoke } from '@/utils/runtime';
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
  const heartbeatIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const sessionExtendIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const partnerDisconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const partnerCountRef = useRef<number>(0);
  const fileTransfersRef = useRef<Map<string, { chunks: string[]; received: number; total: number; iv: string; fileName: string; fileType: string; timestamp: number; cleanupTimer: ReturnType<typeof setTimeout> | null }>>(new Map());
  const localFingerprintRef = useRef<string>('');
  const isTerminatingRef = useRef(false);
  const verificationShownRef = useRef(false);
  const systemMessagesShownRef = useRef<Set<string>>(new Set());
  const lastTerminationRef = useRef<number>(0);

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
      cleanup();
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

    if (window.visualViewport) {
      window.visualViewport.addEventListener('resize', scrollToBottom);
    }

    return () => {
      if (window.visualViewport) {
        window.visualViewport.removeEventListener('resize', scrollToBottom);
      }
    };
  }, []);

  useEffect(() => {
    const handleVisibilityChange = () => {
      setIsWindowVisible(!document.hidden);
    };

    const handleBlur = () => {
      setIsWindowVisible(false);
    };

    const handleFocus = () => {
      setIsWindowVisible(true);
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('blur', handleBlur);
    window.addEventListener('focus', handleFocus);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('blur', handleBlur);
      window.removeEventListener('focus', handleFocus);
    };
  }, []);

  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = 'Leave Ghost session? Click "End Session" to properly terminate.';
      return e.returnValue;
    };

    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [sessionId]);

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

    window.addEventListener('pagehide', handlePageHide);
    window.addEventListener('unload', handlePageHide);
    return () => {
      window.removeEventListener('pagehide', handlePageHide);
      window.removeEventListener('unload', handlePageHide);
    };
  }, [sessionId]);

  const initializeSession = async () => {
    try {
      setConnectionState({ status: 'validating', progress: 10 });

      verificationShownRef.current = false;
      localFingerprintRef.current = '';
      partnerPublicKeyRef.current = null;
      sessionKeyRef.current = null;
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
      const extended = await SessionService.extendSession(sessionId);
      if (!extended) {
        addSystemMessage('⚠️ Session extension failed - connection may expire soon');
      }

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
        setupHeartbeatMonitoring();

        if (sessionExtendIntervalRef.current) {
          clearInterval(sessionExtendIntervalRef.current);
        }
        sessionExtendIntervalRef.current = setInterval(() => {
          SessionService.extendSession(sessionId).catch(() => {
          });
        }, 10 * 60 * 1000);
      }
    });

    manager.onMessage('file', async (payload) => {
      try {
        if (!encryptionEngineRef.current) return;

        const data = payload.data;
        if (!data || !data.fileId || !data.kind) return;

        if (data.kind === 'init') {
          const existing = fileTransfersRef.current.get(data.fileId);
          if (existing?.cleanupTimer) {
            clearTimeout(existing.cleanupTimer);
          }

          const cleanupTimer = setTimeout(() => {
            const t = fileTransfersRef.current.get(data.fileId);
            if (t?.cleanupTimer) {
              clearTimeout(t.cleanupTimer);
            }
            fileTransfersRef.current.delete(data.fileId);
          }, 5 * 60 * 1000);

          fileTransfersRef.current.set(data.fileId, {
            chunks: new Array(Math.max(0, Number(data.totalChunks) || 0)).fill(''),
            received: 0,
            total: Math.max(0, Number(data.totalChunks) || 0),
            iv: String(data.iv || ''),
            fileName: String(data.fileName || ''),
            fileType: String(data.fileType || 'application/octet-stream'),
            timestamp: Number(data.timestamp) || payload.timestamp,
            cleanupTimer
          });
          return;
        }

        if (data.kind === 'chunk') {
          let t = fileTransfersRef.current.get(data.fileId);
          if (!t) {
            const total = Math.max(0, Number(data.totalChunks) || 0);
            if (!total) return;

            const cleanupTimer = setTimeout(() => {
              const existing = fileTransfersRef.current.get(data.fileId);
              if (existing?.cleanupTimer) {
                clearTimeout(existing.cleanupTimer);
              }
              fileTransfersRef.current.delete(data.fileId);
            }, 5 * 60 * 1000);

            t = {
              chunks: new Array(total).fill(''),
              received: 0,
              total,
              iv: String(data.iv || ''),
              fileName: String(data.fileName || ''),
              fileType: String(data.fileType || 'application/octet-stream'),
              timestamp: Number(data.timestamp) || payload.timestamp,
              cleanupTimer
            };
            fileTransfersRef.current.set(data.fileId, t);
          }
          const idx = Number(data.index);
          if (!Number.isFinite(idx) || idx < 0 || idx >= t.total) return;
          if (t.chunks[idx]) return;

          t.chunks[idx] = String(data.chunk || '');
          t.received += 1;

          if (t.received >= t.total && t.total > 0) {
            const encrypted = t.chunks.join('');
            const decrypted = await encryptionEngineRef.current.decryptBytes(encrypted, t.iv);
            const decryptedBytes = new Uint8Array(decrypted);
            const blob = new Blob([decryptedBytes], { type: t.fileType || 'application/octet-stream' });
            const objectUrl = URL.createObjectURL(blob);
            decryptedBytes.fill(0);

            if (t.cleanupTimer) {
              clearTimeout(t.cleanupTimer);
            }
            fileTransfersRef.current.delete(data.fileId);

            messageQueueRef.current.addMessage(sessionId, {
              id: data.fileId,
              content: objectUrl,
              sender: 'partner',
              timestamp: t.timestamp,
              type: 'file',
              fileName: t.fileName
            });
            syncMessagesFromQueue();
          }

          return;
        }
      } catch {
        // Silent
      }
    });

    manager.onPresenceChange(async (participants) => {
      const partnerCount = participants.filter(id => id !== participantIdRef.current).length;
      const hasPartner = partnerCount > 0;
      partnerCountRef.current = partnerCount;
      setIsPartnerConnected(hasPartner);

      if (hasPartner) {
        if (partnerDisconnectTimeoutRef.current) {
          clearTimeout(partnerDisconnectTimeoutRef.current);
          partnerDisconnectTimeoutRef.current = null;
        }
      } else if (partnerWasPresentRef.current && !isTerminatingRef.current) {
        if (!partnerDisconnectTimeoutRef.current) {
          addSystemMessage('⚠️ Partner connection unstable - waiting...');
          partnerDisconnectTimeoutRef.current = setTimeout(async () => {
            partnerDisconnectTimeoutRef.current = null;
            if (isTerminatingRef.current) return;
            if (!realtimeManagerRef.current) return;
            if (partnerCountRef.current === 0) {
              partnerWasPresentRef.current = false;
              addSystemMessage('⚠️ Partner disconnected - waiting for reconnection...');
            }
          }, 30000);
        }
      }

      if (hasPartner) {
        partnerWasPresentRef.current = true;
        sendPublicKey();
      }
    });

    manager.onMessage('key-exchange', async (payload) => {
      try {
        const partnerPublicKey = await KeyExchange.importPublicKey(payload.data.publicKey);
        partnerPublicKeyRef.current = partnerPublicKey;

        if (keyPairRef.current) {
          if (isTauriRuntime()) {
            const sharedSecretBytes = await KeyExchange.deriveSharedSecretBytes(
              keyPairRef.current.privateKey,
              partnerPublicKey
            );

            const bytes = new Uint8Array(sharedSecretBytes);
            const chunkSize = 0x8000;
            const chunks: string[] = [];
            for (let i = 0; i < bytes.length; i += chunkSize) {
              const sub = bytes.subarray(i, i + chunkSize);
              chunks.push(String.fromCharCode.apply(null, sub as unknown as number[]));
            }
            const keyBase64 = btoa(chunks.join(''));

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

          if (!localFingerprintRef.current && keyPairRef.current) {
            try {
              localFingerprintRef.current = await KeyExchange.generateFingerprint(keyPairRef.current.publicKey);
            } catch {
            }
          }

          const remoteFingerprint = await KeyExchange.generateFingerprint(partnerPublicKey);

          // Only show verification modal ONCE per session
          if (!verificationShownRef.current) {
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
        if (!encryptionEngineRef.current) return;

        if (payload.data.type === 'file') {
          const decrypted = await encryptionEngineRef.current.decryptBytes(
            payload.data.encrypted,
            payload.data.iv
          );
          const decryptedBytes = new Uint8Array(decrypted);
          const blob = new Blob([decryptedBytes], { type: payload.data.fileType || 'application/octet-stream' });
          const objectUrl = URL.createObjectURL(blob);

          decryptedBytes.fill(0);

          messageQueueRef.current.addMessage(sessionId, {
            id: payload.nonce,
            content: objectUrl,
            sender: 'partner',
            timestamp: payload.timestamp,
            type: 'file',
            fileName: payload.data.fileName
          });
        } else {
          const decrypted = await encryptionEngineRef.current.decryptMessage(
            payload.data.encrypted,
            payload.data.iv
          );

          messageQueueRef.current.addMessage(sessionId, {
            id: payload.nonce,
            content: decrypted,
            sender: 'partner',
            timestamp: payload.timestamp,
            type: payload.data.type || 'text',
            fileName: payload.data.fileName
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
        if (!encryptionEngineRef.current) return;

        const decrypted = await encryptionEngineRef.current.decryptBytes(
          payload.data.encrypted,
          payload.data.iv
        );

        const decryptedBytes = new Uint8Array(decrypted);
        const blob = new Blob([decryptedBytes], { type: 'audio/webm;codecs=opus' });

        decryptedBytes.fill(0);

        setVoiceMessages(prev => [...prev, {
          id: payload.nonce,
          blob,
          duration: payload.data.duration,
          sender: 'partner',
          timestamp: payload.timestamp,
          played: false
        }]);

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
      messageQueueRef.current.acknowledgeMessage(sessionId, payload.data.messageId);
    });

    manager.onMessage('session-terminated', async () => {
      isTerminatingRef.current = true;
      await triggerSessionTermination('partner_left');
      await cleanup();
    });
  };

  const setupHeartbeatMonitoring = () => {
    if (heartbeatIntervalRef.current) {
      clearInterval(heartbeatIntervalRef.current);
    }

    heartbeatIntervalRef.current = setInterval(() => {
      if (!realtimeManagerRef.current) return;

      const channel = (realtimeManagerRef.current as any).channel;
      if (channel && channel.state !== 'joined') {
        if (heartbeatIntervalRef.current) {
          clearInterval(heartbeatIntervalRef.current);
          heartbeatIntervalRef.current = null;
        }
      }
    }, 10000);
  };

  const sendPublicKey = async () => {
    if (!realtimeManagerRef.current || !keyPairRef.current) return;

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
    addSystemMessage('⚠️ Security verification failed - voice disabled');
    toast.error('Security codes did not match');
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

      setVoiceMessages(prev => [...prev, {
        id: messageId,
        blob,
        duration,
        sender: 'me',
        timestamp: Date.now(),
        played: false
      }]);

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
      prev.map(vm => vm.id === messageId ? { ...vm, played: true } : vm)
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
      const { encrypted, iv } = await encryptionEngineRef.current.encryptMessage(inputText.trim());

      const { displayTimestamp } = generatePlausibleTimestamp();

      messageQueueRef.current.addMessage(sessionId, {
        id: messageId,
        content: inputText.trim(),
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

        const chunkSize = 45_000;
        const totalChunks = Math.ceil(encrypted.length / chunkSize);

        let sent = true;
        if (totalChunks <= 1) {
          sent = await realtimeManagerRef.current?.send('chat-message', {
            encrypted,
            iv,
            type: 'file',
            fileName: sanitizedName,
            fileType: file.type,
            messageId
          }) ?? false;
        } else {
          sent = (await realtimeManagerRef.current?.send('file', {
            kind: 'init',
            fileId: messageId,
            fileName: sanitizedName,
            fileType: file.type,
            iv,
            totalChunks,
            timestamp: displayTimestamp
          })) ?? false;

          if (sent) {
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
                timestamp: displayTimestamp
              })) ?? false;
              if (!ok) {
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

    if (!deleted) {
      toast.error('Server deletion failed - session ended locally');
    }
  };

  const destroyLocalSessionData = () => {
    if (heartbeatIntervalRef.current) {
      clearInterval(heartbeatIntervalRef.current);
      heartbeatIntervalRef.current = null;
    }

    if (sessionExtendIntervalRef.current) {
      clearInterval(sessionExtendIntervalRef.current);
      sessionExtendIntervalRef.current = null;
    }

    if (partnerDisconnectTimeoutRef.current) {
      clearTimeout(partnerDisconnectTimeoutRef.current);
      partnerDisconnectTimeoutRef.current = null;
    }

    fileTransfersRef.current.forEach((t) => {
      if (t.cleanupTimer) {
        clearTimeout(t.cleanupTimer);
      }
    });
    fileTransfersRef.current.clear();

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
    // localStorage.removeItem(`ghost_session_${sessionId}`);
    // localStorage.removeItem(`ghost_keys_${sessionId}`);

    if (typeof (window as any).gc === 'function') {
      try {
        (window as any).gc();
      } catch {
        // Ignore
      }
    }
  };

  const cleanup = async () => {
    if (heartbeatIntervalRef.current) {
      clearInterval(heartbeatIntervalRef.current);
    }

    if (sessionExtendIntervalRef.current) {
      clearInterval(sessionExtendIntervalRef.current);
      sessionExtendIntervalRef.current = null;
    }

    if (partnerDisconnectTimeoutRef.current) {
      clearTimeout(partnerDisconnectTimeoutRef.current);
      partnerDisconnectTimeoutRef.current = null;
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

    // 1. Server-side nuclear wipe (atomic)
    const deleted = await SessionService.deleteSession(sessionId);

    // 2. Clear all in-memory state
    destroyLocalSessionData();

    // 3. Full memory cleanup (keys, trapState, buffers)
    await fullCleanup();

    // 4. Disconnect realtime
    await cleanup();

    // 5. Redirect with no trace (history.replace)
    navigate('/', { replace: true });

    if (!deleted) {
      toast.error('Server deletion failed - session ended locally');
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

        {isPartnerConnected && verificationState.verified && (
          <div className="fixed top-0 left-0 right-0 z-[60] secure-line-banner md:hidden pt-[env(safe-area-inset-top,0px)]">
            SECURE LINE ACTIVE
          </div>
        )}

        <header className={cn(
          "mobile-header fixed left-0 right-0 z-50 glass border-b border-border/30 h-14 md:h-16",
          isPartnerConnected && verificationState.verified ? "top-[calc(28px+env(safe-area-inset-top,0px))] md:top-9" : "top-[env(safe-area-inset-top,0px)] md:top-9"
        )}>
          <div className="container mx-auto px-2 md:px-4 h-full flex items-center">
            <div className="flex items-center justify-between w-full gap-2">
              <div className="flex items-center gap-1.5 md:gap-3 flex-1 min-w-0">
                <Ghost className="h-5 w-5 md:h-6 md:w-6 text-primary flex-shrink-0" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] md:text-xs text-primary truncate">{sessionId}</span>
                    <div className="md:hidden flex-shrink-0">
                      <div className={cn(
                        "mobile-connection-badge text-[9px] px-1.5 py-0.5",
                        isPartnerConnected ? "bg-accent/20 text-accent" : "bg-yellow-500/20 text-yellow-500"
                      )}>
                        <div className={cn(
                          "w-1.5 h-1.5 rounded-full",
                          isPartnerConnected ? "bg-accent animate-pulse" : "bg-yellow-500"
                        )} />
                        {isPartnerConnected ? "Live" : "Wait"}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-1 md:gap-2 text-[9px] md:text-xs text-muted-foreground">
                    <Shield className="h-2.5 w-2.5 md:h-3 md:w-3 flex-shrink-0" />
                    <span className="truncate">{isKeyExchangeComplete ? 'E2E Encrypted' : 'Connecting...'}</span>
                  </div>
                </div>
              </div>

              <div className="hidden md:flex items-center gap-2">
                <ConnectionStatusIndicator state={connectionState} isPartnerConnected={isPartnerConnected} />
              </div>

              <div className="flex items-center gap-0.5 md:gap-2 flex-shrink-0">
                <div className="hidden lg:flex items-center gap-1 px-2 py-1 rounded bg-secondary/50 text-xs text-muted-foreground">
                  <HardDrive className="h-3 w-3" />
                  <span>{memoryStats.messageCount} msgs</span>
                  <span className="text-muted-foreground/50">|</span>
                  <span>{formatBytes(memoryStats.estimatedBytes)}</span>
                </div>

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

                  return (
                    <div
                      key={message.id}
                      className={cn(
                        "flex",
                        message.type === 'system' ? 'justify-center' : message.sender === 'me' ? 'justify-end' : 'justify-start'
                      )}
                    >
                      {message.type === 'system' ? (
                        <div className="px-4 py-2 rounded-full bg-secondary/50 text-sm text-muted-foreground max-w-[90%] text-center">
                          {message.content}
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
                            message.content.startsWith('data:image') ? (
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
                                content={message.content}
                                sender={message.sender}
                              />
                            )
                          ) : message.content.startsWith('http://') || message.content.startsWith('https://') ? (
                            <FilePreviewCard
                              fileName={message.content}
                              content={message.content}
                              sender={message.sender}
                            />
                          ) : (
                            <p className="whitespace-pre-wrap break-words">{message.content}</p>
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
                    setTimeout(() => {
                      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
                    }, 300);
                  }}
                  placeholder={isKeyExchangeComplete ? "Type your message..." : "Connecting..."}
                  disabled={!isKeyExchangeComplete}
                  rows={1}
                  className="mobile-text-input flex-1"
                />

                <button
                  onClick={sendMessage}
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
                  onClick={() => fileInputRef.current?.click()}
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
                  disabled={!isKeyExchangeComplete || !verificationState.verified}
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
const ConnectionStatusIndicator = ({ state, isPartnerConnected }: { state: ConnectionState; isPartnerConnected: boolean }) => {
  const getStatusInfo = () => {
    if (state.status === 'connected' && isPartnerConnected) {
      return { text: 'Partner Connected', color: 'text-accent', dot: 'bg-accent' };
    }
    if (state.status === 'connected') {
      return { text: 'Waiting for Partner', color: 'text-yellow-500', dot: 'bg-yellow-500' };
    }
    if (state.status === 'error') {
      return { text: state.error || 'Connection Error', color: 'text-destructive', dot: 'bg-destructive' };
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
