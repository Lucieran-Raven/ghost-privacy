import { useState, useEffect, useRef, useCallback, type KeyboardEvent } from 'react';
import { Ghost, Send, Paperclip, Shield, X, Loader2, Trash2, HardDrive, FileText, FileSpreadsheet, FileImage, FileArchive, FileCode, File as FileIcon, AlertTriangle, Clock, Download, Video } from 'lucide-react';
import { toast } from 'sonner';
import { EncryptionEngine } from '@/utils/encryption';
import { SecurityManager, sanitizeFileName } from '@/utils/security';
import { RealtimeManager, ConnectionState } from '@/lib/realtimeManager';
import { SessionService } from '@/lib/sessionService';
import { getMessageQueue, QueuedMessage } from '@/utils/clientMessageQueue';
import { cn } from '@/lib/utils';
import { isTimestampObfuscationEnabled } from '@/utils/plausibleTimestamp';
import { useMemoryCleanup } from '@/hooks/useMemoryCleanup';
import { getReplayProtection, destroyReplayProtection } from '@/utils/replayProtection';
import { useMediaVoice } from './hooks/useMediaVoice';
import { normalizeFileNameForMime, sniffMimeFromBytes } from './hooks/fileTransferUtils';
import { useFileTransfers } from './hooks/useFileTransfers';
import { useChatTransport } from './hooks/useChatTransport';
import { useQuarantine } from './hooks/useQuarantine';
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

interface VerificationState {
  show: boolean;
  localFingerprint: string;
  remoteFingerprint: string;
  verified: boolean;
}

const ChatInterface = ({ sessionId, token, channelToken, isHost, timerMode, onEndSession }: ChatInterfaceProps) => {
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
    voiceVerified,
    setVoiceVerified,
    handleRequestVoiceVerification,
    voiceMessages,
    voiceMessagesById,
    sendVoiceMessage,
    addIncomingVoiceMessage,
    handleVoiceMessagePlayed,
    clearVoiceMessages,
  } = useMediaVoice({
    sessionId,
    getParticipantId: () => participantIdRef.current,
    encryptionEngineRef,
    realtimeManagerRef,
    replayProtectionRef,
    isKeyExchangeComplete,
    markActivity,
    buildVoiceAad,
    addMessageToQueue: (sid, message) => {
      messageQueueRef.current.addMessage(sid, message);
    },
    scheduleSyncMessagesFromQueue,
    verificationState,
    setVerificationState,
    verificationShownRef,
  });

  const {
    sendMessage,
    addSystemMessage,
    destroyLocalSessionData,
    handleEndSession,
    handleNuclearPurge,
    initializeSession,
    cleanup,
  } = useChatTransport({
    sessionId,
    token,
    channelToken,
    isHost,
    onEndSession,
    fullCleanup,

    realtimeManagerRef,
    encryptionEngineRef,
    keyPairRef,
    partnerPublicKeyRef,
    participantIdRef,
    sessionKeyRef,

    replayProtectionRef,

    partnerWasPresentRef,
    partnerDisconnectTimeoutRef,
    autoTerminateTimeoutRef,
    focusScrollTimeoutRef,
    partnerCountRef,
    inactivityIntervalRef,
    lastActivityRef,

    localFingerprintRef,
    isTerminatingRef,
    verificationShownRef,
    systemMessagesShownRef,
    lastTerminationRef,

    lastPublicKeySendRef,
    publicKeyResendIntervalRef,
    publicKeyResendAttemptsRef,
    isKeyExchangeCompleteRef,

    decodedTextCacheRef,
    aadPrefixesRef,
    textEncoderRef,
    textDecoderRef,

    getTextEncoder,
    getTextDecoder,

    buildChatAad,
    buildVoiceAad,
    buildFileAad,

    messageQueueRef,
    scheduleSyncMessagesFromQueue,
    markActivity,

    setConnectionState,
    setIsPartnerConnected,
    setIsKeyExchangeComplete,
    setVerificationState,
    setInputText,
    setMessages,
    setMemoryStats,
    clearVoiceMessages,

    destroyFileTransferState,
    handleRealtimeFileMessage,
    addIncomingVoiceMessage,

    getInputText: () => inputText,
    setInputTextState: setInputText,
    getIsKeyExchangeComplete: () => isKeyExchangeComplete,
    getVerificationState: () => verificationState,

    isCapacitorNative,
  });

  const {
    isWindowVisible,
    setIsWindowVisible,
  } = useQuarantine({
    sessionId,
    isTerminatingRef,
    isCapacitorNative,
    destroyLocalSessionData,
    purgeActiveNativeVideoDropsBestEffort,
    setInputText,
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
    isKeyExchangeCompleteRef.current = isKeyExchangeComplete;
  }, [isKeyExchangeComplete]);

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
