/**
 * Responsibilities:
 * - Owns the realtime session lifecycle (connect, key exchange, presence, termination).
 * - Owns authenticated message send/receive wiring and replay/sequence enforcement.
 * - Owns shutdown ordering and best-effort cleanup/zeroization paths.
 *
 * Security guarantees:
 * - Fail-closed behavior where required for cryptographic operations.
 * - Does not persist plaintext chat payloads beyond the in-memory queue.
 * - Enforces replay protection and validation on inbound traffic.
 *
 * Caveats / limitations:
 * - This module cannot prevent OS-level capture (screenshots, keyloggers, etc.).
 * - Cleanup is best-effort on abrupt process termination.
 *
 * Cross-module dependencies:
 * - Requires message queue + replay protection refs owned by the shell.
 * - Delegates file/voice payload handling to the respective subsystems.
 */

import { useCallback, type MutableRefObject } from 'react';
import { toast } from 'sonner';
import { EncryptionEngine, KeyExchange, generateNonce } from '@/utils/encryption';
import { SecurityManager, validateMessage, sanitizeFileName } from '@/utils/security';
import { checkOrPinFingerprint } from '@/utils/tofuFingerprintStore';
import { RealtimeManager, type BroadcastPayload, type ConnectionState } from '@/lib/realtimeManager';
import { SessionService } from '@/lib/sessionService';
import type { QueuedMessage } from '@/utils/clientMessageQueue';
import { generatePlausibleTimestamp } from '@/utils/plausibleTimestamp';
import { isTauriRuntime, tauriInvoke } from '@/utils/runtime';
import { base64ToBytes, bytesToBase64 } from '@/utils/algorithms/encoding/base64';
import { secureZeroUint8Array } from '@/utils/algorithms/memory/zeroization';
import { getReplayProtection, destroyReplayProtection } from '@/utils/replayProtection';
import { createMinDelay } from '@/utils/interactionTiming';
import { normalizeFileNameForMime, sniffMimeFromBytes } from './fileTransferUtils';

export type TerminationReason = 'partner_left' | 'connection_lost' | 'channel_dead' | 'manual';

export interface VerificationState {
  show: boolean;
  localFingerprint: string;
  remoteFingerprint: string;
  verified: boolean;
}

export function useChatTransport(params: {
  sessionId: string;
  token: string;
  channelToken: string;
  isHost: boolean;
  onEndSession: (showToast?: boolean) => void;
  fullCleanup: () => Promise<unknown>;

  realtimeManagerRef: MutableRefObject<RealtimeManager | null>;
  encryptionEngineRef: MutableRefObject<EncryptionEngine | null>;
  keyPairRef: MutableRefObject<CryptoKeyPair | null>;
  partnerPublicKeyRef: MutableRefObject<CryptoKey | null>;
  participantIdRef: MutableRefObject<string>;
  sessionKeyRef: MutableRefObject<CryptoKey | null>;

  replayProtectionRef: MutableRefObject<ReturnType<typeof getReplayProtection>>;

  partnerWasPresentRef: MutableRefObject<boolean>;
  partnerDisconnectTimeoutRef: MutableRefObject<ReturnType<typeof setTimeout> | null>;
  autoTerminateTimeoutRef: MutableRefObject<ReturnType<typeof setTimeout> | null>;
  focusScrollTimeoutRef: MutableRefObject<ReturnType<typeof setTimeout> | null>;
  partnerCountRef: MutableRefObject<number>;
  inactivityIntervalRef: MutableRefObject<ReturnType<typeof setInterval> | null>;
  lastActivityRef: MutableRefObject<number>;

  localFingerprintRef: MutableRefObject<string>;
  isTerminatingRef: MutableRefObject<boolean>;
  verificationShownRef: MutableRefObject<boolean>;
  systemMessagesShownRef: MutableRefObject<Set<string>>;
  lastTerminationRef: MutableRefObject<number>;

  lastPublicKeySendRef: MutableRefObject<number>;
  publicKeyResendIntervalRef: MutableRefObject<ReturnType<typeof setInterval> | null>;
  publicKeyResendAttemptsRef: MutableRefObject<number>;
  isKeyExchangeCompleteRef: MutableRefObject<boolean>;

  decodedTextCacheRef: MutableRefObject<Map<string, string>>;
  aadPrefixesRef: MutableRefObject<{ sessionId: string; chat: string; voice: string; file: string } | null>;
  textEncoderRef: MutableRefObject<TextEncoder | null>;
  textDecoderRef: MutableRefObject<TextDecoder | null>;

  getTextEncoder: () => TextEncoder;
  getTextDecoder: () => TextDecoder;

  buildChatAad: (args: { senderId: string; messageId: string; sequence: number; type: string }) => Uint8Array;
  buildVoiceAad: (args: { senderId: string; messageId: string; sequence: number; duration: number }) => Uint8Array;
  buildFileAad: (args: { senderId: string; fileId: string }) => Uint8Array;

  messageQueueRef: MutableRefObject<{
    addMessage: (sessionId: string, msg: Omit<QueuedMessage, 'receivedAt' | 'acknowledged'> & Partial<Pick<QueuedMessage, 'receivedAt' | 'acknowledged'>>) => void;
    acknowledgeMessage: (sessionId: string, id: string) => void;
    destroySession: (sessionId: string) => void;
    nuclearPurge: () => void;
  }>;

  scheduleSyncMessagesFromQueue: () => void;
  markActivity: () => void;

  setConnectionState: (state: ConnectionState) => void;
  setIsPartnerConnected: (v: boolean) => void;
  setIsKeyExchangeComplete: (v: boolean) => void;
  setVerificationState: (next: VerificationState | ((prev: VerificationState) => VerificationState)) => void;
  setInputText: (v: string) => void;
  setMessages: (v: QueuedMessage[]) => void;
  setMemoryStats: (v: { messageCount: number; estimatedBytes: number }) => void;
  setVoiceVerified: (v: boolean) => void;

  clearVoiceMessages: () => void;

  destroyFileTransferState: () => void;
  handleRealtimeFileMessage: (payload: BroadcastPayload) => Promise<void>;
  addIncomingVoiceMessage: (msg: {
    id: string;
    blob: Blob;
    duration: number;
    sender: 'partner' | 'me';
    timestamp: number;
    played?: boolean;
  }) => void;

  getInputText: () => string;
  setInputTextState: (v: string) => void;
  getIsKeyExchangeComplete: () => boolean;
  getVerificationState: () => VerificationState;

  isCapacitorNative: () => boolean;
}): {
  sendMessage: () => Promise<void>;
  addSystemMessage: (content: string, unique?: boolean) => void;
  destroyLocalSessionData: () => void;
  handleEndSession: () => Promise<void>;
  handleNuclearPurge: () => void;
  initializeSession: () => Promise<void>;
  cleanup: () => Promise<void>;
} {
  const {
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
    setVoiceVerified,
    clearVoiceMessages,
    destroyFileTransferState,
    handleRealtimeFileMessage,
    addIncomingVoiceMessage,
    getInputText,
    setInputTextState,
    getIsKeyExchangeComplete,
    getVerificationState,
    isCapacitorNative,
  } = params;

  const stopPublicKeyResend = useCallback(() => {
    if (publicKeyResendIntervalRef.current) {
      clearInterval(publicKeyResendIntervalRef.current);
      publicKeyResendIntervalRef.current = null;
    }
    publicKeyResendAttemptsRef.current = 0;
  }, [publicKeyResendAttemptsRef, publicKeyResendIntervalRef]);

  const sendPublicKey = useCallback(async () => {
    if (!realtimeManagerRef.current || !keyPairRef.current) return;

    const now = Date.now();
    if (now - lastPublicKeySendRef.current < 1000) return;
    lastPublicKeySendRef.current = now;

    localFingerprintRef.current = await KeyExchange.generateFingerprint(keyPairRef.current.publicKey);
    const publicKeyExport = await KeyExchange.exportPublicKey(keyPairRef.current.publicKey);
    const seq = replayProtectionRef.current.getNextSequence(participantIdRef.current);
    await realtimeManagerRef.current.send('key-exchange', { publicKey: publicKeyExport, sequence: seq });
  }, [keyPairRef, lastPublicKeySendRef, localFingerprintRef, participantIdRef, realtimeManagerRef, replayProtectionRef]);

  const startPublicKeyResend = useCallback(() => {
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
  }, [isKeyExchangeCompleteRef, isTerminatingRef, partnerPublicKeyRef, publicKeyResendAttemptsRef, publicKeyResendIntervalRef, sendPublicKey, stopPublicKeyResend]);

  const addSystemMessage = useCallback((content: string, unique = true) => {
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
      acknowledged: true,
    };

    messageQueueRef.current.addMessage(sessionId, systemMessage);
    scheduleSyncMessagesFromQueue();
  }, [messageQueueRef, scheduleSyncMessagesFromQueue, sessionId, systemMessagesShownRef]);

  const destroyLocalSessionData = useCallback(() => {
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
    }

    if (isTauriRuntime()) {
      try {
        void tauriInvoke('secure_panic_wipe');
      } catch {
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
      verified: false,
    });

    if (typeof (window as any).gc === 'function') {
      try {
        (window as any).gc();
      } catch {
      }
    }
  }, [
    aadPrefixesRef,
    autoTerminateTimeoutRef,
    clearVoiceMessages,
    decodedTextCacheRef,
    destroyFileTransferState,
    encryptionEngineRef,
    focusScrollTimeoutRef,
    inactivityIntervalRef,
    keyPairRef,
    messageQueueRef,
    partnerDisconnectTimeoutRef,
    partnerPublicKeyRef,
    replayProtectionRef,
    sessionId,
    sessionKeyRef,
    setInputText,
    setIsKeyExchangeComplete,
    setIsPartnerConnected,
    setMemoryStats,
    setMessages,
    setVerificationState,
    setVoiceVerified,
    textDecoderRef,
    textEncoderRef,
  ]);

  const cleanup = useCallback(async () => {
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
    }

    if (isTauriRuntime()) {
      try {
        await tauriInvoke('secure_panic_wipe');
      } catch {
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
  }, [
    autoTerminateTimeoutRef,
    encryptionEngineRef,
    focusScrollTimeoutRef,
    keyPairRef,
    messageQueueRef,
    partnerDisconnectTimeoutRef,
    partnerPublicKeyRef,
    realtimeManagerRef,
    replayProtectionRef,
    sessionId,
    stopPublicKeyResend,
  ]);

  const triggerSessionTermination = useCallback(async (reason: TerminationReason) => {
    try {
      await realtimeManagerRef.current?.send('session-terminated', {
        reason,
        timestamp: Date.now(),
        terminatedBy: participantIdRef.current,
      });
    } catch {
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
    }

    if (!deleted) {
      toast.error('Server deletion failed - session ended locally', { id: 'server-delete-failed' });
    }
  }, [channelToken, destroyLocalSessionData, isHost, participantIdRef, realtimeManagerRef, sessionId, token]);

  const handleEndSession = useCallback(async () => {
    const now = Date.now();
    if (now - lastTerminationRef.current < 2000) {
      return;
    }
    lastTerminationRef.current = now;

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
    }

    try {
      await realtimeManagerRef.current?.send('session-terminated', {
        reason: 'manual',
        timestamp: Date.now(),
        terminatedBy: participantIdRef.current,
      });
    } catch {
    }

    const deleted = isHost ? await SessionService.deleteSession(sessionId, channelToken, token) : true;

    try {
      const mod = await import('@capacitor/core');
      if (mod.Capacitor?.isNativePlatform?.()) {
        const WebViewCleanup = mod.registerPlugin('WebViewCleanup') as { clearWebViewData: () => Promise<{ ok: boolean }> };
        await WebViewCleanup.clearWebViewData();
      }
    } catch {
    }

    destroyLocalSessionData();

    await fullCleanup();

    await cleanup();

    onEndSession(false);

    if (!deleted) {
      toast.error('Server deletion failed - session ended locally', { id: 'server-delete-failed' });
    }
  }, [
    channelToken,
    cleanup,
    destroyLocalSessionData,
    fullCleanup,
    inactivityIntervalRef,
    isHost,
    isTerminatingRef,
    lastTerminationRef,
    onEndSession,
    participantIdRef,
    realtimeManagerRef,
    sessionId,
    token,
  ]);

  const setupMessageHandlers = useCallback(() => {
    const manager = realtimeManagerRef.current;
    if (!manager) return;

    manager.onStatusChange((newState) => {
      setConnectionState(newState);
      if (newState.status === 'connected') {
        void sendPublicKey();
        startPublicKeyResend();
      }
    });

    manager.onPresenceChange((participants) => {
      const partnerCount = Math.max(0, participants.length - 1);
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
            const digestBytes = new Uint8Array(view.subarray(0, view.byteLength));
            const hash = await crypto.subtle.digest('SHA-256', digestBytes);
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

        if (!isKeyExchangeCompleteRef.current) {
          void sendPublicKey();
        }

        if (keyPairRef.current) {
          if (isTauriRuntime()) {
            const sharedSecretBytes = await KeyExchange.deriveSharedSecretKeyBytes(
              keyPairRef.current.privateKey,
              partnerPublicKey,
              sessionId,
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
                sessionId,
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
              sessionId,
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

          if (!verificationShownRef.current && localFingerprintRef.current && remoteFingerprint) {
            verificationShownRef.current = true;
            setVerificationState((prev) => ({
              ...prev,
              show: true,
              localFingerprint: localFingerprintRef.current,
              remoteFingerprint,
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
            fileName: displayFileName,
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
            fileName: undefined,
          });
        }

        scheduleSyncMessagesFromQueue();
        await ensureMinAckDelay();
        await manager.send('message-ack', { messageId: payload.nonce });
      } catch {
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
          fileName: undefined,
        });
        scheduleSyncMessagesFromQueue();
        await manager.send('message-ack', { messageId: payload.nonce });
      } catch {
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
      }
      try {
        if (inactivityIntervalRef.current) {
          clearInterval(inactivityIntervalRef.current);
          inactivityIntervalRef.current = null;
        }
      } catch {
      }
      destroyLocalSessionData();
      await fullCleanup();
      await cleanup();
      onEndSession(false);
    });
  }, [
    addIncomingVoiceMessage,
    addSystemMessage,
    buildChatAad,
    buildFileAad,
    buildVoiceAad,
    cleanup,
    destroyLocalSessionData,
    encryptionEngineRef,
    fullCleanup,
    handleEndSession,
    handleRealtimeFileMessage,
    inactivityIntervalRef,
    isKeyExchangeCompleteRef,
    isTerminatingRef,
    keyPairRef,
    localFingerprintRef,
    markActivity,
    messageQueueRef,
    onEndSession,
    partnerCountRef,
    partnerDisconnectTimeoutRef,
    partnerPublicKeyRef,
    partnerWasPresentRef,
    realtimeManagerRef,
    replayProtectionRef,
    scheduleSyncMessagesFromQueue,
    sendPublicKey,
    sessionId,
    setConnectionState,
    setIsKeyExchangeComplete,
    setIsPartnerConnected,
    setVerificationState,
    startPublicKeyResend,
    stopPublicKeyResend,
    token,
    verificationShownRef,
  ]);

  const initializeSession = useCallback(async () => {
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
        verified: false,
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
  }, [
    addSystemMessage,
    channelToken,
    encryptionEngineRef,
    inactivityIntervalRef,
    isHost,
    isTerminatingRef,
    keyPairRef,
    lastActivityRef,
    localFingerprintRef,
    markActivity,
    participantIdRef,
    partnerPublicKeyRef,
    replayProtectionRef,
    realtimeManagerRef,
    sessionId,
    sessionKeyRef,
    setConnectionState,
    setVerificationState,
    setupMessageHandlers,
    startPublicKeyResend,
    stopPublicKeyResend,
    token,
    triggerSessionTermination,
    verificationShownRef,
  ]);

  const sendMessage = useCallback(async () => {
    const inputText = getInputText();
    const validation = validateMessage(inputText);
    if (!validation.valid) {
      toast.error(validation.error);
      return;
    }

    if (!encryptionEngineRef.current || !getIsKeyExchangeComplete()) {
      toast.error('Secure connection not established yet');
      return;
    }

    const verificationState = getVerificationState();
    if (!verificationState.verified) {
      toast.error('Please verify security codes before sending messages');
      if (!verificationState.show) {
        setVerificationState((prev) => ({ ...prev, show: true }));
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
        }
      }

      const { displayTimestamp } = generatePlausibleTimestamp();

      messageQueueRef.current.addMessage(sessionId, {
        id: messageId,
        content: messageBytes,
        sender: 'me',
        timestamp: displayTimestamp,
        type: 'text',
      });
      scheduleSyncMessagesFromQueue();

      const sent = await realtimeManagerRef.current?.send('chat-message', {
        encrypted,
        iv,
        type: 'text',
        messageId,
        sequence: seq,
      });

      if (!sent) {
        toast.error('Message may not have been delivered');
      }

      setInputTextState('');
    } catch {
      toast.error('Failed to send message');
    }
  }, [
    buildChatAad,
    encryptionEngineRef,
    getInputText,
    getIsKeyExchangeComplete,
    getVerificationState,
    markActivity,
    messageQueueRef,
    participantIdRef,
    realtimeManagerRef,
    replayProtectionRef,
    scheduleSyncMessagesFromQueue,
    sessionId,
    setInputTextState,
    setVerificationState,
  ]);

  const handleNuclearPurge = useCallback(() => {
    messageQueueRef.current.destroySession(sessionId);
    try {
      decodedTextCacheRef.current.clear();
    } catch {
    }
    setMessages([]);
    setMemoryStats({ messageCount: 0, estimatedBytes: 0 });
    toast.success('All messages purged from memory');
  }, [decodedTextCacheRef, messageQueueRef, sessionId, setMemoryStats, setMessages]);

  return {
    sendMessage,
    addSystemMessage,
    destroyLocalSessionData,
    handleEndSession,
    handleNuclearPurge,
    initializeSession,
    cleanup,
  };
}
