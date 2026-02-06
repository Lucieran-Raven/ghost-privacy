import { useCallback, useMemo, useState, type MutableRefObject } from 'react';
import { toast } from 'sonner';
import { generateNonce, type EncryptionEngine } from '@/utils/encryption';
import type { QueuedMessage } from '@/utils/clientMessageQueue';
import type { RealtimeManager } from '@/lib/realtimeManager';
import { getReplayProtection } from '@/utils/replayProtection';

export interface VoiceMessageData {
  id: string;
  blob: Blob;
  duration: number;
  sender: 'me' | 'partner';
  timestamp: number;
  played: boolean;
}

export function useVoiceMessaging(params: {
  sessionId: string;
  getParticipantId: () => string;
  encryptionEngineRef: MutableRefObject<EncryptionEngine | null>;
  realtimeManagerRef: MutableRefObject<RealtimeManager | null>;
  replayProtectionRef: MutableRefObject<ReturnType<typeof getReplayProtection>>;
  isKeyExchangeComplete: boolean;
  voiceVerified: boolean;
  markActivity: () => void;
  buildVoiceAad: (args: { senderId: string; messageId: string; sequence: number; duration: number }) => Uint8Array;
  addMessageToQueue: (sessionId: string, message: Omit<QueuedMessage, 'receivedAt' | 'acknowledged'>) => void;
  scheduleSyncMessagesFromQueue: () => void;
  maxVoiceMessages?: number;
}): {
  voiceMessages: VoiceMessageData[];
  voiceMessagesById: Map<string, VoiceMessageData>;
  sendVoiceMessage: (blob: Blob, duration: number) => Promise<void>;
  addIncomingVoiceMessage: (msg: Omit<VoiceMessageData, 'played'> & { played?: boolean }) => void;
  handleVoiceMessagePlayed: (messageId: string) => void;
  clearVoiceMessages: () => void;
} {
  const {
    sessionId,
    getParticipantId,
    encryptionEngineRef,
    realtimeManagerRef,
    replayProtectionRef,
    isKeyExchangeComplete,
    voiceVerified,
    markActivity,
    buildVoiceAad,
    addMessageToQueue,
    scheduleSyncMessagesFromQueue,
    maxVoiceMessages = 50,
  } = params;

  const [voiceMessages, setVoiceMessages] = useState<VoiceMessageData[]>([]);

  const voiceMessagesById = useMemo(() => {
    const map = new Map<string, VoiceMessageData>();
    for (const vm of voiceMessages) {
      map.set(vm.id, vm);
    }
    return map;
  }, [voiceMessages]);

  const clearVoiceMessages = useCallback(() => {
    setVoiceMessages([]);
  }, []);

  const addIncomingVoiceMessage = useCallback((msg: Omit<VoiceMessageData, 'played'> & { played?: boolean }) => {
    setVoiceMessages(prev => {
      const next = [...prev, {
        ...msg,
        played: Boolean(msg.played),
      }];
      return next.length > maxVoiceMessages ? next.slice(-maxVoiceMessages) : next;
    });
  }, [maxVoiceMessages]);

  const sendVoiceMessage = useCallback(async (blob: Blob, duration: number) => {
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

      const participantId = getParticipantId();
      const seq = replayProtectionRef.current.getNextSequence(participantId);

      const arrayBuffer = await blob.arrayBuffer();
      const aad = buildVoiceAad({ senderId: participantId, messageId, sequence: seq, duration });
      const { encrypted, iv } = await encryptionEngineRef.current.encryptBytes(arrayBuffer, aad);
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

      setVoiceMessages(prev => {
        const next = [...prev, {
          id: messageId,
          blob,
          duration,
          sender: 'me' as const,
          timestamp: Date.now(),
          played: false,
        }];
        return next.length > maxVoiceMessages ? next.slice(-maxVoiceMessages) : next;
      });

      addMessageToQueue(sessionId, {
        id: messageId,
        content: '[Voice Message]',
        sender: 'me',
        timestamp: Date.now(),
        type: 'voice',
      });
      scheduleSyncMessagesFromQueue();

      const sent = await realtimeManagerRef.current?.send('voice-message', {
        encrypted,
        iv,
        duration,
        messageId,
        sequence: seq,
      });

      if (!sent) {
        toast.error('Voice message may not have been delivered');
      }
    } catch {
      toast.error('Failed to send voice message');
    }
  }, [addMessageToQueue, buildVoiceAad, encryptionEngineRef, getParticipantId, isKeyExchangeComplete, markActivity, maxVoiceMessages, realtimeManagerRef, replayProtectionRef, scheduleSyncMessagesFromQueue, sessionId, voiceVerified]);

  const handleVoiceMessagePlayed = useCallback((messageId: string) => {
    setVoiceMessages(prev =>
      prev.map(vm => {
        if (vm.id !== messageId) return vm;
        return { ...vm, played: true, blob: new Blob([], { type: 'application/octet-stream' }) };
      })
    );
  }, []);

  return {
    voiceMessages,
    voiceMessagesById,
    sendVoiceMessage,
    addIncomingVoiceMessage,
    handleVoiceMessagePlayed,
    clearVoiceMessages,
  };
}
