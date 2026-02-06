import { useCallback, useState, type MutableRefObject } from 'react';
import { toast } from 'sonner';
import type { EncryptionEngine } from '@/utils/encryption';
import type { QueuedMessage } from '@/utils/clientMessageQueue';
import type { RealtimeManager } from '@/lib/realtimeManager';
import { getReplayProtection } from '@/utils/replayProtection';
import { useVoiceMessaging, type VoiceMessageData } from './useVoiceMessaging';

export interface VerificationState {
  show: boolean;
  localFingerprint: string;
  remoteFingerprint: string;
  verified: boolean;
}

export function useMediaVoice(params: {
  sessionId: string;
  getParticipantId: () => string;
  encryptionEngineRef: MutableRefObject<EncryptionEngine | null>;
  realtimeManagerRef: MutableRefObject<RealtimeManager | null>;
  replayProtectionRef: MutableRefObject<ReturnType<typeof getReplayProtection>>;
  isKeyExchangeComplete: boolean;
  markActivity: () => void;
  buildVoiceAad: (args: { senderId: string; messageId: string; sequence: number; duration: number }) => Uint8Array;
  addMessageToQueue: (sessionId: string, message: Omit<QueuedMessage, 'receivedAt' | 'acknowledged'>) => void;
  scheduleSyncMessagesFromQueue: () => void;

  verificationState: VerificationState;
  setVerificationState: (next: VerificationState | ((prev: VerificationState) => VerificationState)) => void;
  verificationShownRef: MutableRefObject<boolean>;
}): {
  voiceVerified: boolean;
  setVoiceVerified: (v: boolean) => void;
  handleRequestVoiceVerification: () => void;

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
    markActivity,
    buildVoiceAad,
    addMessageToQueue,
    scheduleSyncMessagesFromQueue,
    verificationState,
    setVerificationState,
    verificationShownRef,
  } = params;

  const [voiceVerified, setVoiceVerified] = useState(false);

  const handleRequestVoiceVerification = useCallback(() => {
    if (verificationState.verified) {
      setVoiceVerified(true);
      toast.success('Voice messaging enabled');
    } else if (!verificationShownRef.current || !verificationState.show) {
      setVerificationState((prev) => ({ ...prev, show: true }));
    }
  }, [setVerificationState, verificationShownRef, verificationState.verified, verificationState.show]);

  const {
    voiceMessages,
    voiceMessagesById,
    sendVoiceMessage,
    addIncomingVoiceMessage,
    handleVoiceMessagePlayed,
    clearVoiceMessages,
  } = useVoiceMessaging({
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
  });

  return {
    voiceVerified,
    setVoiceVerified,
    handleRequestVoiceVerification,
    voiceMessages,
    voiceMessagesById,
    sendVoiceMessage,
    addIncomingVoiceMessage,
    handleVoiceMessagePlayed,
    clearVoiceMessages,
  };
}
