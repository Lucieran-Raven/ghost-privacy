import { useState } from 'react';

export interface VoiceMessageData {
  id: string;
  blob: Blob;
  duration: number;
  sender: 'me' | 'partner';
  timestamp: number;
  played: boolean;
}

/**
 * Media/voice subsystem state.
 *
 * Responsibilities:
 * - Owns voice message state and voice verification toggle.
 * - Keeps media-related state isolated from transport/session state.
 *
 * Security guarantees:
 * - Stores media objects in ephemeral in-memory React state only.
 * - Zeroization/teardown is executed by higher-level session purge handlers.
 *
 * Caveats:
 * - Upload/encryption/decryption pipelines are orchestrated by shell handlers.
 */
export function useMediaVoice() {
  const [voiceMessages, setVoiceMessages] = useState<VoiceMessageData[]>([]);
  const [voiceVerified, setVoiceVerified] = useState(false);

  return {
    voiceMessages,
    setVoiceMessages,
    voiceVerified,
    setVoiceVerified
  };
}
