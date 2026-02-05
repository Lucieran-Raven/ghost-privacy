import { useState } from 'react';
import { type ConnectionState } from '@/lib/realtimeManager';
import { type QueuedMessage } from '@/utils/clientMessageQueue';

/**
 * Transport & session lifecycle state container.
 *
 * Responsibilities:
 * - Owns transport/session state for message flow and verification lifecycle.
 * - Exposes typed setters for orchestration in `ChatInterfaceShell`.
 *
 * Security guarantees:
 * - Keeps message/session state in ephemeral component memory only.
 * - Does not persist plaintext or keys; persistence decisions remain in callers.
 *
 * Caveats:
 * - This hook stores state only; network/realtime effects are orchestrated by shell logic.
 *
 * Cross-hook dependencies:
 * - Works alongside `useMediaVoice` and `useQuarantine` for full session composition.
 */
export function useChatTransport() {
  const [messages, setMessages] = useState<QueuedMessage[]>([]);
  const [inputText, setInputText] = useState('');
  const [isPartnerConnected, setIsPartnerConnected] = useState(false);
  const [connectionState, setConnectionState] = useState<ConnectionState>({ status: 'connecting', progress: 0 });
  const [isKeyExchangeComplete, setIsKeyExchangeComplete] = useState(false);
  const [memoryStats, setMemoryStats] = useState({ messageCount: 0, estimatedBytes: 0 });
  const [verificationState, setVerificationState] = useState({
    show: false,
    localFingerprint: '',
    remoteFingerprint: '',
    verified: false
  });

  return {
    messages,
    setMessages,
    inputText,
    setInputText,
    isPartnerConnected,
    setIsPartnerConnected,
    connectionState,
    setConnectionState,
    isKeyExchangeComplete,
    setIsKeyExchangeComplete,
    memoryStats,
    setMemoryStats,
    verificationState,
    setVerificationState
  };
}
