/**
 * Memory Lifecycle (in-memory message queue)
 * Purpose: Pure algorithms for maintaining an in-RAM message queue without persistence.
 * Input: Current queue state + message operations.
 * Output: New queue state and derived results.
 * Privacy: NEVER logs, NEVER stores, NEVER makes network requests, NEVER persists beyond caller-managed memory.
 */

export interface QueuedMessage {
  id: string;
  content: string | Uint8Array;
  sender: 'me' | 'partner';
  timestamp: number;
  type: 'text' | 'file' | 'system' | 'voice' | 'video';
  fileName?: string;
  receivedAt: number;
  acknowledged: boolean;
}

export interface MessageQueueState {
  messages: Map<string, QueuedMessage[]>;
}

export function createMessageQueueState(): MessageQueueState {
  return { messages: new Map<string, QueuedMessage[]>() };
}

export function addMessage(
  state: MessageQueueState,
  input: {
    sessionId: string;
    message: Omit<QueuedMessage, 'receivedAt' | 'acknowledged'>;
    now: number;
    maxMessagesPerSession: number;
  }
): MessageQueueState {
  if (!state || !(state.messages instanceof Map)) {
    return createMessageQueueState();
  }
  if (!input || typeof input !== 'object') return state;
  if (typeof input.sessionId !== 'string' || input.sessionId.length === 0 || input.sessionId.length > 64) return state;
  if (!Number.isFinite(input.now)) return state;
  if (!Number.isSafeInteger(input.maxMessagesPerSession) || input.maxMessagesPerSession <= 0 || input.maxMessagesPerSession > 5000) {
    return state;
  }
  if (!input.message || typeof input.message !== 'object') return state;
  if (typeof input.message.id !== 'string' || input.message.id.length === 0 || input.message.id.length > 256) return state;
  if (!(typeof input.message.content === 'string' || input.message.content instanceof Uint8Array)) return state;
  if (typeof input.message.content === 'string' && input.message.content.length > 250_000) return state;
  if (input.message.content instanceof Uint8Array && input.message.content.byteLength > 250_000) return state;
  if (!Number.isFinite(input.message.timestamp) || input.message.timestamp <= 0) return state;
  if (input.message.sender !== 'me' && input.message.sender !== 'partner') return state;
  if (
    input.message.type !== 'text' &&
    input.message.type !== 'file' &&
    input.message.type !== 'system' &&
    input.message.type !== 'voice' &&
    input.message.type !== 'video'
  ) {
    return state;
  }
  if (typeof input.message.fileName !== 'undefined' && typeof input.message.fileName !== 'string') return state;

  const sessionMessages = state.messages.get(input.sessionId) || [];

  if (sessionMessages.some((m) => m.id === input.message.id)) {
    return state;
  }

  const nextMessages = [...sessionMessages];

  if (nextMessages.length >= input.maxMessagesPerSession) {
    nextMessages.shift();
  }

  nextMessages.push({
    ...input.message,
    receivedAt: input.now,
    acknowledged: false
  });

  const messages = new Map(state.messages);
  messages.set(input.sessionId, nextMessages);

  return { messages };
}

export function getMessages(state: MessageQueueState, sessionId: string): QueuedMessage[] {
  if (!state || !(state.messages instanceof Map)) return [];
  if (typeof sessionId !== 'string' || sessionId.length === 0) return [];
  return state.messages.get(sessionId) || [];
}

export function acknowledgeMessage(
  state: MessageQueueState,
  input: { sessionId: string; messageId: string }
): MessageQueueState {
  if (!state || !(state.messages instanceof Map)) return state;
  if (!input || typeof input !== 'object') return state;
  if (typeof input.sessionId !== 'string' || input.sessionId.length === 0) return state;
  if (typeof input.messageId !== 'string' || input.messageId.length === 0) return state;
  const sessionMessages = state.messages.get(input.sessionId);
  if (!sessionMessages) {
    return state;
  }

  const idx = sessionMessages.findIndex((m) => m.id === input.messageId);
  if (idx === -1) {
    return state;
  }

  const next = [...sessionMessages];
  next[idx] = { ...next[idx], acknowledged: true };

  const messages = new Map(state.messages);
  messages.set(input.sessionId, next);

  return { messages };
}

export function getMemoryStats(
  state: MessageQueueState,
  sessionId: string
): { messageCount: number; estimatedBytes: number } {
  if (!state || !(state.messages instanceof Map)) {
    return { messageCount: 0, estimatedBytes: 0 };
  }
  if (typeof sessionId !== 'string' || sessionId.length === 0) {
    return { messageCount: 0, estimatedBytes: 0 };
  }
  const messages = state.messages.get(sessionId) || [];
  const estimatedBytes = messages.reduce((total, msg) => {
    const contentBytes = typeof msg.content === 'string' ? (msg.content?.length || 0) * 2 : msg.content.byteLength;
    return total + contentBytes + 200;
  }, 0);
  return { messageCount: messages.length, estimatedBytes };
}

export function destroySession(state: MessageQueueState, sessionId: string): MessageQueueState {
  if (!state || !(state.messages instanceof Map)) return state;
  if (typeof sessionId !== 'string' || sessionId.length === 0) return state;
  if (!state.messages.has(sessionId)) {
    return state;
  }
  const messages = new Map(state.messages);
  messages.delete(sessionId);
  return { messages };
}

export function nuclearPurge(): MessageQueueState {
  return createMessageQueueState();
}
