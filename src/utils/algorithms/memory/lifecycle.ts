/**
 * Memory Lifecycle (in-memory message queue)
 * Purpose: Pure algorithms for maintaining an in-RAM message queue without persistence.
 * Input: Current queue state + message operations.
 * Output: New queue state and derived results.
 * Privacy: NEVER logs, NEVER stores, NEVER makes network requests, NEVER persists beyond caller-managed memory.
 */

export interface QueuedMessage {
  id: string;
  content: string;
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
  return state.messages.get(sessionId) || [];
}

export function acknowledgeMessage(
  state: MessageQueueState,
  input: { sessionId: string; messageId: string }
): MessageQueueState {
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
  const messages = state.messages.get(sessionId) || [];
  const estimatedBytes = messages.reduce((total, msg) => total + (msg.content?.length || 0) * 2 + 200, 0);
  return { messageCount: messages.length, estimatedBytes };
}

export function destroySession(state: MessageQueueState, sessionId: string): MessageQueueState {
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
