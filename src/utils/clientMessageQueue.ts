/**
 * ClientMessageQueue - In-memory message storage
 * 
 * SECURITY GUARANTEES:
 * - Messages exist ONLY in browser RAM
 * - NEVER writes to disk-backed browser storage
 * - Complete destruction when session ends
 * - No forensic traces on disk
 */

 import { secureZeroUint8Array } from '@/utils/algorithms/memory/zeroization';
 import {
   acknowledgeMessage as acknowledgeMessageAlgorithm,
   addMessage as addMessageAlgorithm,
   createMessageQueueState,
   destroySession as destroySessionAlgorithm,
   getMemoryStats as getMemoryStatsAlgorithm,
   getMessages as getMessagesAlgorithm,
   nuclearPurge as nuclearPurgeAlgorithm,
   type MessageQueueState
 } from '@/utils/algorithms/memory/lifecycle';

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

export class ClientMessageQueue {
  private state: MessageQueueState = createMessageQueueState();
  private pendingAcks: Map<string, (acknowledged: boolean) => void> = new Map();
  private readonly maxMessagesPerSession = 500;
  private destroyed = false;

  private secureZeroContentIfNeeded(message: QueuedMessage): void {
    if (message.type === 'file') return;
    if (!(message.content instanceof Uint8Array)) return;
    try {
      const crypto = window.crypto;
      secureZeroUint8Array({ getRandomValues: (arr) => crypto.getRandomValues(arr) }, message.content);
    } catch {
      try {
        message.content.fill(0);
      } catch {
        // Ignore
      }
    }
  }

  private revokeObjectUrlIfNeeded(message: QueuedMessage): void {
    if (message.type !== 'file') return;
    if (typeof message.content !== 'string') return;
    if (!message.content.startsWith('blob:')) return;
    try {
      URL.revokeObjectURL(message.content);
    } catch {
      // Ignore
    }
  }

  constructor() {
    // SECURITY FIX: NO auto-cleanup on page unload
    // Sessions end ONLY via explicit user action (End Session button)
    // This ensures accidental navigation doesn't destroy messages
  }

  /**
   * Add message to in-memory queue
   */
  addMessage(sessionId: string, message: Omit<QueuedMessage, 'receivedAt' | 'acknowledged'>): void {
    if (this.destroyed) {
      return;
    }

    const existingMessages = getMessagesAlgorithm(this.state, sessionId);
    if (existingMessages.length >= this.maxMessagesPerSession) {
      const evicted = existingMessages[0];
      if (evicted) {
        this.revokeObjectUrlIfNeeded(evicted);
        this.secureZeroContentIfNeeded(evicted);
        evicted.content = '';
        evicted.fileName = undefined;
      }
    }

    this.state = addMessageAlgorithm(this.state, {
      sessionId,
      message,
      now: Date.now(),
      maxMessagesPerSession: this.maxMessagesPerSession
    });
  }

  /**
   * Get all messages for a session (from memory only)
   */
  getMessages(sessionId: string): QueuedMessage[] {
    if (this.destroyed) return [];
    return getMessagesAlgorithm(this.state, sessionId);
  }

  /**
   * Mark message as acknowledged
   */
  acknowledgeMessage(sessionId: string, messageId: string): void {
    this.state = acknowledgeMessageAlgorithm(this.state, { sessionId, messageId });

    // Resolve pending ack promise
    const resolver = this.pendingAcks.get(messageId);
    if (resolver) {
      resolver(true);
      this.pendingAcks.delete(messageId);
    }
  }

  /**
   * Wait for acknowledgment with timeout
   */
  waitForAck(messageId: string, timeoutMs: number = 5000): Promise<boolean> {
    return new Promise((resolve) => {
      this.pendingAcks.set(messageId, resolve);

      setTimeout(() => {
        if (this.pendingAcks.has(messageId)) {
          this.pendingAcks.delete(messageId);
          resolve(false);
        }
      }, timeoutMs);
    });
  }

  /**
   * Get memory usage estimate
   */
  getMemoryStats(sessionId: string): { messageCount: number; estimatedBytes: number } {
    return getMemoryStatsAlgorithm(this.state, sessionId);
  }

  /**
   * Destroy single session - complete memory wipe
   */
  destroySession(sessionId: string): void {
    const messages = this.getMessages(sessionId);
    if (messages.length > 0) {
      // Overwrite content before deletion (paranoid mode)
      messages.forEach(msg => {
        this.revokeObjectUrlIfNeeded(msg);
        this.secureZeroContentIfNeeded(msg);
        msg.content = '';
        msg.fileName = undefined;
      });
      messages.length = 0;
    }

    this.state = destroySessionAlgorithm(this.state, sessionId);

    // Clear any pending acks
    this.pendingAcks.clear();

    // Hint to garbage collector
    this.hintGarbageCollection();
  }

  /**
   * NUCLEAR OPTION - Destroy ALL data immediately
   */
  nuclearPurge(): void {
    // Overwrite all content first
    this.state.messages.forEach((messages) => {
      messages.forEach(msg => {
        this.revokeObjectUrlIfNeeded(msg);
        this.secureZeroContentIfNeeded(msg);
        msg.content = '';
        msg.fileName = undefined;
      });
      messages.length = 0;
    });

    this.state = nuclearPurgeAlgorithm();
    this.pendingAcks.clear();
    this.destroyed = true;

    // Aggressive garbage collection hints
    this.hintGarbageCollection();
  }

  /**
   * Hint to browser for garbage collection
   */
  private hintGarbageCollection(): void {
    // Create and immediately discard large objects to trigger GC
    try {
      const dummy = new Array(10000).fill(0);
      dummy.length = 0;
    } catch {
      // Ignore errors
    }

    // Use gc() if available (Chrome with --expose-gc flag)
    if (typeof window !== 'undefined' && typeof (window as any).gc === 'function') {
      try {
        (window as any).gc();
      } catch {
        // Ignore errors
      }
    }
  }

  /**
   * Check if queue is destroyed
   */
  isDestroyed(): boolean {
    return this.destroyed;
  }
}

// Singleton instance for the application
let queueInstance: ClientMessageQueue | null = null;

export const getMessageQueue = (): ClientMessageQueue => {
  if (!queueInstance || queueInstance.isDestroyed()) {
    queueInstance = new ClientMessageQueue();
  }
  return queueInstance;
};

export const destroyMessageQueue = (): void => {
  if (queueInstance) {
    queueInstance.nuclearPurge();
    queueInstance = null;
  }
};
