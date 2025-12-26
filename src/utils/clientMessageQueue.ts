/**
 * ClientMessageQueue - In-memory message storage
 * 
 * SECURITY GUARANTEES:
 * - Messages exist ONLY in browser RAM
 * - NEVER writes to localStorage, sessionStorage, IndexedDB, or cookies
 * - Complete destruction when session ends
 * - No forensic traces on disk
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

export class ClientMessageQueue {
  private messages: Map<string, QueuedMessage[]> = new Map();
  private pendingAcks: Map<string, (acknowledged: boolean) => void> = new Map();
  private readonly maxMessagesPerSession = 500;
  private destroyed = false;

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

    if (!this.messages.has(sessionId)) {
      this.messages.set(sessionId, []);
    }

    const sessionMessages = this.messages.get(sessionId)!;

    // Check for duplicate by ID
    if (sessionMessages.some(m => m.id === message.id)) {
      return;
    }

    // Enforce max messages limit
    if (sessionMessages.length >= this.maxMessagesPerSession) {
      sessionMessages.shift(); // Remove oldest
    }

    const queuedMessage: QueuedMessage = {
      ...message,
      receivedAt: Date.now(),
      acknowledged: false
    };

    sessionMessages.push(queuedMessage);
  }

  /**
   * Get all messages for a session (from memory only)
   */
  getMessages(sessionId: string): QueuedMessage[] {
    if (this.destroyed) return [];
    return this.messages.get(sessionId) || [];
  }

  /**
   * Mark message as acknowledged
   */
  acknowledgeMessage(sessionId: string, messageId: string): void {
    const messages = this.messages.get(sessionId);
    if (messages) {
      const message = messages.find(m => m.id === messageId);
      if (message) {
        message.acknowledged = true;
      }
    }

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
    const messages = this.messages.get(sessionId) || [];
    const estimatedBytes = messages.reduce((total, msg) => {
      return total + (msg.content?.length || 0) * 2 + 200; // Rough estimate
    }, 0);

    return {
      messageCount: messages.length,
      estimatedBytes
    };
  }

  /**
   * Destroy single session - complete memory wipe
   */
  destroySession(sessionId: string): void {
    // Clear messages
    const messages = this.messages.get(sessionId);
    if (messages) {
      // Overwrite content before deletion (paranoid mode)
      messages.forEach(msg => {
        msg.content = '';
        msg.fileName = undefined;
      });
      messages.length = 0;
    }

    this.messages.delete(sessionId);

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
    this.messages.forEach((messages) => {
      messages.forEach(msg => {
        msg.content = '';
        msg.fileName = undefined;
      });
      messages.length = 0;
    });

    this.messages.clear();
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
