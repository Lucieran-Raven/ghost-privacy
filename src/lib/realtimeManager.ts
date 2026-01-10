import { supabase } from '@/integrations/supabase/publicClient';
import { RealtimeChannel } from '@supabase/supabase-js';
import { generateNonce } from '@/utils/encryption';
import { deriveRealtimeChannelName } from '@/utils/realtimeChannel';

export interface BroadcastPayload {
  type: 'chat-message' | 'key-exchange' | 'presence' | 'typing' | 'file' | 'message-ack' | 'session-terminated' | 'voice-message' | 'video-message';
  senderId: string;
  data: any;
  timestamp: number;
  nonce: string;
}

export type ConnectionStatus = 'connecting' | 'validating' | 'subscribing' | 'handshaking' | 'connected' | 'reconnecting' | 'disconnected' | 'error';

export interface ConnectionState {
  status: ConnectionStatus;
  progress: number;
  error?: string;
}

export class RealtimeManager {
  private channel: RealtimeChannel | null = null;
  private sessionId: string;
  private capabilityToken: string;
  private participantId: string;
  private outbox: Array<{ payload: BroadcastPayload; retries: number; enqueuedAt: number }> = [];
  private readonly outboxMaxItems = 64;
  private readonly outboxMaxPayloadChars = 200_000;
  private messageHandlers: Map<string, (payload: BroadcastPayload) => void> = new Map();
  private presenceHandlers: ((participants: string[]) => void)[] = [];
  private statusHandlers: ((state: ConnectionState) => void)[] = [];
  private connectionState: ConnectionState = { status: 'connecting', progress: 0 };
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10; // Increased from 2 to 10 for resilience
  private isDestroyed = false;
  private partnerCount = 0;

  private seenIncoming: Map<string, number> = new Map();
  private readonly seenIncomingTtlMs = 10 * 60 * 1000;
  private readonly seenIncomingMaxEntries = 4096;

  constructor(sessionId: string, capabilityToken: string, participantId: string) {
    this.sessionId = sessionId;
    this.capabilityToken = capabilityToken;
    this.participantId = participantId;
  }

  private updateState(status: ConnectionStatus, progress: number, error?: string): void {
    this.connectionState = { status, progress, error };
    this.statusHandlers.forEach(handler => handler(this.connectionState));
  }

  private shouldAcceptIncoming(payload: any): payload is BroadcastPayload {
    if (!payload || typeof payload !== 'object') return false;
    if (typeof payload.senderId !== 'string' || payload.senderId.length === 0) return false;
    if (typeof payload.nonce !== 'string' || payload.nonce.length === 0) return false;

    const now = Date.now();
    const cutoff = now - this.seenIncomingTtlMs;

    if (this.seenIncoming.size > 0) {
      for (const [k, ts] of this.seenIncoming) {
        if (ts < cutoff) {
          this.seenIncoming.delete(k);
        }
      }
    }

    const key = `${payload.senderId}:${payload.nonce}`;
    const prev = this.seenIncoming.get(key);
    if (prev !== undefined && prev >= cutoff) {
      return false;
    }

    this.seenIncoming.set(key, now);

    while (this.seenIncoming.size > this.seenIncomingMaxEntries) {
      const firstKey = this.seenIncoming.keys().next().value as string | undefined;
      if (!firstKey) break;
      this.seenIncoming.delete(firstKey);
    }

    return true;
  }

  private estimatePayloadChars(payload: BroadcastPayload): number {
    // Avoid JSON.stringify for small, frequent events.
    if (payload.type === 'typing' || payload.type === 'presence' || payload.type === 'message-ack') {
      return 512;
    }

    // Key exchange payloads can be moderately sized (public key), but not huge.
    if (payload.type === 'key-exchange') {
      const pk = (payload.data && typeof payload.data.publicKey === 'string') ? payload.data.publicKey.length : 0;
      return 512 + pk;
    }

    // Chat messages contain ciphertext + iv; estimate based on string lengths to avoid stringify.
    if (payload.type === 'chat-message') {
      const enc = (payload.data && typeof payload.data.encrypted === 'string') ? payload.data.encrypted.length : 0;
      const iv = (payload.data && typeof payload.data.iv === 'string') ? payload.data.iv.length : 0;
      const name = (payload.data && typeof payload.data.fileName === 'string') ? payload.data.fileName.length : 0;
      const misc = 256;
      return misc + enc + iv + name;
    }

    // For any other payloads, fall back to stringify (rare).
    try {
      return JSON.stringify(payload).length;
    } catch {
      return Number.POSITIVE_INFINITY;
    }
  }

  private shouldQueuePayload(payload: BroadcastPayload): boolean {
    // Never queue termination events.
    if (payload.type === 'session-terminated') return false;

    // Avoid queueing very large payloads in memory (e.g. file/video/voice encrypted blobs).
    const size = this.estimatePayloadChars(payload);
    if (!Number.isFinite(size) || size > this.outboxMaxPayloadChars) {
      return false;
    }

    return true;
  }

  private enqueuePayload(payload: BroadcastPayload, retries: number): boolean {
    if (this.isDestroyed) return false;
    if (!this.shouldQueuePayload(payload)) return false;

    // Coalesce typing events to avoid outbox growth during unstable networks.
    if (payload.type === 'typing') {
      this.outbox = this.outbox.filter((item) => item.payload.type !== 'typing');
    }

    if (this.outbox.length >= this.outboxMaxItems) {
      // Fail-closed for user content; don't silently drop.
      if (payload.type === 'chat-message' || payload.type === 'voice-message' || payload.type === 'video-message') {
        return false;
      }

      // Best-effort for non-critical messages (acks/typing/etc): drop oldest.
      this.outbox.shift();
    }

    this.outbox.push({ payload, retries, enqueuedAt: Date.now() });
    return true;
  }

  private async sendNow(payload: BroadcastPayload, retries: number): Promise<boolean> {
    if (!this.channel || this.connectionState.status !== 'connected') {
      return false;
    }

    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        const result = await this.channel.send({
          type: 'broadcast',
          event: 'ghost-message',
          payload
        });

        if (result === 'ok') {
          this.lastHeartbeat = Date.now();
          return true;
        }
      } catch {
        // Silent retry
      }

      if (attempt < retries) {
        await new Promise(resolve => setTimeout(resolve, 500 * attempt));
      }
    }

    return false;
  }

  private async flushOutbox(): Promise<void> {
    if (!this.channel || this.connectionState.status !== 'connected') {
      return;
    }

    // Flush oldest-first. Stop on first failure to avoid tight loops while unstable.
    while (this.outbox.length > 0 && this.channel && this.connectionState.status === 'connected') {
      const next = this.outbox.shift();
      if (!next) break;
      const ok = await this.sendNow(next.payload, next.retries);
      if (!ok) {
        // Put it back at the front and stop; we'll retry after reconnect.
        this.outbox.unshift(next);
        break;
      }
    }
  }

  async connect(): Promise<void> {
    if (this.isDestroyed) return;

    const channelName = await deriveRealtimeChannelName(this.sessionId, this.capabilityToken);
    this.updateState('subscribing', 25);

    this.channel = supabase.channel(channelName, {
      config: {
        broadcast: { self: false, ack: true },
        presence: { key: this.participantId }
      }
    });

    // Track presence changes (partner join/leave)
    this.channel.on('presence', { event: 'sync' }, () => {
      const state = this.channel!.presenceState();
      const participants = Object.keys(state);
      const newPartnerCount = Math.max(0, participants.length - 1); // Exclude self
      
      if (newPartnerCount !== this.partnerCount) {
        this.partnerCount = newPartnerCount;
        this.presenceHandlers.forEach(handler => handler(participants));
      }
    });

    // Setup broadcast listener BEFORE subscribing
    this.channel.on('broadcast', { event: 'ghost-message' }, ({ payload }) => {
      if (this.isDestroyed) return;
      if (!payload || payload.senderId === this.participantId) return;
      if (!this.shouldAcceptIncoming(payload)) return;

      const handler = this.messageHandlers.get(payload.type);
      if (handler) {
        handler(payload as BroadcastPayload);
      }
    });

    // Subscribe with promise-based waiting and exponential backoff retry
    return this.connectWithRetry();
  }

  private async connectWithRetry(): Promise<void> {
    // Extended exponential backoff: 500ms, 1s, 2s, 4s, 8s...
    const getBackoffDelay = (attempt: number) => Math.min(500 * Math.pow(2, attempt), 30000);
    
    return new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
          // Silent retry with backoff
          const delay = getBackoffDelay(this.reconnectAttempts);
          void delay;
          this.reconnectAttempts++;
          this.updateState('connecting', 25, 'Secure channel establishing…');
          
          setTimeout(() => {
            if (this.channel) {
              supabase.removeChannel(this.channel).then(() => {
                if (!this.isDestroyed) {
                  this.connect().then(resolve).catch(reject);
                }
              });
            }
          }, delay);
        } else {
          this.updateState('error', 0, 'Secure channel establishing…');
          reject(new Error('Connection timeout'));
        }
      }, 8000); // Increased timeout from 3s to 8s per attempt

      this.channel!.subscribe(async (status) => {
        if (status === 'SUBSCRIBED') {
          clearTimeout(timeout);
          this.updateState('handshaking', 75);

          try {
            await this.channel!.track({ online_at: new Date().toISOString() });
          } catch {
          }

          // Wait for channel stability
          await this.waitForStability();
          
          this.updateState('connected', 100);
          this.reconnectAttempts = 0;
          await this.flushOutbox();
          
          resolve();
        } else if (status === 'CLOSED' || status === 'CHANNEL_ERROR') {
          clearTimeout(timeout);
          
          if (this.reconnectAttempts < this.maxReconnectAttempts) {
            const delay = Math.max(2000, getBackoffDelay(this.reconnectAttempts));
            this.reconnectAttempts++;
            this.updateState('connecting', 25, 'Secure channel establishing…');
            
            setTimeout(() => {
              if (this.channel) {
                supabase.removeChannel(this.channel).then(() => {
                  if (!this.isDestroyed) {
                    this.connect().then(resolve).catch(reject);
                  }
                });
              }
            }, delay);
          } else {
            this.updateState('error', 0, 'Secure channel establishing…');
            this.handleDisconnect();
            reject(new Error(`Channel failed: ${status}`));
          }
        }
      });
    });
  }

  private async waitForStability(): Promise<void> {
    // Wait 500ms for channel to stabilize after subscription
    return new Promise(resolve => setTimeout(resolve, 500));
  }

  private async handleDisconnect(): Promise<void> {
    if (this.connectionState.status !== 'disconnected') {
      await this.attemptReconnect();
    }
  }

  private async attemptReconnect(): Promise<void> {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.updateState('error', 0, 'Failed to reconnect');
      return;
    }

    this.reconnectAttempts++;
    this.updateState('reconnecting', 50);
    
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 10000);
    
    await new Promise(resolve => setTimeout(resolve, delay));

    try {
      if (this.channel) {
        await supabase.removeChannel(this.channel);
      }
      await this.connect();
    } catch {
      if (this.reconnectAttempts < this.maxReconnectAttempts) {
        await this.attemptReconnect();
      }
    }
  }

  async send(type: BroadcastPayload['type'], data: any, retries = 3): Promise<boolean> {
    const payload: BroadcastPayload = {
      type,
      senderId: this.participantId,
      data,
      timestamp: Date.now(),
      nonce: generateNonce()
    };

    // If we're not connected, accept the message into an in-memory outbox when safe.
    if (!this.channel || this.connectionState.status !== 'connected') {
      return this.enqueuePayload(payload, retries);
    }

    const ok = await this.sendNow(payload, retries);
    if (ok) return true;

    // Connection may be unstable; best-effort queue for retry after reconnection.
    return this.enqueuePayload(payload, retries);
  }

  async sendWithAck(type: BroadcastPayload['type'], data: any, ackTimeout = 5000): Promise<{ sent: boolean; messageId: string }> {
    const messageId = generateNonce();
    const dataWithId = { ...data, messageId };
    
    const sent = await this.send(type, dataWithId);
    
    return { sent, messageId };
  }

  onMessage(type: BroadcastPayload['type'], handler: (payload: BroadcastPayload) => void): void {
    this.messageHandlers.set(type, handler);
  }

  onPresenceChange(handler: (participants: string[]) => void): void {
    this.presenceHandlers.push(handler);
  }

  onStatusChange(handler: (state: ConnectionState) => void): void {
    this.statusHandlers.push(handler);
    // Immediately call with current state
    handler(this.connectionState);
  }

  getState(): ConnectionState {
    return this.connectionState;
  }

  getParticipantId(): string {
    return this.participantId;
  }

  async disconnect(): Promise<void> {
    this.isDestroyed = true;
    this.outbox = [];
    this.seenIncoming.clear();
    this.partnerCount = 0;
    
    if (this.channel) {
      await supabase.removeChannel(this.channel);
      this.channel = null;
    }
    
    this.updateState('disconnected', 0);
    this.messageHandlers.clear();
    this.presenceHandlers = [];
  }
}
