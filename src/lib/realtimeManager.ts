import { supabase } from '@/integrations/supabase/publicClient';
import { RealtimeChannel } from '@supabase/supabase-js';
import { generateNonce } from '@/utils/encryption';
import { deriveRealtimeChannelName } from '@/utils/algorithms/session/realtimeChannel';

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
  private heartbeatInterval: ReturnType<typeof setInterval> | null = null;
  private lastHeartbeat = Date.now();
  private isDestroyed = false;
  private presenceGracePeriod: ReturnType<typeof setTimeout> | null = null;
  private lastPresenceState: string[] = [];
  private connectionCheckInterval: ReturnType<typeof setInterval> | null = null;

  constructor(sessionId: string, capabilityToken: string, participantId: string) {
    this.sessionId = sessionId;
    this.capabilityToken = capabilityToken;
    this.participantId = participantId;
  }

  private updateState(status: ConnectionStatus, progress: number, error?: string): void {
    this.connectionState = { status, progress, error };
    this.statusHandlers.forEach(handler => handler(this.connectionState));
  }

  private estimatePayloadChars(payload: BroadcastPayload): number {
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

    // Setup broadcast listener BEFORE subscribing
    this.channel.on('broadcast', { event: 'ghost-message' }, ({ payload }) => {
      if (payload && payload.senderId !== this.participantId) {
        const handler = this.messageHandlers.get(payload.type);
        if (handler) {
          handler(payload as BroadcastPayload);
        }
      }
    });

    // Setup presence tracking with grace period to prevent false disconnects
    this.channel.on('presence', { event: 'sync' }, () => {
      const state = this.channel?.presenceState() || {};
      const participants = Object.keys(state).filter(id => id !== this.participantId);
      
      // Clear any pending grace period timeout
      if (this.presenceGracePeriod) {
        clearTimeout(this.presenceGracePeriod);
        this.presenceGracePeriod = null;
      }
      
      // If we had participants and now we don't, wait before notifying
      if (this.lastPresenceState.length > 0 && participants.length === 0) {
        this.presenceGracePeriod = setTimeout(() => {
          // Re-check presence after grace period
          const currentState = this.channel?.presenceState() || {};
          const currentParticipants = Object.keys(currentState).filter(id => id !== this.participantId);
          
          if (currentParticipants.length === 0) {
            this.presenceHandlers.forEach(handler => handler([]));
          }
          this.presenceGracePeriod = null;
        }, 5000); // 5 second grace period before reporting disconnect
      } else {
        this.presenceHandlers.forEach(handler => handler(participants));
      }
      
      this.lastPresenceState = participants;
    });

    this.channel.on('presence', { event: 'join' }, () => {
      // Cancel any pending disconnect grace period
      if (this.presenceGracePeriod) {
        clearTimeout(this.presenceGracePeriod);
        this.presenceGracePeriod = null;
      }
    });

    this.channel.on('presence', { event: 'leave' }, () => {
      // Silent - presence sync handles state with grace period
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
          
          // Track presence
          try {
            await this.channel?.track({
              participantId: this.participantId,
              joinedAt: Date.now()
            });
          } catch (e) {
            void e;
          }

          // Wait for channel stability
          await this.waitForStability();
          
          this.updateState('connected', 100);
          this.reconnectAttempts = 0;
          this.startHeartbeatMonitor();
          await this.flushOutbox();
          
          resolve();
        } else if (status === 'CLOSED' || status === 'CHANNEL_ERROR') {
          clearTimeout(timeout);
          
          if (this.reconnectAttempts < this.maxReconnectAttempts) {
            const delay = getBackoffDelay(this.reconnectAttempts);
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

  private startHeartbeatMonitor(): void {
    this.lastHeartbeat = Date.now();
    
    // Clear any existing intervals
    this.stopHeartbeatMonitor();
    
    // Heartbeat check every 15 seconds
    this.heartbeatInterval = setInterval(() => {
      const timeSinceHeartbeat = Date.now() - this.lastHeartbeat;
      
      // Only reconnect if no heartbeat for 2 minutes (increased from 30s)
      if (timeSinceHeartbeat > 120000) {
        this.attemptReconnect();
      }
    }, 15000);

    // Periodic connection health check every 30 seconds
    this.connectionCheckInterval = setInterval(() => {
      if (this.channel && this.connectionState.status === 'connected') {
        // Send a presence heartbeat to keep connection alive
        this.channel.track({
          participantId: this.participantId,
          lastActive: Date.now()
        }).catch(() => {
          // Silent - presence tracking can fail temporarily
        });
        this.lastHeartbeat = Date.now();
      }
    }, 30000);
  }

  private stopHeartbeatMonitor(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
    if (this.connectionCheckInterval) {
      clearInterval(this.connectionCheckInterval);
      this.connectionCheckInterval = null;
    }
    if (this.presenceGracePeriod) {
      clearTimeout(this.presenceGracePeriod);
      this.presenceGracePeriod = null;
    }
  }

  private async handleDisconnect(): Promise<void> {
    this.stopHeartbeatMonitor();
    
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
    this.stopHeartbeatMonitor();
    this.outbox = [];
    
    if (this.channel) {
      try {
        await this.channel.untrack();
      } catch {
        // Silent - best effort
      }
      
      await supabase.removeChannel(this.channel);
      this.channel = null;
    }
    
    this.updateState('disconnected', 0);
    this.messageHandlers.clear();
    this.presenceHandlers = [];
  }
}
