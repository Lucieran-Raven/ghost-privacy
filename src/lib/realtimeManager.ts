import { supabase } from '@/integrations/supabase/client';
import { RealtimeChannel } from '@supabase/supabase-js';
import { generateNonce } from '@/utils/encryption';

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
  private participantId: string;
  private messageHandlers: Map<string, (payload: BroadcastPayload) => void> = new Map();
  private presenceHandlers: ((participants: string[]) => void)[] = [];
  private statusHandlers: ((state: ConnectionState) => void)[] = [];
  private connectionState: ConnectionState = { status: 'connecting', progress: 0 };
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 2; // 2 silent retries per spec
  private heartbeatInterval: NodeJS.Timeout | null = null;
  private lastHeartbeat = Date.now();
  private isDestroyed = false;

  constructor(sessionId: string, participantId: string) {
    this.sessionId = sessionId;
    this.participantId = participantId;
  }

  /**
   * CRITICAL: Channel name MUST be exactly `ghost-session-${sessionId}` for both peers
   */
  private getChannelName(): string {
    return `ghost-session-${this.sessionId}`;
  }

  private updateState(status: ConnectionStatus, progress: number, error?: string): void {
    this.connectionState = { status, progress, error };
    this.statusHandlers.forEach(handler => handler(this.connectionState));
  }

  async connect(): Promise<void> {
    if (this.isDestroyed) return;
    
    const channelName = this.getChannelName();
    console.debug('[GHOST] Connecting to channel:', channelName);
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

    // Setup presence tracking
    this.channel.on('presence', { event: 'sync' }, () => {
      const state = this.channel?.presenceState() || {};
      const participants = Object.keys(state).filter(id => id !== this.participantId);
      this.presenceHandlers.forEach(handler => handler(participants));
    });

    this.channel.on('presence', { event: 'join' }, () => {
      // Silent - presence sync handles state
    });

    this.channel.on('presence', { event: 'leave' }, () => {
      // Silent - presence sync handles state
    });

    // Subscribe with promise-based waiting and exponential backoff retry
    return this.connectWithRetry();
  }

  private async connectWithRetry(): Promise<void> {
    const backoffDelays = [500, 1000]; // Exponential backoff: 500ms, 1s
    
    return new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
          // Silent retry with backoff
          const delay = backoffDelays[this.reconnectAttempts] || 1000;
          console.debug(`[GHOST] Connection attempt ${this.reconnectAttempts + 1} failed, retrying in ${delay}ms`);
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
      }, 3000); // 3 second timeout per attempt

      this.channel!.subscribe(async (status) => {
        if (status === 'SUBSCRIBED') {
          clearTimeout(timeout);
          console.debug('[GHOST] Channel subscribed successfully');
          this.updateState('handshaking', 75);
          
          // Track presence
          try {
            await this.channel?.track({
              participantId: this.participantId,
              joinedAt: Date.now()
            });
          } catch (e) {
            console.debug('[GHOST] Presence tracking failed:', e);
          }

          // Wait for channel stability
          await this.waitForStability();
          
          this.updateState('connected', 100);
          this.reconnectAttempts = 0;
          this.startHeartbeatMonitor();
          
          resolve();
        } else if (status === 'CLOSED' || status === 'CHANNEL_ERROR') {
          clearTimeout(timeout);
          console.debug('[GHOST] Channel error:', status);
          
          if (this.reconnectAttempts < this.maxReconnectAttempts) {
            const delay = backoffDelays[this.reconnectAttempts] || 1000;
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
    
    this.heartbeatInterval = setInterval(() => {
      const timeSinceHeartbeat = Date.now() - this.lastHeartbeat;
      
      if (timeSinceHeartbeat > 30000) {
        this.attemptReconnect();
      }
    }, 10000);
  }

  private stopHeartbeatMonitor(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
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
    if (!this.channel || this.connectionState.status !== 'connected') {
      return false;
    }

    const payload: BroadcastPayload = {
      type,
      senderId: this.participantId,
      data,
      timestamp: Date.now(),
      nonce: generateNonce()
    };

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
