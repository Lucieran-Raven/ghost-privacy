import { supabase } from '@/integrations/supabase/publicClient';
import { RealtimeChannel } from '@supabase/supabase-js';
import { generateNonce } from '@/utils/encryption';
import { deriveRealtimeChannelName } from '@/utils/realtimeChannel';

const PADDED_FRAME_TOTAL_CHARS = 1024;
const PADDED_FRAME_HEADER_CHARS = 6;
const PADDED_FRAME_PAYLOAD_CHARS = PADDED_FRAME_TOTAL_CHARS - PADDED_FRAME_HEADER_CHARS;

const PADDED_FRAME_MAX_INNER_FRAMES = 256;
const PADDED_FRAME_BUFFER_TTL_MS = 30 * 1000;
const PADDED_FRAME_MAX_INFLIGHT = 128;

const COVER_TRAFFIC_HEARTBEAT_INTERVAL_MS = 30 * 1000;

function encodeUtf8ToBase64(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function decodeBase64ToUtf8(b64: string): string {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

function toFixedLenFrameString(innerJson: string): string {
  const len = innerJson.length;
  const lenStr = String(len).padStart(PADDED_FRAME_HEADER_CHARS, '0');
  if (lenStr.length !== PADDED_FRAME_HEADER_CHARS) {
    throw new Error('frame header overflow');
  }
  if (len > PADDED_FRAME_PAYLOAD_CHARS) {
    throw new Error('frame payload overflow');
  }

  const padLen = PADDED_FRAME_PAYLOAD_CHARS - len;
  if (padLen === 0) {
    return `${lenStr}${innerJson}`;
  }

  let pad = '';
  try {
    const bytes = new Uint8Array(Math.ceil((padLen * 3) / 4) + 8);
    crypto.getRandomValues(bytes);
    pad = btoa(String.fromCharCode(...bytes)).replace(/=+$/g, '');
  } catch {
    pad = '0'.repeat(padLen);
  }

  if (pad.length < padLen) {
    pad = pad.padEnd(padLen, '0');
  }

  return `${lenStr}${innerJson}${pad.slice(0, padLen)}`;
}

function fromFixedLenFrameString(p: string): string | null {
  if (typeof p !== 'string') return null;
  if (p.length !== PADDED_FRAME_TOTAL_CHARS) return null;
  const lenStr = p.slice(0, PADDED_FRAME_HEADER_CHARS);
  if (!/^[0-9]{6}$/.test(lenStr)) return null;
  const len = Number.parseInt(lenStr, 10);
  if (!Number.isFinite(len) || len < 0 || len > PADDED_FRAME_PAYLOAD_CHARS) return null;
  return p.slice(PADDED_FRAME_HEADER_CHARS, PADDED_FRAME_HEADER_CHARS + len);
}

export interface BroadcastPayload {
  type: BroadcastType;
  senderId: string;
  data: any;
  timestamp: number;
  nonce: string;
}

export type BroadcastType =
  | 'chat-message'
  | 'key-exchange'
  | 'presence'
  | 'typing'
  | 'heartbeat'
  | 'file'
  | 'message-ack'
  | 'session-terminated'
  | 'voice-message'
  | 'video-message'
  | 'padded-frame';

export type PublicBroadcastType = Exclude<BroadcastType, 'padded-frame'>;

export type ConnectionStatus = 'connecting' | 'validating' | 'subscribing' | 'handshaking' | 'connected' | 'reconnecting' | 'disconnected' | 'error';

export interface ConnectionState {
  status: ConnectionStatus;
  progress: number;
  error?: string;
}

export class RealtimeManager {
  private channel: RealtimeChannel | null = null;
  private sessionId: string;
  private channelToken: string;
  private participantId: string;
  private outbox: Array<{ payload: BroadcastPayload; retries: number; enqueuedAt: number }> = [];
  private readonly outboxMaxItems = 64;
  private readonly outboxMaxPayloadChars = 200_000;
  private readonly incomingMaxPayloadChars = 250_000;
  private messageHandlers: Map<PublicBroadcastType, (payload: BroadcastPayload) => void> = new Map();
  private presenceHandlers: ((participants: string[]) => void)[] = [];
  private statusHandlers: ((state: ConnectionState) => void)[] = [];
  private connectionState: ConnectionState = { status: 'connecting', progress: 0 };
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10; // Increased from 2 to 10 for resilience
  private isDestroyed = false;
  private partnerCount = 0;

  private lastHeartbeat = 0;
  private lastOutboundAt = 0;
  private coverTrafficTimer: ReturnType<typeof setInterval> | null = null;
  private coverTrafficInFlight = false;

  private seenIncoming: Map<string, number> = new Map();
  private readonly seenIncomingTtlMs = 10 * 60 * 1000;
  private readonly seenIncomingMaxEntries = 4096;

  private incomingFrames: Map<string, { total: number; chunks: string[]; received: number; updatedAt: number }> = new Map();

  constructor(sessionId: string, channelToken: string, participantId: string) {
    this.sessionId = sessionId;
    this.channelToken = channelToken;
    this.participantId = participantId;
  }

  private updateState(status: ConnectionStatus, progress: number, error?: string): void {
    this.connectionState = { status, progress, error };
    this.statusHandlers.forEach(handler => handler(this.connectionState));
  }

  private shouldAcceptIncoming(
    payload: any,
    options?: { allowPaddedFrame?: boolean; skipReplayCheck?: boolean }
  ): payload is BroadcastPayload {
    if (!payload || typeof payload !== 'object') return false;
    if (
      payload.type !== 'chat-message' &&
      payload.type !== 'key-exchange' &&
      payload.type !== 'presence' &&
      payload.type !== 'typing' &&
      payload.type !== 'heartbeat' &&
      payload.type !== 'file' &&
      payload.type !== 'message-ack' &&
      payload.type !== 'session-terminated' &&
      payload.type !== 'voice-message' &&
      payload.type !== 'video-message' &&
      payload.type !== 'padded-frame'
    ) {
      return false;
    }
    if (payload.type === 'padded-frame' && !options?.allowPaddedFrame) {
      return false;
    }
    if (typeof payload.senderId !== 'string' || payload.senderId.length === 0) return false;
    if (typeof payload.nonce !== 'string' || payload.nonce.length === 0) return false;

    if (payload.nonce.length > 256) return false;
    if (payload.nonce.indexOf(' ') !== -1 || payload.nonce.indexOf('\n') !== -1 || payload.nonce.indexOf('\r') !== -1) return false;

    if (typeof payload.timestamp !== 'number' || !Number.isFinite(payload.timestamp)) return false;
    const now = Date.now();
    if (Math.abs(now - payload.timestamp) > 15 * 60 * 1000) return false;

    try {
      const approx = this.estimatePayloadChars(payload as BroadcastPayload);
      if (!Number.isFinite(approx) || approx > this.incomingMaxPayloadChars) return false;
    } catch {
      return false;
    }

    const cutoff = now - this.seenIncomingTtlMs;

    if (this.seenIncoming.size > 0) {
      for (const [k, ts] of this.seenIncoming) {
        if (ts < cutoff) {
          this.seenIncoming.delete(k);
        }
      }
    }

    if (!options?.skipReplayCheck) {
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
    }

    return true;
  }

  private estimatePayloadChars(payload: BroadcastPayload): number {
    // Avoid JSON.stringify for small, frequent events.
    if (payload.type === 'typing' || payload.type === 'presence' || payload.type === 'message-ack' || payload.type === 'heartbeat') {
      return 512;
    }

    if (payload.type === 'padded-frame') {
      return PADDED_FRAME_TOTAL_CHARS;
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

    // Never queue cover-traffic heartbeats.
    if (payload.type === 'heartbeat') return false;

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

    let frames: BroadcastPayload[];
    try {
      frames = this.toPaddedFrames(payload);
    } catch {
      return false;
    }

    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        let ok = true;
        for (const frame of frames) {
          const result = await this.channel.send({
            type: 'broadcast',
            event: 'ghost-message',
            payload: frame
          });
          if (result !== 'ok') {
            ok = false;
            break;
          }
        }

        if (ok) {
          this.lastHeartbeat = Date.now();
          this.lastOutboundAt = this.lastHeartbeat;
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

  private startCoverTraffic(): void {
    if (this.coverTrafficTimer) return;

    // Treat connection time as outbound activity so we don't immediately send a cover ping.
    if (!this.lastOutboundAt) {
      this.lastOutboundAt = Date.now();
    }

    this.coverTrafficTimer = setInterval(() => {
      if (this.isDestroyed) return;
      if (!this.channel || this.connectionState.status !== 'connected') return;
      if (this.coverTrafficInFlight) return;

      const now = Date.now();
      if (now - this.lastOutboundAt < COVER_TRAFFIC_HEARTBEAT_INTERVAL_MS) return;

      this.coverTrafficInFlight = true;
      const payload: BroadcastPayload = {
        type: 'heartbeat',
        senderId: this.participantId,
        data: {},
        timestamp: now,
        nonce: generateNonce()
      };

      this.sendNow(payload, 1)
        .catch(() => {
        })
        .finally(() => {
          this.coverTrafficInFlight = false;
        });
    }, 1000);
  }

  private stopCoverTraffic(): void {
    if (!this.coverTrafficTimer) return;
    try {
      clearInterval(this.coverTrafficTimer);
    } catch {
    }
    this.coverTrafficTimer = null;
    this.coverTrafficInFlight = false;
  }

  private cleanupFrameBuffers(now: number): void {
    const cutoff = now - PADDED_FRAME_BUFFER_TTL_MS;
    for (const [k, v] of this.incomingFrames) {
      if (v.updatedAt < cutoff) {
        this.incomingFrames.delete(k);
      }
    }

    while (this.incomingFrames.size > PADDED_FRAME_MAX_INFLIGHT) {
      const firstKey = this.incomingFrames.keys().next().value as string | undefined;
      if (!firstKey) break;
      this.incomingFrames.delete(firstKey);
    }
  }

  private toPaddedFrames(inner: BroadcastPayload): BroadcastPayload[] {
    const innerJson = JSON.stringify(inner);
    const innerB64 = encodeUtf8ToBase64(innerJson);

    // Conservative chunk sizing so the JSON metadata fits.
    // All frames will have identical `data.p` length.
    const maxChunk = 700;
    const total = Math.max(1, Math.ceil(innerB64.length / maxChunk));
    if (total > PADDED_FRAME_MAX_INNER_FRAMES) {
      throw new Error('payload too large');
    }

    const frames: BroadcastPayload[] = [];
    for (let seq = 0; seq < total; seq++) {
      const chunk = innerB64.slice(seq * maxChunk, (seq + 1) * maxChunk);
      const frameData = {
        v: 1,
        mid: inner.nonce,
        seq,
        total,
        chunk
      };
      const frameJson = JSON.stringify(frameData);
      const p = toFixedLenFrameString(frameJson);

      frames.push({
        type: 'padded-frame',
        senderId: inner.senderId,
        data: { p },
        timestamp: inner.timestamp,
        nonce: generateNonce()
      });
    }
    return frames;
  }

  private handleIncomingPaddedFrame(payload: BroadcastPayload): void {
    const now = Date.now();
    this.cleanupFrameBuffers(now);

    const p = payload.data && typeof payload.data.p === 'string' ? payload.data.p : null;
    const frameJson = p ? fromFixedLenFrameString(p) : null;
    if (!frameJson) return;

    let frame: any;
    try {
      frame = JSON.parse(frameJson);
    } catch {
      return;
    }

    if (!frame || frame.v !== 1) return;
    if (typeof frame.mid !== 'string' || frame.mid.length === 0 || frame.mid.length > 256) return;
    if (typeof frame.seq !== 'number' || !Number.isFinite(frame.seq)) return;
    if (typeof frame.total !== 'number' || !Number.isFinite(frame.total)) return;
    if (frame.total < 1 || frame.total > PADDED_FRAME_MAX_INNER_FRAMES) return;
    if (frame.seq < 0 || frame.seq >= frame.total) return;
    if (typeof frame.chunk !== 'string') return;
    if (frame.chunk.length > 2048) return;

    const key = `${payload.senderId}:${frame.mid}`;
    let buf = this.incomingFrames.get(key);
    if (!buf) {
      buf = { total: frame.total, chunks: new Array(frame.total).fill(''), received: 0, updatedAt: now };
      this.incomingFrames.set(key, buf);
    }

    if (buf.total !== frame.total) {
      this.incomingFrames.delete(key);
      return;
    }

    if (!buf.chunks[frame.seq]) {
      buf.chunks[frame.seq] = frame.chunk;
      buf.received++;
    }
    buf.updatedAt = now;

    if (buf.received !== buf.total) {
      return;
    }

    this.incomingFrames.delete(key);
    const innerB64 = buf.chunks.join('');
    let innerPayload: any;
    try {
      const innerJsonDecoded = decodeBase64ToUtf8(innerB64);
      innerPayload = JSON.parse(innerJsonDecoded);
    } catch {
      return;
    }

    if (!this.shouldAcceptIncoming(innerPayload, { allowPaddedFrame: false })) {
      return;
    }

    const type = innerPayload.type as PublicBroadcastType;
    const handler = this.messageHandlers.get(type);
    if (handler) {
      handler(innerPayload as BroadcastPayload);
    }
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

    this.stopCoverTraffic();

    const channelName = await deriveRealtimeChannelName(this.sessionId, this.channelToken);
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

      // Frames are fixed-size; suppress per-frame replay tracking to avoid filling replay cache.
      if (payload.type === 'padded-frame') {
        if (!this.shouldAcceptIncoming(payload, { allowPaddedFrame: true, skipReplayCheck: true })) return;
        this.handleIncomingPaddedFrame(payload as BroadcastPayload);
        return;
      }

      // Cover traffic: ignore.
      if (payload.type === 'heartbeat') {
        if (!this.shouldAcceptIncoming(payload, { allowPaddedFrame: false })) return;
        return;
      }

      if (!this.shouldAcceptIncoming(payload, { allowPaddedFrame: false })) return;

      const type = payload.type as PublicBroadcastType;
      const handler = this.messageHandlers.get(type);
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

          this.startCoverTraffic();
          
          resolve();
        } else if (status === 'CLOSED' || status === 'CHANNEL_ERROR') {
          clearTimeout(timeout);

          this.stopCoverTraffic();
          
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

  async send(type: PublicBroadcastType, data: any, retries = 3): Promise<boolean> {
    let nonce = generateNonce();
    try {
      const mid = data && typeof data.messageId === 'string' ? data.messageId : '';
      if ((type === 'chat-message' || type === 'voice-message' || type === 'video-message') && mid.length > 0 && mid.length <= 256) {
        if (mid.indexOf(' ') === -1 && mid.indexOf('\n') === -1 && mid.indexOf('\r') === -1) {
          nonce = mid;
        }
      }
    } catch {
    }

    const payload: BroadcastPayload = {
      type,
      senderId: this.participantId,
      data,
      timestamp: Date.now(),
      nonce
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

  async sendWithAck(type: PublicBroadcastType, data: any, ackTimeout = 5000): Promise<{ sent: boolean; messageId: string }> {
    const messageId = generateNonce();
    const dataWithId = { ...data, messageId };
    
    const sent = await this.send(type, dataWithId);
    
    return { sent, messageId };
  }

  onMessage(type: PublicBroadcastType, handler: (payload: BroadcastPayload) => void): void {
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

    this.stopCoverTraffic();
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
