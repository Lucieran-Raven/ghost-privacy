import { supabase } from '@/integrations/supabase/publicClient';
import { RealtimeChannel } from '@supabase/supabase-js';
import { generateNonce } from '@/utils/encryption';
import { deriveRealtimeChannelName } from '@/utils/realtimeChannel';

const PADDED_FRAME_TOTAL_CHARS = 1024;
const PADDED_FRAME_HEADER_CHARS = 6;
const PADDED_FRAME_PAYLOAD_CHARS = PADDED_FRAME_TOTAL_CHARS - PADDED_FRAME_HEADER_CHARS;

const PADDED_FRAME_VERSION = 2;
const SEALED_CHUNK_BYTES = 384;
const SEALED_CHUNK_B64_CHARS = 512;
const SEALED_TAG_BYTES = 16;
const SEALED_LEN_PREFIX_BYTES = 4;
const SEALED_MIN_BUCKET_FRAMES = 8;
const SEND_FRAME_JITTER_MAX_MS = 25;

const PADDED_FRAME_MAX_INNER_FRAMES = 256;
const PADDED_FRAME_BUFFER_TTL_MS = 30 * 1000;
const PADDED_FRAME_MAX_INFLIGHT = 128;

const COVER_TRAFFIC_HEARTBEAT_INTERVAL_MS = 30 * 1000;

const DIRECT_BROADCAST_MAX_CHARS = 90_000;

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

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecodeToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

function nextPowerOfTwo(n: number): number {
  let p = 1;
  while (p < n) p <<= 1;
  return p;
}

function randomInt(maxExclusive: number): number {
  if (maxExclusive <= 0) return 0;
  try {
    const buf = new Uint32Array(1);
    crypto.getRandomValues(buf);
    return buf[0] % maxExclusive;
  } catch {
    return Math.floor(Math.random() * maxExclusive);
  }
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

  private transportKeyPromise: Promise<CryptoKey> | null = null;

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
      if (payload.type === 'chat-message' || payload.type === 'voice-message' || payload.type === 'video-message' || payload.type === 'file') {
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

    const shouldSendDirect = (() => {
      if (payload.type === 'file') {
        try {
          return JSON.stringify(payload).length <= DIRECT_BROADCAST_MAX_CHARS;
        } catch {
          return false;
        }
      }
      if (payload.type === 'message-ack' || payload.type === 'typing' || payload.type === 'presence') return true;
      if (payload.type === 'key-exchange') return true;
      if (payload.type === 'voice-message' || payload.type === 'video-message') {
        try {
          return JSON.stringify(payload).length <= DIRECT_BROADCAST_MAX_CHARS;
        } catch {
          return false;
        }
      }
      if (payload.type === 'chat-message') {
        try {
          return JSON.stringify(payload).length <= DIRECT_BROADCAST_MAX_CHARS;
        } catch {
          return false;
        }
      }
      return false;
    })();

    if (shouldSendDirect) {
      for (let attempt = 1; attempt <= retries; attempt++) {
        try {
          const jitter = randomInt(SEND_FRAME_JITTER_MAX_MS + 1);
          if (jitter > 0) {
            await new Promise(resolve => setTimeout(resolve, jitter));
          }
          const result = await this.channel.send({
            type: 'broadcast',
            event: 'ghost-message',
            payload
          });
          if (result === 'ok') {
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

    let frames: BroadcastPayload[];
    try {
      frames = await this.toPaddedFrames(payload);
    } catch {
      return false;
    }

    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        let ok = true;
        for (const frame of frames) {
          const jitter = randomInt(SEND_FRAME_JITTER_MAX_MS + 1);
          if (jitter > 0) {
            await new Promise(resolve => setTimeout(resolve, jitter));
          }
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

  private async getTransportKey(): Promise<CryptoKey> {
    if (this.transportKeyPromise) return this.transportKeyPromise;

    this.transportKeyPromise = (async () => {
      const tokenBytes = base64UrlDecodeToBytes(this.channelToken);
      const sidBytes = new TextEncoder().encode(this.sessionId);
      const material = concatBytes([tokenBytes, sidBytes]);
      const digest = await crypto.subtle.digest('SHA-256', material.buffer as ArrayBuffer);
      return await crypto.subtle.importKey(
        'raw',
        digest,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
      );
    })();

    return this.transportKeyPromise;
  }

  private async sealPayload(inner: BroadcastPayload, bucketFrames: number): Promise<{ ivB64: string; chunksB64: string[] }> {
    const innerJson = JSON.stringify(inner);
    const innerBytes = new TextEncoder().encode(innerJson);

    const plaintextLen = bucketFrames * SEALED_CHUNK_BYTES - SEALED_TAG_BYTES;
    if (plaintextLen <= SEALED_LEN_PREFIX_BYTES) {
      throw new Error('invalid sealing size');
    }
    if (innerBytes.length > plaintextLen - SEALED_LEN_PREFIX_BYTES) {
      throw new Error('payload too large');
    }

    const plaintext = new Uint8Array(plaintextLen);
    crypto.getRandomValues(plaintext);

    const dv = new DataView(plaintext.buffer);
    dv.setUint32(0, innerBytes.length, false);
    plaintext.set(innerBytes, SEALED_LEN_PREFIX_BYTES);

    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);

    const key = await this.getTransportKey();
    const aad = new TextEncoder().encode(`${this.sessionId}|${inner.nonce}`);

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad },
      key,
      plaintext.buffer as ArrayBuffer
    );

    const ctBytes = new Uint8Array(ciphertext);
    if (ctBytes.length !== bucketFrames * SEALED_CHUNK_BYTES) {
      throw new Error('unexpected ciphertext length');
    }

    const chunksB64: string[] = [];
    for (let i = 0; i < bucketFrames; i++) {
      const chunkBytes = ctBytes.slice(i * SEALED_CHUNK_BYTES, (i + 1) * SEALED_CHUNK_BYTES);
      const chunkB64 = base64UrlEncodeBytes(chunkBytes);
      if (chunkB64.length !== SEALED_CHUNK_B64_CHARS) {
        throw new Error('unexpected chunk encoding');
      }
      chunksB64.push(chunkB64);
    }

    try {
      plaintext.fill(0);
      innerBytes.fill(0);
    } catch {
    }

    return { ivB64: base64UrlEncodeBytes(iv), chunksB64 };
  }

  private async unsealPayload(
    senderId: string,
    mid: string,
    ivB64: string,
    chunksB64: string[]
  ): Promise<any | null> {
    if (chunksB64.length < 1 || chunksB64.length > PADDED_FRAME_MAX_INNER_FRAMES) return null;

    const chunksBytes: Uint8Array[] = [];
    for (const c of chunksB64) {
      if (typeof c !== 'string' || c.length !== SEALED_CHUNK_B64_CHARS) return null;
      let b: Uint8Array;
      try {
        b = base64UrlDecodeToBytes(c);
      } catch {
        return null;
      }
      if (b.length !== SEALED_CHUNK_BYTES) return null;
      chunksBytes.push(b);
    }

    let iv: Uint8Array;
    try {
      iv = base64UrlDecodeToBytes(ivB64);
    } catch {
      return null;
    }
    if (iv.length !== 12) return null;

    const ciphertextBytes = concatBytes(chunksBytes);

    const key = await this.getTransportKey();
    const aad = new TextEncoder().encode(`${this.sessionId}|${mid}`);

    let plaintextBuf: ArrayBuffer;
    try {
      plaintextBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: aad },
        key,
        ciphertextBytes.buffer as ArrayBuffer
      );
    } catch {
      return null;
    }

    const plaintext = new Uint8Array(plaintextBuf);
    if (plaintext.length < SEALED_LEN_PREFIX_BYTES) return null;

    const dv = new DataView(plaintext.buffer);
    const msgLen = dv.getUint32(0, false);
    if (!Number.isFinite(msgLen) || msgLen <= 0 || msgLen > plaintext.length - SEALED_LEN_PREFIX_BYTES) return null;

    const msgBytes = plaintext.slice(SEALED_LEN_PREFIX_BYTES, SEALED_LEN_PREFIX_BYTES + msgLen);

    let json: string;
    try {
      json = new TextDecoder().decode(msgBytes);
    } catch {
      return null;
    }

    let inner: any;
    try {
      inner = JSON.parse(json);
    } catch {
      return null;
    }

    if (!inner || typeof inner !== 'object') return null;
    if (typeof inner.senderId !== 'string' || inner.senderId !== senderId) return null;
    if (typeof inner.nonce !== 'string' || inner.nonce !== mid) return null;

    try {
      plaintext.fill(0);
      msgBytes.fill(0);
    } catch {
    }

    return inner;
  }

  private async toPaddedFrames(inner: BroadcastPayload): Promise<BroadcastPayload[]> {
    const innerJson = JSON.stringify(inner);
    const innerBytes = new TextEncoder().encode(innerJson);

    const neededPlain = SEALED_LEN_PREFIX_BYTES + innerBytes.length;
    let totalFrames = SEALED_MIN_BUCKET_FRAMES;
    while (totalFrames * SEALED_CHUNK_BYTES - SEALED_TAG_BYTES < neededPlain) {
      totalFrames *= 2;
      if (totalFrames > PADDED_FRAME_MAX_INNER_FRAMES) {
        throw new Error('payload too large');
      }
    }

    const bucket = Math.max(SEALED_MIN_BUCKET_FRAMES, nextPowerOfTwo(totalFrames));
    if (bucket > PADDED_FRAME_MAX_INNER_FRAMES) {
      throw new Error('payload too large');
    }

    const sealed = await this.sealPayload(inner, bucket);

    const frames: BroadcastPayload[] = [];
    for (let seq = 0; seq < bucket; seq++) {
      const frameData = {
        v: PADDED_FRAME_VERSION,
        mid: inner.nonce,
        seq,
        total: bucket,
        iv: sealed.ivB64,
        chunk: sealed.chunksB64[seq]
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

  private async handleIncomingPaddedFrame(payload: BroadcastPayload): Promise<void> {
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

    if (!frame || (frame.v !== 1 && frame.v !== PADDED_FRAME_VERSION)) return;
    if (typeof frame.mid !== 'string' || frame.mid.length === 0 || frame.mid.length > 256) return;
    if (typeof frame.seq !== 'number' || !Number.isFinite(frame.seq)) return;
    if (typeof frame.total !== 'number' || !Number.isFinite(frame.total)) return;
    if (frame.total < 1 || frame.total > PADDED_FRAME_MAX_INNER_FRAMES) return;
    if (frame.seq < 0 || frame.seq >= frame.total) return;
    if (frame.v === PADDED_FRAME_VERSION) {
      if (typeof frame.iv !== 'string' || frame.iv.length !== 16) return;
      if (typeof frame.chunk !== 'string' || frame.chunk.length !== SEALED_CHUNK_B64_CHARS) return;
    } else {
      if (typeof frame.chunk !== 'string') return;
      if (frame.chunk.length > 2048) return;
    }

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

    if (frame.v === PADDED_FRAME_VERSION) {
      const innerPayload = await this.unsealPayload(payload.senderId, frame.mid, frame.iv, buf.chunks);
      if (!innerPayload) return;
      if (!this.shouldAcceptIncoming(innerPayload, { allowPaddedFrame: false })) {
        return;
      }

      const type = innerPayload.type as PublicBroadcastType;
      const handler = this.messageHandlers.get(type);
      if (handler) {
        handler(innerPayload as BroadcastPayload);
      }
      return;
    }

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
        void this.handleIncomingPaddedFrame(payload as BroadcastPayload);
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
    const getBackoffDelay = (attempt: number) => {
      const base = Math.min(500 * Math.pow(2, attempt), 30000);
      return Math.max(250, Math.floor(base));
    };
    
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
          reject(new Error('Connection failed'));
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
            reject(new Error('Connection failed'));
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
      this.updateState('error', 0, 'Secure channel establishing…');
      return;
    }

    this.reconnectAttempts++;
    this.updateState('reconnecting', 50);
    
    const baseDelay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 10000);
    const delay = Math.max(250, Math.floor(baseDelay));
    
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
    if (ok) {
      if (this.outbox.length > 0) {
        void this.flushOutbox().catch(() => {
        });
      }
      return true;
    }

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
