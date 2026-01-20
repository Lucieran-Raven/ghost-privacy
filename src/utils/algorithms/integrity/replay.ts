/**
 * Replay Protection (message deduplication + ordering)
 * Purpose: Detect replayed messages using nonce uniqueness, strict sequence monotonicity, and timestamp skew limits.
 * Input: Previous replay state, message metadata, current time.
 * Output: Validation result and next replay state.
 * Privacy: NEVER logs, NEVER stores, NEVER makes network requests, NEVER persists beyond caller-managed memory.
 */

export interface MessageMetadata {
  nonce: string;
  sequence: number;
  timestamp: number;
  receivedAt: number;
}

export interface ReplayProtectionConfig {
  maxTimeSkewMs: number;
  nonceRetentionMs: number;
  maxSequenceGap: number;
}

export interface ReplayProtectionState {
  seenNonces: Set<string>;
  lastSequence: Map<string, number>;
  nonceMetadata: Map<string, MessageMetadata>;
}

export interface ReplayValidationResult {
  valid: boolean;
  reason?: string;
}

export const DEFAULT_REPLAY_CONFIG: ReplayProtectionConfig = {
  maxTimeSkewMs: 60 * 60 * 1000,
  nonceRetentionMs: 30 * 60 * 1000,
  maxSequenceGap: 32
};

export function createReplayState(): ReplayProtectionState {
  return {
    seenNonces: new Set<string>(),
    lastSequence: new Map<string, number>(),
    nonceMetadata: new Map<string, MessageMetadata>()
  };
}

export function validateMessage(
  state: ReplayProtectionState,
  input: { sessionId: string; nonce: string; sequence: number; timestamp: number },
  now: number,
  config: ReplayProtectionConfig = DEFAULT_REPLAY_CONFIG
): { state: ReplayProtectionState; result: ReplayValidationResult } {
  if (!Number.isSafeInteger(input.sequence) || input.sequence <= 0) {
    return { state, result: { valid: false, reason: 'Invalid sequence' } };
  }
  if (!Number.isFinite(input.timestamp)) {
    return { state, result: { valid: false, reason: 'Invalid timestamp' } };
  }
  if (typeof input.nonce !== 'string' || input.nonce.length === 0 || input.nonce.length > 256) {
    return { state, result: { valid: false, reason: 'Invalid nonce' } };
  }

  const nonceKey = `${input.sessionId}:${input.nonce}`;

  if (state.seenNonces.has(nonceKey)) {
    return { state, result: { valid: false, reason: 'Duplicate nonce detected - possible replay attack' } };
  }

  const lastSeq = state.lastSequence.get(input.sessionId) || 0;
  if (input.sequence <= lastSeq) {
    return {
      state,
      result: {
        valid: false,
        reason: `Out-of-order/replayed sequence: last ${lastSeq}, got ${input.sequence}`
      }
    };
  }

  if (input.sequence > lastSeq + config.maxSequenceGap) {
    return {
      state,
      result: {
        valid: false,
        reason: `Sequence gap too large: last ${lastSeq}, got ${input.sequence}`
      }
    };
  }

  const timeDiff = Math.abs(now - input.timestamp);
  if (timeDiff > config.maxTimeSkewMs) {
    return { state, result: { valid: false, reason: `Timestamp too old: ${timeDiff}ms skew` } };
  }

  const seenNonces = new Set(state.seenNonces);
  const lastSequence = new Map(state.lastSequence);
  const nonceMetadata = new Map(state.nonceMetadata);

  seenNonces.add(nonceKey);
  lastSequence.set(input.sessionId, input.sequence);
  nonceMetadata.set(nonceKey, {
    nonce: input.nonce,
    sequence: input.sequence,
    timestamp: input.timestamp,
    receivedAt: now
  });

  return { state: { seenNonces, lastSequence, nonceMetadata }, result: { valid: true } };
}

export function getNextSequence(
  state: ReplayProtectionState,
  sessionId: string
): { state: ReplayProtectionState; sequence: number } {
  const lastSeq = state.lastSequence.get(sessionId) || 0;
  const nextSeq = lastSeq + 1;

  const lastSequence = new Map(state.lastSequence);
  lastSequence.set(sessionId, nextSeq);

  return { state: { ...state, lastSequence }, sequence: nextSeq };
}

export function resetSession(state: ReplayProtectionState, sessionId: string): ReplayProtectionState {
  const lastSequence = new Map(state.lastSequence);
  lastSequence.delete(sessionId);
  return { ...state, lastSequence };
}

export function cleanupOldNonces(
  state: ReplayProtectionState,
  now: number,
  config: ReplayProtectionConfig = DEFAULT_REPLAY_CONFIG
): ReplayProtectionState {
  if (state.nonceMetadata.size === 0) {
    return state;
  }

  const toDelete: string[] = [];
  state.nonceMetadata.forEach((metadata, nonce) => {
    if (now - metadata.receivedAt > config.nonceRetentionMs) {
      toDelete.push(nonce);
    }
  });

  if (toDelete.length === 0) {
    return state;
  }

  const seenNonces = new Set(state.seenNonces);
  const nonceMetadata = new Map(state.nonceMetadata);

  for (const nonce of toDelete) {
    seenNonces.delete(nonce);
    nonceMetadata.delete(nonce);
  }

  return { ...state, seenNonces, nonceMetadata };
}

export function getStats(state: ReplayProtectionState): { nonceCount: number; sessionCount: number } {
  return {
    nonceCount: state.seenNonces.size,
    sessionCount: state.lastSequence.size
  };
}

export function purge(): ReplayProtectionState {
  return createReplayState();
}
