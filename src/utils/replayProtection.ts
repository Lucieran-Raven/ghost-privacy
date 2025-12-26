/**
 * GHOST PRIVACY - REPLAY ATTACK PROTECTION
 * 
 * Prevents attackers from capturing and replaying encrypted messages
 * 
 * Features:
 * - Message sequence numbers (monotonically increasing)
 * - Nonce tracking (prevents duplicate message IDs)
 * - Timestamp validation (rejects old messages)
 * - Automatic cleanup of old nonces
 */

interface MessageMetadata {
    nonce: string;
    sequence: number;
    timestamp: number;
    receivedAt: number;
}

class ReplayProtection {
    private seenNonces: Set<string> = new Set();
    private lastSequence: Map<string, number> = new Map(); // sessionId -> last sequence
    private nonceMetadata: Map<string, MessageMetadata> = new Map();
    private readonly MAX_TIME_SKEW = 5 * 60 * 1000; // 5 minutes
    private readonly NONCE_RETENTION = 30 * 60 * 1000; // 30 minutes

    constructor() {
        // Auto-cleanup old nonces every 5 minutes
        setInterval(() => {
            this.cleanupOldNonces();
        }, 5 * 60 * 1000);
    }

    /**
     * Validate incoming message for replay attacks
     * Returns true if message is valid, false if it's a replay
     */
    validateMessage(
        sessionId: string,
        nonce: string,
        sequence: number,
        timestamp: number
    ): { valid: boolean; reason?: string } {
        const now = Date.now();

        // Check 1: Nonce must be unique (prevent exact replay)
        if (this.seenNonces.has(nonce)) {
            return { valid: false, reason: 'Duplicate nonce detected - possible replay attack' };
        }

        // Check 2: Sequence must be monotonically increasing (prevent out-of-order replay)
        const lastSeq = this.lastSequence.get(sessionId) || 0;
        if (sequence <= lastSeq) {
            return { valid: false, reason: `Invalid sequence: ${sequence} <= ${lastSeq}` };
        }

        // Check 3: Timestamp must be within acceptable range (prevent old message replay)
        const timeDiff = Math.abs(now - timestamp);
        if (timeDiff > this.MAX_TIME_SKEW) {
            return { valid: false, reason: `Timestamp too old: ${timeDiff}ms skew` };
        }

        // Message is valid - record it
        this.seenNonces.add(nonce);
        this.lastSequence.set(sessionId, sequence);
        this.nonceMetadata.set(nonce, {
            nonce,
            sequence,
            timestamp,
            receivedAt: now,
        });

        return { valid: true };
    }

    /**
     * Generate next sequence number for outgoing message
     */
    getNextSequence(sessionId: string): number {
        const lastSeq = this.lastSequence.get(sessionId) || 0;
        const nextSeq = lastSeq + 1;
        this.lastSequence.set(sessionId, nextSeq);
        return nextSeq;
    }

    /**
     * Reset session (on session end)
     */
    resetSession(sessionId: string): void {
        this.lastSequence.delete(sessionId);

        // Remove all nonces for this session
        this.nonceMetadata.forEach((metadata, nonce) => {
            // Note: We don't have sessionId in metadata, so we keep nonces
            // They'll be cleaned up by time-based cleanup
        });
    }

    /**
     * Cleanup old nonces (prevent memory leak)
     */
    private cleanupOldNonces(): void {
        const now = Date.now();
        const toDelete: string[] = [];

        this.nonceMetadata.forEach((metadata, nonce) => {
            if (now - metadata.receivedAt > this.NONCE_RETENTION) {
                toDelete.push(nonce);
            }
        });

        toDelete.forEach(nonce => {
            this.seenNonces.delete(nonce);
            this.nonceMetadata.delete(nonce);
        });

        if (toDelete.length > 0) {
            console.log(`[ReplayProtection] Cleaned up ${toDelete.length} old nonces`);
        }
    }

    /**
     * Get statistics
     */
    getStats(): { nonceCount: number; sessionCount: number } {
        return {
            nonceCount: this.seenNonces.size,
            sessionCount: this.lastSequence.size,
        };
    }

    /**
     * Nuclear purge (on app shutdown)
     */
    purge(): void {
        this.seenNonces.clear();
        this.lastSequence.clear();
        this.nonceMetadata.clear();
    }
}

// Singleton instance
let replayProtectionInstance: ReplayProtection | null = null;

export const getReplayProtection = (): ReplayProtection => {
    if (!replayProtectionInstance) {
        replayProtectionInstance = new ReplayProtection();
    }
    return replayProtectionInstance;
};

export const destroyReplayProtection = (): void => {
    if (replayProtectionInstance) {
        replayProtectionInstance.purge();
        replayProtectionInstance = null;
    }
};

export default getReplayProtection;
