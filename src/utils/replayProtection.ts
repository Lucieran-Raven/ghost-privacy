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

 import {
   cleanupOldNonces as cleanupOldNoncesAlgorithm,
   createReplayState,
   getNextSequence as getNextSequenceAlgorithm,
   getStats as getStatsAlgorithm,
   resetSession as resetSessionAlgorithm,
   validateMessage as validateMessageAlgorithm,
   type ReplayProtectionState
 } from '@/utils/algorithms/integrity/replay';

class ReplayProtection {
    private state: ReplayProtectionState = createReplayState();
    private readonly cleanupInterval: ReturnType<typeof setInterval>;

    constructor() {
        // Auto-cleanup old nonces every 5 minutes
        this.cleanupInterval = setInterval(() => {
            this.state = cleanupOldNoncesAlgorithm(this.state, Date.now());
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
        if (typeof sessionId !== 'string' || sessionId.length === 0 || sessionId.length > 128) {
            return { valid: false, reason: 'Invalid session' };
        }
        const now = Date.now();
        const { state, result } = validateMessageAlgorithm(
            this.state,
            { sessionId, nonce, sequence, timestamp },
            now
        );
        this.state = state;
        return result;
    }

    /**
     * Generate next sequence number for outgoing message
     */
    getNextSequence(sessionId: string): number {
        if (typeof sessionId !== 'string' || sessionId.length === 0 || sessionId.length > 128) {
            return 0;
        }
        const { state, sequence } = getNextSequenceAlgorithm(this.state, sessionId);
        this.state = state;
        return sequence;
    }

    /**
     * Reset session (on session end)
     */
    resetSession(sessionId: string): void {
        if (typeof sessionId !== 'string' || sessionId.length === 0 || sessionId.length > 128) {
            return;
        }
        this.state = resetSessionAlgorithm(this.state, sessionId);
    }

    /**
     * Get statistics
     */
    getStats(): { nonceCount: number; sessionCount: number } {
        return getStatsAlgorithm(this.state);
    }

    /**
     * Nuclear purge (on app shutdown)
     */
    purge(): void {
        this.state = createReplayState();
        clearInterval(this.cleanupInterval);
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
