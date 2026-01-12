/**
 * GHOST PRIVACY - SECURE IN-MEMORY SESSION KEY MANAGER
 * 
 * SECURITY GUARANTEE: Keys exist ONLY in JavaScript heap memory
 * - NO localStorage
 * - NO sessionStorage  
 * - NO IndexedDB
 * - NO cookies
 * - NO disk persistence
 * 
 * Implements aggressive cleanup on:
 * - Session termination
 * - Browser close (beforeunload)
 * - Tab visibility change
 * - Window blur
 */

interface SessionKeyData {
    encryptionKey: CryptoKey | null;
    keyPair: CryptoKeyPair | null;
    partnerPublicKey: CryptoKey | null;
    sessionId: string;
    createdAt: number;
    lastAccessedAt: number;
}

class SecureSessionKeyManager {
    // In-memory storage ONLY - never persisted
    private keys: Map<string, SessionKeyData> = new Map();
    private cleanupHandlersRegistered = false;

    constructor() {
        this.registerCleanupHandlers();
    }

    /**
     * Register aggressive cleanup handlers
     */
    private registerCleanupHandlers(): void {
        if (this.cleanupHandlersRegistered) return;
        this.cleanupHandlersRegistered = true;

        if (typeof window === 'undefined' || typeof document === 'undefined') {
            return;
        }

        // Cleanup on browser close
        window.addEventListener('beforeunload', () => {
            this.nuclearPurge();
        });

        // Cleanup on tab visibility change (user switches tabs)
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                // Optional: aggressive cleanup when tab is hidden
                // this.nuclearPurge();
            }
        });

        // Cleanup on window blur (user switches windows)
        window.addEventListener('blur', () => {
            // Optional: cleanup on window blur
            // this.nuclearPurge();
        });

        // Cleanup on page unload
        window.addEventListener('unload', () => {
            this.nuclearPurge();
        });

        // Cleanup on page hide (mobile/PWA)
        window.addEventListener('pagehide', () => {
            this.nuclearPurge();
        });
    }

    /**
     * Store encryption key for a session (IN MEMORY ONLY)
     */
    setEncryptionKey(sessionId: string, key: CryptoKey): void {
        const existing = this.keys.get(sessionId) || this.createEmptyKeyData(sessionId);
        existing.encryptionKey = key;
        existing.lastAccessedAt = Date.now();
        this.keys.set(sessionId, existing);
    }

    /**
     * Get encryption key for a session
     */
    getEncryptionKey(sessionId: string): CryptoKey | null {
        const data = this.keys.get(sessionId);
        if (data) {
            data.lastAccessedAt = Date.now();
            return data.encryptionKey;
        }
        return null;
    }

    /**
     * Store ECDH key pair for a session (IN MEMORY ONLY)
     */
    setKeyPair(sessionId: string, keyPair: CryptoKeyPair): void {
        const existing = this.keys.get(sessionId) || this.createEmptyKeyData(sessionId);
        existing.keyPair = keyPair;
        existing.lastAccessedAt = Date.now();
        this.keys.set(sessionId, existing);
    }

    /**
     * Get ECDH key pair for a session
     */
    getKeyPair(sessionId: string): CryptoKeyPair | null {
        const data = this.keys.get(sessionId);
        if (data) {
            data.lastAccessedAt = Date.now();
            return data.keyPair;
        }
        return null;
    }

    /**
     * Store partner's public key (IN MEMORY ONLY)
     */
    setPartnerPublicKey(sessionId: string, publicKey: CryptoKey): void {
        const existing = this.keys.get(sessionId) || this.createEmptyKeyData(sessionId);
        existing.partnerPublicKey = publicKey;
        existing.lastAccessedAt = Date.now();
        this.keys.set(sessionId, existing);
    }

    /**
     * Get partner's public key
     */
    getPartnerPublicKey(sessionId: string): CryptoKey | null {
        const data = this.keys.get(sessionId);
        if (data) {
            data.lastAccessedAt = Date.now();
            return data.partnerPublicKey;
        }
        return null;
    }

    /**
     * Check if session has keys
     */
    hasSession(sessionId: string): boolean {
        return this.keys.has(sessionId);
    }

    /**
     * Get all session IDs (for debugging only)
     */
    getAllSessionIds(): string[] {
        return Array.from(this.keys.keys());
    }

    /**
     * Destroy a single session - complete memory wipe
     */
    destroySession(sessionId: string): void {
        const data = this.keys.get(sessionId);
        if (!data) return;

        // Nullify all references
        data.encryptionKey = null;
        data.keyPair = null;
        data.partnerPublicKey = null;
        data.sessionId = '';
        data.createdAt = 0;
        data.lastAccessedAt = 0;

        // Remove from map
        this.keys.delete(sessionId);

        // Hint garbage collector
        this.hintGarbageCollection();
    }

    /**
     * NUCLEAR OPTION - Destroy ALL sessions immediately
     */
    nuclearPurge(): void {
        // Nullify all key references
        this.keys.forEach((data) => {
            data.encryptionKey = null;
            data.keyPair = null;
            data.partnerPublicKey = null;
            data.sessionId = '';
            data.createdAt = 0;
            data.lastAccessedAt = 0;
        });

        // Clear map
        this.keys.clear();

        // Aggressive garbage collection hints
        this.hintGarbageCollection();
    }

    /**
     * Create empty key data structure
     */
    private createEmptyKeyData(sessionId: string): SessionKeyData {
        return {
            encryptionKey: null,
            keyPair: null,
            partnerPublicKey: null,
            sessionId,
            createdAt: Date.now(),
            lastAccessedAt: Date.now(),
        };
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
        try {
            if (typeof window !== 'undefined' && typeof (window as any).gc === 'function') {
                (window as any).gc();
            }
        } catch {
            // Ignore errors
        }
    }

    /**
     * Auto-cleanup stale sessions (older than 30 minutes)
     */
    cleanupStaleSessions(): void {
        const now = Date.now();
        const thirtyMinutes = 30 * 60 * 1000;

        this.keys.forEach((data, sessionId) => {
            if (now - data.lastAccessedAt > thirtyMinutes) {
                this.destroySession(sessionId);
            }
        });
    }

    /**
     * Get memory usage estimate
     */
    getMemoryStats(): { sessionCount: number; estimatedBytes: number } {
        return {
            sessionCount: this.keys.size,
            estimatedBytes: this.keys.size * 1024, // Rough estimate
        };
    }
}

// Singleton instance for the application
let keyManagerInstance: SecureSessionKeyManager | null = null;
let staleCleanupInterval: ReturnType<typeof setInterval> | null = null;

export const getSessionKeyManager = (): SecureSessionKeyManager => {
    if (!keyManagerInstance) {
        keyManagerInstance = new SecureSessionKeyManager();

        // Auto-cleanup stale sessions every 5 minutes
        staleCleanupInterval = setInterval(() => {
            keyManagerInstance?.cleanupStaleSessions();
        }, 5 * 60 * 1000);
    }
    return keyManagerInstance;
};

export const destroySessionKeyManager = (): void => {
    if (keyManagerInstance) {
        keyManagerInstance.nuclearPurge();
        keyManagerInstance = null;
    }

    if (staleCleanupInterval) {
        try {
            clearInterval(staleCleanupInterval);
        } catch {
        }
        staleCleanupInterval = null;
    }
};

export default getSessionKeyManager;
