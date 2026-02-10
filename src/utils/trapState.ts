/**
 * GHOST MIRAGE: Trap State Management
 * 
 * Client-side only trap state tracking.
 * Client-only state tracking.
 * No server-side storage, no fingerprinting, no persistence.
 */

import {
  createDefaultTrapState,
  escalate as escalateAlgorithm,
  escalateToQuarantine as escalateToQuarantineAlgorithm,
  generateSessionReference as generateSessionReferenceAlgorithm,
  getTimeInTrap as getTimeInTrapAlgorithm,
  getVisualDegradation as getVisualDegradationAlgorithm,
  nuclearPurge as nuclearPurgeAlgorithm,
  recordCommand as recordCommandAlgorithm,
  recordDecoyHit as recordDecoyHitAlgorithm,
  recordFileAttempt as recordFileAttemptAlgorithm,
  recordKeystroke as recordKeystrokeAlgorithm,
  recordMessage as recordMessageAlgorithm,
  recordPaginationLoop as recordPaginationLoopAlgorithm,
  recordPhantomUser as recordPhantomUserAlgorithm,
  recordReconnect as recordReconnectAlgorithm,
  recordTabFocusChange as recordTabFocusChangeAlgorithm,
  recordTwoFactorAttempt as recordTwoFactorAttemptAlgorithm,
  shouldQuarantine as shouldQuarantineAlgorithm,
  shouldShowAdminPanel as shouldShowAdminPanelAlgorithm,
  shouldShowMemoryPressure as shouldShowMemoryPressureAlgorithm,
  type TrapState
} from '@/utils/algorithms/deception/honeypot';

import { secureRandomInt } from '@/utils/secureRng';

class InMemoryTrapState {
  private state: TrapState = createDefaultTrapState({ now: () => Date.now() });
  private cleanupHandlersRegistered = false;

  constructor() {
    this.registerCleanupHandlers();
  }

  /**
   * Register aggressive cleanup handlers for memory-only storage
   */
  private registerCleanupHandlers(): void {
    if (this.cleanupHandlersRegistered) return;
    this.cleanupHandlersRegistered = true;

    if (typeof window === 'undefined' || typeof document === 'undefined') {
      return;
    }

    // Nuclear purge on browser close
    window.addEventListener('beforeunload', (e) => {
      try {
        const hasPrompt = typeof (e as any)?.returnValue === 'string' && (e as any).returnValue.length > 0;
        if (hasPrompt) {
          return;
        }
      } catch {
      }
      this.nuclearPurge();
    });

    // Nuclear purge on tab close
    window.addEventListener('unload', () => {
      this.nuclearPurge();
    });

    // Nuclear purge on page hide (mobile/PWA)
    window.addEventListener('pagehide', () => {
      this.nuclearPurge();
    });

    // Optional: Aggressive cleanup on tab hidden
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        // this.nuclearPurge(); // Uncomment for maximum security
      }
    });

    // Optional: Cleanup on window blur
    window.addEventListener('blur', () => {
      // this.nuclearPurge(); // Uncomment for maximum security
    });
  }

  private load(): TrapState {
    // Always start with fresh state to prevent forensic artifacts
    return createDefaultTrapState({ now: () => Date.now() });
  }

  private save() {
    // State exists ONLY in JavaScript heap memory
    this.state.lastActivityTime = Date.now();
  }

  getState(): TrapState {
    return { ...this.state };
  }

  recordDecoyHit(): void {
    this.state = recordDecoyHitAlgorithm(this.state, { now: () => Date.now() });
  }

  recordMessage(): void {
    this.state = recordMessageAlgorithm(this.state, { now: () => Date.now() });
  }

  recordReconnect(): void {
    this.state = recordReconnectAlgorithm(this.state, { now: () => Date.now() });
  }

  recordFileAttempt(): void {
    this.state = recordFileAttemptAlgorithm(this.state, { now: () => Date.now() });
  }

  recordTwoFactorAttempt(): void {
    this.state = recordTwoFactorAttemptAlgorithm(this.state, { now: () => Date.now() });
  }

  recordCommand(cmd: string) {
    this.state = recordCommandAlgorithm(this.state, cmd, { now: () => Date.now() });
  }

  recordPhantomUser(username: string) {
    this.state = recordPhantomUserAlgorithm(this.state, username, { now: () => Date.now() });
  }

  // Record tab focus change
  recordTabFocusChange(): number {
    const { state, count } = recordTabFocusChangeAlgorithm(this.state, { now: () => Date.now() });
    this.state = state;
    return count;
  }

  // Record keystroke
  recordKeystroke(): number {
    const { state, count } = recordKeystrokeAlgorithm(this.state, { now: () => Date.now() });
    this.state = state;
    return count;
  }

  // Record pagination loop
  recordPaginationLoop(): number {
    const { state, count } = recordPaginationLoopAlgorithm(this.state, { now: () => Date.now() });
    this.state = state;
    return count;
  }

  // Escalate trap level
  escalate(): number {
    const { state, level } = escalateAlgorithm(this.state, { now: () => Date.now() });
    this.state = state;
    return level;
  }

  /**
   * Escalate to level 3 with full memory cleanup
   * Clears all decoy/trap data and prepares for quarantine redirect
   * This is safe and only affects DECOY sessions, never real data
   */
  async escalateToQuarantine(): Promise<void> {
    this.state = escalateToQuarantineAlgorithm(this.state, { now: () => Date.now() });
  }

  // Check if should show admin panel (level 2)
  shouldShowAdminPanel(): boolean {
    return shouldShowAdminPanelAlgorithm(this.state);
  }

  // Check if should enter quarantine (level 3)
  shouldQuarantine(): boolean {
    return shouldQuarantineAlgorithm(this.state, Date.now());
  }

  // Get time spent in trap (ms)
  getTimeInTrap(): number {
    return getTimeInTrapAlgorithm(this.state, Date.now());
  }

  // Check if memory pressure should be shown (10+ minutes)
  shouldShowMemoryPressure(): boolean {
    return shouldShowMemoryPressureAlgorithm(this.state, Date.now());
  }

  // Calculate visual degradation amount (0-1)
  getVisualDegradation(): number {
    return getVisualDegradationAlgorithm(this.state, Date.now());
  }

  // Generate synthetic session reference
  generateSessionReference(): string {
    return generateSessionReferenceAlgorithm({
      now: () => Date.now(),
      randomInt: (maxExclusive) => secureRandomInt(maxExclusive)
    });
  }

  /**
   * NUCLEAR OPTION - Complete memory wipe
   */
  nuclearPurge(): void {
    // Overwrite all state with random data first
    const randomData = Array.from({ length: 100 }, () => secureRandomInt(0x1000000).toString(36));
    void randomData;
    
    // Clear all references
    this.state = nuclearPurgeAlgorithm(this.state);

    // Hint garbage collection
    try {
      const dummy = new Array(10000).fill(0);
      dummy.length = 0;
    } catch {
      // Ignore errors
    }
  }

  // Clear all state
  clear() {
    this.nuclearPurge();
  }
}

// Singleton instance
export const trapState = new InMemoryTrapState();

export default trapState;
