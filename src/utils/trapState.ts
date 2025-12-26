/**
 * GHOST MIRAGE: Trap State Management
 * 
 * Client-side only trap state tracking.
 * Uses sessionStorage - cleared when browser closes.
 * No server-side storage, no fingerprinting, no persistence.
 */

const STORAGE_KEY = 'ghost_mirage_state';

interface TrapState {
  decoyHits: number;
  firstAccessTime: number;
  lastActivityTime: number;
  escalationLevel: number; // 0 = none, 1 = warnings, 2 = admin panel, 3 = quarantine
  messagesTyped: number;
  reconnectAttempts: number;
  filesAttempted: number;
  twoFactorAttempts: number;
  commandsEntered: string[];
  phantomUsersShown: string[];
  tabFocusChanges: number;
  keystrokesLogged: number;
  paginationLoops: number;
}

const DEFAULT_STATE: TrapState = {
  decoyHits: 0,
  firstAccessTime: Date.now(),
  lastActivityTime: Date.now(),
  escalationLevel: 0,
  messagesTyped: 0,
  reconnectAttempts: 0,
  filesAttempted: 0,
  twoFactorAttempts: 0,
  commandsEntered: [],
  phantomUsersShown: [],
  tabFocusChanges: 0,
  keystrokesLogged: 0,
  paginationLoops: 0,
};

class TrapStateManager {
  private state: TrapState;

  constructor() {
    this.state = this.load();
  }

  private load(): TrapState {
    try {
      const stored = sessionStorage.getItem(STORAGE_KEY);
      if (stored) {
        return { ...DEFAULT_STATE, ...JSON.parse(stored) };
      }
    } catch (e) {}
    return { ...DEFAULT_STATE };
  }

  private save() {
    try {
      this.state.lastActivityTime = Date.now();
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(this.state));
    } catch (e) {}
  }

  // Get current state
  getState(): TrapState {
    return { ...this.state };
  }

  // Record a decoy endpoint hit
  recordDecoyHit(): number {
    this.state.decoyHits++;
    this.save();
    return this.state.decoyHits;
  }

  // Record pagination loop attempt
  recordPaginationLoop(): number {
    this.state.paginationLoops++;
    this.save();
    return this.state.paginationLoops;
  }

  // Record message typed
  recordMessage(): number {
    this.state.messagesTyped++;
    this.save();
    return this.state.messagesTyped;
  }

  // Record reconnect attempt
  recordReconnect(): number {
    this.state.reconnectAttempts++;
    this.save();
    return this.state.reconnectAttempts;
  }

  // Record file upload attempt
  recordFileAttempt(): number {
    this.state.filesAttempted++;
    this.save();
    return this.state.filesAttempted;
  }

  // Record 2FA attempt
  recordTwoFactorAttempt(): number {
    this.state.twoFactorAttempts++;
    this.save();
    return this.state.twoFactorAttempts;
  }

  // Record command entered in debug console
  recordCommand(cmd: string) {
    this.state.commandsEntered.push(cmd);
    if (this.state.commandsEntered.length > 100) {
      this.state.commandsEntered = this.state.commandsEntered.slice(-100);
    }
    this.save();
  }

  // Record phantom user shown
  recordPhantomUser(username: string) {
    if (!this.state.phantomUsersShown.includes(username)) {
      this.state.phantomUsersShown.push(username);
      this.save();
    }
  }

  // Record tab focus change
  recordTabFocusChange(): number {
    this.state.tabFocusChanges++;
    this.save();
    return this.state.tabFocusChanges;
  }

  // Record keystroke
  recordKeystroke(): number {
    this.state.keystrokesLogged++;
    this.save();
    return this.state.keystrokesLogged;
  }

  // Escalate trap level
  escalate(): number {
    if (this.state.escalationLevel < 3) {
      this.state.escalationLevel++;
      this.save();
    }
    return this.state.escalationLevel;
  }

  /**
   * Escalate to level 3 with full memory cleanup
   * Clears all decoy/trap data and prepares for quarantine redirect
   * This is safe and only affects DECOY sessions, never real data
   */
  async escalateToQuarantine(): Promise<void> {
    // Set escalation to max level
    this.state.escalationLevel = 3;
    
    // Mark for quarantine
    try {
      sessionStorage.setItem('ghost_escalation_level_3', 'true');
      sessionStorage.setItem('ghost_quarantine_timestamp', Date.now().toString());
    } catch (e) {
      // Storage may be restricted; continue with redirect
    }
    
    this.save();
    
    // Signal successful escalation
    console.warn('[GHOST] ⚠️ ESCALATION LEVEL 3: Quarantine initiated');
    console.warn('[GHOST] ⚠️ This is a TRANSPARENT SIMULATION for security testing');
    console.warn('[GHOST] ⚠️ Real user data is NOT affected');
  }

  // Check if should show admin panel (level 2)
  shouldShowAdminPanel(): boolean {
    return this.state.decoyHits >= 3 || this.state.escalationLevel >= 2;
  }

  // Check if should enter quarantine (level 3)
  shouldQuarantine(): boolean {
    const timeInTrap = Date.now() - this.state.firstAccessTime;
    const fifteenMinutes = 15 * 60 * 1000;
    
    return (
      this.state.escalationLevel >= 3 ||
      timeInTrap > fifteenMinutes ||
      this.state.reconnectAttempts > 10 ||
      this.state.twoFactorAttempts > 20
    );
  }

  // Get time spent in trap (ms)
  getTimeInTrap(): number {
    return Date.now() - this.state.firstAccessTime;
  }

  // Check if memory pressure should be shown (10+ minutes)
  shouldShowMemoryPressure(): boolean {
    return this.getTimeInTrap() > 10 * 60 * 1000;
  }

  // Calculate visual degradation amount (0-1)
  getVisualDegradation(): number {
    const timeInTrap = this.getTimeInTrap();
    const fifteenMinutes = 15 * 60 * 1000;
    return Math.min(1, timeInTrap / fifteenMinutes);
  }

  // Generate synthetic session reference
  generateSessionReference(): string {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789';
    let ref = 'GS-';
    for (let i = 0; i < 4; i++) {
      ref += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    ref += '-';
    for (let i = 0; i < 4; i++) {
      ref += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return ref;
  }

  // Clear all state
  clear() {
    this.state = { ...DEFAULT_STATE };
    try {
      sessionStorage.removeItem(STORAGE_KEY);
    } catch (e) {}
  }
}

// Singleton instance
export const trapState = new TrapStateManager();

export default trapState;
