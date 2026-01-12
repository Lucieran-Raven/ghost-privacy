/**
 * Honeypot / Trap State Algorithms
 * Purpose: Provide deterministic trap-state transitions and quarantine/UX decision logic.
 * Input: Previous trap state, event inputs, and injected time/randomness.
 * Output: Next trap state and derived decisions.
 * Privacy: NEVER logs, NEVER stores, NEVER makes network requests, NEVER persists beyond caller-managed memory.
 */

export interface TrapState {
  decoyHits: number;
  firstAccessTime: number;
  lastActivityTime: number;
  escalationLevel: number;
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

export interface TrapDeps {
  now: () => number;
  randomInt: (maxExclusive: number) => number;
}

function clampNonNegativeInt(value: number, max: number): number {
  if (!Number.isFinite(value) || value < 0) return 0;
  return Math.min(Math.floor(value), max);
}

function sanitizeShortLabel(input: string, maxLen: number): string {
  const trimmed = input.trim().slice(0, maxLen);
  return trimmed;
}

export function createDefaultTrapState(deps: Pick<TrapDeps, 'now'>): TrapState {
  const now = deps.now();
  return {
    decoyHits: 0,
    firstAccessTime: now,
    lastActivityTime: now,
    escalationLevel: 0,
    messagesTyped: 0,
    reconnectAttempts: 0,
    filesAttempted: 0,
    twoFactorAttempts: 0,
    commandsEntered: [],
    phantomUsersShown: [],
    tabFocusChanges: 0,
    keystrokesLogged: 0,
    paginationLoops: 0
  };
}

function withActivity(state: TrapState, now: number): TrapState {
  return { ...state, lastActivityTime: now };
}

export function recordDecoyHit(state: TrapState, deps: Pick<TrapDeps, 'now'>): TrapState {
  const now = deps.now();
  return withActivity({ ...state, decoyHits: state.decoyHits + 1 }, now);
}

export function recordMessage(state: TrapState, deps: Pick<TrapDeps, 'now'>): TrapState {
  const now = deps.now();
  return withActivity({ ...state, messagesTyped: state.messagesTyped + 1 }, now);
}

export function recordReconnect(state: TrapState, deps: Pick<TrapDeps, 'now'>): TrapState {
  const now = deps.now();
  return withActivity({ ...state, reconnectAttempts: state.reconnectAttempts + 1 }, now);
}

export function recordFileAttempt(state: TrapState, deps: Pick<TrapDeps, 'now'>): TrapState {
  const now = deps.now();
  return withActivity({ ...state, filesAttempted: state.filesAttempted + 1 }, now);
}

export function recordTwoFactorAttempt(state: TrapState, deps: Pick<TrapDeps, 'now'>): TrapState {
  const now = deps.now();
  return withActivity({ ...state, twoFactorAttempts: state.twoFactorAttempts + 1 }, now);
}

export function recordCommand(state: TrapState, cmd: string, deps: Pick<TrapDeps, 'now'>): TrapState {
  const now = deps.now();
  const safeCmd = sanitizeShortLabel(typeof cmd === 'string' ? cmd : String(cmd), 256);
  const commandsEntered = [...state.commandsEntered, safeCmd];
  const trimmed = commandsEntered.length > 50 ? commandsEntered.slice(-50) : commandsEntered;
  return withActivity({ ...state, commandsEntered: trimmed }, now);
}

export function recordPhantomUser(state: TrapState, username: string, deps: Pick<TrapDeps, 'now'>): TrapState {
  const safeUsername = sanitizeShortLabel(typeof username === 'string' ? username : String(username), 64);
  if (safeUsername.length === 0) {
    return state;
  }
  if (state.phantomUsersShown.includes(safeUsername)) {
    return state;
  }
  const now = deps.now();
  const nextList = [...state.phantomUsersShown, safeUsername];
  const bounded = nextList.length > 100 ? nextList.slice(-100) : nextList;
  return withActivity({ ...state, phantomUsersShown: bounded }, now);
}

export function recordTabFocusChange(state: TrapState, deps: Pick<TrapDeps, 'now'>): { state: TrapState; count: number } {
  const now = deps.now();
  const next = state.tabFocusChanges + 1;
  return { state: withActivity({ ...state, tabFocusChanges: next }, now), count: next };
}

export function recordKeystroke(state: TrapState, deps: Pick<TrapDeps, 'now'>): { state: TrapState; count: number } {
  const now = deps.now();
  const next = state.keystrokesLogged + 1;
  return { state: withActivity({ ...state, keystrokesLogged: next }, now), count: next };
}

export function recordPaginationLoop(state: TrapState, deps: Pick<TrapDeps, 'now'>): { state: TrapState; count: number } {
  const now = deps.now();
  const next = state.paginationLoops + 1;
  return { state: withActivity({ ...state, paginationLoops: next }, now), count: next };
}

export function escalate(state: TrapState, deps: Pick<TrapDeps, 'now'>): { state: TrapState; level: number } {
  const now = deps.now();
  const nextLevel = state.escalationLevel < 3 ? state.escalationLevel + 1 : 3;
  return { state: withActivity({ ...state, escalationLevel: nextLevel }, now), level: nextLevel };
}

export function escalateToQuarantine(state: TrapState, deps: Pick<TrapDeps, 'now'>): TrapState {
  const now = deps.now();
  return withActivity({ ...state, escalationLevel: 3 }, now);
}

export function shouldShowAdminPanel(state: TrapState): boolean {
  return state.decoyHits >= 3 || state.escalationLevel >= 2;
}

export function shouldQuarantine(state: TrapState, now: number): boolean {
  if (!Number.isFinite(now) || !Number.isFinite(state.firstAccessTime)) {
    return true;
  }
  if (now < 0 || state.firstAccessTime < 0 || state.firstAccessTime > now) {
    return true;
  }
  const timeInTrap = now - state.firstAccessTime;
  const fifteenMinutes = 15 * 60 * 1000;

  return (
    state.escalationLevel >= 3 ||
    timeInTrap > fifteenMinutes ||
    clampNonNegativeInt(state.reconnectAttempts, 1000) > 10 ||
    clampNonNegativeInt(state.twoFactorAttempts, 10000) > 20
  );
}

export function getTimeInTrap(state: TrapState, now: number): number {
  return now - state.firstAccessTime;
}

export function shouldShowMemoryPressure(state: TrapState, now: number): boolean {
  return getTimeInTrap(state, now) > 10 * 60 * 1000;
}

export function getVisualDegradation(state: TrapState, now: number): number {
  const timeInTrap = getTimeInTrap(state, now);
  const fifteenMinutes = 15 * 60 * 1000;
  return Math.min(1, timeInTrap / fifteenMinutes);
}

export function generateSessionReference(deps: TrapDeps): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789';
  let ref = 'GS-';
  for (let i = 0; i < 4; i++) {
    ref += chars.charAt(deps.randomInt(chars.length));
  }
  ref += '-';
  for (let i = 0; i < 4; i++) {
    ref += chars.charAt(deps.randomInt(chars.length));
  }
  return ref;
}

export function nuclearPurge(state: TrapState): TrapState {
  return {
    ...state,
    decoyHits: 0,
    twoFactorAttempts: 0,
    reconnectAttempts: 0,
    escalationLevel: 0,
    lastActivityTime: 0,
    firstAccessTime: 0,
    messagesTyped: 0,
    filesAttempted: 0,
    commandsEntered: [],
    phantomUsersShown: [],
    tabFocusChanges: 0,
    keystrokesLogged: 0,
    paginationLoops: 0
  };
}
