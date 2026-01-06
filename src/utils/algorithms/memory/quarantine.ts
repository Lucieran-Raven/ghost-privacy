/**
 * Quarantine Decision Algorithm
 * Purpose: Determine whether a session should be isolated based on trap/escalation indicators.
 * Input: trap state summary and current time.
 * Output: quarantine decision.
 * Privacy: NEVER logs, NEVER stores, NEVER makes network requests, NEVER persists beyond caller-managed memory.
 */

export interface QuarantineIndicators {
  escalationLevel: number;
  firstAccessTime: number;
  reconnectAttempts: number;
  twoFactorAttempts: number;
}

export function shouldQuarantine(indicators: QuarantineIndicators, now: number): boolean {
  const timeInTrap = now - indicators.firstAccessTime;
  const fifteenMinutes = 15 * 60 * 1000;

  return (
    indicators.escalationLevel >= 3 ||
    timeInTrap > fifteenMinutes ||
    indicators.reconnectAttempts > 10 ||
    indicators.twoFactorAttempts > 20
  );
}
