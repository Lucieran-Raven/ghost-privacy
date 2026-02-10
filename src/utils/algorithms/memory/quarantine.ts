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
  if (!indicators || typeof indicators !== 'object') return true;
  if (!Number.isFinite(now)) return true;
  if (!Number.isFinite(indicators.escalationLevel)) return true;
  if (!Number.isFinite(indicators.firstAccessTime)) return true;
  if (!Number.isFinite(indicators.reconnectAttempts)) return true;
  if (!Number.isFinite(indicators.twoFactorAttempts)) return true;
  if (indicators.escalationLevel < 0) return true;
  if (indicators.reconnectAttempts < 0) return true;
  if (indicators.twoFactorAttempts < 0) return true;
  if (indicators.firstAccessTime > now) return true;

  const timeInTrap = now - indicators.firstAccessTime;
  const fifteenMinutes = 15 * 60 * 1000;

  return (
    indicators.escalationLevel >= 3 ||
    timeInTrap > fifteenMinutes ||
    indicators.reconnectAttempts > 10 ||
    indicators.twoFactorAttempts > 20
  );
}
