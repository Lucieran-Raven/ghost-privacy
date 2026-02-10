/**
 * Distress Keyword Detection (client-only)
 * Purpose: Detect distress keywords locally to prioritize UX behavior without AI.
 * Input: plaintext message (string).
 * Output: boolean flags and matched keywords.
 * Privacy: NEVER logs, NEVER stores, NEVER makes network requests, NEVER persists beyond caller-managed memory.
 */

export interface DistressDetectionResult {
  matched: boolean;
  keywords: string[];
}

const DEFAULT_KEYWORDS = ['help', 'panic', 'emergency', 'SOS', 'police', 'unsafe'];

export function detectDistressKeywords(message: string, keywords: readonly string[] = DEFAULT_KEYWORDS): DistressDetectionResult {
  const normalized = message.toLowerCase();
  const matchedKeywords = keywords.filter((k) => normalized.includes(k.toLowerCase()));
  return {
    matched: matchedKeywords.length > 0,
    keywords: matchedKeywords
  };
}
