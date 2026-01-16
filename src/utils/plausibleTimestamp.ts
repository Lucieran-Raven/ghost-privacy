// Plausible Timestamps - Generate fake timestamps to break timing correlation
// Messages appear sent at random times within a configurable window

import { secureRandomInt } from '@/utils/secureRng';

export interface TimestampConfig {
  enabled: boolean;
  windowMinutes: number; // ±window from real time
  mode: 'random' | 'delayed' | 'advanced';
}

const DEFAULT_CONFIG: TimestampConfig = {
  enabled: false,
  windowMinutes: 120, // ±2 hours by default
  mode: 'random'
};

let currentConfig: TimestampConfig = { ...DEFAULT_CONFIG };

/**
 * Set timestamp obfuscation configuration
 */
export function setTimestampConfig(config: Partial<TimestampConfig>): void {
  currentConfig = { ...currentConfig, ...config };
}

/**
 * Get current timestamp configuration
 */
export function getTimestampConfig(): TimestampConfig {
  return { ...currentConfig };
}

/**
 * Generate a plausible fake timestamp based on configuration
 * @param realTimestamp - The actual timestamp
 * @returns An object with display timestamp and real timestamp
 */
export function generatePlausibleTimestamp(realTimestamp: number = Date.now()): {
  displayTimestamp: number;
  realTimestamp: number;
} {
  if (!currentConfig.enabled) {
    return { displayTimestamp: realTimestamp, realTimestamp };
  }
  
  const windowMs = currentConfig.windowMinutes * 60 * 1000;
  const safeWindowMs = Number.isFinite(windowMs) && windowMs > 0 ? Math.floor(windowMs) : 0;
  let offset: number;
  
  switch (currentConfig.mode) {
    case 'random':
      // Random offset within ±window
      offset = safeWindowMs > 0 ? secureRandomInt(safeWindowMs * 2 + 1) - safeWindowMs : 0;
      break;
      
    case 'delayed':
      // Always show as sent earlier (past)
      offset = safeWindowMs > 0 ? -secureRandomInt(safeWindowMs + 1) : 0;
      break;
      
    case 'advanced':
      // Always show as sent later (future)
      offset = safeWindowMs > 0 ? secureRandomInt(safeWindowMs + 1) : 0;
      break;
      
    default:
      offset = 0;
  }
  
  return {
    displayTimestamp: realTimestamp + offset,
    realTimestamp
  };
}

/**
 * Format timestamp for display
 */
export function formatTimestamp(timestamp: number): string {
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now.getTime() - timestamp;
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  
  // If in the future (due to advanced mode), show as "just now"
  if (diffMs < 0) {
    return 'just now';
  }
  
  // Less than 1 minute
  if (diffMins < 1) {
    return 'just now';
  }
  
  // Less than 1 hour
  if (diffMins < 60) {
    return `${diffMins}m ago`;
  }
  
  // Less than 24 hours
  if (diffHours < 24) {
    return `${diffHours}h ago`;
  }
  
  // Same year - show month/day
  if (date.getFullYear() === now.getFullYear()) {
    return date.toLocaleDateString(undefined, { 
      month: 'short', 
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }
  
  // Different year - show full date
  return date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });
}

/**
 * Generate batch of plausible timestamps for message history
 * Ensures timestamps are roughly chronological while still obfuscated
 */
export function generateBatchTimestamps(
  count: number,
  startTime: number = Date.now() - 3600000 // 1 hour ago
): number[] {
  if (!currentConfig.enabled) {
    const interval = 60000; // 1 minute between messages
    return Array.from({ length: count }, (_, i) => startTime + i * interval);
  }
  
  const timestamps: number[] = [];
  let currentTime = startTime;
  
  for (let i = 0; i < count; i++) {
    const { displayTimestamp } = generatePlausibleTimestamp(currentTime);
    timestamps.push(displayTimestamp);
    // Advance real time by 1-5 minutes randomly
    currentTime += secureRandomInt(240000) + 60000;
  }
  
  // Sort to maintain rough chronological order
  return timestamps.sort((a, b) => a - b);
}

/**
 * Check if timestamp obfuscation is currently active
 */
export function isTimestampObfuscationEnabled(): boolean {
  return currentConfig.enabled;
}
