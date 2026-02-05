import { useState } from 'react';

/**
 * Purge/quarantine lifecycle UI state.
 *
 * Responsibilities:
 * - Owns quarantine-adjacent UI state: visibility shield, timestamp modal, and
 *   downloaded artifact tracking sets used for one-time download controls.
 *
 * Security guarantees:
 * - State is process-memory only and cleared on unmount/session teardown.
 *
 * Caveats:
 * - Destructive purge/zeroization execution remains in session teardown handlers.
 */
export function useQuarantine() {
  const [isWindowVisible, setIsWindowVisible] = useState(true);
  const [showTimestampSettings, setShowTimestampSettings] = useState(false);
  const [downloadedVideoDrops, setDownloadedVideoDrops] = useState<Set<string>>(new Set());
  const [downloadedFileDrops, setDownloadedFileDrops] = useState<Set<string>>(new Set());

  return {
    isWindowVisible,
    setIsWindowVisible,
    showTimestampSettings,
    setShowTimestampSettings,
    downloadedVideoDrops,
    setDownloadedVideoDrops,
    downloadedFileDrops,
    setDownloadedFileDrops
  };
}
