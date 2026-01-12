/**
 * Trap Audio Algorithm (selection + clamping)
 * Purpose: Provide deterministic selection and clamping logic for trap audio effects.
 * Input: effect type and requested volume.
 * Output: Embedded audio URI and safe volume.
 * Privacy: NEVER logs, NEVER stores, NEVER makes network requests, NEVER persists beyond caller-managed memory.
 */

export const AUDIO_DATA = {
  tick: 'data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1ueoiSkI+Cco93hZCJhXyDkYyKgHaDjIuIf4KEi4mCgIOJh4GBgoaFgYGCg4OCgYGBgYCBgYCAgICAgA==',
  join: 'data:audio/wav;base64,UklGRl9vT19teleUQAAAU05EAAAAAAYAAABsb29wAAAAAgAAACQAAABkYXRhUwAAAICA',
  type: 'data:audio/wav;base64,UklGRiQFAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YQAFAACA',
  access: 'data:audio/wav;base64,UklGRh4FAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YfoEAACA',
  ambient: 'data:audio/wav;base64,UklGRhwFAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YfgEAACA',
  focus: 'data:audio/wav;base64,UklGRh4FAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YfoEAACA'
} as const;

export type TrapAudioType = keyof typeof AUDIO_DATA;

export const MAX_VOLUME = 0.15;
export const AMBIENT_VOLUME = 0.08;

export function clampVolume(volume: number, max: number = MAX_VOLUME): number {
  if (!Number.isFinite(volume) || volume < 0) return 0;
  const safeMax = Number.isFinite(max) && max > 0 ? max : MAX_VOLUME;
  return Math.min(Math.max(volume, 0), safeMax);
}

export function getAudioUri(type: TrapAudioType): string {
  const uri = (AUDIO_DATA as Record<string, string>)[type as unknown as string];
  return typeof uri === 'string' ? uri : AUDIO_DATA.tick;
}
