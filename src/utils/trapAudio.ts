/**
 * GHOST MIRAGE: Trap Audio System
 * 
 * Subtle, non-startling audio feedback for honeypot traps.
 * All audio is client-side, volume-limited, and professional.
 * No sirens, no alarms - just ambiguity and uncertainty.
 */

 import {
   AMBIENT_VOLUME,
   MAX_VOLUME,
   clampVolume,
   getAudioUri,
   type TrapAudioType
 } from '@/utils/algorithms/deception/trapAudio';

 import { secureRandomInt } from '@/utils/secureRng';

class TrapAudioManager {
  private audioContext: AudioContext | null = null;
  private enabled: boolean = true;
  private ambientOscillator: OscillatorNode | null = null;
  private ambientGain: GainNode | null = null;

  constructor() {
    // Initialize on first interaction (browser requirement)
    if (typeof window !== 'undefined') {
      document.addEventListener('click', () => this.initContext(), { once: true });
      document.addEventListener('keydown', () => this.initContext(), { once: true });
    }
  }

  private initContext() {
    if (typeof window === 'undefined') return;
    if (!this.audioContext) {
      const Ctx = window.AudioContext || (window as any).webkitAudioContext;
      if (!Ctx) return;
      this.audioContext = new Ctx();
    }
  }

  // Enable/disable all audio
  setEnabled(enabled: boolean) {
    this.enabled = enabled;
    if (!enabled) {
      this.stopAmbient();
    }
  }

  // Play a short sound effect
  async play(type: TrapAudioType, volume: number = MAX_VOLUME) {
    if (!this.enabled) return;
    
    try {
      this.initContext();
      if (!this.audioContext) return;

      // Use Web Audio API for more control
      const audio = new Audio(getAudioUri(type));
      audio.volume = clampVolume(volume, MAX_VOLUME);
      await audio.play().catch(() => {}); // Silently fail if blocked
    } catch (e) {
      // Audio blocked - silent fail
    }
  }

  // Play tick sound for loading operations
  playTick() {
    this.play('tick', 0.1);
  }

  // Play join/leave sound for phantom users
  playJoin() {
    this.play('join', 0.12);
  }

  playLeave() {
    this.play('join', 0.08); // Same sound, quieter
  }

  // Play typing sound (not user's own typing)
  playType() {
    this.play('type', 0.05);
  }

  // Play access granted for fake admin discovery
  playAccessGranted() {
    this.play('access', MAX_VOLUME);
  }

  // Play focus notification when tab regains focus
  playFocusNotification() {
    this.play('focus', 0.1);
  }

  // Start ambient drone for quarantine state
  startAmbient() {
    if (!this.enabled || this.ambientOscillator) return;
    
    try {
      this.initContext();
      if (!this.audioContext) return;

      this.ambientOscillator = this.audioContext.createOscillator();
      this.ambientGain = this.audioContext.createGain();
      
      this.ambientOscillator.type = 'sine';
      this.ambientOscillator.frequency.setValueAtTime(60, this.audioContext.currentTime); // Low drone
      
      this.ambientGain.gain.setValueAtTime(0, this.audioContext.currentTime);
      this.ambientGain.gain.linearRampToValueAtTime(AMBIENT_VOLUME, this.audioContext.currentTime + 2);
      
      this.ambientOscillator.connect(this.ambientGain);
      this.ambientGain.connect(this.audioContext.destination);
      this.ambientOscillator.start();
    } catch (e) {
      // Audio blocked - silent fail
    }
  }

  // Stop ambient drone
  stopAmbient() {
    if (this.ambientOscillator && this.ambientGain && this.audioContext) {
      try {
        this.ambientGain.gain.linearRampToValueAtTime(0, this.audioContext.currentTime + 1);
        setTimeout(() => {
          this.ambientOscillator?.stop();
          this.ambientOscillator = null;
          this.ambientGain = null;
        }, 1000);
      } catch (e) {}
    }
  }

  // Periodic tick for fake operations
  startTickLoop(intervalMs: number = 500): () => void {
    const interval = setInterval(() => this.playTick(), intervalMs);
    return () => clearInterval(interval);
  }

  // Random typing sounds (not synced to user input)
  startPhantomTyping(): () => void {
    let running = true;
    let loopTimeout: ReturnType<typeof setTimeout> | null = null;

    const type = () => {
      if (!running) return;
      this.playType();
      // Random interval between 100-400ms
      loopTimeout = setTimeout(type, 100 + secureRandomInt(301));
    };

    const startTimeout = setTimeout(type, secureRandomInt(2000));

    // Stop after random duration (5-15 seconds)
    const stopTimeout = setTimeout(() => {
      running = false;
      if (loopTimeout) clearTimeout(loopTimeout);
      loopTimeout = null;
    }, 5000 + secureRandomInt(10001));

    return () => {
      running = false;
      clearTimeout(startTimeout);
      clearTimeout(stopTimeout);
      if (loopTimeout) clearTimeout(loopTimeout);
      loopTimeout = null;
    };
  }
}

// Singleton instance
export const trapAudio = new TrapAudioManager();

export default trapAudio;
