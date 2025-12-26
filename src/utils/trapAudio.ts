/**
 * GHOST MIRAGE: Trap Audio System
 * 
 * Subtle, non-startling audio feedback for honeypot traps.
 * All audio is client-side, volume-limited, and professional.
 * No sirens, no alarms - just ambiguity and uncertainty.
 */

// Base64-encoded minimal audio clips (tiny, embedded, no external requests)
const AUDIO_DATA = {
  // Soft click for loading indicators
  tick: 'data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1ueoiSkI+Cco93hZCJhXyDkYyKgHaDjIuIf4KEi4mCgIOJh4GBgoaFgYGCg4OCgYGBgYCBgYCAgICAgA==',
  
  // Quiet notification for phantom user join/leave
  join: 'data:audio/wav;base64,UklGRl9vT19teleUQAAAU05EAAAAAAYAAABsb29wAAAAAgAAACQAAABkYXRhUwAAAICA',
  
  // Subtle typing sound
  type: 'data:audio/wav;base64,UklGRiQFAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YQAFAACA',
  
  // Access granted beep (for fake admin discovery)
  access: 'data:audio/wav;base64,UklGRh4FAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YfoEAACA',
  
  // Low ambient tone for quarantine
  ambient: 'data:audio/wav;base64,UklGRhwFAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YfgEAACA',
  
  // Focus notification chime
  focus: 'data:audio/wav;base64,UklGRh4FAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YfoEAACA',
};

// Volume limits - never startling
const MAX_VOLUME = 0.15; // 15% max
const AMBIENT_VOLUME = 0.08; // 8% for ambient

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
    if (!this.audioContext) {
      this.audioContext = new (window.AudioContext || (window as any).webkitAudioContext)();
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
  async play(type: keyof typeof AUDIO_DATA, volume: number = MAX_VOLUME) {
    if (!this.enabled) return;
    
    try {
      this.initContext();
      if (!this.audioContext) return;

      // Use Web Audio API for more control
      const audio = new Audio(AUDIO_DATA[type]);
      audio.volume = Math.min(volume, MAX_VOLUME);
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
    const type = () => {
      this.playType();
      // Random interval between 100-400ms
      setTimeout(type, 100 + Math.random() * 300);
    };
    
    const timeout = setTimeout(type, Math.random() * 2000);
    let running = true;
    
    // Stop after random duration (5-15 seconds)
    const stopTimeout = setTimeout(() => {
      running = false;
    }, 5000 + Math.random() * 10000);
    
    return () => {
      clearTimeout(timeout);
      clearTimeout(stopTimeout);
      running = false;
    };
  }
}

// Singleton instance
export const trapAudio = new TrapAudioManager();

export default trapAudio;
