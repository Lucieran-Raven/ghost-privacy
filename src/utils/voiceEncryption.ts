// Secure Voice Encryption - Following Plantir Security Spec
// Zero-retention capture with per-message key derivation

import {
  decryptAudioChunk as decryptAudioChunkAlgorithm,
  encryptAudioChunk as encryptAudioChunkAlgorithm,
  secureZeroBuffer as secureZeroBufferAlgorithm,
  type EncryptedVoiceMessage
} from '@/utils/algorithms/encryption/voice';

export type { EncryptedVoiceMessage };

const voiceDeps = {
  subtle: crypto.subtle,
  getRandomValues: crypto.getRandomValues.bind(crypto),
  now: () => Date.now()
};

// Securely zero out a buffer (best effort in JS)
export function secureZeroBuffer(buffer: ArrayBuffer): void {
  secureZeroBufferAlgorithm({ getRandomValues: crypto.getRandomValues.bind(crypto) }, buffer);
}

// Encrypt audio chunk immediately after capture
export async function encryptAudioChunk(
  chunk: ArrayBuffer,
  sessionKey: CryptoKey,
  chunkIndex: number
): Promise<{ encrypted: string; iv: string }> {
  return encryptAudioChunkAlgorithm(voiceDeps, chunk, sessionKey, chunkIndex);
}

// Decrypt audio chunk for playback
export async function decryptAudioChunk(
  encryptedBase64: string,
  ivBase64: string,
  sessionKey: CryptoKey,
  chunkIndex: number,
  timestamp: number
): Promise<ArrayBuffer> {
  return decryptAudioChunkAlgorithm({ subtle: crypto.subtle }, encryptedBase64, ivBase64, sessionKey, chunkIndex, timestamp);
}

// Secure Voice Recorder Class
export class SecureVoiceRecorder {
  private mediaRecorder: MediaRecorder | null = null;
  private audioChunks: Blob[] = [];
  private stream: MediaStream | null = null;
  private sessionKey: CryptoKey | null = null;
  private chunkIndex: number = 0;
  private isRecording: boolean = false;
  private startTime: number = 0;

  constructor(sessionKey: CryptoKey) {
    this.sessionKey = sessionKey;
  }

  async startRecording(): Promise<void> {
    if (this.isRecording) return;
    
    try {
      this.stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          channelCount: 1,
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true
        }
      });

      const preferredMimeTypes = [
        'audio/webm;codecs=opus',
        'audio/webm',
        'audio/mp4',
        'audio/aac'
      ];

      const supportedMimeType = preferredMimeTypes.find((t) => {
        try {
          return MediaRecorder.isTypeSupported(t);
        } catch {
          return false;
        }
      });

      const options: MediaRecorderOptions = {
        audioBitsPerSecond: 24000
      };

      if (supportedMimeType) {
        options.mimeType = supportedMimeType;
      }

      this.mediaRecorder = new MediaRecorder(this.stream, options);

      this.audioChunks = [];
      this.chunkIndex = 0;
      this.startTime = Date.now();

      this.mediaRecorder.ondataavailable = (event) => {
        if (event.data.size > 0) {
          this.audioChunks.push(event.data);
        }
      };

      this.mediaRecorder.start(100); // 100ms chunks
      this.isRecording = true;
    } catch (err) {
      throw err;
    }
  }

  async stopRecording(): Promise<{ blob: Blob; duration: number }> {
    return new Promise((resolve, reject) => {
      if (!this.mediaRecorder || !this.isRecording) {
        reject(new Error('No recording in progress'));
        return;
      }

      this.mediaRecorder.onstop = () => {
        const duration = Date.now() - this.startTime;
        const blob = new Blob(this.audioChunks, { type: this.mediaRecorder?.mimeType });
        
        // Cleanup
        this.cleanup();
        
        resolve({ blob, duration });
      };

      this.mediaRecorder.stop();
      this.isRecording = false;
    });
  }

  cancelRecording(): void {
    if (this.mediaRecorder && this.isRecording) {
      this.mediaRecorder.stop();
    }
    this.cleanup();
  }

  private cleanup(): void {
    // Stop all tracks
    if (this.stream) {
      this.stream.getTracks().forEach(track => track.stop());
      this.stream = null;
    }
    
    // Clear chunks
    this.audioChunks = [];
    this.mediaRecorder = null;
    this.isRecording = false;
    
    // Hint garbage collection
    if (typeof (window as any).gc === 'function') {
      try { (window as any).gc(); } catch {}
    }
  }

  getIsRecording(): boolean {
    return this.isRecording;
  }
}

// Secure Voice Player Class - One-time playback
export class SecureVoicePlayer {
  private audioContext: AudioContext | null = null;
  private playedMessages: Set<string> = new Set();
  private currentSource: AudioBufferSourceNode | null = null;

  async playVoiceMessage(
    audioBlob: Blob,
    messageId: string,
    onPlaybackEnd: () => void
  ): Promise<void> {
    // Check for replay attacks
    if (this.playedMessages.has(messageId)) {
      throw new Error('Voice message already played - possible replay attack');
    }

    try {
      // Create audio context
      this.audioContext = new AudioContext();
      
      // Convert blob to array buffer
      const arrayBuffer = await audioBlob.arrayBuffer();
      
      // Decode audio data
      const audioBuffer = await this.audioContext.decodeAudioData(arrayBuffer);
      
      // Create source
      this.currentSource = this.audioContext.createBufferSource();
      this.currentSource.buffer = audioBuffer;
      this.currentSource.connect(this.audioContext.destination);
      
      // Mark as played (prevent replay)
      this.playedMessages.add(messageId);
      
      // Setup destruction after playback
      this.currentSource.onended = () => {
        this.destroyAudioData(audioBuffer, arrayBuffer, messageId);
        onPlaybackEnd();
      };
      
      // Start playback
      this.currentSource.start();
      
    } catch (error) {
      throw error;
    }
  }

  stopPlayback(): void {
    if (this.currentSource) {
      try {
        this.currentSource.stop();
      } catch {}
      this.currentSource = null;
    }
    this.closeContext();
  }

  private destroyAudioData(
    audioBuffer: AudioBuffer,
    decryptedBuffer: ArrayBuffer,
    _messageId: string
  ): void {
    // 1. Clear AudioBuffer channels with silence
    for (let i = 0; i < audioBuffer.numberOfChannels; i++) {
      const channel = audioBuffer.getChannelData(i);
      channel.fill(0);
    }
    
    // 2. Zero out decrypted buffer
    secureZeroBuffer(decryptedBuffer);
    
    // 3. Close audio context
    this.closeContext();
    
    // 4. Force garbage collection hint
    if (typeof (window as any).gc === 'function') {
      try { (window as any).gc(); } catch {}
    }
  }

  private closeContext(): void {
    if (this.audioContext) {
      try {
        this.audioContext.close();
      } catch {}
      this.audioContext = null;
    }
    this.currentSource = null;
  }

  // Clear played messages on session end
  clearPlayedMessages(): void {
    this.playedMessages.clear();
  }
}
