// Secure Voice Encryption - Following Plantir Security Spec
// Zero-retention capture with per-message key derivation

import { EncryptionEngine } from './encryption';

// Convert ArrayBuffer to base64
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Convert base64 to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// Securely zero out a buffer (best effort in JS)
export function secureZeroBuffer(buffer: ArrayBuffer): void {
  const view = new Uint8Array(buffer);
  crypto.getRandomValues(view); // Overwrite with random data first
  view.fill(0); // Then zero out
}

// Derive unique key per voice chunk using HKDF
async function deriveChunkKey(
  sessionKey: CryptoKey,
  chunkIndex: number,
  timestamp: number
): Promise<CryptoKey> {
  // Export session key for HKDF
  const sessionKeyData = await crypto.subtle.exportKey('raw', sessionKey);
  
  // Create unique info for this chunk
  const info = new TextEncoder().encode(`voice-chunk-${chunkIndex}-${timestamp}`);
  
  // Import as HKDF key
  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    sessionKeyData,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );
  
  // Derive per-chunk key
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32), // Could use random salt for extra security
      info
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

// Encrypt audio chunk immediately after capture
export async function encryptAudioChunk(
  chunk: ArrayBuffer,
  sessionKey: CryptoKey,
  chunkIndex: number
): Promise<{ encrypted: string; iv: string; chunkKey: string }> {
  const timestamp = Date.now();
  
  // Derive unique key for this chunk (Plantir's per-note key derivation)
  const chunkKey = await deriveChunkKey(sessionKey, chunkIndex, timestamp);
  
  // Generate random IV
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  // Encrypt chunk
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    chunkKey,
    chunk
  );
  
  // Export chunk key for receiver
  const exportedChunkKey = await crypto.subtle.exportKey('raw', chunkKey);
  
  return {
    encrypted: arrayBufferToBase64(encrypted),
    iv: arrayBufferToBase64(iv.buffer),
    chunkKey: arrayBufferToBase64(exportedChunkKey)
  };
}

// Decrypt audio chunk for playback
export async function decryptAudioChunk(
  encryptedBase64: string,
  ivBase64: string,
  chunkKeyBase64: string
): Promise<ArrayBuffer> {
  const encrypted = base64ToArrayBuffer(encryptedBase64);
  const iv = new Uint8Array(base64ToArrayBuffer(ivBase64));
  const chunkKeyData = base64ToArrayBuffer(chunkKeyBase64);
  
  // Import chunk key
  const chunkKey = await crypto.subtle.importKey(
    'raw',
    chunkKeyData,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  
  // Decrypt
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    chunkKey,
    encrypted
  );
}

// Package encrypted voice message
export interface EncryptedVoiceMessage {
  messageId: string;
  chunks: Array<{
    encrypted: string;
    iv: string;
    chunkKey: string;
  }>;
  totalDuration: number;
  timestamp: number;
  playedCount: number; // For replay protection
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
          sampleRate: 16000,
          echoCancellation: true,
          noiseSuppression: true
        }
      });

      // Determine supported MIME type
      const mimeType = MediaRecorder.isTypeSupported('audio/webm;codecs=opus')
        ? 'audio/webm;codecs=opus'
        : MediaRecorder.isTypeSupported('audio/webm')
          ? 'audio/webm'
          : 'audio/mp4';

      this.mediaRecorder = new MediaRecorder(this.stream, {
        mimeType,
        audioBitsPerSecond: 24000
      });

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
    } catch {
      throw new Error('Microphone access denied');
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
