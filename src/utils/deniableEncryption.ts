// Deniable File Encryption - VeraCrypt-style hidden volumes
// Two-key system: outer key shows decoy, inner key reveals real content

import { EncryptionEngine } from './encryption';

interface HiddenVolumeData {
  outerEncrypted: string;
  outerIv: string;
  innerEncrypted: string;
  innerIv: string;
  salt: string;
}

// Derive encryption key from password using PBKDF2
async function deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);
  
  // Import password as key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveKey']
  );
  
  // Ensure salt is a proper ArrayBuffer (handle SharedArrayBuffer case)
  const saltBuffer = new Uint8Array(salt).buffer as ArrayBuffer;
  
  // Derive AES-256 key using PBKDF2
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

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
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export class DeniableEncryption {
  /**
   * Create a hidden volume with two layers:
   * - Outer layer: decoy content (shown with wrong password)
   * - Inner layer: real content (shown with correct password)
   */
  static async createHiddenVolume(
    realContent: string,
    decoyContent: string,
    outerPassword: string,
    innerPassword: string
  ): Promise<HiddenVolumeData> {
    // Generate random salt
    const salt = crypto.getRandomValues(new Uint8Array(16));
    
    // Derive keys from passwords
    const outerKey = await deriveKeyFromPassword(outerPassword, salt);
    const innerKey = await deriveKeyFromPassword(innerPassword, salt);
    
    // Generate IVs
    const outerIv = crypto.getRandomValues(new Uint8Array(12));
    const innerIv = crypto.getRandomValues(new Uint8Array(12));
    
    // Encrypt decoy content with outer key
    const outerEncrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: outerIv },
      outerKey,
      new TextEncoder().encode(decoyContent)
    );
    
    // Encrypt real content with inner key
    const innerEncrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: innerIv },
      innerKey,
      new TextEncoder().encode(realContent)
    );
    
    return {
      outerEncrypted: arrayBufferToBase64(outerEncrypted),
      outerIv: arrayBufferToBase64(outerIv.buffer),
      innerEncrypted: arrayBufferToBase64(innerEncrypted),
      innerIv: arrayBufferToBase64(innerIv.buffer),
      salt: arrayBufferToBase64(salt.buffer)
    };
  }
  
  /**
   * Attempt to decrypt hidden volume
   * Returns decoy if outer password, real content if inner password
   * Returns null if neither password works
   */
  static async decryptHiddenVolume(
    data: HiddenVolumeData,
    password: string
  ): Promise<{ content: string; isDecoy: boolean } | null> {
    const salt = new Uint8Array(base64ToArrayBuffer(data.salt));
    const key = await deriveKeyFromPassword(password, salt);
    
    // Try inner (real) content first
    try {
      const innerIv = new Uint8Array(base64ToArrayBuffer(data.innerIv));
      const innerEncrypted = base64ToArrayBuffer(data.innerEncrypted);
      
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: innerIv },
        key,
        innerEncrypted
      );
      
      return {
        content: new TextDecoder().decode(decrypted),
        isDecoy: false
      };
    } catch {
      // Inner decryption failed, try outer
    }
    
    // Try outer (decoy) content
    try {
      const outerIv = new Uint8Array(base64ToArrayBuffer(data.outerIv));
      const outerEncrypted = base64ToArrayBuffer(data.outerEncrypted);
      
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: outerIv },
        key,
        outerEncrypted
      );
      
      return {
        content: new TextDecoder().decode(decrypted),
        isDecoy: true
      };
    } catch {
      // Both failed - wrong password
      return null;
    }
  }
  
  /**
   * Create a hidden file (wraps file data in hidden volume)
   */
  static async createHiddenFile(
    realFileBase64: string,
    decoyFileBase64: string,
    outerPassword: string,
    innerPassword: string
  ): Promise<string> {
    const hiddenVolume = await this.createHiddenVolume(
      realFileBase64,
      decoyFileBase64,
      outerPassword,
      innerPassword
    );
    
    // Pack into single blob
    return btoa(JSON.stringify(hiddenVolume));
  }
  
  /**
   * Decrypt a hidden file
   */
  static async decryptHiddenFile(
    packedData: string,
    password: string
  ): Promise<{ content: string; isDecoy: boolean } | null> {
    try {
      const hiddenVolume = JSON.parse(atob(packedData)) as HiddenVolumeData;
      return this.decryptHiddenVolume(hiddenVolume, password);
    } catch {
      return null;
    }
  }
}

// Generate secure decoy content based on file type
export function generateDecoyContent(fileType: string): string {
  const decoys: Record<string, string[]> = {
    image: [
      'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
      'Family vacation photo - Summer 2024',
      'Random cat photo from internet'
    ],
    document: [
      'Shopping list:\n- Milk\n- Bread\n- Eggs\n- Butter',
      'Meeting notes - Q4 Planning\nAttendees: Marketing team\nAgenda: Budget review',
      'Recipe: Chocolate Chip Cookies\n1. Preheat oven to 350°F\n2. Mix ingredients...'
    ],
    spreadsheet: [
      'Monthly Budget\nRent: $1500\nUtilities: $200\nGroceries: $400',
      'Workout Log\nMonday: Chest\nTuesday: Back\nWednesday: Rest'
    ],
    default: [
      'Lorem ipsum dolor sit amet, consectetur adipiscing elit.',
      'Nothing to see here - just random text.',
      'Personal notes - miscellaneous'
    ]
  };
  
  const category = decoys[fileType] || decoys.default;
  return category[Math.floor(Math.random() * category.length)];
}
