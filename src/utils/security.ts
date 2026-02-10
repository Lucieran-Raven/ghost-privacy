// Security Manager - Fingerprinting and MITM Protection

import { isValidCapabilityToken, isValidSessionId } from '@/utils/algorithms/session/binding';

export class SecurityManager {
  private static sessionHostTokens: Map<string, string> = new Map();

  static async generateFingerprint(): Promise<string> {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  static setCapabilityToken(sessionId: string, capabilityToken: string): void {
    this.setHostToken(sessionId, capabilityToken);
  }

  static getCapabilityToken(sessionId: string): string | null {
    return this.getHostToken(sessionId);
  }

  static clearCapabilityToken(sessionId: string): void {
    this.clearHostToken(sessionId);
  }

  static clearAllCapabilityTokens(): void {
    this.clearAllHostTokens();
  }

  static setHostToken(sessionId: string, hostToken: string): void {
    if (!isValidSessionId(sessionId)) {
      throw new Error('invalid session id');
    }
    if (!isValidCapabilityToken(hostToken)) {
      throw new Error('invalid host token');
    }

    const existing = this.sessionHostTokens.get(sessionId);
    if (existing && existing !== hostToken) {
      throw new Error('host token already set');
    }

    this.sessionHostTokens.set(sessionId, hostToken);
  }

  static getHostToken(sessionId: string): string | null {
    return this.sessionHostTokens.get(sessionId) || null;
  }

  static clearHostToken(sessionId: string): void {
    this.sessionHostTokens.delete(sessionId);
  }

  static clearAllHostTokens(): void {
    this.sessionHostTokens.clear();
  }

  private static generateRandomBytes(length: number): string {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  private static arrayBufferToHex(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // Verify message signature using HMAC-SHA256
  static async signMessage(message: string, key: CryptoKey): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);

    try {
      const signature = await crypto.subtle.sign(
        { name: 'HMAC' },
        key,
        data
      );

      return this.arrayBufferToHex(signature);
    } finally {
      try {
        data.fill(0);
      } catch {
        // Ignore
      }
    }
  }

  // Generate HMAC key for message signing
  static async generateHMACKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify']
    );
  }
}

// Message validation
export const MESSAGE_VALIDATION = {
  MAX_LENGTH: 5000,
  MIN_LENGTH: 1
};

export const validateMessage = (text: string): { valid: boolean; error?: string } => {
  const trimmed = text.trim();
  
  if (!trimmed || trimmed.length < MESSAGE_VALIDATION.MIN_LENGTH) {
    return { valid: false, error: 'Message cannot be empty' };
  }
  
  if (trimmed.length > MESSAGE_VALIDATION.MAX_LENGTH) {
    return { valid: false, error: `Message exceeds ${MESSAGE_VALIDATION.MAX_LENGTH} characters` };
  }
  
  // Prevent potential injection attacks
  if (/<script|javascript:|on\w+=/i.test(trimmed)) {
    return { valid: false, error: 'Invalid message content detected' };
  }
  
  return { valid: true };
};

// File validation - EXPANDED for professional document types
export const FILE_VALIDATION = {
  MAX_SIZE: 20 * 1024 * 1024, // 20MB
  
  // Allowed file types - expanded for professionals
  ALLOWED_TYPES: [
    // Images
    'image/jpeg',
    'image/png', 
    'image/gif',
    'image/webp',
    
    // Videos - MP4 only (no recording, upload only)
    'video/mp4',
    
    // Documents (TOP PRIORITY)
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document', // .docx
    
    // Text files
    'text/plain',
    'text/csv',
    'application/rtf',
    
    // Spreadsheets
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', // .xlsx
    
    // Presentations
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation', // .pptx
    
    // Archives (with caution)
    'application/zip',
    'application/x-rar-compressed',
    
    // Code files
    'text/javascript',
    'application/json',
    'text/html',
    'text/css',
    'text/markdown'
  ] as const,
  
  // Dangerous types to block
  BLOCKED_TYPES: [
    'application/x-msdownload', // .exe
    'application/x-msdos-program',
    'application/x-msi', // installer
    'application/x-apple-diskimage', // .dmg
    'application/vnd.android.package-archive', // .apk
    'application/x-elf',
    'application/x-mach-binary'
  ] as const,

  // Dangerous extensions to block (covers platforms where MIME is empty/unknown)
  BLOCKED_EXTENSIONS: [
    'exe', 'com', 'bat', 'cmd', 'msi', 'msp',
    'apk', 'aab', 'dmg', 'app',
    'elf'
  ] as const,

  // Extensions that are allowed but should warn (scripts/macros). Not blocked because users may legitimately share them.
  WARN_EXTENSIONS: [
    'ps1', 'psm1', 'vbs', 'js', 'jse', 'wsf',
    'sh', 'bash', 'zsh', 'fish'
  ] as const,
  
  // User-friendly type names for display
  TYPE_NAMES: {
    'image/jpeg': 'JPEG Image',
    'image/png': 'PNG Image',
    'image/gif': 'GIF Image',
    'image/webp': 'WebP Image',
    'application/pdf': 'PDF Document',
    'application/msword': 'Word Document (.doc)',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'Word Document (.docx)',
    'text/plain': 'Text File',
    'text/csv': 'CSV Spreadsheet',
    'application/rtf': 'Rich Text File',
    'application/vnd.ms-excel': 'Excel Spreadsheet (.xls)',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'Excel Spreadsheet (.xlsx)',
    'application/vnd.ms-powerpoint': 'PowerPoint (.ppt)',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'PowerPoint (.pptx)',
    'application/zip': 'ZIP Archive',
    'application/x-rar-compressed': 'RAR Archive',
    'text/javascript': 'JavaScript File',
    'application/json': 'JSON File',
    'text/html': 'HTML File',
    'text/css': 'CSS File',
    'text/markdown': 'Markdown File'
  } as Record<string, string>,
  
  // Allowed extensions (fallback for unknown MIME types)
  ALLOWED_EXTENSIONS: [
    'jpg', 'jpeg', 'png', 'gif', 'webp',
    'mp4', // Video - MP4 only
    'pdf', 'doc', 'docx', 'txt', 'csv', 'rtf',
    'xls', 'xlsx', 'ppt', 'pptx',
  ] as const
};

export const validateFile = (file: File): { valid: boolean; error?: string; warning?: string } => {
  // Size check
  if (file.size > FILE_VALIDATION.MAX_SIZE) {
    return { 
      valid: false, 
      error: `File too large. Maximum size is ${FILE_VALIDATION.MAX_SIZE / 1024 / 1024}MB` 
    };
  }

  // Block dangerous types
  if (FILE_VALIDATION.BLOCKED_TYPES.includes(file.type as typeof FILE_VALIDATION.BLOCKED_TYPES[number])) {
    return { 
      valid: false, 
      error: 'This file type is not allowed for security reasons (executable files blocked)' 
    };
  }

  // Block dangerous extensions (mobile often provides empty/incorrect MIME)
  const extension = file.name.split('.').pop()?.toLowerCase() || '';
  if (extension && FILE_VALIDATION.BLOCKED_EXTENSIONS.includes(extension as typeof FILE_VALIDATION.BLOCKED_EXTENSIONS[number])) {
    return {
      valid: false,
      error: 'This file extension is not allowed for security reasons (executable/script blocked)'
    };
  }

  const allowedByExtension = extension
    ? ['pdf', 'doc', 'docx', 'ppt', 'pptx', 'jpg', 'jpeg', 'png', 'mp4'].includes(extension)
    : false;

  const allowedByMime = file.type
    ? [
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'image/jpeg',
        'image/png',
        'video/mp4'
      ].includes(file.type)
    : false;

  if (!allowedByExtension && !allowedByMime) {
    return {
      valid: false,
      error: 'Only PDF, Word, PowerPoint, JPEG/PNG images, and MP4 videos are supported'
    };
  }

  // Warn when we cannot confidently identify MIME.
  if (!file.type || file.type === 'application/octet-stream') {
    return { valid: true, warning: 'File type could not be detected (mobile limitation). Ensure this file is safe.' };
  }

  return { valid: true };
};

// Get user-friendly file type name
export const getFileTypeName = (file: File): string => {
  return FILE_VALIDATION.TYPE_NAMES[file.type] ||
         file.type ||
         `File (${file.name.split('.').pop()?.toUpperCase() || 'Unknown'})`;
};

// Get file icon based on type
export const getFileIcon = (file: File): string => {
  const type = file.type.toLowerCase();
  if (type.includes('pdf')) return '📄';
  if (type.includes('word') || type.includes('document')) return '📝';
  if (type.includes('excel') || type.includes('sheet')) return '📊';
  if (type.includes('powerpoint') || type.includes('presentation')) return '📽️';
  if (type.includes('image')) return '🖼️';
  if (type.includes('text') || type.includes('csv')) return '📃';
  if (type.includes('zip') || type.includes('rar')) return '🗜️';
  if (type.includes('javascript') || type.includes('json') || type.includes('html') || type.includes('css')) return '💻';
  return '📎';
};

export const sanitizeFileName = (name: string): string => {
  const input = String(name ?? '');
  const withoutControlChars = Array.from(input)
    .filter((ch) => {
      const code = ch.charCodeAt(0);
      return !(code <= 0x1f || code === 0x7f);
    })
    .join('');
  const stripped = withoutControlChars
    .replace(/[\\/]/g, '')
    .replace(/[<>:"'&|?*]/g, '')
    .replace(/\.{2,}/g, '.')
    .replace(/\s+/g, ' ')
    .trim();
  const limited = stripped.slice(0, 128);
  return limited || 'file';
};

// Format file size for display
export const formatFileSize = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
};

// Get file icon component name based on type (for Lucide icons)
export const getFileIconType = (fileName: string): 'pdf' | 'doc' | 'spreadsheet' | 'image' | 'archive' | 'code' | 'generic' => {
  const ext = fileName.split('.').pop()?.toLowerCase() || '';
  if (ext === 'pdf') return 'pdf';
  if (['doc', 'docx', 'rtf', 'txt', 'md'].includes(ext)) return 'doc';
  if (['xls', 'xlsx', 'csv'].includes(ext)) return 'spreadsheet';
  if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(ext)) return 'image';
  if (['zip', 'rar'].includes(ext)) return 'archive';
  if (['js', 'json', 'html', 'css'].includes(ext)) return 'code';
  return 'generic';
};