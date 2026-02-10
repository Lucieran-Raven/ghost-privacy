import { isTauriRuntime, tauriInvoke } from '@/utils/runtime';
import { bytesToBase64 } from '@/utils/algorithms/encoding/base64';

export interface DownloadOptions {
  fileName: string;
  mimeType?: string;
  data?: ArrayBuffer | Uint8Array | string;
}

/**
 * Detect if running on iOS
 */
function isIOS(): boolean {
  if (typeof navigator === 'undefined') return false;
  return /iPad|iPhone|iPod/.test(navigator.userAgent) && !(window as any).MSStream;
}

/**
 * Detect if running on Android
 */
function isAndroid(): boolean {
  if (typeof navigator === 'undefined') return false;
  return /Android/.test(navigator.userAgent);
}

/**
 * Detect if running on mobile
 */
function isMobile(): boolean {
  return isIOS() || isAndroid();
}

/**
 * Check if Web Share API with files is supported
 */
async function canShareFiles(): Promise<boolean> {
  if (typeof navigator === 'undefined') return false;
  const nav = navigator as any;
  if (typeof nav.canShare !== 'function') return false;
  if (typeof nav.share !== 'function') return false;
  if (typeof File === 'undefined') return false;
  
  try {
    const testFile = new File([''], 'test.txt', { type: 'text/plain' });
    return nav.canShare({ files: [testFile] });
  } catch {
    return false;
  }
}

/**
 * Download via Web Share API (best for mobile)
 */
async function downloadViaWebShare(blob: Blob, fileName: string, mimeType: string): Promise<boolean> {
  const nav = navigator as any;
  
  try {
    const file = new File([blob], fileName, { type: mimeType });
    
    if (typeof nav.canShare === 'function' && !nav.canShare({ files: [file] })) {
      return false;
    }
    
    await nav.share({
      files: [file],
      title: fileName,
    });
    
    return true;
  } catch (err) {
    // User cancelled or sharing failed
    return false;
  }
}

/**
 * Download via standard browser method
 */
async function downloadViaBrowser(url: string, fileName: string): Promise<boolean> {
  if (typeof document === 'undefined') return false;
  
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  link.rel = 'noopener noreferrer';
  link.style.display = 'none';
  
  document.body.appendChild(link);
  
  try {
    link.click();
    return true;
  } catch {
    // Fallback: try window.open for iOS
    if (isIOS()) {
      try {
        window.open(url, '_blank');
        return true;
      } catch {
        return false;
      }
    }
    return false;
  } finally {
    setTimeout(() => {
      try {
        document.body.removeChild(link);
      } catch {
        // Ignore
      }
    }, 100);
  }
}

/**
 * Download via Tauri native dialog
 */
async function downloadViaTauri(data: ArrayBuffer, fileName: string, mimeType: string): Promise<boolean> {
  if (!isTauriRuntime()) return false;
  
  try {
    const base64 = bytesToBase64(new Uint8Array(data));
    
    await tauriInvoke('save_file_dialog', {
      file_name: fileName,
      mime_type: mimeType,
      data_base64: base64,
    });
    
    return true;
  } catch {
    return false;
  }
}

/**
 * Download via Capacitor native plugin
 */
async function downloadViaCapacitor(data: ArrayBuffer, fileName: string, mimeType: string): Promise<boolean> {
  try {
    const mod = await import('@capacitor/core');
    const isNative = mod.Capacitor?.isNativePlatform?.();
    
    if (!isNative) return false;
    
    // Try FileSaver plugin first
    const isPluginAvailable = (mod.Capacitor as any).isPluginAvailable?.('FileSaver');
    if (!isPluginAvailable) return false;
    
    const FileSaver = mod.registerPlugin('FileSaver') as any;
    const base64 = bytesToBase64(new Uint8Array(data));
    
    await FileSaver.saveFile({
      data: base64,
      fileName,
      mimeType,
    });
    
    return true;
  } catch {
    return false;
  }
}

/**
 * Main cross-platform download function
 * Tries multiple methods in order of preference
 */
export async function crossPlatformDownload(options: DownloadOptions): Promise<boolean> {
  const { fileName, mimeType = 'application/octet-stream', data } = options;

  if (!data) {
    return false;
  }
  
  // Convert data to Blob
  let blob: Blob;
  let arrayBuffer: ArrayBuffer | null = null;
  let objectUrl: string | null = null;
  
  if (typeof data === 'string') {
    // data URL or blob URL
    if (data.startsWith('blob:')) {
      try {
        const response = await fetch(data);
        blob = await response.blob();
        arrayBuffer = await blob.arrayBuffer();
        objectUrl = data;
      } catch {
        return false;
      }
    } else if (data.startsWith('data:')) {
      // Convert data URL to blob
      try {
        const response = await fetch(data);
        blob = await response.blob();
        arrayBuffer = await blob.arrayBuffer();
      } catch {
        return false;
      }
    } else {
      return false;
    }
  } else if (data instanceof ArrayBuffer) {
    blob = new Blob([data], { type: mimeType });
    arrayBuffer = data;
  } else if (data instanceof Uint8Array) {
    blob = new Blob([data], { type: mimeType });
    arrayBuffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
  } else {
    return false;
  }
  
  // Method 1: Tauri native (desktop)
  if (isTauriRuntime() && arrayBuffer) {
    const success = await downloadViaTauri(arrayBuffer, fileName, mimeType);
    if (success) return true;
  }
  
  // Method 2: Capacitor native (mobile app)
  if (arrayBuffer) {
    const success = await downloadViaCapacitor(arrayBuffer, fileName, mimeType);
    if (success) return true;
  }
  
  // Method 3: Web Share API (best for mobile web)
  if (isMobile() && await canShareFiles()) {
    const success = await downloadViaWebShare(blob, fileName, mimeType);
    if (success) return true;
  }
  
  // Method 4: Standard browser download
  if (!objectUrl) {
    objectUrl = URL.createObjectURL(blob);
  }
  
  const success = await downloadViaBrowser(objectUrl, fileName);
  
  // Clean up object URL if we created it
  if (objectUrl && !options.data?.toString().startsWith('blob:')) {
    setTimeout(() => {
      URL.revokeObjectURL(objectUrl!);
    }, 30000);
  }
  
  return success;
}

/**
 * Legacy download function for backward compatibility
 * Uses the simplest method available
 */
export function legacyDownload(url: string, fileName: string): void {
  if (typeof document === 'undefined') return;
  
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  link.rel = 'noopener noreferrer';
  link.style.display = 'none';
  document.body.appendChild(link);
  
  try {
    link.click();
  } catch {
    window.open(url, '_blank');
  } finally {
    setTimeout(() => {
      try {
        document.body.removeChild(link);
      } catch {}
    }, 100);
  }
}
