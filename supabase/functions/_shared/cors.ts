/**
 * Shared CORS configuration for all Supabase Edge Functions
 * Environment-driven to prevent localhost origins in production
 */

export function getAllowedOrigins(): Set<string> {
  const env = Deno.env.get('ENVIRONMENT') || 'development';

  const nativeOrigins = [
    'tauri://localhost',
    'https://tauri.localhost',
    'http://tauri.localhost',
    'capacitor://localhost',
    'ionic://localhost',
    'http://localhost',
    'https://localhost',
    'http://127.0.0.1',
    'https://127.0.0.1',
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://[::1]:5173',
    'http://localhost:4173',
    'http://127.0.0.1:4173',
    'http://[::1]:4173',
    'http://10.0.2.2',
    'http://localhost:1420',
    'http://127.0.0.1:1420'
  ];

  if (env === 'production') {
    // Production: only allow explicit production origins
    const prodOrigins = Deno.env.get('PROD_ALLOWED_ORIGINS');
    if (prodOrigins) {
      return new Set([...prodOrigins.split(',').map(origin => origin.trim()), ...nativeOrigins]);
    }
    return new Set(['https://ghostprivacy.netlify.app', ...nativeOrigins]);
  }

  // Development/Staging: allow explicit dev origins (+ Lovable preview domains via suffix match)
  const devOrigins = Deno.env.get('DEV_ALLOWED_ORIGINS');
  if (devOrigins) {
    return new Set([...devOrigins.split(',').map(origin => origin.trim()), ...nativeOrigins]);
  }

  return new Set([
    'https://ghostprivacy.netlify.app',
    'http://localhost:8080',
    'http://127.0.0.1:8080',
    'http://[::1]:8080',
    ...nativeOrigins
  ]);
}

function safeHostname(origin: string): string | null {
  try {
    return new URL(origin).hostname;
  } catch {
    return null;
  }
}

/**
 * In development/staging we also accept Lovable preview origins without needing hardcoded IDs.
 * Production remains strict (exact-match via getAllowedOrigins).
 */
export function isAllowedOrigin(origin: string, allowedOrigins?: Set<string>): boolean {
  if (!origin) return false;
  const origins = allowedOrigins || getAllowedOrigins();
  if (origins.has(origin)) return true;

  const env = Deno.env.get('ENVIRONMENT') || 'development';
  if (env === 'production') return false;

  const hostname = safeHostname(origin);
  if (!hostname) return false;

  // Development/staging: allow localhost origins on any port.
  // This avoids hardcoding Vite dev ports and keeps production strict.
  if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
    return true;
  }

  return false;
}

export function corsHeaders(req: Request, allowedOrigins?: Set<string>) {
  const origin = req.headers.get('origin') || '';
  const allowOrigin = isAllowedOrigin(origin, allowedOrigins) ? origin : 'null';

  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Headers': 'authorization, apikey, content-type, x-ghost-session-id',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Vary': 'Origin'
  };
}

