import { createClient } from '@supabase/supabase-js';
import type { Database } from './types';

const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL;
const SUPABASE_PUBLISHABLE_KEY = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;

// SECURITY: Fail explicitly if environment variables are missing
if (!SUPABASE_URL || !SUPABASE_PUBLISHABLE_KEY) {
  throw new Error('Missing Supabase configuration. Set VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY.');
}

// SECURITY FIX: Use sessionStorage instead of localStorage for ephemeral auth
// Sessions are destroyed when browser closes - no disk persistence
export const supabase = createClient<Database>(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
  auth: {
    storage: {
      getItem: (key: string) => sessionStorage.getItem(key),
      setItem: (key: string, value: string) => sessionStorage.setItem(key, value),
      removeItem: (key: string) => sessionStorage.removeItem(key),
    },
    persistSession: false, // CRITICAL: No session persistence across browser restarts
    autoRefreshToken: false, // Disable auto-refresh for ephemeral sessions
    detectSessionInUrl: false, // Disable URL-based session detection
  },
});