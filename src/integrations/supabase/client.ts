import { createClient } from '@supabase/supabase-js';
import type { Database } from './types';

import { PUBLIC_SUPABASE_PUBLISHABLE_KEY, PUBLIC_SUPABASE_URL } from '@/config/publicEnv';

function scrubTelemetryHeaders(init?: RequestInit): RequestInit | undefined {
  if (!init || !init.headers) return init;
  const h = new Headers(init.headers);
  h.delete('x-client-info');
  h.delete('X-Client-Info');
  h.delete('x-supabase-api-version');
  h.delete('X-Supabase-Api-Version');
  return { ...init, headers: h };
}

const scrubbedFetch: typeof fetch = (input, init) => {
  return fetch(input as any, scrubTelemetryHeaders(init));
};

export const supabase = createClient<Database>(PUBLIC_SUPABASE_URL, PUBLIC_SUPABASE_PUBLISHABLE_KEY, {
  global: {
    fetch: scrubbedFetch,
  },
});
