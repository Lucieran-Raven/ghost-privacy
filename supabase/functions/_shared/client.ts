import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

declare const Deno: {
  env: {
    get(key: string): string | undefined;
  };
};

let cachedClient: ReturnType<typeof createClient> | null = null;

function scrubTelemetryHeaders(init?: RequestInit): RequestInit | undefined {
  if (!init || !init.headers) return init;
  const h = new Headers(init.headers);
  h.delete('x-client-info');
  h.delete('X-Client-Info');
  h.delete('x-supabase-api-version');
  h.delete('X-Supabase-Api-Version');
  return { ...init, headers: h };
}

const scrubbedFetch: typeof fetch = (input: RequestInfo | URL, init?: RequestInit) => {
  return fetch(input, scrubTelemetryHeaders(init));
};

export function getSupabaseServiceClient() {
  if (cachedClient) return cachedClient;

  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if (!supabaseUrl || !supabaseServiceKey) {
    throw new Error('Missing Supabase service client environment');
  }

  cachedClient = createClient(supabaseUrl, supabaseServiceKey, {
    global: {
      fetch: scrubbedFetch,
    },
  });
  return cachedClient;
}
