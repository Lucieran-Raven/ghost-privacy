import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

declare const Deno: {
  env: {
    get(key: string): string | undefined;
  };
};

let cachedClient: ReturnType<typeof createClient> | null = null;

export function getSupabaseServiceClient() {
  if (cachedClient) return cachedClient;

  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if (!supabaseUrl || !supabaseServiceKey) {
    throw new Error('Missing Supabase service client environment');
  }

  cachedClient = createClient(supabaseUrl, supabaseServiceKey);
  return cachedClient;
}
